use devlock::agent;
use devlock::cli;
use devlock::config;
use devlock::path_safety;
use devlock::policy;
use devlock::proxy;
use devlock::sandbox;
use devlock::seccomp;
use devlock::sys;

use agent::AgentCredentials;
use anyhow::Context;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use std::env;
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use tempfile::TempDir;
use which::which;
use zeroize::Zeroize;

struct ParentContext {
    session_token: String,
    supervisor_inputs: sandbox::parent::SupervisorInputs,
    creds: AgentCredentials,
    tunnel_listener: std::net::TcpListener,
    api_listener: std::net::TcpListener,
    allowlist: Vec<String>,
    tmp_dir: TempDir,
    log_dir: PathBuf,
    tunnel_config: policy::agent::TunnelConfig,
    proxy_config: policy::agent::ProxyConfig,
}

fn run_parent(
    child: nix::unistd::Pid,
    parent_sock_fd: RawFd,
    child_sock_fd: RawFd,
    context: ParentContext,
) -> anyhow::Result<()> {
    let ParentContext {
        session_token,
        supervisor_inputs,
        mut creds,
        tunnel_listener,
        api_listener,
        allowlist,
        tmp_dir,
        log_dir,
        tunnel_config,
        proxy_config,
    } = context;

    // Fork the proxy before any thread spawns so the supervisor can zero its
    // heap copies of the OAuth tokens. A later supervisor compromise then
    // cannot read them from /proc/self/mem.
    let mut session_token_for_proxy = session_token.clone();
    let mut access_token = std::mem::take(&mut creds.access_token);
    let mut refresh_token = std::mem::take(&mut creds.refresh_token);
    let proxy_pid = match unsafe { fork() }? {
        ForkResult::Child => {
            sys::close_fd(parent_sock_fd);
            sys::close_fd(child_sock_fd);
            drop(supervisor_inputs);

            // Supervisor owns tmp_dir. Forget this process's copy so
            // any ? below cannot unwind TempDir::drop and remove the
            // scratch directory the supervisor and agent still use.
            std::mem::forget(tmp_dir);

            // Die with the supervisor so a skipped kill path cannot orphan
            // a process still holding the refresh token.
            unsafe {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
            }

            init_tracing(&log_dir)?;

            // Apply sandbox after tracing opens its files (landlock denies
            // writes outside log_dir) and before tokio starts, so the filter
            // does not need to cover runtime bootstrap.
            sandbox::proxy_restrict::restrict_proxy_worker(&log_dir)?;

            let res = proxy::run_proxy(
                proxy::ProxyCredentials {
                    access_token,
                    refresh_token,
                    expires_at_ms: creds.expires_at_ms,
                    session_token: session_token_for_proxy,
                },
                proxy::ProxyListeners {
                    tunnel: tunnel_listener,
                    api: api_listener,
                },
                allowlist,
                tunnel_config,
                proxy_config,
            );
            let code = if res.is_ok() { 0 } else { 1 };
            std::process::exit(code);
        }
        ForkResult::Parent { child: pid } => {
            drop(tunnel_listener);
            drop(api_listener);
            drop(allowlist);
            access_token.zeroize();
            refresh_token.zeroize();
            session_token_for_proxy.zeroize();
            creds.expires_at_ms = 0;
            pid
        }
    };

    init_tracing(&log_dir)?;
    eprintln!("[devlock] logs: {}", log_dir.display());
    eprintln!("[devlock] proxy pid: {proxy_pid}");

    sandbox::parent::activate_supervisor(child, parent_sock_fd, child_sock_fd, supervisor_inputs)?;

    // SIGKILL both children on any shutdown signal so the cleanup thread
    // can drop tmp_dir before exit. Repeat on every signal so a second
    // Ctrl-C still works if the first one raced.
    std::thread::spawn(move || {
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ])
        .expect("install signal handler");
        for _ in signals.forever() {
            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::signal::kill(proxy_pid, nix::sys::signal::Signal::SIGKILL);
        }
    });

    // Supervise both children. Whichever dies first, kill the other so the
    // session tears down as a unit: a live sandbox with a dead proxy is
    // useless, and a live proxy without its agent is just a credential
    // server with no speaker.
    let log_dir_for_cleanup = log_dir.clone();
    std::thread::spawn(move || {
        let child_status = wait_both(child, proxy_pid);
        drop(tmp_dir);
        print_post_mortem(&log_dir_for_cleanup, child_status);
        exit(0);
    });

    // The main thread has nothing else to do. Park until the cleanup
    // thread calls exit(). We cannot simply return because that would run
    // Drop on stack state the cleanup thread still needs.
    loop {
        std::thread::park();
    }
}

/// Wait for both children to exit. When the first dies, SIGKILL the other
/// and keep reaping until both are gone. Returns the sandboxed-agent's
/// WaitStatus (not the proxy's) so print_post_mortem can surface the
/// agent's death cause if one exists.
fn wait_both(child: Pid, proxy_pid: Pid) -> Option<WaitStatus> {
    let mut child_status: Option<WaitStatus> = None;
    let mut child_dead = false;
    let mut proxy_dead = false;
    while !(child_dead && proxy_dead) {
        match waitpid(None, None) {
            Ok(status) => {
                let pid = match status {
                    WaitStatus::Exited(p, _) | WaitStatus::Signaled(p, _, _) => p,
                    _ => continue,
                };
                if pid == child {
                    child_status = Some(status);
                    child_dead = true;
                    if !proxy_dead {
                        let _ =
                            nix::sys::signal::kill(proxy_pid, nix::sys::signal::Signal::SIGKILL);
                    }
                } else if pid == proxy_pid {
                    proxy_dead = true;
                    if !child_dead {
                        let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                    }
                }
            }
            Err(_) => break,
        }
    }
    child_status
}

/// Print a short post-mortem to stderr when the child exits abnormally.
/// Stays quiet on clean exits so normal sessions aren't noisy.
fn print_post_mortem(log_dir: &Path, status: Option<nix::sys::wait::WaitStatus>) {
    use nix::sys::wait::WaitStatus;

    let (abnormal, header) = match status {
        Some(WaitStatus::Exited(_, 0)) => (false, String::new()),
        Some(WaitStatus::Exited(_, code)) => (true, format!("agent exited with code {code}")),
        Some(WaitStatus::Signaled(_, sig, _)) => (true, format!("agent killed by signal {sig:?}")),
        _ => (false, String::new()),
    };
    if !abnormal {
        return;
    }

    eprintln!("[devlock] {header}");

    let log_path = log_dir.join("seccomp.log");
    let contents = match std::fs::read_to_string(&log_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[devlock] no log to report");
            return;
        }
    };
    // ERROR lines are death causes. Surface all of them - there's rarely
    // more than one and it's the smoking gun.
    let errors: Vec<&str> = contents
        .lines()
        .filter(|l| l.contains("\"level\":\"ERROR\""))
        .collect();
    if !errors.is_empty() {
        eprintln!("[devlock] fatal events:");
        for l in &errors {
            eprintln!("  {l}");
        }
    }

    // File denials - exclude high-frequency noise (unix_connect_denied,
    // notify_recv_error) that drowns out the signal.
    let denies: Vec<&str> = contents
        .lines()
        .filter(|l| l.contains("\"event\":\"denied\""))
        .collect();
    if denies.is_empty() && errors.is_empty() {
        eprintln!("[devlock] no denials recorded");
    } else if !denies.is_empty() {
        let tail = denies.len().saturating_sub(5);
        eprintln!("[devlock] last denials:");
        for l in &denies[tail..] {
            eprintln!("  {l}");
        }
    }
    eprintln!("[devlock] log: {}", log_path.display());
}

fn init_tracing(log_dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Mutex;
    use tracing_subscriber::{Layer, Registry, filter::filter_fn, fmt, prelude::*};

    // 0600 so another process at the same uid (or group members if the log
    // root ever loosens from 0700) cannot read or tamper with the session
    // telemetry that drives supervisor post-mortems.
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true).mode(0o600);
    let seccomp_file = open.open(log_dir.join(path_safety::reject_traversal("seccomp.log")?))?;
    let network_file = open.open(log_dir.join(path_safety::reject_traversal("network.log")?))?;

    let seccomp_layer = fmt::layer()
        .json()
        .with_writer(Mutex::new(seccomp_file))
        .with_filter(filter_fn(|m| m.target() == "seccomp"));

    let network_layer = fmt::layer()
        .json()
        .with_writer(Mutex::new(network_file))
        .with_filter(filter_fn(|m| m.target() == "proxy"));

    Registry::default()
        .with(seccomp_layer)
        .with(network_layer)
        .try_init()
        .map_err(|e| anyhow::anyhow!("tracing subscriber init failed: {e}"))?;
    Ok(())
}

fn new_log_dir() -> anyhow::Result<PathBuf> {
    // A plain directory, not a TempDir. Logs persist across sessions in
    // $XDG_STATE_HOME/devlock/logs so developers can inspect prior runs
    // after logout. Stale entries are pruned at startup by
    // prune_old_logs.
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let root = sys::devlock_logs_root()?;
    let home = dirs::home_dir().context("no home dir")?;
    let root_canonical =
        path_safety::safe_canonical_under(&root, &[home.as_path(), Path::new("/tmp")])
            .with_context(|| format!("refusing unsafe logs dir {}", root.display()))?;
    let suffix = format!("logs-{ts}-{pid}");
    path_safety::reject_traversal(&suffix)?;
    let dir = root_canonical.join(&suffix);
    std::fs::create_dir_all(&dir)?;
    // Narrow from umask-influenced default to 0700 so group or world can't
    // list logs even if the containing $XDG_STATE_HOME/devlock/logs parent
    // is ever loosened beyond its current 0700.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

const LOG_RETENTION: std::time::Duration = std::time::Duration::from_secs(14 * 24 * 60 * 60);

/// Best-effort removal of `logs-*` subdirs older than LOG_RETENTION.
/// Errors are swallowed so a stale permission or symlink never blocks startup.
fn prune_old_logs(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("logs-") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        let Ok(age) = now.duration_since(mtime) else {
            continue;
        };
        if age > LOG_RETENTION {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn pick_shell() -> anyhow::Result<PathBuf> {
    const SUPPORTED: &[&str] = &["zsh", "bash"];

    if let Ok(requested) = env::var("SHELL")
        && let Some(name) = Path::new(&requested).file_name().and_then(|s| s.to_str())
        && SUPPORTED.contains(&name)
        && let Ok(path) = which(name)
    {
        return Ok(path);
    }

    for name in SUPPORTED {
        if let Ok(path) = which(name) {
            return Ok(path);
        }
    }

    Err(anyhow::anyhow!(
        "no supported shell found in PATH (need zsh or bash)"
    ))
}

fn main() -> anyhow::Result<()> {
    let shell_exe = pick_shell()?;
    let home = dirs::home_dir().context("no home dir")?;

    let args = cli::parse_args();
    // Guarantees policy::install::cleanup runs even on early `?` returns
    // below (bad agent name, bucket conflict, missing creds, etc.). Without
    // this the static OVERLAY leaks its TempDir into $XDG_RUNTIME_DIR/devlock
    // on every error path because Rust does not drop statics at process exit.
    let _overlay_guard = policy::install::OverlayGuard;
    let yaml_agent = cli::make_yaml_agent(&args.agent_name, &home)?;
    let policy_snapshot = yaml_agent.policy().clone();
    let agent: Box<dyn agent::Agent> = Box::new(yaml_agent);

    if !agent.is_authenticated() {
        eprintln!("No credentials. Running login.");
        if let Err(e) = agent.login() {
            eprintln!("Login failed: {e}");
            exit(1);
        }
        let exe = env::current_exe()?;
        let orig_args: Vec<String> = env::args().skip(1).collect();
        return Err(Command::new(&exe).args(&orig_args).exec().into());
    }

    let creds = agent.credentials()?;

    let cfg = config::Config::from_policy(&policy_snapshot);
    cfg.validate()?;
    // Merge the agent's own allowlist with the profile's. Both sides are
    // policy owned so append-only is safe.
    let mut merged_allowlist = agent.allowlist();
    merged_allowlist.extend(devlock::policy::filesystem::load(&args.profile)?.network_allowlist);
    let allowlist = cfg.normalized_allowlist(merged_allowlist);

    let session_token = sys::random_hex(32)?;
    let tmp_dir = sandbox::temp::create_devlock_tmp_dir()?;
    if let Ok(logs_root) = sys::devlock_logs_root() {
        prune_old_logs(&logs_root);
    }
    let log_dir = new_log_dir()?;

    let tunnel_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let tunnel_port = tunnel_listener.local_addr()?.port();
    let api_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let api_port = api_listener.local_addr()?.port();

    let resolved =
        sandbox::collect_paths(&*agent, &cfg, &home, Some(tmp_dir.path()), &args.profile)?;
    // Policy files have been read into memory; the materialized overlay is
    // no longer needed. Static overlay state doesn't Drop at process exit,
    // so clean up explicitly here.
    policy::install::cleanup();
    if args.inspect {
        // Surface the required Landlock ABI up front so operators can confirm
        // the HardRequirement pin is intact before the sandbox even runs.
        // Also acts as a fast fail on kernels that do not support V6.
        sandbox::detect_landlock_abi(tunnel_port, api_port)?;
        sandbox::log_resolved_config(&sandbox::InspectContext {
            agent: &*agent,
            agent_name: &args.agent_name,
            profile_name: &args.profile,
            tunnel_port,
            api_port,
            home: &home,
            tmp_dir: tmp_dir.path(),
            allowlist: &allowlist,
            paths: &resolved,
        });
        return Ok(());
    }
    let seccomp_policy = devlock::policy::seccomp::load()?;
    let supervisor_inputs = sandbox::parent::SupervisorInputs {
        read_only_enforced: resolved.read_only.clone(),
        allowed_write: resolved.seccomp_write(),
        allowed_delete: resolved.seccomp_delete(),
        allowed_read: resolved.seccomp_read(),
        allowed_exec: resolved.seccomp_exec(),
        tunnel_port,
        api_port,
        clone3_allowed_flags: seccomp_policy.supervisor.clone3_allowed_flags,
        handlers: seccomp::handler_map(&seccomp_policy)?,
    };

    let (parent_sock, child_sock) = std::os::unix::net::UnixStream::pair()?;
    let parent_sock_fd = parent_sock.into_raw_fd();
    let child_sock_fd = child_sock.into_raw_fd();

    let tmp_path = tmp_dir.path().to_path_buf();

    match unsafe { fork() }? {
        ForkResult::Parent { child } => run_parent(
            child,
            parent_sock_fd,
            child_sock_fd,
            ParentContext {
                session_token,
                supervisor_inputs,
                creds,
                tunnel_listener,
                api_listener,
                allowlist,
                tmp_dir,
                log_dir,
                tunnel_config: cfg.tunnel.clone(),
                proxy_config: policy_snapshot.proxy.clone(),
            },
        ),
        ForkResult::Child => {
            sys::close_fd(parent_sock_fd);
            sandbox::run_child(sandbox::ChildParams {
                agent: &*agent,
                tunnel_port,
                api_port,
                session_token: &session_token,
                home: &home,
                shell_exe: &shell_exe,
                args: args.passthrough,
                shell: args.shell,
                config: &cfg,
                allowlist: &allowlist,
                notify_sock: child_sock_fd,
                tmp_dir: &tmp_path,
                skip_verify: false,
                profile: &args.profile,
            })?;
            Ok(())
        }
    }
}
