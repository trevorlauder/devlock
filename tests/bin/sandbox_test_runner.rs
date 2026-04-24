//! Applies the production sandbox to a forked child running an escape probe, then exits with
//! the child's status. Agent config lives in `policy/agents/test.yaml`. The proxy is not
//! started because the probes do not exercise it.

use devlock::config::Config;
use devlock::sandbox::{self, ChildParams, temp};
use devlock::seccomp;
use devlock::sys;
use devlock::yaml_agent::YamlAgent;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork};
use std::env;
use std::os::fd::IntoRawFd;
use std::path::PathBuf;
use std::process::exit;

fn main() -> anyhow::Result<()> {
    let probe = env::args().nth(1).expect("probe name required");
    let probe_binary = env::var("DEVLOCK_PROBE_BIN")
        .map(PathBuf::from)
        .expect("DEVLOCK_PROBE_BIN must point at the escape-probe binary");

    let home = dirs::home_dir().expect("home");

    let tunnel = std::net::TcpListener::bind("127.0.0.1:0")?;
    let api = std::net::TcpListener::bind("127.0.0.1:0")?;
    let tunnel_port = tunnel.local_addr()?.port();
    let api_port = api.local_addr()?.port();
    drop(tunnel);
    drop(api);

    let session_token = "00000000000000000000000000000000".to_string();
    let tmp_dir = temp::create_devlock_tmp_dir()?;
    let sandbox_tmp = tmp_dir.path().to_path_buf();
    let probe_dir = probe_binary
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));

    let read_only_test_dir = sandbox_tmp.join("read_only_dir");
    std::fs::create_dir_all(&read_only_test_dir)?;
    std::fs::write(read_only_test_dir.join("HEAD"), b"inside read_only dir\n")?;
    let read_only_test_file = sandbox_tmp.join("read_only_test");
    std::fs::write(&read_only_test_file, b"do not replace\n")?;

    let agent = YamlAgent::new("test", &home)?;
    let cfg = Config::from_policy(agent.policy());
    let allowlist: Vec<String> = vec![];

    // Resolve buckets through the same pipeline main.rs uses so the supervisor lists match
    // Landlock.
    let resolved =
        sandbox::paths::collect_paths(&agent, &cfg, &home, Some(&sandbox_tmp), "default")?;
    let mut read_only_enforced = vec![read_only_test_dir.clone(), read_only_test_file.clone()];
    read_only_enforced.extend(resolved.read_only.iter().cloned());
    let mut allowed_exec = resolved.seccomp_exec();
    allowed_exec.push(probe_dir);

    let seccomp_policy = devlock::policy::seccomp::load()?;
    let supervisor_inputs = sandbox::parent::SupervisorInputs {
        read_only_enforced,
        allowed_write: resolved.seccomp_write(),
        allowed_delete: resolved.seccomp_delete(),
        allowed_read: resolved.seccomp_read(),
        allowed_exec,
        tunnel_port,
        api_port,
        clone3_allowed_flags: seccomp_policy.supervisor.clone3_allowed_flags,
        handlers: seccomp::handler_map(&seccomp_policy)?,
    };

    let (parent_sock, child_sock) = std::os::unix::net::UnixStream::pair()?;
    let parent_sock_fd = parent_sock.into_raw_fd();
    let child_sock_fd = child_sock.into_raw_fd();

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            sandbox::parent::activate_supervisor(
                child,
                parent_sock_fd,
                child_sock_fd,
                supervisor_inputs,
            )?;
            let status = waitpid(child, None)?;
            drop(tmp_dir);
            let code = match status {
                WaitStatus::Exited(_, code) => code,
                WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                _ => 3,
            };
            exit(code);
        }
        ForkResult::Child => {
            sys::close_fd(parent_sock_fd);
            let tmp_path = tmp_dir.path().to_path_buf();
            let result = sandbox::run_child(ChildParams {
                agent: &agent,
                tunnel_port,
                api_port,
                session_token: &session_token,
                home: &home,
                shell_exe: &probe_binary,
                args: vec![probe.clone()],
                shell: false,
                config: &cfg,
                allowlist: &allowlist,
                notify_sock: child_sock_fd,
                tmp_dir: &tmp_path,
                skip_verify: true,
                profile: "default",
            });
            eprintln!("child run_child returned: {result:?}");
            exit(64);
        }
    }
}
