use crate::agent::Agent;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const DENIED_PASSTHROUGH_ENV: &[&str] = &[
    // Devlock sets these itself. A parent value would conflict or be wrong.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "PATH",
    "HOME",
    "ZDOTDIR",
    "TMPDIR",
    // Dynamic linker: load arbitrary native code or redirect library resolution.
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_ASSUME_KERNEL",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DYNAMIC_WEAKER",
    "LD_POINTER_GUARD",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    // glibc internals: redirect charset, locale, and resolver lookups to arbitrary files.
    "GCONV_PATH",
    "GETCONF_DIR",
    "GLIBC_TUNABLES",
    "HOSTALIASES",
    "LOCPATH",
    "NLSPATH",
    "RES_OPTIONS",
    // Shell startup hooks: sourced or executed before any policy takes effect.
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    // Language runtimes: module/script paths and flag injection.
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "RUBYLIB",
    "RUBYOPT",
    "GEM_PATH",
    "GEM_HOME",
];

#[must_use]
pub fn is_passthrough_env_allowed(key: &str) -> bool {
    !DENIED_PASSTHROUGH_ENV
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key))
}

// Bash needs explicit flags to skip real dotfiles; zsh uses ZDOTDIR instead.
fn shell_args(shell_exe: &Path) -> Vec<String> {
    let name = shell_exe.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name == "bash" {
        vec!["--norc".to_string(), "--noprofile".to_string()]
    } else {
        vec![]
    }
}

fn build_child_path(path_prepend: &[PathBuf]) -> String {
    path_prepend
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

pub struct ExecParams<'a> {
    pub agent: &'a dyn Agent,
    pub shell: bool,
    pub shell_exe: &'a Path,
    pub args: Vec<String>,
    pub home: &'a Path,
    pub tmp_dir: &'a Path,
    pub tunnel_port: u16,
    pub api_port: u16,
    pub session_token: &'a str,
    pub path_prepend: &'a [PathBuf],
    pub base_env: &'a [(String, String)],
}

/// Build the complete env vec in precedence order: hardcoded shell env <
/// base YAML env < passthrough < agent YAML (non-locked) < locked. Pure
/// so it can be unit tested without fork/exec.
pub(crate) fn build_child_env(
    home: &Path,
    tmp_dir: &Path,
    tunnel_port: u16,
    path_prepend: &[PathBuf],
    base_env: &[(String, String)],
    passthrough_env: &[(String, Option<String>)],
    agent_env: &[(String, String)],
) -> Vec<(String, String)> {
    let tunnel_url = format!("http://127.0.0.1:{tunnel_port}");
    let locked: [(&str, String); 5] = [
        ("HOME", home.to_string_lossy().into_owned()),
        ("TMPDIR", tmp_dir.to_string_lossy().into_owned()),
        ("PATH", build_child_path(path_prepend)),
        ("HTTPS_PROXY", tunnel_url),
        ("NO_PROXY", "127.0.0.1,localhost".to_string()),
    ];
    let locked_keys: std::collections::HashSet<&str> = locked.iter().map(|(k, _)| *k).collect();

    let mut out: Vec<(String, String)> = Vec::new();
    let push = |out: &mut Vec<(String, String)>, k: &str, v: String| {
        if let Some(slot) = out.iter_mut().find(|(ek, _)| ek == k) {
            slot.1 = v;
        } else {
            out.push((k.to_string(), v));
        }
    };

    push(&mut out, "ZDOTDIR", tmp_dir.to_string_lossy().into_owned());
    push(
        &mut out,
        "ZSH_COMPDUMP",
        tmp_dir.join(".zcompdump").to_string_lossy().into_owned(),
    );
    push(&mut out, "ZSH_DISABLE_COMPFIX", "true".to_string());
    push(&mut out, "HISTFILE", String::new());
    push(&mut out, "HISTSIZE", "0".to_string());
    push(&mut out, "SAVEHIST", "0".to_string());
    push(&mut out, "TERM", std::env::var("TERM").unwrap_or_default());

    for (key, value) in base_env {
        if locked_keys.contains(key.as_str()) {
            eprintln!("[devlock] base env var {key} is locked by devlock, skipping");
            continue;
        }
        push(&mut out, key, value.clone());
    }

    for (key, value) in passthrough_env {
        if !is_passthrough_env_allowed(key) {
            eprintln!("[devlock] rejected passthrough env var: {key}");
            continue;
        }
        if let Some(v) = value {
            push(&mut out, key, v.clone());
        }
    }

    for (key, value) in agent_env {
        if locked_keys.contains(key.as_str()) {
            eprintln!("[devlock] agent env var {key} is locked by devlock, skipping");
            continue;
        }
        push(&mut out, key, value.clone());
    }

    for (key, value) in &locked {
        push(&mut out, key, value.clone());
    }
    out
}

pub fn exec_agent(params: ExecParams<'_>) -> std::io::Error {
    let (program, cmd_args) = if params.shell {
        (
            params.shell_exe.to_string_lossy().to_string(),
            shell_args(params.shell_exe),
        )
    } else {
        let mut all_args = params.agent.extra_args(params.tmp_dir);
        all_args.extend(params.args);
        (
            params.agent.executable().to_string_lossy().to_string(),
            all_args,
        )
    };

    let agent_env = params.agent.env_vars(
        params.home,
        params.tmp_dir,
        params.tunnel_port,
        params.api_port,
        params.session_token,
    );
    let env = build_child_env(
        params.home,
        params.tmp_dir,
        params.tunnel_port,
        params.path_prepend,
        params.base_env,
        &[],
        &agent_env,
    );

    let mut cmd = Command::new(&program);
    cmd.args(&cmd_args).env_clear();
    for (key, value) in &env {
        cmd.env(key, value);
    }

    // Set non-dumpable as the last step before exec to guard the brief pre-exec
    // window against same-UID ptrace. Must come after seccomp install and
    // devlock verification because PR_SET_DUMPABLE=0 prevents the parent from
    // reading /proc/{pid}/mem, which the seccomp supervisor requires.
    // exec(2) resets dumpable to 1 for non-setuid binaries, so this only covers
    // the window between the prctl call and the execve syscall itself.
    let _ = nix::sys::prctl::set_dumpable(false);

    cmd.exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_args_picks_bash_flags_for_bash_path() {
        assert_eq!(
            shell_args(Path::new("/usr/bin/bash")),
            vec!["--norc".to_string(), "--noprofile".to_string()]
        );
        assert_eq!(
            shell_args(Path::new("/bin/bash")),
            vec!["--norc", "--noprofile"]
        );
    }

    #[test]
    fn shell_args_returns_nothing_for_zsh() {
        let empty: Vec<String> = vec![];
        assert_eq!(shell_args(Path::new("/usr/bin/zsh")), empty);
        assert_eq!(shell_args(Path::new("/bin/zsh")), empty);
    }

    #[test]
    fn denied_list_is_case_insensitive() {
        assert!(!is_passthrough_env_allowed("ld_preload"));
        assert!(!is_passthrough_env_allowed("Ld_Audit"));
        assert!(!is_passthrough_env_allowed("http_proxy"));
    }

    #[test]
    fn build_child_path_joins_with_colons_in_order() {
        let dirs = vec![
            PathBuf::from("/first"),
            PathBuf::from("/second"),
            PathBuf::from("/third"),
        ];
        assert_eq!(build_child_path(&dirs), "/first:/second:/third");
    }

    #[test]
    fn build_child_path_empty() {
        assert_eq!(build_child_path(&[]), "");
    }

    fn env_get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn locked_env_wins_over_agent_yaml_env() {
        // Agent tries to reroute HOME, PATH, HTTPS_PROXY, NO_PROXY, TMPDIR.
        // Devlock's locked values must win.
        let agent_env: Vec<(String, String)> = vec![
            ("HOME".into(), "/pwn".into()),
            ("PATH".into(), "/pwn/bin".into()),
            ("HTTPS_PROXY".into(), "http://evil:1/".into()),
            ("NO_PROXY".into(), "evil".into()),
            ("TMPDIR".into(), "/pwn/tmp".into()),
            ("ANTHROPIC_BASE_URL".into(), "http://127.0.0.1:9/".into()),
        ];
        let home = PathBuf::from("/home/u");
        let tmp = PathBuf::from("/tmp/devlock-x");
        let prepend = vec![PathBuf::from("/usr/bin")];

        let env = build_child_env(&home, &tmp, 4242, &prepend, &[], &[], &agent_env);

        assert_eq!(env_get(&env, "HOME"), Some("/home/u"));
        assert_eq!(env_get(&env, "TMPDIR"), Some("/tmp/devlock-x"));
        assert_eq!(env_get(&env, "PATH"), Some("/usr/bin"));
        assert_eq!(env_get(&env, "HTTPS_PROXY"), Some("http://127.0.0.1:4242"));
        assert_eq!(env_get(&env, "NO_PROXY"), Some("127.0.0.1,localhost"));
        // Non locked agent env still passes through.
        assert_eq!(
            env_get(&env, "ANTHROPIC_BASE_URL"),
            Some("http://127.0.0.1:9/")
        );
    }

    #[test]
    fn agent_env_beats_passthrough_but_passthrough_blocklist_rejected() {
        let passthrough = vec![
            ("ANTHROPIC_BASE_URL".into(), Some("http://parent/".into())),
            ("NODE_OPTIONS".into(), Some("--inspect".into())),
            ("LD_PRELOAD".into(), Some("/tmp/evil.so".into())),
        ];
        let agent_env: Vec<(String, String)> =
            vec![("ANTHROPIC_BASE_URL".into(), "http://127.0.0.1:9/".into())];
        let home = PathBuf::from("/home/u");
        let tmp = PathBuf::from("/tmp/d");
        let env = build_child_env(&home, &tmp, 1, &[], &[], &passthrough, &agent_env);

        // Agent value wins.
        assert_eq!(
            env_get(&env, "ANTHROPIC_BASE_URL"),
            Some("http://127.0.0.1:9/")
        );
        // Passthrough blocklist rejects LD_PRELOAD and NODE_OPTIONS.
        assert!(env_get(&env, "LD_PRELOAD").is_none());
        assert!(env_get(&env, "NODE_OPTIONS").is_none());
    }
}
