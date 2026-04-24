//! Orchestrates Landlock and seccomp setup for the forked child.
mod error;
mod exec;
mod landlock;
pub mod paths;
pub use landlock::detect_landlock_abi;
pub use paths::{InspectContext, collect_paths, log_resolved_config};
pub mod parent;
mod privs;
pub mod proxy_restrict;
mod seccomp;
pub mod temp;
mod verify;

use crate::agent::Agent;
use crate::sandbox::error::DevlockError;
use std::os::fd::RawFd;
use std::path::Path;

pub struct ChildParams<'a> {
    pub agent: &'a dyn Agent,
    pub tunnel_port: u16,
    pub api_port: u16,
    pub session_token: &'a str,
    pub home: &'a Path,
    pub shell_exe: &'a Path,
    pub args: Vec<String>,
    pub shell: bool,
    pub config: &'a crate::config::Config,
    pub allowlist: &'a [String],
    pub notify_sock: RawFd,
    /// Parent owned scratch. The child writes into it but never creates or removes it.
    pub tmp_dir: &'a Path,
    /// Skip runtime verification, which requires a running proxy.
    pub skip_verify: bool,
    pub profile: &'a str,
}

pub fn run_child(params: ChildParams<'_>) -> anyhow::Result<()> {
    // Landlock requires NoNewPrivs without CAP_SYS_ADMIN. Set it ourselves
    // rather than relying on a crate side effect.
    privs::set_no_new_privs()
        .map_err(|e| DevlockError::Policy(format!("set PR_SET_NO_NEW_PRIVS. {e}")))?;

    let abi = landlock::detect_landlock_abi(params.tunnel_port, params.api_port)
        .map_err(|e| DevlockError::Policy(e.to_string()))?;
    let paths = paths::collect_paths(
        params.agent,
        params.config,
        params.home,
        Some(params.tmp_dir),
        params.profile,
    )
    .map_err(|e| DevlockError::Policy(e.to_string()))?;

    let path_prepend = paths.path_prepend.clone();
    let base_env = paths.base_env.clone();
    landlock::apply_landlock(abi, params.tunnel_port, params.api_port, paths)
        .map_err(|e| DevlockError::Policy(e.to_string()))?;

    // Close every cap surface before seccomp. Bounding covers future exec,
    // ambient survives exec, securebits locks the model against re enablement.
    // drop_all_caps runs last so the calls that need CAP_SETPCAP see it first.
    privs::drop_bounding_set();
    privs::clear_ambient_caps();
    privs::lock_securebits();
    privs::drop_all_caps();

    seccomp::install_seccomp_notify(params.notify_sock)
        .map_err(|e| DevlockError::Policy(format!("seccomp notify install failed. {e}")))?;

    if !params.skip_verify {
        verify::verify_policy(
            params.agent,
            params.tunnel_port,
            params.api_port,
            params.session_token,
        )?;
    }

    Err(exec::exec_agent(exec::ExecParams {
        agent: params.agent,
        shell: params.shell,
        shell_exe: params.shell_exe,
        args: params.args,
        home: params.home,
        tmp_dir: params.tmp_dir,
        tunnel_port: params.tunnel_port,
        api_port: params.api_port,
        session_token: params.session_token,
        path_prepend: &path_prepend,
        base_env: &base_env,
    })
    .into())
}
