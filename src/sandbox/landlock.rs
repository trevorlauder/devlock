use crate::sandbox::paths::ResolvedPaths;
use landlock::*;
use std::path::PathBuf;

/// Required Landlock ABI. Pinned to the latest version devlock was
/// audited against so newer access bits (Truncate, Refer, IoctlDev)
/// are guaranteed to be enforced. The previous fall-through loop
/// silently degraded on older kernels and let those bits slip.
const REQUIRED_ABI: ABI = ABI::V6;

pub fn detect_landlock_abi(tunnel_port: u16, api_port: u16) -> anyhow::Result<ABI> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_ABI))
        .map_err(|e| {
            anyhow::anyhow!(
                "Landlock ABI {:?} not supported by this kernel: {e}. \
                 devlock requires a kernel with full Landlock v6 support \
                 (Linux 6.10+). Refusing to start.",
                REQUIRED_ABI
            )
        })?;
    let abi = REQUIRED_ABI;

    let net_access = AccessNet::BindTcp | AccessNet::ConnectTcp;
    let scopes = Scope::AbstractUnixSocket | Scope::Signal;
    let fmt = |flags: Vec<String>| flags.join(" | ");
    eprintln!("Landlock ABI: {abi:?}");
    eprintln!(
        "  fs:    {}",
        fmt(AccessFs::from_all(abi)
            .iter()
            .map(|f| format!("{f:?}"))
            .collect())
    );
    let net_summary: Vec<String> = net_access
        .iter()
        .map(|a| match a {
            AccessNet::ConnectTcp => format!("{a:?} (ports {tunnel_port}, {api_port})"),
            a => format!("{a:?} (denied)"),
        })
        .collect();
    eprintln!("  net:   {}", net_summary.join(" | "));
    eprintln!(
        "  scope: {}",
        fmt(scopes.iter().map(|f| format!("{f:?}")).collect())
    );

    Ok(abi)
}

fn existing(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|p| p.exists()).collect()
}

pub fn apply_landlock(
    abi: ABI,
    tunnel_port: u16,
    api_port: u16,
    paths: ResolvedPaths,
) -> anyhow::Result<()> {
    let net_access = AccessNet::BindTcp | AccessNet::ConnectTcp;
    let scopes = Scope::AbstractUnixSocket | Scope::Signal;

    let read_exec = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let read_list = AccessFs::ReadFile | AccessFs::ReadDir;
    let read_write = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::RemoveFile
        | AccessFs::MakeDir
        | AccessFs::RemoveDir
        | AccessFs::MakeSock
        | AccessFs::MakeFifo;

    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(net_access)?
        .scope(scopes)?
        .create()?
        .add_rule(NetPort::new(tunnel_port, AccessNet::ConnectTcp))?
        .add_rule(NetPort::new(api_port, AccessNet::ConnectTcp))?
        .add_rules(path_beneath_rules(
            existing(paths.full_access),
            AccessFs::from_all(abi),
        ))?
        .add_rules(path_beneath_rules(existing(paths.read_exec), read_exec))?
        .add_rules(path_beneath_rules(existing(paths.read_list), read_list))?
        // dir_create deliberately omits ReadFile, WriteFile and Truncate.
        // Agents can list, create, or remove entries, and fully write a
        // file they just created (they hold the fd). They cannot read or
        // overwrite an existing file. To grant read or write on specific
        // children, list them under read_only or read_write.
        .add_rules(path_beneath_rules(
            existing(paths.dir_create),
            AccessFs::ReadDir
                | AccessFs::MakeReg
                | AccessFs::RemoveFile
                | AccessFs::MakeDir
                | AccessFs::RemoveDir,
        ))?
        .add_rules(path_beneath_rules(existing(paths.read_write), read_write))?
        .add_rules(path_beneath_rules(
            existing(paths.read_only),
            AccessFs::ReadFile,
        ))?
        .restrict_self()?;

    Ok(())
}
