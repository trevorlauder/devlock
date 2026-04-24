//! End to end smoke test. Spawns the real `devlock` binary against the
//! `test` agent and checks that the full fork, run_parent, run_child,
//! verify, exec path completes cleanly. Catches ordering bugs invisible
//! to the in-process test harness in `sandbox_test_runner`, like the
//! PR_SET_DUMPABLE race that blocked open_child_mem.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn full_flow_with_test_agent_exits_cleanly() {
    let devlock = env!("CARGO_BIN_EXE_devlock");
    let probe = env!("CARGO_BIN_EXE_escape-probe");
    let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy");

    let cwd = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(cwd.path().join(".git")).expect("mkdir .git");

    let out = Command::new(devlock)
        .current_dir(cwd.path())
        .arg("--agent")
        .arg("test")
        .arg("--")
        .arg("fs_write_etc")
        .env("DEVLOCK_PROBE_BIN", probe)
        .env("DEVLOCK_POLICY_DIR", &policy_dir)
        .output()
        .expect("spawn devlock");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "devlock did not exit cleanly.\nstatus: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status,
    );
}

#[test]
fn inspect_reports_required_landlock_abi() {
    // Inspect must surface the pinned Landlock ABI so an operator can
    // confirm the HardRequirement has not silently degraded. Regression
    // guard for a gap where inspect returned before calling
    // detect_landlock_abi and the ABI line was never printed.
    let devlock = env!("CARGO_BIN_EXE_devlock");
    let probe = env!("CARGO_BIN_EXE_escape-probe");
    let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy");

    let cwd = tempfile::tempdir().expect("tempdir");

    let out = Command::new(devlock)
        .current_dir(cwd.path())
        .arg("--agent")
        .arg("test")
        .arg("--inspect")
        .env("DEVLOCK_PROBE_BIN", probe)
        .env("DEVLOCK_POLICY_DIR", &policy_dir)
        .output()
        .expect("spawn devlock");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "devlock --inspect did not exit 0.\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("Landlock ABI: V6"),
        "inspect stderr must contain pinned ABI line.\nstderr:\n{stderr}",
    );
}

#[test]
fn session_logs_are_owner_only() {
    // A session at the same uid (or a tightened log root) must not expose
    // the supervisor telemetry to any other reader. The tracing layer used
    // to rely on umask, which yielded 0664 files and a 0775 log dir -
    // group- and world-readable on a default 0022 umask. This regression
    // pins the dir to 0700 and the log files to 0600.
    use std::os::unix::fs::PermissionsExt;
    let devlock = env!("CARGO_BIN_EXE_devlock");
    let probe = env!("CARGO_BIN_EXE_escape-probe");
    let policy_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy");

    let cwd = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(cwd.path().join(".git")).expect("mkdir .git");

    let out = Command::new(devlock)
        .current_dir(cwd.path())
        .arg("--agent")
        .arg("test")
        .arg("--")
        .arg("fs_write_etc")
        .env("DEVLOCK_PROBE_BIN", probe)
        .env("DEVLOCK_POLICY_DIR", &policy_dir)
        .output()
        .expect("spawn devlock");
    assert!(out.status.success(), "devlock did not exit cleanly");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let log_dir = stderr
        .lines()
        .find_map(|l| l.strip_prefix("[devlock] logs: "))
        .map(PathBuf::from)
        .expect("log dir banner missing from stderr");

    let dir_mode = std::fs::metadata(&log_dir)
        .expect("stat log dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode,
        0o700,
        "log dir {} must be 0700, got {dir_mode:o}",
        log_dir.display()
    );

    for name in ["seccomp.log", "network.log"] {
        let p = log_dir.join(name);
        let mode = std::fs::metadata(&p)
            .expect("stat log file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{} must be 0600, got {mode:o}", p.display());
    }
}
