//! Explicit privilege drop so the child runs unprivileged regardless of how the parent was
//! invoked. NoNewPrivs is set ourselves rather than relying on landlock or seccomp crate
//! side effects.

use std::io;

pub fn set_no_new_privs() -> io::Result<()> {
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// No op without CAP_SETPCAP. Matters under sudo so a later exec cannot pick up residual caps.
pub fn drop_bounding_set() {
    for cap in 0..64 {
        let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            break;
        }
    }
}

/// Ambient caps survive exec, so a non empty set under sudo would otherwise leak into the shell.
pub fn clear_ambient_caps() {
    let _ = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
}

/// Locks the cap model so a setuid exec cannot regain privileges. Silent without CAP_SETPCAP.
pub fn lock_securebits() {
    let bits: libc::c_ulong = (libc::SECBIT_NOROOT
        | libc::SECBIT_NOROOT_LOCKED
        | libc::SECBIT_NO_SETUID_FIXUP
        | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
        | libc::SECBIT_KEEP_CAPS_LOCKED) as libc::c_ulong;
    let _ = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0) };
}

/// Zero effective, permitted, and inheritable so the agent holds no caps
/// even under sudo or as root. Must run after calls that need CAP_SETPCAP.
pub fn drop_all_caps() {
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    unsafe {
        libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr());
    }
}
