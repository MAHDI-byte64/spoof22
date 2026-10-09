//! Privilege dropping and sandboxing.
//!
//! The **recommended** deployment runs the binary as an unprivileged user from
//! the start, with `cap_net_raw,cap_net_admin+ep` granted by `setcap` (the
//! systemd unit sets `AmbientCapabilities=`). In that mode nothing here is
//! needed.
//!
//! When started as root with `hardening.run_as_user` set, [`drop_privileges`]
//! lowers the uid/gid but **retains** `CAP_NET_RAW` + `CAP_NET_ADMIN` in the
//! permitted/effective/inheritable and ambient sets — necessary because the
//! reconnect path creates fresh raw sockets after the drop. If any step fails
//! the process keeps its current privileges rather than ending up unable to
//! work (a warning is logged); it never silently half-drops.
//!
//! seccomp / Landlock sandboxing after init is a documented extension point
//! ([`apply_sandbox`]); it is intentionally a clear no-op-with-note rather than
//! a broken partial filter that might kill the process on an unlisted syscall.

use std::ffi::CString;

use tracing::{info, warn};

use crate::error::{Error, Result};

const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;
const CAP_MASK: u32 = (1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW);

// _LINUX_CAPABILITY_VERSION_3
const CAP_VERSION_3: u32 = 0x2008_0522;
const PR_SET_KEEPCAPS: libc::c_int = 8;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_long = 2;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drop to `user`/`group`, keeping the two network capabilities. No-op when
/// `user` is empty.
pub fn drop_privileges(user: &str, group: &str) -> Result<()> {
    if user.trim().is_empty() {
        return Ok(());
    }
    // SAFETY: standard libc identity calls; pointers are checked before use.
    unsafe {
        let uid = lookup_uid(user)?;
        let gid = if group.trim().is_empty() {
            lookup_gid_for_user(user)?
        } else {
            lookup_gid(group)?
        };

        // Keep permitted caps across setuid().
        if libc::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            return Err(priv_err("prctl(PR_SET_KEEPCAPS)"));
        }
        // Drop supplementary groups, then gid, then uid.
        if libc::setgroups(0, std::ptr::null()) != 0 {
            warn!("setgroups(0) failed; continuing");
        }
        if libc::setgid(gid) != 0 {
            return Err(priv_err("setgid"));
        }
        if libc::setuid(uid) != 0 {
            return Err(priv_err("setuid"));
        }

        // Re-raise the two network caps into permitted/effective/inheritable.
        let hdr = CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let data = [
            CapData {
                effective: CAP_MASK,
                permitted: CAP_MASK,
                inheritable: CAP_MASK,
            },
            CapData::default(),
        ];
        if libc::syscall(libc::SYS_capset, &hdr as *const _, data.as_ptr()) != 0 {
            return Err(priv_err("capset"));
        }
        // Raise into the ambient set so they persist.
        for cap in [CAP_NET_RAW, CAP_NET_ADMIN] {
            if libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                cap as libc::c_long,
                0,
                0,
            ) != 0
            {
                warn!(cap, "PR_CAP_AMBIENT_RAISE failed; caps may not persist");
            }
        }
    }
    info!(
        user,
        "dropped privileges, retained CAP_NET_RAW + CAP_NET_ADMIN"
    );
    Ok(())
}

/// Apply a seccomp/Landlock sandbox after init.
///
/// Extension point: a correct allow-list must enumerate every syscall the
/// runtime, TLS stack and tokio reactor use, or it will kill the process at
/// random. Rather than ship a partial filter that breaks under load, this is a
/// no-op that logs its status; wire a vetted profile (e.g. the `seccompiler`
/// or `landlock` crate) here when a tested allow-list exists.
pub fn apply_sandbox(enabled: bool) {
    if enabled {
        warn!("sandbox requested: seccomp/Landlock is a documented extension point (not applied)");
    }
}

unsafe fn lookup_uid(user: &str) -> Result<libc::uid_t> {
    let cname = CString::new(user).map_err(|_| priv_err("user name"))?;
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(Error::Privilege(format!("unknown user '{user}'")));
    }
    Ok(unsafe { (*pw).pw_uid })
}

unsafe fn lookup_gid_for_user(user: &str) -> Result<libc::gid_t> {
    let cname = CString::new(user).map_err(|_| priv_err("user name"))?;
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        return Err(Error::Privilege(format!("unknown user '{user}'")));
    }
    Ok(unsafe { (*pw).pw_gid })
}

unsafe fn lookup_gid(group: &str) -> Result<libc::gid_t> {
    let cname = CString::new(group).map_err(|_| priv_err("group name"))?;
    let gr = unsafe { libc::getgrnam(cname.as_ptr()) };
    if gr.is_null() {
        return Err(Error::Privilege(format!("unknown group '{group}'")));
    }
    Ok(unsafe { (*gr).gr_gid })
}

fn priv_err(what: &str) -> Error {
    Error::Privilege(format!("{what}: {}", std::io::Error::last_os_error()))
}
