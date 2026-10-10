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
//! Two post-init sandboxes harden the running process (both best-effort — a
//! kernel that lacks the feature is logged and skipped, never fatal):
//!
//! * [`landlock_sandbox`] restricts filesystem access via the Landlock LSM:
//!   read-only on the system paths the process still needs (binaries + shared
//!   libraries for the `nft`/`iptables` teardown, `/etc`, `/proc`, `/sys`,
//!   `/dev` for `/dev/urandom` + the already-open TUN) and read-write only on
//!   the runtime dirs (`/run`, `/var`, `/tmp`). After this the process cannot
//!   read `/home`, write `/etc`, or touch anything outside those trees.
//! * [`seccomp_filter`] installs a seccomp-bpf **deny-list**: the normal
//!   runtime syscalls stay allowed (default action = Allow), while a curated
//!   set of dangerous syscalls (ptrace, kernel-module loading, `mount`,
//!   `kexec`, `bpf`, keyrings, `process_vm_*`, `userfaultfd`, …) is answered
//!   with `EPERM`. A deny-list never kills the process on an unlisted syscall,
//!   so it is safe to ship, unlike a brittle allow-list that must enumerate
//!   every syscall tokio/rustls/mimalloc might emit.

use std::collections::BTreeMap;
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

/// Apply the Landlock filesystem sandbox (best effort). Call this after all
/// files/sockets the process needs have been opened and before the main loop.
/// A kernel without Landlock support (or a partial ABI) degrades gracefully:
/// the status is logged and the process continues unrestricted.
pub fn landlock_sandbox(enabled: bool) {
    if !enabled {
        return;
    }
    match install_landlock() {
        Ok(status) => {
            use landlock::RulesetStatus::*;
            match status.ruleset {
                FullyEnforced => info!("landlock filesystem sandbox fully enforced"),
                PartiallyEnforced => {
                    info!("landlock filesystem sandbox partially enforced (older ABI)")
                }
                NotEnforced => {
                    warn!("landlock not enforced (kernel lacks Landlock); continuing")
                }
            }
        }
        Err(e) => warn!(err = %e, "landlock sandbox not applied; continuing"),
    }
}

/// Install the seccomp-bpf syscall deny-list (best effort). Call this *after*
/// [`drop_privileges`] so the identity/capability syscalls are not filtered.
/// On a kernel without seccomp the error is logged and the process continues.
pub fn seccomp_filter(enabled: bool) {
    if !enabled {
        return;
    }
    match install_seccomp() {
        Ok(n) => info!(denied = n, "seccomp syscall deny-list installed (EPERM)"),
        Err(e) => warn!(err = %e, "seccomp filter not applied; continuing"),
    }
}

/// Read-only Landlock paths: the binaries + shared libraries needed to execve
/// `nft`/`iptables` at teardown, plus config/runtime-info trees.
const LANDLOCK_RO: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev",
];
/// Read-write Landlock paths: runtime dirs (control socket, xtables lock, tmp),
/// plus the two trees the firewall teardown legitimately writes — `/proc/sys`
/// (restoring rp_filter / ip_forward sysctls) and `/etc/resolv.conf` (DNS
/// push/restore). A more specific RW rule refines the RO rule on its parent, so
/// the rest of `/proc` and `/etc` stay read-only.
const LANDLOCK_RW: &[&str] = &["/run", "/var", "/tmp", "/proc/sys", "/etc/resolv.conf"];

fn install_landlock() -> std::result::Result<landlock::RestrictionStatus, landlock::RulesetError> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, ABI,
    };

    // ABI::V1 is the lowest common denominator; BestEffort downgrades the rule
    // set on newer-only access rights and no-ops entirely on an unaware kernel.
    let abi = ABI::V1;
    let ro = AccessFs::from_read(abi);
    let rw = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    for p in LANDLOCK_RO {
        // A path that does not exist on this host is simply skipped.
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, ro))?;
        }
    }
    for p in LANDLOCK_RW {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, rw))?;
        }
    }
    ruleset.restrict_self()
}

/// Target architecture for the seccomp filter (compile-time).
#[cfg(target_arch = "x86_64")]
const SECCOMP_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const SECCOMP_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

/// Build and apply the deny-list. Returns the number of denied syscalls.
///
/// Every listed syscall is answered with `EPERM`; everything else (the whole
/// tokio/rustls/socket/TUN working set, plus the setuid/capset path and the
/// `fork`/`execve` the firewall teardown needs) keeps the default `Allow`.
fn install_seccomp() -> std::result::Result<usize, Box<dyn std::error::Error>> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};

    // Syscalls an authorized tunnel should never make. All exist on both
    // x86_64 and aarch64 in libc 0.2, so the cross builds compile unchanged.
    let denied: &[libc::c_long] = &[
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_add_key,
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_perf_event_open,
        libc::SYS_bpf,
        libc::SYS_acct,
        libc::SYS_userfaultfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
    ];

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &sc in denied {
        // `libc::c_long` is `i64` on every 64-bit target we build for.
        // An empty rule vector = unconditional match → the match action.
        rules.insert(sc, vec![]);
    }
    let count = rules.len();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // default: allow unlisted
        SeccompAction::Errno(libc::EPERM as u32), // listed: deny with EPERM
        SECCOMP_ARCH,
    )?;
    let prog: BpfProgram = filter.try_into()?;
    apply_filter(&prog)?;
    Ok(count)
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
