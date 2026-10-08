//! Native Linux TUN device: created via `TUNSETIFF` ioctl, driven async with
//! tokio's [`AsyncFd`]. Configured as a point-to-point link (no packet-info
//! prefix), so reads/writes are raw IPv4 packets.

use std::fs::{File, OpenOptions};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use tokio::io::unix::AsyncFd;
use tokio::process::Command;

use crate::config::TunConfig;
use crate::error::{Error, Result};

// TUN/TAP constants (stable Linux ABI).
const TUNSETIFF: IoctlReq = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;

// `ioctl` request type differs between glibc (unsigned long) and musl (int).
#[cfg(target_env = "musl")]
type IoctlReq = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlReq = libc::c_ulong;

/// Kernel `struct ifreq` layout for the flags case (40 bytes on Linux).
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// An async TUN device.
pub struct TunDevice {
    afd: AsyncFd<File>,
    name: String,
    mtu: u32,
}

impl TunDevice {
    /// Create and bring up the TUN device described by `cfg`.
    pub async fn create(cfg: &TunConfig) -> Result<TunDevice> {
        if cfg.tun_name.len() >= IFNAMSIZ {
            return Err(Error::Tun(format!(
                "tun_name too long (max {})",
                IFNAMSIZ - 1
            )));
        }

        // Open the clone device non-blocking.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")
            .map_err(|e| map_priv(e, "open /dev/net/tun"))?;

        // Fill the ifreq and attach this fd to a TUN interface.
        let mut req = IfReq {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (i, b) in cfg.tun_name.as_bytes().iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
        if ret < 0 {
            return Err(map_priv(io::Error::last_os_error(), "TUNSETIFF"));
        }

        let dev = TunDevice {
            afd: AsyncFd::new(file).map_err(Error::from)?,
            name: cfg.tun_name.clone(),
            mtu: cfg.tun_mtu,
        };

        dev.configure(cfg).await?;
        Ok(dev)
    }

    /// Assign addresses, MTU, and bring the link up via `ip`.
    async fn configure(&self, cfg: &TunConfig) -> Result<()> {
        // Point-to-point addressing: local peer form.
        run_ip(&[
            "addr",
            "add",
            &cfg.tun_ip.to_string(),
            "peer",
            &cfg.tun_peer_ip.to_string(),
            "dev",
            &self.name,
        ])
        .await?;

        run_ip(&[
            "link",
            "set",
            "dev",
            &self.name,
            "mtu",
            &cfg.tun_mtu.to_string(),
            "up",
        ])
        .await?;
        Ok(())
    }

    /// Interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Configured MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Read one inbound IP packet from the TUN (traffic leaving the host toward
    /// the tunnel). Returns the number of bytes read.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.afd.readable().await.map_err(Error::from)?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(r) => return r.map_err(Error::from),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet into the TUN (delivering tunnelled traffic to the
    /// host stack).
    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.afd.writable().await.map_err(Error::from)?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(r) => return r.map_err(Error::from),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Prefix length (CIDR) from a dotted netmask.
pub fn prefix_len(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Run an `ip` subcommand, mapping failure to a clear error.
async fn run_ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .await
        .map_err(|e| Error::Tun(format!("spawning `ip {}`: {e}", args.join(" "))))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Tun(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

fn map_priv(e: io::Error, what: &str) -> Error {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => Error::Privilege(format!(
            "{what} failed: needs CAP_NET_ADMIN (grant with `setcap cap_net_raw,cap_net_admin+ep` or run as root)"
        )),
        _ => Error::Tun(format!("{what}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_from_mask() {
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 255, 252)), 30);
        assert_eq!(prefix_len(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_len(Ipv4Addr::new(255, 0, 0, 0)), 8);
    }
}
