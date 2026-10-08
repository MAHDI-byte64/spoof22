//! Raw IPv4 socket with `IP_HDRINCL`, wrapped for async use with tokio.
//!
//! This socket lets us emit packets whose IPv4 header we build ourselves —
//! including a forged source address — and receive all inbound packets of a
//! given IP protocol (we then filter by the authenticated session, never by
//! the source field). Requires `CAP_NET_RAW`.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::error::{Error, Result};

/// An async raw IPv4 socket bound to one physical interface and one protocol.
pub struct RawIpSocket {
    afd: AsyncFd<Socket>,
    protocol: u8,
}

impl RawIpSocket {
    /// Create a raw socket for `protocol`, bound to `interface` (if non-empty),
    /// with `IP_HDRINCL` enabled and the requested socket buffer sizes.
    pub fn new(protocol: u8, interface: &str, sndbuf: usize, rcvbuf: usize) -> Result<RawIpSocket> {
        let sock = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(protocol as i32)),
        )
        .map_err(|e| map_priv(e, "create raw socket"))?;

        // IP_HDRINCL: we provide the IPv4 header (and thus the forged source).
        enable_hdrincl(&sock)?;

        if !interface.is_empty() {
            sock.bind_device(Some(interface.as_bytes()))
                .map_err(|e| map_priv(e, "SO_BINDTODEVICE"))?;
        }

        // Best-effort large socket buffers (spec: 4 MiB each by default).
        let _ = sock.set_send_buffer_size(sndbuf);
        let _ = sock.set_recv_buffer_size(rcvbuf);

        sock.set_nonblocking(true).map_err(Error::from)?;

        let afd = AsyncFd::new(sock).map_err(Error::from)?;
        Ok(RawIpSocket { afd, protocol })
    }

    /// The IP protocol number this socket rides on.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Send a fully-formed IPv4 packet (header + payload) to `dst`.
    ///
    /// With `IP_HDRINCL` the kernel takes the source from our header (forged),
    /// but still needs the destination for routing, supplied here.
    pub async fn send_to(&self, packet: &[u8], dst: Ipv4Addr) -> Result<usize> {
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from(dst).to_be();

        loop {
            let mut guard = self.afd.writable().await.map_err(Error::from)?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: `packet`/`addr` outlive the call; lengths are correct.
                let n = unsafe {
                    libc::sendto(
                        fd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };
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

    /// Receive one inbound IPv4 packet (including its header) into `buf`.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.afd.readable().await.map_err(Error::from)?;
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: `buf` is valid for `buf.len()` bytes.
                let n =
                    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
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

/// Enable `IP_HDRINCL` on a raw socket.
fn enable_hdrincl(sock: &Socket) -> Result<()> {
    let one: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(map_priv(io::Error::last_os_error(), "set IP_HDRINCL"));
    }
    Ok(())
}

/// Map `EPERM`/`EACCES` to a clearer privilege error.
fn map_priv(e: io::Error, what: &str) -> Error {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => Error::Privilege(format!(
            "{what} failed: needs CAP_NET_RAW (grant with `setcap cap_net_raw,cap_net_admin+ep` or run as root)"
        )),
        _ => Error::Io(e),
    }
}
