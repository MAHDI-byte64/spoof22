//! Raw IPv4 socket with `IP_HDRINCL`, wrapped for async use with tokio.
//!
//! This socket lets us emit packets whose IPv4 header we build ourselves —
//! including a forged source address — and receive all inbound packets of a
//! given IP protocol (we then filter by the authenticated session, never by
//! the source field). Requires `CAP_NET_RAW`.
//!
//! For throughput there are batched send/receive paths
//! ([`RawIpSocket::send_mmsg`] / [`RawIpSocket::recv_mmsg`]) that move a whole
//! burst of packets per syscall via `sendmmsg(2)`/`recvmmsg(2)`, each with a
//! transparent fall-back to the single-message path on a kernel that lacks
//! them. Note that UDP segmentation offload (`UDP_SEGMENT`/GSO) is *not* usable
//! here: it applies to kernel-owned UDP sockets, whereas this socket uses
//! `IP_HDRINCL` and builds every IPv4 header itself — so we batch syscalls with
//! `sendmmsg` instead of offloading segmentation to the NIC.

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

    /// Send many fully-formed IPv4 packets in a single `sendmmsg(2)` syscall,
    /// returning the number sent. Each entry is `(packet_bytes, dst)`. Partial
    /// sends are resumed; `EAGAIN` waits for writability. If the kernel lacks
    /// `sendmmsg` (`ENOSYS`/`EOPNOTSUPP`) it transparently falls back to a loop
    /// of [`RawIpSocket::send_to`], so callers always observe a full send.
    pub async fn send_mmsg(&self, pkts: &[(&[u8], Ipv4Addr)]) -> Result<usize> {
        if pkts.is_empty() {
            return Ok(0);
        }
        let n = pkts.len();
        let mut offset = 0usize;
        while offset < n {
            let mut guard = self.afd.writable().await.map_err(Error::from)?;
            // The sockaddr/iovec/mmsghdr arrays hold raw pointers and are built
            // and consumed entirely inside this synchronous closure, so they
            // never cross an await point (keeping the future `Send`).
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let rem = &pkts[offset..];
                let cnt = rem.len();
                let mut addrs: Vec<libc::sockaddr_in> = Vec::with_capacity(cnt);
                let mut iovs: Vec<libc::iovec> = Vec::with_capacity(cnt);
                for (buf, dst) in rem {
                    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    a.sin_family = libc::AF_INET as libc::sa_family_t;
                    a.sin_port = 0;
                    a.sin_addr.s_addr = u32::from(*dst).to_be();
                    addrs.push(a);
                    iovs.push(libc::iovec {
                        iov_base: buf.as_ptr() as *mut libc::c_void,
                        iov_len: buf.len(),
                    });
                }
                let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(cnt);
                for i in 0..cnt {
                    let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
                    h.msg_hdr.msg_name = std::ptr::addr_of_mut!(addrs[i]) as *mut libc::c_void;
                    h.msg_hdr.msg_namelen =
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                    h.msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovs[i]);
                    h.msg_hdr.msg_iovlen = 1;
                    msgs.push(h);
                }
                // SAFETY: the mmsghdrs reference `addrs`/`iovs`, both live for
                // the duration of the call; nothing is resized after capture.
                let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), cnt as libc::c_uint, 0) };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(rc as usize)
                }
            });
            match res {
                Ok(Ok(sent)) if sent > 0 => offset += sent,
                Ok(Ok(_)) => continue, // 0 sent — retry
                Ok(Err(e)) if is_unsupported(&e) => {
                    // Fall back to individual sends for the remainder.
                    for (buf, dst) in &pkts[offset..] {
                        self.send_to(buf, *dst).await?;
                    }
                    return Ok(n);
                }
                Ok(Err(e)) => return Err(Error::from(e)),
                Err(_would_block) => continue,
            }
        }
        Ok(n)
    }

    /// Receive a burst of inbound IPv4 packets in a single `recvmmsg(2)`
    /// syscall. `bufs` supplies the (already-sized) scratch buffers; the return
    /// value is the per-message received length for the first `k` buffers that
    /// were filled. Waits for readability, then drains without blocking. Falls
    /// back to a single [`RawIpSocket::recv`] if `recvmmsg` is unavailable.
    pub async fn recv_mmsg(&self, bufs: &mut [Vec<u8>]) -> Result<Vec<usize>> {
        if bufs.is_empty() {
            return Ok(Vec::new());
        }
        loop {
            let mut guard = self.afd.readable().await.map_err(Error::from)?;
            // Built and consumed inside the closure (raw pointers are never
            // carried across the await above), returning the per-message
            // lengths — all `Send` — to the caller.
            let res = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = bufs.len();
                let mut iovs: Vec<libc::iovec> = bufs
                    .iter_mut()
                    .map(|b| libc::iovec {
                        iov_base: b.as_mut_ptr() as *mut libc::c_void,
                        iov_len: b.len(),
                    })
                    .collect();
                let mut msgs: Vec<libc::mmsghdr> = iovs
                    .iter_mut()
                    .map(|iov| {
                        let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
                        h.msg_hdr.msg_iov = iov as *mut libc::iovec;
                        h.msg_hdr.msg_iovlen = 1;
                        h
                    })
                    .collect();
                // SAFETY: `msgs`/`iovs` are live; iov buffers belong to `bufs`.
                let rc = unsafe {
                    libc::recvmmsg(
                        fd,
                        msgs.as_mut_ptr(),
                        n as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok((0..rc as usize)
                        .map(|i| msgs[i].msg_len as usize)
                        .collect::<Vec<usize>>())
                }
            });
            match res {
                Ok(Ok(lens)) => return Ok(lens),
                Ok(Err(e)) if is_unsupported(&e) => {
                    let one = self.recv(&mut bufs[0]).await?;
                    return Ok(vec![one]);
                }
                Ok(Err(e)) => return Err(Error::from(e)),
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

/// Whether an error means the batched syscall is unsupported by this kernel
/// (so the caller should fall back to the single-message path).
fn is_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
    )
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
