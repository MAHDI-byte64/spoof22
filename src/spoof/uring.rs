//! Optional io_uring batched raw-send backend (`--features io_uring`).
//!
//! When the `io_uring` cargo feature is enabled, [`crate::transport::raw_core`]
//! routes its batched send path through a [`UringSender`] instead of
//! `sendmmsg(2)`. Each send becomes an `IORING_OP_SENDMSG` submission; a whole
//! batch is pushed and reaped in one `io_uring_enter`, which on busy links cuts
//! the syscall and copy overhead further than `sendmmsg`.
//!
//! The sender is driven synchronously (`submit_and_wait`) behind a mutex, so
//! callers invoke it from a blocking context (`tokio::task::spawn_blocking`) to
//! keep the async reactor free. Buffers are owned by the caller for the whole
//! submit-and-wait, so the kernel never reads freed memory. This module is
//! compiled only with the feature on; the default build never references the
//! io-uring crate.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::sync::Mutex;

use io_uring::{opcode, types, IoUring};

/// A reusable io_uring instance for batched raw sends.
pub struct UringSender {
    ring: Mutex<IoUring>,
    depth: usize,
}

impl UringSender {
    /// Create an io_uring with `depth` submission/completion entries.
    pub fn new(depth: u32) -> io::Result<UringSender> {
        let depth = depth.max(1);
        Ok(UringSender {
            ring: Mutex::new(IoUring::new(depth)?),
            depth: depth as usize,
        })
    }

    /// Send every packet in `pkts` (each `(ip_packet_bytes, dst)`) on the raw
    /// socket `fd` via `IORING_OP_SENDMSG`, blocking until the whole set has
    /// completed. Returns the number the kernel accepted. Submitted in chunks
    /// of the ring depth so an arbitrarily large batch is safe.
    ///
    /// Blocking: run under `spawn_blocking`. The `sockaddr`/`iovec`/`msghdr`
    /// arrays live until after `submit_and_wait`, so the kernel reads only
    /// valid memory.
    pub fn send_batch_blocking(
        &self,
        fd: RawFd,
        pkts: &[(Vec<u8>, Ipv4Addr)],
    ) -> io::Result<usize> {
        if pkts.is_empty() {
            return Ok(0);
        }
        let mut ring = self
            .ring
            .lock()
            .map_err(|_| io::Error::other("uring mutex poisoned"))?;

        let mut accepted = 0usize;
        for chunk in pkts.chunks(self.depth) {
            accepted += Self::submit_chunk(&mut ring, fd, chunk)?;
        }
        Ok(accepted)
    }

    /// Submit and complete one depth-bounded chunk.
    fn submit_chunk(
        ring: &mut IoUring,
        fd: RawFd,
        chunk: &[(Vec<u8>, Ipv4Addr)],
    ) -> io::Result<usize> {
        let n = chunk.len();

        // Backing arrays, kept alive across submit_and_wait.
        let mut addrs: Vec<libc::sockaddr_in> = Vec::with_capacity(n);
        let mut iovs: Vec<libc::iovec> = Vec::with_capacity(n);
        for (buf, dst) in chunk {
            let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            a.sin_family = libc::AF_INET as libc::sa_family_t;
            a.sin_port = 0; // raw IP_HDRINCL socket: port lives in our L4 header
            a.sin_addr.s_addr = u32::from(*dst).to_be();
            addrs.push(a);
            iovs.push(libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            });
        }
        let mut msgs: Vec<libc::msghdr> = Vec::with_capacity(n);
        for i in 0..n {
            let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
            mh.msg_name = std::ptr::addr_of_mut!(addrs[i]) as *mut libc::c_void;
            mh.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            mh.msg_iov = std::ptr::addr_of_mut!(iovs[i]);
            mh.msg_iovlen = 1;
            msgs.push(mh);
        }

        // Push one SENDMSG SQE per packet.
        {
            let mut sq = ring.submission();
            for (i, mh) in msgs.iter().enumerate() {
                let entry = opcode::SendMsg::new(types::Fd(fd), mh as *const libc::msghdr)
                    .build()
                    .user_data(i as u64);
                // SAFETY: `entry` references `msgs[i]` → `addrs`/`iovs` → the
                // caller's `chunk` buffers, all live until submit_and_wait
                // returns below (and the SQ is fully drained before we return).
                unsafe {
                    sq.push(&entry)
                        .map_err(|_| io::Error::other("io_uring SQ full"))?;
                }
            }
        }

        ring.submit_and_wait(n)?;

        let mut ok = 0usize;
        for cqe in ring.completion() {
            if cqe.result() >= 0 {
                ok += 1;
            }
        }
        Ok(ok)
    }
}
