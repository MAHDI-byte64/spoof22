//! Forward error correction over sealed frames.
//!
//! FEC protects whole **sealed** datagrams: parity is computed over the
//! encrypted frame bytes, so a lost datagram can be reconstructed and *then*
//! decrypted normally (its header/counter travel inside the shard). Two coders
//! are supported:
//!
//! * **XOR** — a single parity shard per group; recovers exactly one loss.
//! * **Reed-Solomon** — `m` parity shards; recovers up to `m` losses per group.
//!
//! When FEC is enabled, every datagram is FEC-framed (data shards carry the
//! sealed frame, parity shards carry redundancy), so there is no ambiguity on
//! the wire. An [`Adaptive`] controller tunes `m` to the measured loss rate.
//!
//! Wire shard datagram:
//! ```text
//!   [ group_id:u32 | index:u8 | data:u8 | parity:u8 | shard_len:u16 | mode:u8 ]  (10B header)
//!   [ shard_len bytes of shard content ]
//! ```
//! For a data shard the content is `[ sealed_len:u16 | sealed | zero-pad ]`.

pub mod adaptive;

use std::collections::{HashMap, VecDeque};

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::config::FecMode;
use crate::error::{Error, Result};

/// FEC shard header length.
pub const FEC_HEADER: usize = 10;

fn mode_code(m: FecMode) -> u8 {
    match m {
        FecMode::Xor => 0,
        FecMode::ReedSolomon => 1,
    }
}

/// Parsed FEC header.
#[derive(Debug, Clone, Copy)]
struct FecHeader {
    group_id: u32,
    index: u8,
    data_shards: u8,
    parity_shards: u8,
    shard_len: u16,
    mode: u8,
}

impl FecHeader {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.group_id.to_be_bytes());
        out.push(self.index);
        out.push(self.data_shards);
        out.push(self.parity_shards);
        out.extend_from_slice(&self.shard_len.to_be_bytes());
        out.push(self.mode);
    }

    fn decode(buf: &[u8]) -> Result<(FecHeader, &[u8])> {
        if buf.len() < FEC_HEADER {
            return Err(Error::decode("fec: datagram shorter than header"));
        }
        let h = FecHeader {
            group_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            index: buf[4],
            data_shards: buf[5],
            parity_shards: buf[6],
            shard_len: u16::from_be_bytes([buf[7], buf[8]]),
            mode: buf[9],
        };
        Ok((h, &buf[FEC_HEADER..]))
    }
}

/// FEC output: the data-shard datagram to send now, plus any parity datagrams
/// to send once the group is complete.
pub struct FecOut {
    pub data: Vec<u8>,
    pub parity: Vec<Vec<u8>>,
}

/// FEC encoder: groups `data_shards` sealed frames, then emits parity.
pub struct FecEncoder {
    mode: FecMode,
    data_shards: usize,
    parity_shards: usize,
    shard_len: usize,
    group_id: u32,
    buf: Vec<Vec<u8>>,
    rs: Option<ReedSolomon>,
}

impl FecEncoder {
    /// Build an encoder. `shard_len` is the fixed RS shard size (must exceed
    /// the largest sealed frame by at least 2 bytes for the length prefix).
    pub fn new(
        mode: FecMode,
        data_shards: usize,
        parity_shards: usize,
        shard_len: usize,
    ) -> Result<FecEncoder> {
        if data_shards < 2 {
            return Err(Error::config("fec: data_shards must be >= 2"));
        }
        let parity_shards = match mode {
            FecMode::Xor => 1,
            FecMode::ReedSolomon => parity_shards.max(1),
        };
        let rs = match mode {
            FecMode::ReedSolomon => Some(
                ReedSolomon::new(data_shards, parity_shards)
                    .map_err(|e| Error::config(format!("fec: reed-solomon init: {e}")))?,
            ),
            FecMode::Xor => None,
        };
        let mut seed = [0u8; 4];
        let _ = getrandom::getrandom(&mut seed);
        Ok(FecEncoder {
            mode,
            data_shards,
            parity_shards,
            shard_len,
            group_id: u32::from_be_bytes(seed),
            buf: Vec::with_capacity(data_shards),
            rs,
        })
    }

    fn header(&self, index: u8) -> FecHeader {
        FecHeader {
            group_id: self.group_id,
            index,
            data_shards: self.data_shards as u8,
            parity_shards: self.parity_shards as u8,
            shard_len: self.shard_len as u16,
            mode: mode_code(self.mode),
        }
    }

    /// Wrap a sealed frame into a data-shard datagram; if the group completes,
    /// also return the parity datagrams.
    pub fn push(&mut self, sealed: &[u8]) -> Result<FecOut> {
        if sealed.len() + 2 > self.shard_len {
            return Err(Error::decode("fec: sealed frame exceeds shard length"));
        }
        // Build the padded shard content: [sealed_len | sealed | zero-pad].
        let mut content = Vec::with_capacity(self.shard_len);
        content.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        content.extend_from_slice(sealed);
        content.resize(self.shard_len, 0);

        let index = self.buf.len() as u8;
        let mut data = Vec::with_capacity(FEC_HEADER + self.shard_len);
        self.header(index).encode_into(&mut data);
        data.extend_from_slice(&content);

        self.buf.push(content);

        let parity = if self.buf.len() == self.data_shards {
            let p = self.build_parity()?;
            self.group_id = self.group_id.wrapping_add(1);
            self.buf.clear();
            p
        } else {
            Vec::new()
        };

        Ok(FecOut { data, parity })
    }

    fn build_parity(&self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(self.parity_shards);
        match self.mode {
            FecMode::Xor => {
                let mut parity = vec![0u8; self.shard_len];
                for shard in &self.buf {
                    for (p, s) in parity.iter_mut().zip(shard.iter()) {
                        *p ^= *s;
                    }
                }
                let mut dg = Vec::with_capacity(FEC_HEADER + self.shard_len);
                self.header(self.data_shards as u8).encode_into(&mut dg);
                dg.extend_from_slice(&parity);
                out.push(dg);
            }
            FecMode::ReedSolomon => {
                let rs = self
                    .rs
                    .as_ref()
                    .ok_or_else(|| Error::crypto("fec: rs missing"))?;
                let mut shards: Vec<Vec<u8>> = self.buf.clone();
                for _ in 0..self.parity_shards {
                    shards.push(vec![0u8; self.shard_len]);
                }
                rs.encode(&mut shards)
                    .map_err(|e| Error::crypto(format!("fec: rs encode: {e}")))?;
                for j in 0..self.parity_shards {
                    let mut dg = Vec::with_capacity(FEC_HEADER + self.shard_len);
                    self.header((self.data_shards + j) as u8)
                        .encode_into(&mut dg);
                    dg.extend_from_slice(&shards[self.data_shards + j]);
                    out.push(dg);
                }
            }
        }
        Ok(out)
    }
}

/// Reconstruction state for one FEC group.
struct Group {
    shards: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
    data_shards: usize,
    parity_shards: usize,
    shard_len: usize,
    got: usize,
}

/// FEC decoder: delivers received data immediately and reconstructs losses.
pub struct FecDecoder {
    mode: FecMode,
    groups: HashMap<u32, Group>,
    lru: VecDeque<u32>,
    max_groups: usize,
}

impl FecDecoder {
    /// Create a decoder holding at most `max_groups` in-flight groups.
    pub fn new(mode: FecMode, max_groups: usize) -> FecDecoder {
        FecDecoder {
            mode,
            groups: HashMap::new(),
            lru: VecDeque::new(),
            max_groups: max_groups.max(1),
        }
    }

    /// Process one FEC datagram, returning any sealed frames ready to decrypt.
    pub fn push(&mut self, datagram: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (h, content) = FecHeader::decode(datagram)?;
        let data_shards = h.data_shards as usize;
        let parity_shards = h.parity_shards as usize;
        let shard_len = h.shard_len as usize;
        let total = data_shards + parity_shards;

        // Sanity bounds — never trust the header blindly.
        if !(2..=255).contains(&data_shards) || parity_shards == 0 || total > 255 {
            return Err(Error::decode("fec: implausible shard counts"));
        }
        if content.len() != shard_len || shard_len < 2 {
            return Err(Error::decode("fec: shard length mismatch"));
        }
        if (h.index as usize) >= total {
            return Err(Error::decode("fec: shard index out of range"));
        }

        let group = self.group_entry(h.group_id, data_shards, parity_shards, shard_len);

        // The group's geometry is pinned at creation. A later datagram reusing
        // the same group_id with DIFFERENT dims must be rejected: its index was
        // bounds-checked against its own (attacker-chosen) total above, not
        // against this group's vectors, so trusting it would index out of
        // bounds. Dropping the inconsistent shard also prevents reconstruction
        // from being poisoned with mismatched geometry.
        if group.data_shards != data_shards
            || group.parity_shards != parity_shards
            || group.shard_len != shard_len
        {
            return Err(Error::decode("fec: group geometry mismatch"));
        }
        let idx = h.index as usize;
        let mut out = Vec::new();

        if group.shards[idx].is_none() {
            group.shards[idx] = Some(content.to_vec());
            group.got += 1;

            // Immediate delivery of a freshly-received data shard.
            if idx < data_shards && !group.delivered[idx] {
                if let Some(sealed) = extract_sealed(group.shards[idx].as_ref().unwrap())? {
                    group.delivered[idx] = true;
                    out.push(sealed);
                }
            }

            // Try to recover missing data shards once enough shards are present.
            if group.got >= data_shards && group.delivered.iter().any(|d| !*d) {
                self.try_reconstruct(h.group_id, &mut out)?;
            }
        }

        Ok(out)
    }

    fn group_entry(
        &mut self,
        id: u32,
        data_shards: usize,
        parity_shards: usize,
        shard_len: usize,
    ) -> &mut Group {
        if !self.groups.contains_key(&id) {
            if self.lru.len() >= self.max_groups {
                if let Some(old) = self.lru.pop_front() {
                    self.groups.remove(&old);
                }
            }
            self.lru.push_back(id);
            self.groups.insert(
                id,
                Group {
                    shards: vec![None; data_shards + parity_shards],
                    delivered: vec![false; data_shards],
                    data_shards,
                    parity_shards,
                    shard_len,
                    got: 0,
                },
            );
        }
        self.groups.get_mut(&id).unwrap()
    }

    fn try_reconstruct(&mut self, id: u32, out: &mut Vec<Vec<u8>>) -> Result<()> {
        let group = match self.groups.get_mut(&id) {
            Some(g) => g,
            None => return Ok(()),
        };
        match self.mode {
            FecMode::Xor => {
                // Recover a single missing data shard from parity + the rest.
                let parity_idx = group.data_shards; // single parity at index k
                let have_parity = group.shards[parity_idx].is_some();
                let missing: Vec<usize> = (0..group.data_shards)
                    .filter(|i| group.shards[*i].is_none())
                    .collect();
                if have_parity && missing.len() == 1 {
                    let m = missing[0];
                    let mut rec = vec![0u8; group.shard_len];
                    for i in 0..=group.data_shards {
                        if i == m {
                            continue;
                        }
                        if let Some(s) = &group.shards[i] {
                            for (r, b) in rec.iter_mut().zip(s.iter()) {
                                *r ^= *b;
                            }
                        }
                    }
                    group.shards[m] = Some(rec);
                }
            }
            FecMode::ReedSolomon => {
                let rs = ReedSolomon::new(group.data_shards, group.parity_shards)
                    .map_err(|e| Error::crypto(format!("fec: rs: {e}")))?;
                let mut shards: Vec<Option<Vec<u8>>> = group.shards.clone();
                if rs.reconstruct(&mut shards).is_ok() {
                    group.shards = shards;
                }
            }
        }
        // Deliver any now-available, not-yet-delivered data shards.
        for i in 0..group.data_shards {
            if !group.delivered[i] {
                if let Some(shard) = &group.shards[i] {
                    if let Some(sealed) = extract_sealed(shard)? {
                        group.delivered[i] = true;
                        out.push(sealed);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Strip the `[sealed_len | sealed | pad]` wrapper from a shard content.
fn extract_sealed(content: &[u8]) -> Result<Option<Vec<u8>>> {
    if content.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([content[0], content[1]]) as usize;
    let end = 2usize
        .checked_add(len)
        .ok_or_else(|| Error::decode("fec: length overflow"))?;
    if end > content.len() {
        return Err(Error::decode("fec: sealed length exceeds shard"));
    }
    Ok(Some(content[2..end].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_with_loss(mode: FecMode, data: usize, parity: usize, drop: &[usize]) {
        let shard_len = 128;
        let mut enc = FecEncoder::new(mode, data, parity, shard_len).unwrap();
        let mut dec = FecDecoder::new(mode, 8);

        // Produce one full group of distinct sealed frames.
        let frames: Vec<Vec<u8>> = (0..data).map(|i| vec![i as u8; 20 + i]).collect();
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        for f in &frames {
            let out = enc.push(f).unwrap();
            datagrams.push(out.data);
            for p in out.parity {
                datagrams.push(p);
            }
        }

        // Drop the indicated datagrams, feed the rest, collect deliveries.
        let mut delivered: Vec<Vec<u8>> = Vec::new();
        for (i, dg) in datagrams.iter().enumerate() {
            if drop.contains(&i) {
                continue;
            }
            delivered.extend(dec.push(dg).unwrap());
        }

        for f in &frames {
            assert!(delivered.contains(f), "frame {:?} not recovered", &f[..1]);
        }
    }

    #[test]
    fn xor_recovers_one_loss() {
        roundtrip_with_loss(FecMode::Xor, 4, 1, &[1]);
    }

    #[test]
    fn rs_recovers_multiple_losses() {
        roundtrip_with_loss(FecMode::ReedSolomon, 6, 3, &[0, 2, 5]);
    }

    #[test]
    fn no_loss_delivers_all() {
        roundtrip_with_loss(FecMode::ReedSolomon, 4, 2, &[]);
    }

    #[test]
    fn rejects_bad_header() {
        let mut dec = FecDecoder::new(FecMode::Xor, 4);
        assert!(dec.push(&[0u8; 4]).is_err());
    }

    /// Craft a raw FEC datagram with an explicit (possibly malicious) header.
    fn raw_dg(gid: u32, index: u8, data: u8, parity: u8, shard_len: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&gid.to_be_bytes());
        v.push(index);
        v.push(data);
        v.push(parity);
        v.extend_from_slice(&shard_len.to_be_bytes());
        v.push(0); // mode byte (ignored by the decoder)
        v.extend_from_slice(&vec![0u8; shard_len as usize]);
        v
    }

    /// Regression: a second datagram reusing a live group_id but redeclaring a
    /// larger geometry and a large index must be rejected, not indexed into the
    /// smaller shard vector (which previously panicked out of bounds — a remote
    /// DoS reachable with two crafted, unauthenticated datagrams).
    #[test]
    fn rejects_group_geometry_change() {
        let mut dec = FecDecoder::new(FecMode::Xor, 8);
        // First datagram pins the group to 2 data + 1 parity (3 shard slots);
        // index 2 is a parity shard, so no sealed-frame extraction is attempted.
        let a = raw_dg(7, 2, 2, 1, 4);
        let _ = dec.push(&a); // group created
                              // Same id, far larger geometry, index 240: must be a decode error.
        let b = raw_dg(7, 240, 200, 50, 4);
        assert!(
            dec.push(&b).is_err(),
            "geometry-changing shard must be rejected, not indexed OOB"
        );
    }
}
