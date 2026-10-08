//! On-wire framing and protocol versioning.
//!
//! Every frame begins with a fixed 20-byte header. For `Data` frames the
//! header is the AEAD **associated data**, so the version, type, flags,
//! session id and nonce counter are all authenticated. For handshake frames
//! the body is a self-authenticating Noise message and the header is only used
//! for routing.
//!
//! ```text
//!  0      1      2      3      4                    12                   20
//!  +------+------+------+------+--------------------+--------------------+--------
//!  | ver  | type | flag | rsvd |     session_id     |      counter       | body...
//!  +------+------+------+------+--------------------+--------------------+--------
//!        (u8)   (u8)   (u8)   (u8)       (u64 BE)            (u64 BE)
//! ```

use crate::error::{Error, Result};

/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 20;

/// Frame kinds carried in the header `type` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Encrypted tunnelled IP packet (single or mux batch — see flags).
    Data = 0,
    /// Keepalive / heartbeat (may carry an encrypted timestamp).
    Keepalive = 1,
    /// Noise handshake message 1 (initiator → responder).
    Handshake1 = 2,
    /// Noise handshake message 2 (responder → initiator).
    Handshake2 = 3,
    /// In-band control (rekey, migration, transport switch).
    Control = 4,
    /// Cover / chaff traffic (decrypts to nothing meaningful).
    Chaff = 5,
    /// FEC parity frame.
    FecParity = 6,
}

impl FrameType {
    /// Parse a type byte, rejecting unknown values.
    pub fn from_u8(v: u8) -> Result<FrameType> {
        Ok(match v {
            0 => FrameType::Data,
            1 => FrameType::Keepalive,
            2 => FrameType::Handshake1,
            3 => FrameType::Handshake2,
            4 => FrameType::Control,
            5 => FrameType::Chaff,
            6 => FrameType::FecParity,
            other => return Err(Error::decode(format!("unknown frame type {other}"))),
        })
    }
}

/// Header flag bits.
pub mod flags {
    /// The data body is a multiplexed batch of inner packets.
    pub const MUX_BATCH: u8 = 0b0000_0001;
    /// The body carries FEC-protected data (group member).
    pub const FEC_GROUP: u8 = 0b0000_0010;
    /// The body was padded by the obfuscation layer.
    pub const PADDED: u8 = 0b0000_0100;
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u8,
    pub ftype: FrameType,
    pub flags: u8,
    pub session_id: u64,
    pub counter: u64,
}

impl Header {
    /// Build a new header for the current protocol version.
    pub fn new(ftype: FrameType, flags: u8, session_id: u64, counter: u64) -> Header {
        Header {
            version: crate::PROTOCOL_VERSION,
            ftype,
            flags,
            session_id,
            counter,
        }
    }

    /// Serialize the header into the start of `out` (which must have room).
    pub fn encode_into(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = self.version;
        out[1] = self.ftype as u8;
        out[2] = self.flags;
        out[3] = 0;
        out[4..12].copy_from_slice(&self.session_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.counter.to_be_bytes());
    }

    /// Serialize the header to a fresh array.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        self.encode_into(&mut out);
        out
    }

    /// Strictly decode a header from the front of `buf`, returning the header
    /// and the remaining body slice. Never trusts length fields; every access
    /// is bounds-checked.
    pub fn decode(buf: &[u8]) -> Result<(Header, &[u8])> {
        if buf.len() < HEADER_LEN {
            return Err(Error::decode("frame shorter than header"));
        }
        let version = buf[0];
        if version != crate::PROTOCOL_VERSION {
            // A data frame with the wrong version is dropped (droppable error),
            // not a hard failure — handshake negotiates the real version.
            return Err(Error::decode(format!(
                "frame protocol version {version} != {}",
                crate::PROTOCOL_VERSION
            )));
        }
        let ftype = FrameType::from_u8(buf[1])?;
        let flags = buf[2];
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&buf[4..12]);
        let mut ctr = [0u8; 8];
        ctr.copy_from_slice(&buf[12..20]);
        let header = Header {
            version,
            ftype,
            flags,
            session_id: u64::from_be_bytes(sid),
            counter: u64::from_be_bytes(ctr),
        };
        Ok((header, &buf[HEADER_LEN..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header::new(FrameType::Data, flags::PADDED, 0x0102030405060708, 0xDEAD);
        let bytes = h.to_bytes();
        let (dec, body) = Header::decode(&bytes).unwrap();
        assert_eq!(dec.ftype, FrameType::Data);
        assert_eq!(dec.flags, flags::PADDED);
        assert_eq!(dec.session_id, 0x0102030405060708);
        assert_eq!(dec.counter, 0xDEAD);
        assert!(body.is_empty());
    }

    #[test]
    fn short_frame_rejected() {
        assert!(Header::decode(&[0u8; 5]).is_err());
    }

    #[test]
    fn unknown_type_rejected() {
        let mut b = Header::new(FrameType::Data, 0, 1, 1).to_bytes().to_vec();
        b[1] = 200;
        assert!(Header::decode(&b).is_err());
    }
}
