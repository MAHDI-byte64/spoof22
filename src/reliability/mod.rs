//! Reliability: congestion control, keepalive/heartbeat, dead-peer detection
//! and the reconnection backoff. Connection migration and auto-reconnect are
//! driven by the session manager (see [`crate::session`]).

pub mod congestion;
pub mod keepalive;

pub use congestion::Congestion;
pub use keepalive::{Backoff, Liveness};
