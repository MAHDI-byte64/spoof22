//! TUN device, NAT/firewall, routing, kill switch.
//!
//! Milestone 1 provides the async TUN device ([`device`]). The firewall/NAT,
//! routing modes, kill switch and DNS handling are layered on in later
//! milestones ([`firewall`], [`routing`]).

pub mod device;

pub use device::TunDevice;
