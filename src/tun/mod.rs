//! TUN device, NAT/firewall, routing, kill switch.
//!
//! * [`device`] — the async TUN device (TUNSETIFF + AsyncFd).
//! * [`firewall`] — sysctls, NAT, port forwarding, kill switch, routing and
//!   DNS, with clean teardown.

pub mod device;
pub mod firewall;

pub use device::TunDevice;
pub use firewall::Firewall;
