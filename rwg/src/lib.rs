//! rwg - rusty wireguard

pub use self::device::Device;
pub use self::key::Key;
pub use self::peer::{AllowedIp, Endpoint, Peer};

mod device;
mod key;
mod net;
mod peer;

#[cfg(test)]
mod tests;
