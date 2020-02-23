//! WireGuard peer management.

use std::mem;
use std::net::IpAddr;
use std::ptr;

use libwg_sys as sys;

use crate::key::Key;
use crate::net;

/// A set of authorized IP addresses associated with a peer. Takes the form of a network address
/// and a netmask.
#[derive(Debug, Clone, PartialEq)]
pub struct AllowedIp {
    address: IpAddr,
    mask: u8,
}

impl AllowedIp {
    /// Create a new allowed IP.
    pub fn new(addr: IpAddr, netmask: u8) -> AllowedIp {
        AllowedIp {
            address: addr,
            mask: netmask,
        }
    }

    /// Construct an `AllowedIp` object from a C library handle.
    fn from_handle(h: *mut sys::wg_allowedip) -> AllowedIp {
        let addr = unsafe {
            match (*h).family as u32 {
                sys::AF_INET => {
                    let addr = net::read_ip4_from_in_addr(&(*h).__bindgen_anon_1.ip4);
                    IpAddr::V4(addr)
                }

                sys::AF_INET6 => {
                    let addr = net::read_ip6_from_in6_addr(&(*h).__bindgen_anon_1.ip6);
                    IpAddr::V6(addr)
                }

                wtf => panic!("Got an invalid AF address family: {}", wtf),
            }
        };

        let mask = unsafe { (*h).cidr };

        AllowedIp {
            address: addr,
            mask: mask,
        }
    }

    /// Get the C library handle.
    fn handle(&self) -> sys::wg_allowedip {
        let mut allowed_ip = unsafe {
            let mut allowed_ip: sys::wg_allowedip = mem::zeroed();

            match self.address {
                IpAddr::V4(ref ip4) => {
                    allowed_ip.family = sys::AF_INET as u16;
                    net::write_ip4_to_in_addr(ip4, &mut allowed_ip.__bindgen_anon_1.ip4);
                }

                IpAddr::V6(ref ip6) => {
                    allowed_ip.family = sys::AF_INET6 as u16;
                    net::write_ip6_to_in6_addr(ip6, &mut allowed_ip.__bindgen_anon_1.ip6);
                }
            };

            allowed_ip
        };

        allowed_ip.cidr = self.mask;
        allowed_ip
    }

    /// Get the IP address.
    pub fn addr(&self) -> &IpAddr {
        &self.address
    }

    /// Get the network mask in CIDR form.
    pub fn mask(&self) -> u8 {
        self.mask
    }
}

/// Type alias to represent the endpoint of a peer on the internet. Consists of an IP address and a
/// UDP port number.
pub type Endpoint = (IpAddr, u16);

/// A WireGuard peer attached to a device.
#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    public_key: Option<Key>,
    endpoint: Option<Endpoint>,
    allowed_ips: Vec<AllowedIp>,
}

impl Peer {
    /// Create a new peer.
    pub fn new(public_key: Key, endpoint: Option<Endpoint>) -> Peer {
        Peer {
            public_key: Some(public_key),
            endpoint: endpoint,
            allowed_ips: Vec::new(),
        }
    }

    /// Construct a `Peer` object from a C library handle.
    pub(super) fn from_handle(h: *mut sys::wg_peer) -> Peer {
        let public_key = unsafe {
            if (*h).flags & sys::wg_peer_flags_WGPEER_HAS_PUBLIC_KEY != 0 {
                Some(Key::from_bytes((*h).public_key))
            } else {
                None
            }
        };

        let endpoint = unsafe { net::sockaddr_to_endpoint(&(*h).endpoint.addr) };

        let allowed_ips = unsafe {
            let mut ips = Vec::new();
            let mut ip = (*h).first_allowedip;

            while ip != ptr::null_mut() {
                ips.push(AllowedIp::from_handle(ip));
                ip = (*ip).next_allowedip;
            }

            ips
        };

        Peer {
            public_key: public_key,
            endpoint: endpoint,
            allowed_ips: allowed_ips,
        }
    }

    /// Get the C library handle for this peer.
    pub(super) fn handle(&self) -> Handle {
        unsafe {
            let mut h: sys::wg_peer = mem::zeroed();

            if let Some(ref key) = self.public_key {
                h.flags |= sys::wg_peer_flags_WGPEER_HAS_PUBLIC_KEY;
                h.public_key.copy_from_slice(key.as_bytes());
            }

            if let Some(ref endpoint) = self.endpoint {
                net::endpoint_to_sockaddr(endpoint, &mut h.endpoint.addr);
            } else {
                h.endpoint = mem::zeroed();
            }

            h.flags |= sys::wg_peer_flags_WGPEER_REPLACE_ALLOWEDIPS;

            let mut allowed_ips = self
                .allowed_ips
                .iter()
                .map(|ip| ip.handle())
                .collect::<Vec<_>>();

            let allowed_ips_len = allowed_ips.len();
            let allowed_ips_ptr = allowed_ips.as_mut_ptr();

            if !self.allowed_ips.is_empty() {
                for (i, ip) in allowed_ips.iter_mut().enumerate() {
                    if i + 1 < allowed_ips_len {
                        ip.next_allowedip = allowed_ips_ptr.add(i + 1);
                    }
                }

                h.first_allowedip = allowed_ips_ptr;
                h.last_allowedip = allowed_ips_ptr.add(allowed_ips_len - 1);
            } else {
                h.first_allowedip = ptr::null_mut();
                h.last_allowedip = ptr::null_mut();
            }

            Handle {
                handle: h,
                allowed_ips: allowed_ips,
            }
        }
    }

    /// Set the IP address and port of this peer on the internet.
    pub fn set_endpoint(&mut self, endpoint: Endpoint) {
        self.endpoint.replace(endpoint);
    }

    /// Add a new allowed IP to this peer.
    pub fn add_allowed_ip(&mut self, ip: AllowedIp) {
        self.allowed_ips.push(ip);
    }

    /// Get the public key of this peer, if it has been specified.
    pub fn public_key(&self) -> Option<&Key> {
        self.public_key.as_ref()
    }

    /// Get the internet endpoint of this peer.
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    /// Get the list of allowed IPs.
    pub fn allowed_ips(&self) -> &[AllowedIp] {
        self.allowed_ips.as_ref()
    }

    /// Get a mutable reference to the list of allowed IPs of this peer.
    pub fn allowed_ips_mut(&mut self) -> &mut Vec<AllowedIp> {
        &mut self.allowed_ips
    }
}

/// Handle to a peer for the C library.
pub(super) struct Handle {
    pub handle: sys::wg_peer,
    pub allowed_ips: Vec<sys::wg_allowedip>,
}
