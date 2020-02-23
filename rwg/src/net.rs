//! Network-related utility functions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use libwg_sys as sys;

use crate::peer::Endpoint;

/// Given a peer endpoint, write the IP address and UDP port into the specified sockaddr C struct.
pub fn endpoint_to_sockaddr(endpoint: &Endpoint, saddr: *mut sys::sockaddr) {
    let (addr, port) = endpoint;

    match addr {
        IpAddr::V4(ip4) => unsafe {
            let mut in4 = saddr as *mut sys::sockaddr_in;

            (*in4).sin_family = sys::AF_INET as u16;
            (*in4).sin_port = *port;

            write_ip4_to_in_addr(&ip4, &mut (*in4).sin_addr);
        },

        IpAddr::V6(ip6) => unsafe {
            let mut in6 = saddr as *mut sys::sockaddr_in6;

            (*in6).sin6_family = sys::AF_INET6 as u16;
            (*in6).sin6_port = *port;

            write_ip6_to_in6_addr(&ip6, &mut (*in6).sin6_addr);
        },
    }
}

/// Convert the given sockaddr C struct into a peer endpoint.
pub fn sockaddr_to_endpoint(saddr: *const sys::sockaddr) -> Option<Endpoint> {
    unsafe {
        match (*saddr).sa_family as u32 {
            sys::AF_INET => {
                let in4 = saddr as *const sys::sockaddr_in;
                let bytes = (*in4).sin_addr.s_addr.to_le_bytes();

                let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);

                Some((IpAddr::V4(addr), (*in4).sin_port))
            }

            sys::AF_INET6 => {
                let in6 = saddr as *const sys::sockaddr_in6;

                Some((
                    IpAddr::V6(read_ip6_from_in6_addr(&(*in6).sin6_addr)),
                    (*in6).sin6_port,
                ))
            }

            0 => None,

            wtf => panic!("Unknown AF address family: {}", wtf),
        }
    }
}

/// Read the specified in_addr C struct and return the IPv4 address its contains.
pub fn read_ip4_from_in_addr(addr: *const sys::in_addr) -> Ipv4Addr {
    let bytes = unsafe { (*addr).s_addr.to_le_bytes() };
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Read the specified in6_addr C struct and return the IPv6 address its contains.
pub fn read_ip6_from_in6_addr(addr: *const sys::in6_addr) -> Ipv6Addr {
    let segments = unsafe { (*addr).__in6_u.__u6_addr16 };

    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
}

/// Write the specified IPv4 address into a C in_addr struct.
pub fn write_ip4_to_in_addr(ip4: &Ipv4Addr, addr: *mut sys::in_addr) {
    unsafe {
        ptr::copy_nonoverlapping(
            ip4.octets().as_ref().as_ptr() as *const u32,
            &mut (*addr).s_addr as *mut u32,
            4,
        );
    }
}

/// Write the specified IPv6 address into a C in6_addr struct.
pub fn write_ip6_to_in6_addr(ip6: &Ipv6Addr, addr: *mut sys::in6_addr) {
    unsafe {
        (*addr)
            .__in6_u
            .__u6_addr8
            .copy_from_slice(ip6.octets().as_ref());
    }
}
