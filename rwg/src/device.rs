//! WireGuard device management.

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::ptr;

use libwg_sys as sys;

use crate::key::Key;
use crate::peer::{self, Peer};

/// A WireGuard device / interface.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    name: String,
    private_key: Option<Key>,
    listen_port: Option<u16>,
    peers: Vec<Peer>,
}

impl Device {
    /// Open all WireGuard devices on this machine.
    pub fn all() -> Result<Vec<Device>, io::Error> {
        let names = unsafe {
            let mut names = Vec::new();
            let mut pointer = sys::wg_list_device_names();

            while *pointer != 0 as i8 {
                let name = CStr::from_ptr(pointer);

                pointer = pointer.add(name.to_bytes().len() + 1);
                names.push(name);
            }

            names
        };

        let mut devices = Vec::with_capacity(names.len());

        for name in names {
            devices.push(Device::open(name.to_string_lossy())?);
        }

        Ok(devices)
    }

    /// Create a new WireGuard device.
    pub fn create<S: Into<String>>(name: S, private_key: Option<Key>) -> Result<Device, io::Error> {
        let name = CString::new(name.into()).expect("Invalid device name");

        unsafe {
            if sys::wg_add_device(name.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Device {
            name: name.into_string().unwrap(),
            private_key: private_key,
            listen_port: None,
            peers: Vec::new(),
        })
    }

    /// Open an existing WireGuard device.
    pub fn open<S: Into<String>>(name: S) -> Result<Device, io::Error> {
        let name = CString::new(name.into()).expect("Invalid device name");

        let handle = unsafe {
            let mut h: *mut sys::wg_device = mem::zeroed();

            if sys::wg_get_device(&mut h, name.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }

            h
        };

        Ok(Device::from_handle(handle))
    }

    /// Create a `Device` object from the C library handle.
    fn from_handle(h: *mut sys::wg_device) -> Device {
        let name = unsafe { CStr::from_ptr((*h).name.as_ptr() as *const i8) };

        let private_key = unsafe {
            if (*h).flags & sys::wg_device_flags_WGDEVICE_HAS_PRIVATE_KEY != 0 {
                Some(Key::from_bytes((*h).private_key))
            } else {
                None
            }
        };

        let listen_port = unsafe {
            let port = (*h).listen_port;

            if port > 0 {
                Some(port)
            } else {
                None
            }
        };

        let peers = unsafe {
            let mut peers = Vec::new();
            let mut peer = (*h).first_peer;

            while peer != ptr::null_mut() {
                peers.push(Peer::from_handle(peer));
                peer = (*peer).next_peer;
            }

            peers
        };

        Device {
            name: String::from(
                name.to_str()
                    .expect("Get an invalid interface name from wg"),
            ),
            private_key: private_key,
            listen_port: listen_port,
            peers: peers,
        }
    }

    /// Get the C library handle that corresponds to this device.
    fn handle(&self) -> Handle {
        unsafe {
            let mut h: sys::wg_device = mem::zeroed();
            let name = CString::new(self.name.clone()).unwrap();

            ptr::copy_nonoverlapping(
                name.as_ptr(),
                h.name.as_mut_ptr(),
                self.name.as_bytes().len(),
            );

            if let Some(ref key) = self.private_key {
                h.flags |= sys::wg_device_flags_WGDEVICE_HAS_PRIVATE_KEY;

                h.private_key.copy_from_slice(key.as_bytes());
                h.public_key.copy_from_slice(key.derive_public().as_bytes());
            }

            if let Some(listen_port) = self.listen_port {
                h.flags |= sys::wg_device_flags_WGDEVICE_HAS_LISTEN_PORT;
                h.listen_port = listen_port;
            }

            h.flags |= sys::wg_device_flags_WGDEVICE_REPLACE_PEERS;

            let mut peers = self
                .peers
                .iter()
                .map(|peer| peer.handle())
                .collect::<Vec<_>>();

            if !peers.is_empty() {
                let peers_len = peers.len();
                let peers_ptr = peers.as_mut_ptr();

                for (i, peer) in peers.iter_mut().enumerate() {
                    if i + 1 < peers_len {
                        peer.handle.next_peer = peers_ptr.add(i + 1) as *mut sys::wg_peer;
                    } else {
                        peer.handle.next_peer = ptr::null_mut();
                    }
                }

                h.first_peer = peers_ptr as *mut sys::wg_peer;
                h.last_peer = peers_ptr.add(peers_len - 1) as *mut sys::wg_peer;
            } else {
                h.first_peer = ptr::null_mut();
                h.last_peer = ptr::null_mut();
            }

            Handle { h: h, peers: peers }
        }
    }

    /// Set the UDP listening port of this device.
    pub fn set_listen_port(&mut self, port: u16) {
        self.listen_port = Some(port);
    }

    /// Attach a new peer to the device.
    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.push(peer);
    }

    /// Get the name of this device.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the public key of this device, if any.
    pub fn public_key(&self) -> Option<Key> {
        self.private_key.as_ref().map(|key| key.derive_public())
    }

    /// Get the private key of this device, if any.
    pub fn private_key(&self) -> Option<&Key> {
        self.private_key.as_ref()
    }

    /// Get the UDP listening port of this device, if it has been set.
    pub fn listen_port(&self) -> Option<u16> {
        self.listen_port
    }

    /// Get a read-only reference to the list of peers associated to this device.
    pub fn peers(&self) -> &[Peer] {
        self.peers.as_ref()
    }

    /// Get a mutable reference to the list of peers associated to this device.
    pub fn peers_mut(&mut self) -> &mut Vec<Peer> {
        &mut self.peers
    }

    /// Save the changes made to the device and push them to the kernel. Consumes `self`.
    pub fn save(self) -> io::Result<()> {
        let mut handle = self.handle();

        unsafe {
            if sys::wg_set_device(&mut handle.h) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
}

/// Handle to a device that can be used by the C library.
#[repr(C)]
struct Handle {
    h: sys::wg_device,
    peers: Vec<peer::Handle>,
}
