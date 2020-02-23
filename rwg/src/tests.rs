//! Library tests.

use std::net::{IpAddr, Ipv4Addr};

use crate::{AllowedIp, Device, Key, Peer};

#[test]
fn create_and_retrieve() {
    let dev_name = "testwg0";

    // Create a new test device.
    let mut dev = Device::create(dev_name, Some(Key::generate_private())).unwrap();
    dev.set_listen_port(1337);

    let mut peer = Peer::new(
        Key::generate_private().derive_public(),
        Some((IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 42069)),
    );

    peer.add_allowed_ip(AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32));
    dev.add_peer(peer);

    let mut peer = Peer::new(Key::generate_private().derive_public(), None);

    peer.add_allowed_ip(AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 32));
    dev.add_peer(peer);

    dev.clone().save().unwrap();

    // Verify that the device has been correctly configured.
    assert_eq!(1, Device::all().unwrap().len());
    assert_eq!(dev, Device::open(dev_name).unwrap());
}
