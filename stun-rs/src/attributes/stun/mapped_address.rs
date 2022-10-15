use crate::attributes::address_port::{address_port_attribute, address_port_tests};
use crate::{Decode, Encode};

const MAPPED_ADDRESS: u16 = 0x0001;

address_port_attribute!(
    /// The MAPPED-ADDRESS attribute indicates a reflexive transport
    /// address of the client.
    ///
    /// # Examples
    ///```rust
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use stun_rs::attributes::stun::MappedAddress;
    /// let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    /// let attr = MappedAddress::from(socket);
    ///
    /// assert_eq!(attr.socket_address().port(), 8080);
    /// assert!(attr.socket_address().is_ipv4());
    ///```
    MappedAddress,
    MAPPED_ADDRESS
);

address_port_tests!(MappedAddress, super);
