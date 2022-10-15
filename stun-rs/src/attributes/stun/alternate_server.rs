use crate::attributes::address_port::{address_port_attribute, address_port_tests};
use crate::{Decode, Encode};

const ALTERNATE_SERVER: u16 = 0x8023;

address_port_attribute!(
    /// The alternate server represents an alternate transport address
    /// identifying a different STUN server that the STUN client should try.
    ///
    /// # Examples
    ///```rust
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use stun_rs::attributes::stun::AlternateServer;
    /// let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    /// let attr = AlternateServer::from(socket);
    ///
    /// assert_eq!(attr.socket_address().port(), 8080);
    /// assert!(attr.socket_address().is_ipv4());
    ///```
    AlternateServer,
    ALTERNATE_SERVER
);

address_port_tests!(AlternateServer, super);
