const XOR_PEER_ADDRESS: u16 = 0x0012;

crate::common::xor_socket_addr_attribute!(
    /// The `XorPeerAddress` attribute specifies the address and port of the
    ///  peer as seen from the TURN server.  (For example, the peer's server-
    ///  reflexive transport address if the peer is behind a NAT.)
    ///
    /// # Examples
    ///```rust
    /// # use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    /// # use stun_rs::attributes::turn::XorPeerAddress;
    /// let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    /// let attr = XorPeerAddress::from(socket);
    ///
    /// let socket = attr.socket_address();
    /// assert_eq!(socket.port(), 8080);
    /// assert_eq!(socket.is_ipv4(), true);
    ///```
    XorPeerAddress,
    XOR_PEER_ADDRESS,
);
