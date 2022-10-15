const DONT_FRAGMENT: u16 = 0x001A;

crate::common::empty_attribute!(
    /// This attribute is used by the client to request that the server set
    /// the `DF` (Don't Fragment) bit in the IP header when relaying the
    /// application data onward to the peer and for determining the server
    /// capability in Allocate requests
    ///
    /// # Examples
    ///```rust
    /// # use stun_rs::attributes::{AttributeType, StunAttributeType};
    /// # use stun_rs::attributes::turn::DontFragment;
    /// let attr = DontFragment::default();
    /// assert_eq!(attr.attribute_type(), AttributeType::from(0x001A));
    ///```
    DontFragment,
    DONT_FRAGMENT,
);
