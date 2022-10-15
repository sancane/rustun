const ICE_CONTROLLED: u16 = 0x8029;

crate::common::integer_attribute!(
    /// The controlled agent MUST include the [`IceControlled`]
    /// attribute in a Binding request. The content of this value
    /// is used as tiebreaker values when an ICE role
    /// [conflict](https://datatracker.ietf.org/doc/html/rfc8445#section-7.3.1.1) occurs
    ///
    /// # Examples
    ///```rust
    /// # use stun_rs::attributes::ice::IceControlled;
    /// let attr = IceControlled::from(1234);
    /// assert_eq!(attr, 1234);
    ///```
    IceControlled,
    ICE_CONTROLLED,
    u64,
);
