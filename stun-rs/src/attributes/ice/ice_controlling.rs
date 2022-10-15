const ICE_CONTROLLING: u16 = 0x802A;

crate::common::integer_attribute!(
    /// The controlling agent MUST include the [`IceControlling`] attribute in a
    /// Binding request. The content of this value
    /// is used as tiebreaker values when an ICE role
    /// [conflict](https://datatracker.ietf.org/doc/html/rfc8445#section-7.3.1.1) occurs
    ///
    /// # Examples
    ///```rust
    /// # use stun_rs::attributes::ice::IceControlling;
    /// let attr = IceControlling::from(1234);
    /// assert_eq!(attr, 1234);
    ///```
    IceControlling,
    ICE_CONTROLLING,
    u64,
);
