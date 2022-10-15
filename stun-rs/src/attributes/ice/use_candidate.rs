const USE_CANDIDATE: u16 = 0x0025;

crate::common::empty_attribute!(
    /// The controlling agent MUST include the [`UseCandidate`] attribute in
    /// order to nominate a candidate pair
    /// [Section 8.1.1](https://datatracker.ietf.org/doc/html/rfc8445#section-8.1.1).
    /// The controlled agent MUST NOT include the [`UseCandidate`] attribute in a Binding request.
    ///
    /// # Examples
    ///```rust
    /// # use stun_rs::attributes::{AttributeType, StunAttributeType};
    /// # use stun_rs::attributes::ice::UseCandidate;
    /// let attr = UseCandidate::default();
    /// assert_eq!(attr.attribute_type(), AttributeType::from(0x0025));
    ///```
    UseCandidate,
    USE_CANDIDATE,
);
