const PRIORITY: u16 = 0x0024;

crate::common::integer_attribute!(
    /// The [`Priority`] attribute MUST be included in a Binding request and be
    /// set to the value computed by the algorithm in
    /// [Section 5.1.2](https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2)
    /// for the local candidate, but with the candidate type preference of
    /// peer-reflexive candidates.
    ///
    /// # Examples
    ///```rust
    /// # use stun_rs::attributes::ice::Priority;
    /// let attr = Priority::from(1234);
    /// assert_eq!(attr, 1234);
    ///```
    Priority,
    PRIORITY,
    u32,
);
