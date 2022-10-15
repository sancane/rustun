const LIFETIME: u16 = 0x000D;

crate::common::integer_attribute!(
    /// The `LifeTime` attribute represents the duration for which the server
    /// will maintain an allocation in the absence of a refresh.  The TURN
    /// client can include the LIFETIME attribute with the desired lifetime
    /// in Allocate and Refresh requests.  The value portion of this
    /// attribute is 4 bytes long and consists of a 32-bit unsigned integral
    /// value representing the number of seconds remaining until expiration.
    ///
    /// # Examples
    ///```rust
    /// # use stun_rs::attributes::turn::LifeTime;
    /// let attr = LifeTime::from(1234);
    /// assert_eq!(attr, 1234);
    ///```
    LifeTime,
    LIFETIME,
    u32,
);
