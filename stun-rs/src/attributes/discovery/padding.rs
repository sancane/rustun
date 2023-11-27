const PADDING: u16 = 0x0026;
const MAX_ENCODED_SIZE: usize = 64000;
const MAX_DECODED_SIZE: usize = 64000;

crate::common::string_attribute!(
    /// The padding attribute allows for the entire message to be padded to
    /// force the STUN message to be divided into IP fragments.  This attribute
    /// consists entirely of a free-form string, the value of which does not
    /// matter. Padding can be used in either Binding Requests or Binding
    /// Responses.
    ///
    /// # Examples
    ///```rust
    /// # use std::error::Error;
    /// # use stun_rs::attributes::discovery::Padding;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let attr = Padding::new("ABCDEFGHIJK...")?;
    /// assert_eq!(attr, "ABCDEFGHIJK...");
    /// #
    /// #  Ok(())
    /// # }
    ///```
    Padding,
    PADDING,
    MAX_ENCODED_SIZE,
    MAX_DECODED_SIZE,
);
