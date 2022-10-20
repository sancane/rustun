use crate::attributes::{stunt_attribute, DecodeAttributeValue, EncodeAttributeValue};
use crate::context::{AttributeDecoderContext, AttributeEncoderContext};
use crate::{Decode, Encode, StunError, StunErrorType};
use std::convert::TryFrom;

const SOFTWARE: u16 = 0x8022;

const MAX_ENCODED_SIZE: usize = 509;
const MAX_DECODED_SIZE: usize = 763;

/// The [`Software`] attribute contains a textual description of the software
/// being used by the agent sending the message.  It is used by clients
/// and servers.  Its value SHOULD include manufacturer and version
/// number.  The attribute has no impact on operation of the protocol and
/// serves only as a tool for diagnostic and debugging purposes.
///
/// # Examples
///```rust
/// # use std::error::Error;
/// # use stun_rs::attributes::stun::Software;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let attr = Software::new("STUN test client")?;
/// assert_eq!(attr, "STUN test client");
/// #
/// #  Ok(())
/// # }
///```
#[derive(Debug, PartialEq, Clone, Hash, Eq, PartialOrd, Ord)]
pub struct Software(String);

impl Software {
    /// Creates a new SOFTWARE attribute
    pub fn new<S>(value: S) -> Result<Self, StunError>
    where
        S: Into<String>,
    {
        let value: String = value.into();
        let value_len = value.len();
        (value.len() <= MAX_ENCODED_SIZE)
            .then_some(Self(value))
            .ok_or_else(|| {
                StunError::new(
                    StunErrorType::ValueTooLong,
                    format!(
                        "Value length {} > max. encoded size {}",
                        value_len, MAX_ENCODED_SIZE
                    ),
                )
            })
    }

    /// Returns a slice representation of the SOFTWARE attribute value
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<&str> for Software {
    type Error = StunError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Software::new(value)
    }
}

impl TryFrom<&String> for Software {
    type Error = StunError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Software::new(value)
    }
}

impl TryFrom<String> for Software {
    type Error = StunError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Software::new(value)
    }
}

impl PartialEq<&str> for Software {
    fn eq(&self, other: &&str) -> bool {
        self.as_str().eq(*other)
    }
}

impl PartialEq<Software> for &str {
    fn eq(&self, other: &Software) -> bool {
        other.as_str().eq(*self)
    }
}

impl PartialEq<str> for Software {
    fn eq(&self, other: &str) -> bool {
        self.as_str().eq(other)
    }
}

impl PartialEq<String> for Software {
    fn eq(&self, other: &String) -> bool {
        other.eq(self.as_str())
    }
}

impl PartialEq<Software> for String {
    fn eq(&self, other: &Software) -> bool {
        self.eq(other.as_str())
    }
}

impl AsRef<str> for Software {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<String> for Software {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl DecodeAttributeValue for Software {
    fn decode(ctx: AttributeDecoderContext) -> Result<(Self, usize), StunError> {
        let raw_value = ctx.raw_value();

        if raw_value.len() > MAX_DECODED_SIZE {
            return Err(StunError::new(
                StunErrorType::ValueTooLong,
                format!(
                    "Value length {} > max. decoded size {}",
                    raw_value.len(),
                    MAX_DECODED_SIZE
                ),
            ));
        }

        let (val, size) = <&'_ str as Decode<'_>>::decode(ctx.raw_value())?;
        Ok((Self(val.to_string()), size))
    }
}

impl EncodeAttributeValue for Software {
    fn encode(&self, mut ctx: AttributeEncoderContext) -> Result<usize, StunError> {
        if self.as_str().len() > MAX_ENCODED_SIZE {
            return Err(StunError::new(
                StunErrorType::ValueTooLong,
                format!(
                    "Value length {} > max. encoded size {}",
                    self.as_str().len(),
                    MAX_ENCODED_SIZE
                ),
            ));
        }

        self.0.as_str().encode(ctx.raw_value_mut())
    }
}

impl crate::attributes::AsVerifiable for Software {}

stunt_attribute!(Software, SOFTWARE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StunAttribute;

    #[test]
    fn constructor() {
        let name = String::from("Test Software v1.0");
        let attr_1 = Software::try_from(&name).expect("Can not create Software attribute");
        let attr_2 = Software::new(&name).expect("Can not create Software attribute");
        let attr_3 = Software::try_from(name.as_str()).expect("Can not create Software attribute");
        let attr_4 = Software::try_from(name.clone()).expect("Can not create Software attribute");

        assert_eq!(attr_1, name);
        assert_eq!(name, attr_1);
        assert_eq!(name, attr_3);
        assert_eq!(name, attr_4);
        assert_eq!(attr_1, "Test Software v1.0");
        assert_eq!("Test Software v1.0", attr_1);
        assert_eq!(attr_1, attr_2);

        let value: &String = attr_1.as_ref();
        assert!(name.eq(value));

        let value: &str = attr_1.as_ref();
        assert!(name.eq(value));

        let value = "x".repeat(MAX_ENCODED_SIZE);
        let _result = Software::new(value.as_str()).expect("Can not create a Sofware attribute");

        let value = "x".repeat(MAX_ENCODED_SIZE + 1);
        let result = Software::new(value);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::ValueTooLong
        );
    }

    #[test]
    fn decode_software_value() {
        let dummy_msg = [];
        // Software: example.org
        let value = "example";
        let ctx = AttributeDecoderContext::new(None, &dummy_msg, value.as_bytes());

        let (software, size) = Software::decode(ctx).expect("Can not decode Software");
        assert_eq!(size, 7);
        assert_eq!(software.as_str(), "example");

        let value = "x".repeat(MAX_DECODED_SIZE);
        let ctx = AttributeDecoderContext::new(None, &dummy_msg, value.as_bytes());
        let (_nonce, size) = Software::decode(ctx).expect("Can not decode Software");
        assert_eq!(size, MAX_DECODED_SIZE);

        let value = "x".repeat(MAX_DECODED_SIZE + 1);
        let ctx = AttributeDecoderContext::new(None, &dummy_msg, value.as_bytes());
        assert_eq!(
            Software::decode(ctx).expect_err("Error expected"),
            StunErrorType::ValueTooLong
        );
    }

    #[test]
    fn encode_software_value() {
        let dummy_msg: [u8; 0] = [0x0; 0];
        let software =
            Software::try_from("test software").expect("Can not create a Sofware attribute");

        let mut buffer: [u8; 13] = [0x0; 13];
        let ctx = AttributeEncoderContext::new(None, &dummy_msg, &mut buffer);
        let result = software.encode(ctx);
        assert_eq!(result, Ok(13));

        let mut buffer: [u8; MAX_ENCODED_SIZE] = [0x0; MAX_ENCODED_SIZE];
        let software = Software::try_from("x".repeat(MAX_ENCODED_SIZE))
            .expect("Can not create a Sofware attribute");
        let ctx = AttributeEncoderContext::new(None, &dummy_msg, &mut buffer);
        let result = software.encode(ctx);
        assert_eq!(result, Ok(MAX_ENCODED_SIZE));

        let mut buffer: [u8; 12] = [0x0; 12];
        let ctx = AttributeEncoderContext::new(None, &dummy_msg, &mut buffer);
        let result = software.encode(ctx);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::SmallBuffer
        );

        let mut buffer: [u8; MAX_ENCODED_SIZE + 1] = [0x0; MAX_ENCODED_SIZE + 1];
        let software = Software("x".repeat(MAX_ENCODED_SIZE + 1));
        let ctx = AttributeEncoderContext::new(None, &dummy_msg, &mut buffer);
        let result = software.encode(ctx);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::ValueTooLong
        );
    }

    #[test]
    fn software_stunt_attribute() {
        let attr = StunAttribute::Software(
            Software::new("test").expect("Can not create Software attribute"),
        );
        assert!(attr.is_software());
        assert!(attr.as_software().is_ok());
        assert!(attr.as_unknown().is_err());

        let dbg_fmt = format!("{:?}", attr);
        assert_eq!("Software(Software(\"test\"))", dbg_fmt);
    }
}
