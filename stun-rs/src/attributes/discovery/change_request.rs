use crate::attributes::{
    stunt_attribute, AsVerifiable, AttributeDecoderContext, AttributeEncoderContext,
    DecodeAttributeValue, EncodeAttributeValue,
};

const CHANGE_REQUEST: u16 = 0x0003;

/// The change request attribute contains two flags to control the IP
/// address and port that the server uses to send the response. These
/// flags are called the "change IP" and "change port" flags.
/// This attribute is allowed only in the Binding Request. The
/// "change IP" and "change port" flags are useful for determining the
/// current filtering behavior of a NAT. They instruct the server to
/// send the Binding Responses from the alternate source IP address
/// and/or alternate port. The change request attribute is optional in
/// the Binding Request.
#[derive(Debug, Clone, Copy)]
pub struct ChangeRequest(u32);

impl ChangeRequest {
    /// cerates a new change request attribute
    /// # Arguments
    /// - `change_ip`: The change IP flag
    /// - `change_port`: The change port flag
    /// # Returns
    /// The change request attribute
    pub fn new(change_ip: bool, change_port: bool) -> Self {
        let value = (change_ip as u32) << 2 | (change_port as u32) << 1;
        Self(value)
    }

    /// Returns true if the change port flag is set
    pub fn change_ip(&self) -> bool {
        (self.0 & 0b100) != 0
    }

    /// Returns true if the change port flag is set
    pub fn change_port(&self) -> bool {
        (self.0 & 0b010) != 0
    }
}

impl DecodeAttributeValue for ChangeRequest {
    fn decode(ctx: AttributeDecoderContext) -> Result<(Self, usize), crate::StunError> {
        use crate::Decode;
        let (value, size) = u32::decode(ctx.raw_value())?;
        Ok((ChangeRequest(value), size))
    }
}

impl EncodeAttributeValue for ChangeRequest {
    fn encode(&self, mut ctx: AttributeEncoderContext) -> Result<usize, crate::StunError> {
        use crate::Encode;
        self.0.encode(ctx.raw_value_mut())
    }
}

impl AsVerifiable for ChangeRequest {}

stunt_attribute!(ChangeRequest, CHANGE_REQUEST);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StunErrorType;
    use crate::StunAttribute;

    #[test]
    fn change_request_attribute() {
        let attr = ChangeRequest::new(true, false);
        assert!(attr.change_ip());
        assert!(!attr.change_port());
    }

    #[test]
    fn decode_change_request_attribute() {
        let dummy_msg = [];
        let raw_value = [0x00, 0x00, 0x04];
        let ctx = AttributeDecoderContext::new(None, &dummy_msg, &raw_value);
        assert_eq!(
            ChangeRequest::decode(ctx).expect_err("Error expected"),
            StunErrorType::SmallBuffer
        );

        let raw_value = [0x00, 0x00, 0x00, 0x04];
        let ctx = AttributeDecoderContext::new(None, &dummy_msg, &raw_value);
        let (attr, size) = ChangeRequest::decode(ctx).unwrap();
        assert!(attr.change_ip());
        assert!(!attr.change_port());
        assert_eq!(size, 4);
    }

    #[test]
    fn encode_change_request_attribute() {
        let dummy_msg = [];
        let attr = ChangeRequest::new(false, true);
        let mut raw_value = [0x00; 3];
        let ctx = AttributeEncoderContext::new(None, &dummy_msg, &mut raw_value);
        let result = attr.encode(ctx);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::SmallBuffer
        );

        let mut raw_value = [0x00; 4];
        let ctx = AttributeEncoderContext::new(None, &dummy_msg, &mut raw_value);
        let size = attr.encode(ctx).unwrap();
        assert_eq!(raw_value, [0x00, 0x00, 0x00, 0x02]);
        assert_eq!(size, 4);
    }

    #[test]
    fn change_request_stunt_attribute() {
        let attr = StunAttribute::ChangeRequest(ChangeRequest::new(false, true));
        assert!(attr.is_change_request());
        assert!(attr.as_change_request().is_ok());
        assert!(attr.as_error_code().is_err());

        let dbg_fmt = format!("{:?}", attr);
        assert_eq!("ChangeRequest(ChangeRequest(2))", dbg_fmt);
    }
}
