use crate::message::StunAttributes;
use crate::StunAgentError;
use stun_rs::attributes::stun::Fingerprint;
use stun_rs::{get_input_text, StunAttribute, StunMessage};

pub fn validate_fingerprint_attribute(
    raw_buffer: &[u8],
    attr: &StunAttribute,
) -> Result<bool, StunAgentError> {
    let fingerprint = attr
        .as_fingerprint()
        .map_err(|_| StunAgentError::StunCheckFailed)?;
    let Some(input) = get_input_text::<Fingerprint>(raw_buffer) else {
        return Err(StunAgentError::StunCheckFailed);
    };

    Ok(fingerprint.validate(&input))
}

pub fn validate_fingerprint(raw_buffer: &[u8], msg: &StunMessage) -> Result<bool, StunAgentError> {
    // When fingerprint is used, the message must contain the FINGERPRINT attribute
    // which aids in distinguishing STUN packets from packets of other protocols,
    // and the value of the FINGERPRINT attribute contains the correct value
    let fingerprint = msg
        .get::<Fingerprint>()
        .ok_or(StunAgentError::StunCheckFailed)?;
    validate_fingerprint_attribute(raw_buffer, fingerprint)
}

// When the FINGERPRINT extension is used, an agent includes the
// FINGERPRINT attribute in messages it sends to another agent.
// Section 14.7 describes the placement and value of this attribute.
pub fn add_fingerprint_attribute(attributes: &mut StunAttributes) {
    attributes.add(Fingerprint::default());
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use stun_rs::attributes::stun::{Software, UserName};
    use stun_rs::methods::BINDING;
    use stun_rs::{
        MessageClass, MessageDecoderBuilder, MessageEncoderBuilder, StunAttribute,
        StunMessageBuilder,
    };

    const USERNAME: &str = "test-username";
    const SOFTWARE: &str = "STUN test client";

    fn create_response_message(buffer: &mut [u8], use_fingerprint: bool) -> usize {
        let software = Software::new(SOFTWARE).expect("Could not create Software attribute");
        let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");

        let mut builder = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
            .with_attribute(user_name)
            .with_attribute(software);
        if use_fingerprint {
            builder = builder.with_attribute(Fingerprint::default());
        }

        let enc_msg = builder.build();

        let encoder = MessageEncoderBuilder::default().build();
        encoder
            .encode(buffer, &enc_msg)
            .expect("Failed to encode message")
    }

    fn check_fingerprint(attributes: &[StunAttribute], use_fingerprint: bool) {
        let mut iter = attributes.iter();

        if use_fingerprint {
            let attr = iter.next().expect("Expected attribute Fingerprint");
            assert!(attr.is_fingerprint());
        }

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_recv_message() {
        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_response_message(&mut buffer, true);

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        assert!(validate_fingerprint(&buffer, &msg).expect("Failed to validate fingerprint"));

        // Change the byte 2 of the message type to make the integrity check fail
        buffer[1] += 1;
        assert!(!validate_fingerprint(&buffer, &msg).expect("Failed to validate fingerprint"));

        // Create a message without FINGERPRINT
        let _ = create_response_message(&mut buffer, false);
        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");
        // we get a StunCheckFailed error if we try to get the Fingerprint attribute when it is not used
        assert!(validate_fingerprint(&buffer, &msg).is_err());
    }

    #[test]
    fn test_validate_fingerprint_attribute() {
        let mut buffer: [u8; 150] = [0x00; 150];
        let username =
            UserName::try_from("test-username").expect("Can not create USERNAME attribute");
        let error =
            validate_fingerprint_attribute(&buffer, &username.into()).expect_err("Expected error");
        assert_eq!(error, StunAgentError::StunCheckFailed);

        let fingerprint = Fingerprint::default();
        let error = validate_fingerprint_attribute(&buffer, &fingerprint.into())
            .expect_err("Expected error");
        assert_eq!(error, StunAgentError::StunCheckFailed);

        let _ = create_response_message(&mut buffer, true);
        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        let fingerprint = msg
            .get::<Fingerprint>()
            .expect("Expected Fingerprint attribute");
        assert!(validate_fingerprint_attribute(&buffer, fingerprint)
            .expect("Failed to validate fingerprint attribute"));
    }

    #[test]
    fn test_send_message() {
        let mut attributes = StunAttributes::default();
        add_fingerprint_attribute(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_fingerprint(&attrs, true);
    }
}
