use crate::message::StunAttributes;
use stun_rs::attributes::stun::{Fingerprint, MessageIntegrity, MessageIntegritySha256};
use stun_rs::{get_input_text, HMACKey, MessageClass, StunAttribute, StunMessage};


fn validate(raw_buffer: &[u8], msg: &StunMessage) -> bool {
    let Some(attr) =  msg.get::<Fingerprint>() else {
        return false;
    };
    let Ok(fingerprint) = attr.as_fingerprint() else {
        return false;
    };
    let Some(input) = get_input_text::<Fingerprint>(raw_buffer) else {
        return false;
    };
    fingerprint.validate(&input)
}

// When the FINGERPRINT extension is used, an agent includes the
// FINGERPRINT attribute in messages it sends to another agent.
// Section 14.7 describes the placement and value of this attribute.
pub fn send_message(attributes: &mut StunAttributes) {
    attributes.add(Fingerprint::default());
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use stun_rs::attributes::stun::{Software, UserName};
    use stun_rs::{MessageClass, MessageDecoderBuilder, MessageEncoderBuilder, StunMessageBuilder};
    use stun_rs::methods::BINDING;

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

        assert!(validate(&buffer, &msg));

        // Change a value will make validation fail (change a value in the transactio id)
        buffer[15] = 0xff;
        assert!(!validate(&buffer, &msg));

        // Create a message without FINGERPRINT
        let _ = create_response_message(&mut buffer, false);
        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");
        // We can not validate a message without the FINGERPRINT attribute
        assert!(!validate(&buffer, &msg));
    }

    #[test]
    fn test_send_message() {
        let mut attributes = StunAttributes::default();
        send_message(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_fingerprint(&attrs, true);
    }
}