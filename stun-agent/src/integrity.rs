use log::debug;
use std::collections::HashSet;
use stun_rs::{
    attributes::stun::{MessageIntegrity, MessageIntegritySha256},
    get_input_text, HMACKey, StunAttribute, StunMessage, TransactionId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityError {
    Discarded,
    NotRetryable,
    ProtectionViolated,
    Retry,
}

#[derive(Debug, Default)]
pub struct TransportIntegrity {
    transactions: HashSet<TransactionId>,
    is_reliable: bool,
}

fn validate_message_integrity(integrity: &StunAttribute, key: &HMACKey, raw_buffer: &[u8]) -> bool {
    match integrity {
        StunAttribute::MessageIntegrity(attr) => {
            let Some(input) = get_input_text::<MessageIntegrity>(raw_buffer) else {
                return false;
            };
            attr.validate(&input, key)
        }
        StunAttribute::MessageIntegritySha256(attr) => {
            let Some(input) = get_input_text::<MessageIntegritySha256>(raw_buffer) else {
                return false;
            };
            attr.validate(&input, key)
        }
        _ => false,
    }
}

impl TransportIntegrity {
    pub fn new(is_reliable: bool) -> Self {
        Self {
            transactions: HashSet::new(),
            is_reliable,
        }
    }

    fn discard_message(&mut self, message: &StunMessage) -> IntegrityError {
        if message.class() == stun_rs::MessageClass::Indication {
            // If the request was an indication, the response MUST be discarded
            return IntegrityError::Discarded;
        }

        // success and error responses are handled differently
        if self.is_reliable {
            // If the request was sent over a reliable transport, the response MUST
            // be discarded, and the layer MUST immediately end the transaction and
            // signal that the integrity protection was violated.
            IntegrityError::ProtectionViolated
        } else {
            // If the request was sent over an unreliable transport, the response
            // MUST be discarded, as if it had never been received.  This means that
            // retransmits, if applicable, will continue.  If all the responses
            // received are discarded, then instead of signaling a timeout after
            // ending the transaction, the layer MUST signal that the integrity
            // protection was violated.
            self.transactions.insert(*message.transaction_id());
            IntegrityError::Discarded
        }
    }

    pub fn compute_message_integrity(
        &mut self,
        key: &HMACKey,
        integrity: Option<&StunAttribute>,
        raw_buffer: &[u8],
        message: &StunMessage,
    ) -> Result<(), IntegrityError> {
        if let Some(integrity) = integrity {
            // Check that the message can be authenticated
            if validate_message_integrity(integrity, key, raw_buffer) {
                if message.class() != stun_rs::MessageClass::Indication {
                    self.transactions.remove(message.transaction_id());
                }
                return Ok(());
            }
        }

        debug!(
            "[{:?}] Failed to compute integrity",
            message.transaction_id()
        );
        // both MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256 attributes are absent
        // or failed to compute integrity check, the processing depends on whether the
        // request was sent over a reliable or an unreliable transport
        Err(self.discard_message(message))
    }

    pub fn signal_protection_violated_on_timeout(
        &mut self,
        transaction_id: &TransactionId,
    ) -> bool {
        self.transactions.remove(transaction_id)
    }
}

#[cfg(test)]
mod validate_integrity_tests {
    use crate::Integrity;

    use super::*;
    use stun_rs::attributes::stun::{Software, UserName};
    use stun_rs::methods::BINDING;
    use stun_rs::{MessageClass, StunAttribute};
    use stun_rs::{
        MessageDecoderBuilder, MessageEncoderBuilder, StunAttributeType, StunMessageBuilder,
    };

    const USERNAME: &str = "test-username";
    const PASSWORD: &str = "test-password";
    const SOFTWARE: &str = "STUN test client";

    fn create_stun_message(
        buffer: &mut [u8],
        class: MessageClass,
        integrity: Option<Integrity>,
    ) -> usize {
        let software = Software::new(SOFTWARE).expect("Could not create Software attribute");
        let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");

        let mut builder = StunMessageBuilder::new(BINDING, class)
            .with_attribute(software)
            .with_attribute(user_name);

        if let Some(integrity) = integrity {
            let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
            let attr: StunAttribute = match integrity {
                Integrity::MessageIntegrity => MessageIntegrity::new(key).into(),
                Integrity::MessageIntegritySha256 => MessageIntegritySha256::new(key).into(),
            };
            builder = builder.with_attribute(attr);
        }

        let enc_msg = builder.build();

        let encoder = MessageEncoderBuilder::default().build();
        encoder
            .encode(buffer, &enc_msg)
            .expect("Failed to encode message")
    }

    fn integrity_tests<A>()
    where
        A: StunAttributeType,
    {
        let integrity = if A::get_type() == MessageIntegrity::get_type() {
            Integrity::MessageIntegrity
        } else if A::get_type() == MessageIntegritySha256::get_type() {
            Integrity::MessageIntegritySha256
        } else {
            panic!("Invalid integrity attribute type {}", A::get_type());
        };

        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(&mut buffer, MessageClass::SuccessResponse, Some(integrity));

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Check that software is not an integrity attribute
        let attr = msg
            .get::<Software>()
            .ok_or("Software attribute not found")
            .expect("Failed to get Software attribute");
        assert!(!validate_message_integrity(attr, &key, &buffer));

        // MessageIntegrity is valid
        let attr = msg
            .get::<A>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        assert!(validate_message_integrity(attr, &key, &buffer));

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        buffer[4] = 0xFF;
        assert!(!validate_message_integrity(attr, &key, &buffer));
    }

    #[test]
    fn test_integrity_validation() {
        integrity_tests::<MessageIntegrity>();
        integrity_tests::<MessageIntegritySha256>();
    }

    #[test]
    fn test_integrity_validation_failure() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];

        // No integrity attribute
        let _ = create_stun_message(&mut buffer, MessageClass::SuccessResponse, None);
        let attr = MessageIntegrity::new(key.clone()).into();
        assert!(!validate_message_integrity(&attr, &key, &buffer));

        // No integrity sha-256 attribute
        let _ = create_stun_message(&mut buffer, MessageClass::SuccessResponse, None);
        let attr = MessageIntegritySha256::new(key.clone()).into();
        assert!(!validate_message_integrity(&attr, &key, &buffer));
    }

    #[test]
    fn test_transport_integrity_no_realiable_no_attr() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(&mut buffer, MessageClass::SuccessResponse, None);

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut ti = TransportIntegrity::new(false);
        let error = ti
            .compute_message_integrity(&key, None, buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_transport_integrity_no_realiable_valid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        ti.compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect("Message must be valid");

        // No protection violated
        assert!(!ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_no_realiable_invalid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        buffer[4] = 0xFF;

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        let error = ti
            .compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert_eq!(error, IntegrityError::Discarded);

        // Protection violated on timeout
        assert!(ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_no_realiable_invalid_no_protection_violated() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        let prev = buffer[4];
        buffer[4] = 0xff;

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        let error = ti
            .compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert_eq!(error, IntegrityError::Discarded);

        // Restore the buffer
        buffer[4] = prev;

        ti.compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect("Message must be valid");

        // Transaction completed so no protection violated
        assert!(!ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_sha_256_no_realiable_valid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Some(Integrity::MessageIntegritySha256),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        let integrity = msg
            .get::<MessageIntegritySha256>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        ti.compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect("Message must be valid");

        // No protection violated
        assert!(!ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_sha_256_no_realiable_invalid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Some(Integrity::MessageIntegritySha256),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        buffer[4] = 0xFF;

        let integrity = msg
            .get::<MessageIntegritySha256>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        let error = ti
            .compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert_eq!(error, IntegrityError::Discarded);

        // Protection violated on timeout
        assert!(ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_realiable_protection_violated() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        buffer[4] = 0xFF;

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(true);
        let error = ti
            .compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert_eq!(error, IntegrityError::ProtectionViolated);
    }

    #[test]
    fn test_transport_integrity_no_realiable_indication_valid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        ti.compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect("Message must be valid");

        // No protection violated for indications
        assert!(!ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_no_realiable_indication_invalid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        let prev = buffer[4];
        buffer[4] = 0xFF;

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(false);
        let error = ti
            .compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert!(error == IntegrityError::Discarded);

        // No protection violated for indications
        assert!(!ti.signal_protection_violated_on_timeout(msg.transaction_id()));

        // Restore the buffer
        buffer[4] = prev;

        ti.compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect("Message must be valid");
        // No protection violated for indications
        assert!(!ti.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_transport_integrity_realiable_indication_invalid() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Some(Integrity::MessageIntegrity),
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, _) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        buffer[4] = 0xFF;

        let integrity = msg
            .get::<MessageIntegrity>()
            .ok_or("integrity attribute not found")
            .expect("Failed to get integrity attribute");
        let mut ti = TransportIntegrity::new(true);

        // Indication must be discarded on reliable transports
        let error = ti
            .compute_message_integrity(&key, Some(integrity), buffer[..size].as_ref(), &msg)
            .expect_err("Message must be discarded");
        assert!(error == IntegrityError::Discarded);
    }
}
