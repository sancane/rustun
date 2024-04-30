use crate::integrity::{IntegrityError, TransportIntegrity};
use crate::message::StunAttributes;
use crate::{Integrity, ProtectedAttributeIterator};
use log::{debug, info};
use stun_rs::attributes::stun::{MessageIntegrity, MessageIntegritySha256, UserName};
use stun_rs::{HMACKey, MessageClass, StunMessage, TransactionId};

#[derive(Debug)]
pub struct ShortTermCredentialClient {
    user_name: UserName,
    key: HMACKey,
    integrity: Option<Integrity>,
    validator: TransportIntegrity,
}

impl ShortTermCredentialClient {
    pub fn new(
        user_name: UserName,
        key: HMACKey,
        integrity: Option<Integrity>,
        is_reliable: bool,
    ) -> ShortTermCredentialClient {
        Self {
            user_name,
            key,
            integrity,
            validator: TransportIntegrity::new(is_reliable),
        }
    }

    /// 9.1.4 Receiving a Response
    fn process_message(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
    ) -> Result<(), IntegrityError> {
        let mut integrity = None;
        let mut integrity_sha256 = None;

        for attr in msg.attributes().protected_iter() {
            if attr.is_message_integrity() {
                integrity = Some(attr);
            }
            if attr.is_message_integrity_sha256() {
                integrity_sha256 = Some(attr);
            }
            if msg.class() != MessageClass::Indication
                && integrity.is_some()
                && integrity_sha256.is_some()
            {
                // Only one integrity attribute must be set in a response
                info!(
                    "[{:?}], both integrity attributes are set",
                    msg.transaction_id()
                );
                return Err(IntegrityError::Discarded);
            }
        }

        match &self.integrity {
            Some(val) => {
                let integrity = match val {
                    Integrity::MessageIntegrity => integrity,
                    Integrity::MessageIntegritySha256 => integrity_sha256,
                };

                self.validator
                    .compute_message_integrity(&self.key, integrity, raw_buffer, msg)
            }
            None => {
                let integrity = integrity.or(integrity_sha256);
                self.validator
                    .compute_message_integrity(&self.key, integrity, raw_buffer, msg)?;
                if msg.class() != MessageClass::Indication {
                    // We only update the integrity mechanism if the message is either a
                    // success response or an error response
                    if let Some(attr) = integrity {
                        if attr.is_message_integrity() {
                            self.integrity = Some(Integrity::MessageIntegrity);
                        } else {
                            self.integrity = Some(Integrity::MessageIntegritySha256);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    pub fn recv_message(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
    ) -> Result<(), IntegrityError> {
        if msg.class() == MessageClass::Request {
            debug!(
                "[{:?}], received a request message, discarded",
                msg.transaction_id()
            );
            Err(IntegrityError::Discarded)
        } else {
            self.process_message(raw_buffer, msg)
        }
    }

    // 9.1.2.  Forming a Request or Indication
    // For a request or indication message, the agent MUST include the
    // USERNAME, MESSAGE-INTEGRITY-SHA256, and MESSAGE-INTEGRITY attributes
    // in the message unless the agent knows from an external mechanism
    // which message integrity algorithm is supported by both agents.  In
    // this case, either MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 MUST
    // be included in addition to USERNAME.  The HMAC for the MESSAGE-
    // INTEGRITY attribute is computed as described in Section 14.5, and the
    // HMAC for the MESSAGE-INTEGRITY-SHA256 attributes is computed as
    // described in Section 14.6.  Note that the password is never included
    // in the request or indication.
    fn prepare_request_or_indication(&self, attributes: &mut StunAttributes) {
        remove_auth_and_integrity_attrs(attributes);
        // Add username attribute
        attributes.add(self.user_name.clone());

        if let Some(integrity) = &self.integrity {
            // Add integrity attribute
            match integrity {
                Integrity::MessageIntegrity => {
                    attributes.add(MessageIntegrity::new(self.key.clone()))
                }
                Integrity::MessageIntegritySha256 => {
                    attributes.add(MessageIntegritySha256::new(self.key.clone()))
                }
            }
        } else {
            // Add MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256 attributes
            attributes.add(MessageIntegrity::new(self.key.clone()));
            attributes.add(MessageIntegritySha256::new(self.key.clone()));
        }
    }

    pub fn add_attributes(&self, attributes: &mut StunAttributes) {
        self.prepare_request_or_indication(attributes);
    }

    pub fn signal_protection_violated_on_timeout(
        &mut self,
        transaction_id: &TransactionId,
    ) -> bool {
        self.validator
            .signal_protection_violated_on_timeout(transaction_id)
    }
}

// Remove authentication or message integrity attributes
fn remove_auth_and_integrity_attrs(attributes: &mut StunAttributes) {
    attributes.remove::<UserName>();
    attributes.remove::<MessageIntegrity>();
    attributes.remove::<MessageIntegritySha256>();
}

#[cfg(test)]
mod short_term_cred_mech_tests {
    use super::*;
    use stun_rs::attributes::stun::Software;
    use stun_rs::methods::BINDING;
    use stun_rs::StunAttribute;
    use stun_rs::{MessageDecoderBuilder, MessageEncoderBuilder, StunError, StunMessageBuilder};

    const USERNAME: &str = "test-username";
    const PASSWORD: &str = "test-password";
    const SOFTWARE: &str = "STUN test client";

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn create_stun_message(buffer: &mut [u8], class: MessageClass, integrity: Integrity) -> usize {
        let software = Software::new(SOFTWARE).expect("Could not create Software attribute");
        let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let integrity: StunAttribute = match integrity {
            Integrity::MessageIntegrity => MessageIntegrity::new(key).into(),
            Integrity::MessageIntegritySha256 => MessageIntegritySha256::new(key).into(),
        };

        let enc_msg = StunMessageBuilder::new(BINDING, class)
            .with_attribute(software)
            .with_attribute(user_name)
            .with_attribute(integrity)
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        encoder
            .encode(buffer, &enc_msg)
            .expect("Failed to encode message")
    }

    fn check_attributes(integrity: Option<Integrity>, attributes: &[StunAttribute]) {
        let mut iter = attributes.iter();

        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());

        match integrity {
            Some(Integrity::MessageIntegrity) => {
                let attr = iter.next().expect("Expected attribute MessageIntegrity");
                assert!(attr.is_message_integrity());
                assert!(iter.next().is_none());
            }
            Some(Integrity::MessageIntegritySha256) => {
                let attr = iter
                    .next()
                    .expect("Expected attribute MessageIntegritySha256");
                assert!(attr.is_message_integrity_sha256());
                assert!(iter.next().is_none());
            }
            None => {
                let attr = iter.next().expect("Expected attribute MessageIntegrity");
                assert!(attr.is_message_integrity());

                let attr = iter
                    .next()
                    .expect("Expected attribute MessageIntegritySha256");
                assert!(attr.is_message_integrity_sha256());
                assert!(iter.next().is_none());
            }
        }
    }

    fn new_short_term_auth_client(
        integrity: Option<Integrity>,
        is_reliable: bool,
    ) -> Result<ShortTermCredentialClient, StunError> {
        Ok(ShortTermCredentialClient::new(
            UserName::new(USERNAME)?,
            HMACKey::new_short_term(PASSWORD)?,
            integrity,
            is_reliable,
        ))
    }

    #[test]
    fn test_send_request() {
        init_logging();

        let integrity = None;
        let client = new_short_term_auth_client(integrity, false)
            .expect("Failed to create ShortTermAuthClient");
        let mut attributes = StunAttributes::default();
        client.add_attributes(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_attributes(integrity, &attrs);

        let integrity = Some(Integrity::MessageIntegrity);
        let client = new_short_term_auth_client(integrity, false)
            .expect("Failed to create ShortTermAuthClient");
        let mut attributes = StunAttributes::default();
        client.add_attributes(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_attributes(integrity, &attrs);

        let integrity = Some(Integrity::MessageIntegritySha256);
        let client = new_short_term_auth_client(integrity, false)
            .expect("Failed to create ShortTermAuthClient");
        let mut attributes = StunAttributes::default();
        client.add_attributes(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_attributes(integrity, &attrs);
    }

    #[test]
    fn test_recv_response_message_integrity() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Integrity::MessageIntegrity,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Failed to process response");

        // This message should not be timedout out as it was successfully authenticated
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));

        // Processing the message must make the client pick the MessageIntegrity mechanism
        let mut attributes = StunAttributes::default();
        client.add_attributes(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_attributes(Some(Integrity::MessageIntegrity), &attrs);

        // Change the integrity attribute to MessageIntegritySha256 in the next
        // response must make the client drop the message
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Integrity::MessageIntegritySha256,
        );
        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");
        assert_eq!(
            Err(IntegrityError::Discarded),
            client.recv_message(&buffer[..size], &msg)
        );

        // A timeout on this not authenticated message must fire a ProtectionViolated error
        assert!(client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_response_message_integrity_sha256() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Integrity::MessageIntegritySha256,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Failed to process response");

        // This message should not be timeout out as it was successfully authenticated
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));

        // Processing the message must make the client pick the MessageIntegritySha256 mechanism
        let mut attributes = StunAttributes::default();
        client.add_attributes(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_attributes(Some(Integrity::MessageIntegritySha256), &attrs);

        // Change the integrity attribute to MessageIntegrity in the next
        // response must make the client drop the message
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            Integrity::MessageIntegrity,
        );
        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");
        assert_eq!(
            Err(IntegrityError::Discarded),
            client.recv_message(&buffer[..size], &msg)
        );

        // A timout on this not authenticated message must fire a ProtectionViolated error
        assert!(client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_response_message_integrity_both() {
        init_logging();

        let software =
            Software::new("STUN test client").expect("Could not create Software attribute");
        let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");
        let key = HMACKey::new_short_term(PASSWORD).expect("Could not create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
            .with_attribute(software)
            .with_attribute(user_name)
            .with_attribute(integrity)
            .with_attribute(integrity_sha256)
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = encoder
            .encode(&mut buffer, &msg)
            .expect("Failed to encode message");

        // Responses can not have integrity and integrity_sha256 attributes at the same time
        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        assert_eq!(
            Err(IntegrityError::Discarded),
            client.recv_message(&buffer[..size], &msg)
        );

        // Protection violated error should not be signaled if both integrity attributes were present
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_response_message_integrity_miss_both() {
        init_logging();

        let software =
            Software::new("STUN test client").expect("Could not create Software attribute");
        let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");

        let msg = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
            .with_attribute(software)
            .with_attribute(user_name)
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = encoder
            .encode(&mut buffer, &msg)
            .expect("Failed to encode message");

        // Responses have neither integrity nor integrity_sha256 attributes
        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        assert_eq!(
            Err(IntegrityError::Discarded),
            client.recv_message(&buffer[..size], &msg)
        );

        // A timout on this not authenticated message must fire a ProtectionViolated error
        assert!(client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_response_on_reliable() {
        init_logging();

        let software =
            Software::new("STUN test client").expect("Could not create Software attribute");
        let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");

        let msg = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
            .with_attribute(software)
            .with_attribute(user_name)
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buffer: [u8; 150] = [0x00; 150];
        let size = encoder
            .encode(&mut buffer, &msg)
            .expect("Failed to encode message");

        // Responses have neither integrity nor integrity_sha256 attributes
        let mut client =
            new_short_term_auth_client(None, true).expect("Failed to create ShortTermAuthClient");
        assert_eq!(
            Err(IntegrityError::ProtectionViolated),
            client.recv_message(&buffer[..size], &msg)
        );

        // A timout on a reliable channel must not fire a ProtectionViolated error because it was already signaled
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_request_on_unreliable_fail() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Integrity::MessageIntegritySha256,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Failed to process response");

        // No protection violated error should be signaled for indications
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_indication_on_unreliable_valid() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Integrity::MessageIntegritySha256,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Failed to process response");

        // No protection violated error should be signaled for indications
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_indication_on_unreliable_invalid() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Integrity::MessageIntegritySha256,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        // Change the first bit (0x21) of the magic cookie to make the integrity check fail
        buffer[4] = 0xFF;
        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Failed to process response");
        assert_eq!(IntegrityError::Discarded, error);

        // No protection violated error should be signaled for indications
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_recv_request_on_unreliable_discarded() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::Request,
            Integrity::MessageIntegritySha256,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Failed to process response");
        assert_eq!(IntegrityError::Discarded, error);

        // No protection violated error should be signaled for indications
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }

    #[test]
    fn test_no_pick_integrity_on_indication() {
        init_logging();

        let mut buffer: [u8; 150] = [0x00; 150];
        let _ = create_stun_message(
            &mut buffer,
            MessageClass::Indication,
            Integrity::MessageIntegritySha256,
        );

        let decoder = MessageDecoderBuilder::default().build();
        let (msg, size) = decoder.decode(&buffer).expect("Failed to decode message");

        let mut client =
            new_short_term_auth_client(None, false).expect("Failed to create ShortTermAuthClient");
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Failed to process response");

        // Request must set both integrity attributes until the server picks one
        let mut attributes = StunAttributes::default();
        client.add_attributes(&mut attributes);
        let attrs: Vec<StunAttribute> = attributes.into();
        check_attributes(None, &attrs);
    }
}
