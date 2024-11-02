use std::time::Duration;
use stun_agent::{
    CredentialMechanism, Integrity, RttConfig, StunAgentError, StunAttributes, StunClienteBuilder,
    StunTransactionError, StuntClientEvent, TransportReliability,
};
use stun_rs::attributes::stun::{MessageIntegrity, MessageIntegritySha256, UserName};
use stun_rs::methods::BINDING;
use stun_rs::MessageClass::{self, ErrorResponse, Indication, Request, SuccessResponse};
use stun_rs::StunAttribute;
use stun_rs::{
    DecoderContextBuilder, HMACKey, MessageDecoder, MessageDecoderBuilder, MessageEncoderBuilder,
    StunMessageBuilder, MESSAGE_HEADER_SIZE,
};

const USERNAME: &str = "test-username";
const PASSWORD: &str = "test-password";
const CAPACITY: usize = 1024;

fn init_logging() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pool_buffer() -> Vec<u8> {
    vec![0; CAPACITY]
}

fn create_decoder(key: HMACKey) -> MessageDecoder {
    let ctx = DecoderContextBuilder::default()
        .with_key(key)
        .with_validation()
        .build();
    MessageDecoderBuilder::default().with_context(ctx).build()
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

fn create_stun_message(
    buffer: &mut [u8],
    class: MessageClass,
    integrity: Option<Integrity>,
) -> usize {
    let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");

    let mut builder = StunMessageBuilder::new(BINDING, class).with_attribute(user_name);

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

#[test]
fn test_stun_client_send_request_unreliable() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key);

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::ShortTerm(None))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(tid, msg.transaction_id());
    check_attributes(None, msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Request);
}

#[test]
fn test_stun_client_send_indication_unreliable() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key);

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::ShortTerm(None))
            .build()
            .expect("Failed to build");

    let transaction_id = client
        .send_indication(BINDING, StunAttributes::default(), pool_buffer())
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(tid, msg.transaction_id());
    check_attributes(None, msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    // No more events
    assert!(iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Indication);
}

#[test]
fn test_stun_client_send_request_unreliable_with_integrity() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key);

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(
                USERNAME,
                PASSWORD,
                CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
            )
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(tid, &transaction_id);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    check_attributes(Some(Integrity::MessageIntegrity), msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Request);
}

#[test]
fn test_stun_client_send_indication_unreliable_with_integrity() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key);

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(
                USERNAME,
                PASSWORD,
                CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
            )
            .build()
            .expect("Failed to build");

    let transaction_id = client
        .send_indication(BINDING, StunAttributes::default(), pool_buffer())
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(tid, &transaction_id);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    check_attributes(Some(Integrity::MessageIntegrity), msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    // No more events
    assert!(iter.next().is_none());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Indication);
}

#[test]
fn test_stun_client_recv_indication_unreliable_with_wrong_integrity_mech() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(
                USERNAME,
                PASSWORD,
                CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
            )
            .build()
            .expect("Failed to build");

    // Create an indication using the wrong integrity mechanism MessageIntegritySha256
    let instant = std::time::Instant::now();
    let mut buffer = pool_buffer();
    create_stun_message(
        &mut buffer,
        Indication,
        Some(Integrity::MessageIntegritySha256),
    );
    let error = client
        .on_buffer_recv(&buffer, instant)
        .expect_err("Expected Discarded error");
    assert_eq!(error, StunAgentError::Discarded);
}

#[test]
fn test_stun_client_recv_indication_unreliable_corrupted_integrity() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(
                USERNAME,
                PASSWORD,
                CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
            )
            .build()
            .expect("Failed to build");

    // Create an indication using the wrong integrity mechanism MessageIntegritySha256
    let instant = std::time::Instant::now();
    let mut buffer = pool_buffer();
    create_stun_message(&mut buffer, Indication, Some(Integrity::MessageIntegrity));
    // Make integrity check fail changing the second byte of the username payload
    buffer[MESSAGE_HEADER_SIZE + 6] = 45;
    let error = client
        .on_buffer_recv(&buffer, instant)
        .expect_err("Expected Discarded error");
    assert_eq!(error, StunAgentError::Discarded);
}

#[test]
fn test_stun_client_recv_request_unreliable_corrupted_integrity() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key.clone());

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(
                USERNAME,
                PASSWORD,
                CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
            )
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(tid, msg.transaction_id());
    check_attributes(Some(Integrity::MessageIntegrity), msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // Create ErrorReponse with corrupted integrity
    let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");
    let integrity = MessageIntegrity::new(key);
    let resp = StunMessageBuilder::new(BINDING, ErrorResponse)
        .with_transaction_id(*id)
        .with_attribute(user_name)
        .with_attribute(integrity)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &resp)
        .expect("Failed to encode message");
    // Make integrity check fail changing the second byte of the username payload
    buffer[MESSAGE_HEADER_SIZE + 6] = 45;
    let instant = instant + Duration::from_millis(50);
    let error = client
        .on_buffer_recv(&buffer, instant)
        .expect_err("Expected Discarded error");
    assert_eq!(error, StunAgentError::Discarded);

    // Responses were discarded due to integrity failures,
    // a timeout will be signaled as a protection violated event
    let instant = instant + Duration::from_millis(39500);
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::TransactionFailed((id, error)) = iter.next().expect("Expected event")
    else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(&transaction_id, id);
    assert_eq!(*error, StunTransactionError::ProtectionViolated);
    // No more events
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_recv_request_reliable_corrupted_integrity() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key.clone());

    let mut client =
        StunClienteBuilder::new(TransportReliability::Reliable(Duration::from_millis(39500)))
            .with_mechanism(
                USERNAME,
                PASSWORD,
                CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
            )
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(tid, &transaction_id);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    check_attributes(Some(Integrity::MessageIntegrity), msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(&transaction_id, id);
    // No more events
    assert!(iter.next().is_none());

    // Create ErrorReponse with corrupted integrity
    let user_name = UserName::try_from(USERNAME).expect("Can not create USERNAME attribute");
    let integrity = MessageIntegrity::new(key);
    let resp = StunMessageBuilder::new(BINDING, ErrorResponse)
        .with_transaction_id(*id)
        .with_attribute(user_name)
        .with_attribute(integrity)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &resp)
        .expect("Failed to encode message");
    // Make integrity check fail changing the second byte of the username payload
    buffer[MESSAGE_HEADER_SIZE + 6] = 45;
    let instant = instant + Duration::from_millis(50);
    // When transport is reliable, the message is processed
    // and the protection violated event will be raised
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Message should be accepted");

    // Because this is a reliable transport, there must be a protection violated event
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::TransactionFailed((id, error)) = iter.next().expect("Expected event")
    else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(transaction_id, *id);
    assert_eq!(*error, StunTransactionError::ProtectionViolated);
    // No more events
    assert!(iter.next().is_none());
}

fn test_timeout(reliability: TransportReliability) {
    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key.clone());

    let mut client = StunClienteBuilder::new(reliability)
        .with_mechanism(
            USERNAME,
            PASSWORD,
            CredentialMechanism::ShortTerm(Some(Integrity::MessageIntegrity)),
        )
        .build()
        .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(tid, &transaction_id);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    check_attributes(Some(Integrity::MessageIntegrity), msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // Because no response were rejected due to a integrity failure, a timeout must be signaled
    // to the client instead of a protection violation
    let instant = instant + Duration::from_millis(39500);
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::TransactionFailed((id, error)) = iter.next().expect("Expected event")
    else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(&transaction_id, id);
    assert_eq!(*error, StunTransactionError::TimedOut);
    // No more events
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_recv_request_timedout() {
    init_logging();

    test_timeout(TransportReliability::Unreliable(RttConfig::default()));
    test_timeout(TransportReliability::Reliable(Duration::from_millis(39500)));
}

#[test]
fn test_stun_client_picks_cred_mech() {
    init_logging();

    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create key");
    let decoder = create_decoder(key.clone());

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::ShortTerm(None))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(tid, &transaction_id);
    check_attributes(None, msg.attributes());
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // Create SucessReponse with message intigrety sha-256
    let integrity = MessageIntegritySha256::new(key);
    let resp = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_transaction_id(*id)
        .with_attribute(integrity)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &resp)
        .expect("Failed to encode message");

    let instant = instant + Duration::from_millis(50);
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Message should be accepted");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::StunMessageReceived(resp) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    // The timeout should be set for the first message
    assert_eq!(&transaction_id, resp.transaction_id());
    // No more events
    assert!(iter.next().is_none());

    // Any new message must contain only the message integrity sha-256
    let instant = instant + Duration::from_millis(50);
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(tid, &transaction_id);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(&transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(&transaction_id, id);
    check_attributes(Some(Integrity::MessageIntegritySha256), msg.attributes());
}
