use enumflags2::{make_bitflags, BitFlags};
use std::slice::Iter;
use std::time::Duration;
use stun_agent::{
    CredentialMechanism, Integrity, RttConfig, StunAgentError, StunAttributes, StunClient,
    StunClienteBuilder, StunTransactionError, StuntClientEvent, TransportReliability,
};
use stun_rs::attributes::stun::nonce_cookie::StunSecurityFeatures;
use stun_rs::attributes::stun::{
    ErrorCode, MessageIntegrity, MessageIntegritySha256, Realm, UserHash, UserName,
};
use stun_rs::attributes::stun::{Nonce, PasswordAlgorithm, PasswordAlgorithms};
use stun_rs::methods::BINDING;
use stun_rs::MessageClass::Request;
use stun_rs::{
    Algorithm, AlgorithmId, DecoderContextBuilder, HMACKey, MessageClass, MessageDecoder,
    MessageDecoderBuilder, MessageEncoderBuilder, StunAttribute, StunMessage, StunMessageBuilder,
    TransactionId,
};

const USERNAME: &str = "test-username";
const REALM: &str = "test-realm";
const NONCE: &str = "test-nonce";
const PASSWORD: &str = "test-password";
const CAPACITY: usize = 1024;

fn init_logging() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pool_buffer() -> Vec<u8> {
    vec![0; CAPACITY]
}

#[derive(Debug, Default)]
struct StunAttributesConfig {
    with_realm: bool,
    with_username: bool,
    with_userhash: bool,
    with_integrity: bool,
    with_integrity_sha256: bool,
    nonce: Option<stun_rs::attributes::stun::Nonce>,
    error: Option<stun_rs::ErrorCode>,
    algorithm: Option<Algorithm>,
    algorithms: Option<stun_rs::attributes::stun::PasswordAlgorithms>,
}

fn create_attributes(config: StunAttributesConfig) -> StunAttributes {
    let mut attributes = StunAttributes::default();
    let username = UserName::new(USERNAME).expect("Failed to create UserName");
    let realm = Realm::new(REALM).expect("Failed to create Realm");
    let user_hash = UserHash::new(&username, &realm).expect("Failed to create UserHash");

    let key = match &config.algorithm {
        Some(algorithm) => HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm.clone())
            .expect("Failed to create HMACKey"),
        None => HMACKey::new_long_term(
            &username,
            &realm,
            PASSWORD,
            Algorithm::from(AlgorithmId::MD5),
        )
        .expect("Failed to create HMACKey"),
    };

    if config.with_realm {
        attributes.add(realm);
    }
    if let Some(nonce) = config.nonce {
        attributes.add(nonce);
    }
    if config.with_username {
        attributes.add(username);
    }
    if config.with_userhash {
        attributes.add(user_hash);
    }
    if let Some(algorithm) = config.algorithm {
        attributes.add(stun_rs::attributes::stun::PasswordAlgorithm::new(algorithm));
    }
    if let Some(algorithms) = config.algorithms {
        attributes.add(algorithms);
    }
    if let Some(error) = config.error {
        attributes.add(ErrorCode::from(error));
    }
    if config.with_integrity {
        attributes.add(MessageIntegrity::new(key.clone()));
    }
    if config.with_integrity_sha256 {
        attributes.add(MessageIntegritySha256::new(key.clone()));
    }

    attributes
}

fn create_stun_encoded_message(
    transaction_id: Option<TransactionId>,
    buffer: &mut [u8],
    class: MessageClass,
    attributes: StunAttributes,
) -> (StunMessage, usize) {
    let mut builder = StunMessageBuilder::new(BINDING, class);
    if let Some(transaction_id) = transaction_id {
        builder = builder.with_transaction_id(transaction_id);
    }

    let attributes: Vec<StunAttribute> = attributes.into();
    for attr in attributes {
        builder = builder.with_attribute(attr);
    }

    let msg = builder.build();
    let encoder = MessageEncoderBuilder::default().build();
    let size = encoder
        .encode(buffer, &msg)
        .expect("Failed to encode message");
    (msg, size)
}

fn create_decoder(key: Option<HMACKey>) -> MessageDecoder {
    let mut builder = DecoderContextBuilder::default();
    if let Some(key) = key {
        builder = builder.with_key(key).with_validation();
    }
    let ctx = builder.build();
    MessageDecoderBuilder::default().with_context(ctx).build()
}

fn check_first_request(client: &mut StunClient, transaction_id: &TransactionId) {
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(transaction_id, tid);
    let decoder = create_decoder(None);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    // No attributes must be set for the first request
    assert!(msg.attributes().is_empty());

    assert_eq!(transaction_id, msg.transaction_id());
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

fn check_request_attributes(
    attr_iter: &mut Iter<StunAttribute>,
    algorithms: Option<&[AlgorithmId]>,
    flags: Option<BitFlags<StunSecurityFeatures>>,
    nonce: &str,
) {
    let attr = attr_iter.next().expect("Expected an attribute");
    if let Some(flags) = flags {
        if flags.contains(StunSecurityFeatures::UserNameAnonymity) {
            assert!(attr.is_user_hash());
        } else {
            assert!(attr.is_user_name());
        }
    }
    let attr = attr_iter.next().expect("Expected an attribute");
    assert!(attr.is_realm());
    let attr = attr_iter.next().expect("Expected an attribute");
    assert!(attr.is_nonce());
    let nonce_attr = attr.as_nonce().expect("Expected Nonce attribute");
    assert!(nonce_attr.as_str().ends_with(nonce));

    if let Some(flags) = flags {
        if flags.contains(StunSecurityFeatures::PasswordAlgorithms) {
            let attr = attr_iter.next().expect("Expected an attribute");
            assert!(attr.is_password_algorithms());
            let mut found_sha256 = false;
            let vec = algorithms.expect("Expected algorithms");
            let algorithms = attr
                .as_password_algorithms()
                .expect("Expected PasswordAlgorithms attribute");
            {
                // Check password algorithms is MD5 and SHA256
                // Algorithms must be in the same order as in the response
                assert_eq!(algorithms.password_algorithms().len(), vec.len());
                let mut iter_1 = algorithms.iter().peekable();
                let mut iter_2 = vec.iter().peekable();
                while iter_1.peek().is_some() && iter_1.peek().is_some() {
                    let algorithm_id_1 = iter_1.next().expect("Expected an algorithm").algorithm();
                    let algorithm_id_2 = *iter_2.next().expect("Expected algorithmId");
                    if !found_sha256 {
                        found_sha256 = algorithm_id_1 == AlgorithmId::SHA256;
                    }
                    assert_eq!(algorithm_id_1, algorithm_id_2);
                }
            }

            let attr = attr_iter.next().expect("Expected an attribute");
            assert!(attr.is_password_algorithm());
            let algorithm = attr
                .as_password_algorithm()
                .expect("Expected PasswordAlgorithm");
            if found_sha256 {
                assert_eq!(algorithm.algorithm(), AlgorithmId::SHA256);
            } else {
                assert_eq!(algorithm.algorithm(), AlgorithmId::MD5);
            }
        }
    }
}

fn check_request_from_unauthenticated_error(
    client: &mut StunClient,
    transaction_id: &TransactionId,
    algorithms: Option<&[AlgorithmId]>,
    flags: Option<BitFlags<StunSecurityFeatures>>,
    nonce_value: &str,
) {
    let events = client.events();
    let mut events_iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = events_iter.next().expect("Expected event")
    else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(transaction_id, tid);
    let decoder = create_decoder(None);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    // There must be authentication parameters
    assert!(!msg.attributes().is_empty());
    let mut attr_iter = msg.attributes().iter();
    check_request_attributes(&mut attr_iter, algorithms, flags, nonce_value);
    // No message integrity must be set after an unauthenticated error
    assert!(attr_iter.next().is_none());

    assert_eq!(transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) =
        events_iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);

    // No more events
    assert!(events_iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Request);
}

fn check_request_from_stale_nonce_error(
    client: &mut StunClient,
    transaction_id: &TransactionId,
    flags: Option<BitFlags<StunSecurityFeatures>>,
    integrity: Integrity,
    nonce_value: &str,
) {
    let events = client.events();
    let mut events_iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = events_iter.next().expect("Expected event")
    else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(transaction_id, tid);
    let decoder = create_decoder(None);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    // There must be authentication parameters
    assert!(!msg.attributes().is_empty());
    let mut attr_iter = msg.attributes().iter();
    check_request_attributes(&mut attr_iter, None, flags, nonce_value);
    // Message integrity must be set after an unauthenticated error
    let attr = attr_iter.next().expect("Expected an attribute");
    match integrity {
        Integrity::MessageIntegrity => {
            assert!(attr.is_message_integrity());
        }
        Integrity::MessageIntegritySha256 => {
            assert!(attr.is_message_integrity_sha256());
        }
    }

    assert_eq!(transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) =
        events_iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);

    // No more events
    assert!(events_iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Request);
}

fn check_subsequent_request(
    client: &mut StunClient,
    transaction_id: &TransactionId,
    algorithms: Option<&[AlgorithmId]>,
    flags: Option<BitFlags<StunSecurityFeatures>>,
    integrity: Integrity,
    nonce_value: &str,
) {
    let events = client.events();
    let mut events_iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = events_iter.next().expect("Expected event")
    else {
        panic!("Expected OutputBuffer event");
    };
    assert_eq!(transaction_id, tid);
    let decoder = create_decoder(None);
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    // There must be authentication parameters
    assert!(!msg.attributes().is_empty());
    let mut attr_iter = msg.attributes().iter();
    check_request_attributes(&mut attr_iter, algorithms, flags, nonce_value);
    // Message integrity must be set after an unauthenticated error
    let attr = attr_iter.next().expect("Expected an attribute");
    match integrity {
        Integrity::MessageIntegrity => {
            assert!(attr.is_message_integrity());
        }
        Integrity::MessageIntegritySha256 => {
            assert!(attr.is_message_integrity_sha256());
        }
    }
    // No more attributes
    assert!(attr_iter.next().is_none());

    assert_eq!(transaction_id, msg.transaction_id());
    let StuntClientEvent::RestransmissionTimeOut((id, _)) =
        events_iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The timeout should be set for the first message
    assert_eq!(msg.transaction_id(), id);

    // No more events
    assert!(events_iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Request);
}

fn create_auth_error_response(
    transaction_id: TransactionId,
    algorithms: Option<&[AlgorithmId]>,
    flags: Option<BitFlags<StunSecurityFeatures>>,
) -> Vec<u8> {
    let nonce = Nonce::new_nonce_cookie(NONCE, flags).expect("Can not create nonce cookie");
    let error = stun_rs::ErrorCode::new(401, "Unauthenticated").expect("Failed to create error");
    let palgorithms = if let Some(algorithms) = algorithms {
        let mut palgorithms = PasswordAlgorithms::default();
        for i in algorithms {
            palgorithms.add(PasswordAlgorithm::new(Algorithm::from(*i)));
        }
        Some(palgorithms)
    } else {
        None
    };

    let attrs = create_attributes(StunAttributesConfig {
        with_realm: true,
        with_username: false,
        with_userhash: false,
        with_integrity: false,
        with_integrity_sha256: false,
        nonce: Some(nonce),
        error: Some(error),
        algorithm: None,
        algorithms: palgorithms,
    });

    let mut buffer = pool_buffer();
    let (_, _) = create_stun_encoded_message(
        Some(transaction_id),
        &mut buffer,
        MessageClass::ErrorResponse,
        attrs,
    );

    buffer
}

fn create_success_response(
    transaction_id: TransactionId,
    algorithm_id: Option<AlgorithmId>,
    integrity: Integrity,
) -> Vec<u8> {
    algorithm_id.map(Algorithm::from);
    let algorithm = algorithm_id.map(Algorithm::from);
    let key = match algorithm.as_ref() {
        Some(algorithm) => HMACKey::new_long_term(USERNAME, REALM, PASSWORD, algorithm.clone())
            .expect("Failed to create HMACKey"),
        None => {
            HMACKey::new_long_term(USERNAME, REALM, PASSWORD, Algorithm::from(AlgorithmId::MD5))
                .expect("Failed to create HMACKey")
        }
    };

    let mut attrs = StunAttributes::default();
    match integrity {
        Integrity::MessageIntegrity => attrs.add(MessageIntegrity::new(key.clone())),
        Integrity::MessageIntegritySha256 => attrs.add(MessageIntegritySha256::new(key.clone())),
    };

    let mut buffer = pool_buffer();
    let (_, _) = create_stun_encoded_message(
        Some(transaction_id),
        &mut buffer,
        MessageClass::SuccessResponse,
        attrs,
    );

    buffer
}

fn create_stale_nonce_error_response(
    transaction_id: TransactionId,
    algorithms: Option<&[AlgorithmId]>,
    flags: Option<BitFlags<StunSecurityFeatures>>,
    nonce_value: &str,
) -> Vec<u8> {
    let nonce = Nonce::new_nonce_cookie(nonce_value, flags).expect("Can not create nonce cookie");
    let error = stun_rs::ErrorCode::new(438, "Stale Nonce").expect("Failed to create error");
    let palgorithms = if let Some(algorithms) = algorithms {
        let mut palgorithms = PasswordAlgorithms::default();
        for i in algorithms {
            palgorithms.add(PasswordAlgorithm::new(Algorithm::from(*i)));
        }
        Some(palgorithms)
    } else {
        None
    };

    let attrs = create_attributes(StunAttributesConfig {
        with_realm: true,
        with_username: false,
        with_userhash: false,
        with_integrity: false,
        with_integrity_sha256: false,
        nonce: Some(nonce),
        error: Some(error),
        algorithm: None,
        algorithms: palgorithms,
    });

    let mut buffer = pool_buffer();
    let (_, _) = create_stun_encoded_message(
        Some(transaction_id),
        &mut buffer,
        MessageClass::ErrorResponse,
        attrs,
    );

    buffer
}

#[test]
fn test_stun_client_send_request_unreliable() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");

    check_first_request(&mut client, &transaction_id);
}

#[test]
fn test_stun_client_send_indication_unreliable() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
            .build()
            .expect("Failed to build");

    let error = client
        .send_indication(BINDING, StunAttributes::default(), pool_buffer())
        .expect_err("Can not send indications");
    assert_eq!(error, StunAgentError::Ignored);

    assert!(client.events().is_empty());
}

#[test]
fn test_stun_client_authenticate_unreliable() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_first_request(&mut client, &transaction_id);

    // Send unauthenticated error response
    let instant = instant + std::time::Duration::from_millis(10);
    let flags: BitFlags<StunSecurityFeatures> =
        make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms | UserNameAnonymity});
    let algorithms = vec![AlgorithmId::MD5, AlgorithmId::SHA256];
    let buffer = create_auth_error_response(transaction_id, Some(&algorithms), Some(flags));
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to receive buffer");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::Retry(id) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    assert_eq!(&transaction_id, id);
    assert!(iter.next().is_none());

    // Retry request from the unauthenticated error
    let instant = instant + std::time::Duration::from_millis(10);
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_request_from_unauthenticated_error(
        &mut client,
        &transaction_id,
        Some(&algorithms),
        Some(flags),
        NONCE,
    );

    // Send a success response with the integrity attribute to authenticate the user
    let instant = instant + std::time::Duration::from_millis(10);
    let buffer = create_success_response(
        transaction_id,
        Some(AlgorithmId::SHA256),
        Integrity::MessageIntegritySha256,
    );
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to receive buffer");

    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::StunMessageReceived(msg) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    assert_eq!(&transaction_id, msg.transaction_id());
    assert!(iter.next().is_none());

    // Send a subsequent request once the user is authenticated
    let instant = instant + std::time::Duration::from_millis(10);
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_subsequent_request(
        &mut client,
        &transaction_id,
        Some(&algorithms),
        Some(flags),
        Integrity::MessageIntegritySha256,
        NONCE,
    );
}

#[test]
fn test_stun_client_stale_nonce_unreliable() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_first_request(&mut client, &transaction_id);

    // Send unauthenticated error response
    let instant = instant + std::time::Duration::from_millis(10);
    let flags: BitFlags<StunSecurityFeatures> =
        make_bitflags!(StunSecurityFeatures::{UserNameAnonymity});
    let buffer = create_auth_error_response(transaction_id, None, Some(flags));
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to receive buffer");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::Retry(id) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    assert_eq!(&transaction_id, id);
    assert!(iter.next().is_none());

    // Retry request from the unauthenticated error
    let instant = instant + std::time::Duration::from_millis(10);
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_request_from_unauthenticated_error(
        &mut client,
        &transaction_id,
        None,
        Some(flags),
        NONCE,
    );

    // Send a stale nonce error
    let nonce_value = "STALE-NONCE";
    let instant = instant + std::time::Duration::from_millis(10);
    let buffer = create_stale_nonce_error_response(transaction_id, None, Some(flags), nonce_value);
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to receive buffer");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::Retry(id) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    assert_eq!(&transaction_id, id);
    assert!(iter.next().is_none());

    // Retry request from the stale nonce error
    let instant = instant + std::time::Duration::from_millis(10);
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_request_from_stale_nonce_error(
        &mut client,
        &transaction_id,
        Some(flags),
        Integrity::MessageIntegrity,
        nonce_value,
    );
}

fn test_timeout(reliability: TransportReliability) {
    let mut client = StunClienteBuilder::new(reliability)
        .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
        .build()
        .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_first_request(&mut client, &transaction_id);

    // Force timeout
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
fn test_stun_client_timeout_unreliable() {
    init_logging();

    test_timeout(TransportReliability::Unreliable(RttConfig::default()));
    test_timeout(TransportReliability::Reliable(Duration::from_millis(39500)));
}

#[test]
fn test_stun_client_protection_violated() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_first_request(&mut client, &transaction_id);

    // Send unauthenticated error response
    let instant = instant + std::time::Duration::from_millis(10);
    let flags: BitFlags<StunSecurityFeatures> =
        make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms | UserNameAnonymity});
    let algorithms = vec![AlgorithmId::MD5, AlgorithmId::SHA256];
    let buffer = create_auth_error_response(transaction_id, Some(&algorithms), Some(flags));
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to receive buffer");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::Retry(id) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    assert_eq!(&transaction_id, id);
    assert!(iter.next().is_none());

    // Retry request from the unauthenticated error
    let instant = instant + std::time::Duration::from_millis(10);
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_request_from_unauthenticated_error(
        &mut client,
        &transaction_id,
        Some(&algorithms),
        Some(flags),
        NONCE,
    );

    // Send a success response with the integrity attribute to authenticate the user
    let instant = instant + std::time::Duration::from_millis(10);
    let mut buffer = create_success_response(
        transaction_id,
        Some(AlgorithmId::SHA256),
        Integrity::MessageIntegritySha256,
    );
    println!("Buffer size: {:?}", buffer[35]);
    // mofify the byte at the position 35 (message integrity payload) to simulate
    // an integrity error
    buffer[35] += 1;

    let error = client
        .on_buffer_recv(&buffer, instant)
        .expect_err("Failed to receive buffer");
    assert_eq!(error, StunAgentError::Discarded);

    // Force timeout
    // Because the previous response was rejected due to a integrity failure, a protection violation
    // error must be signaled to the client
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
}

#[test]
fn test_stun_client_not_retryable_error() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_mechanism(USERNAME, PASSWORD, CredentialMechanism::LongTerm)
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Can not send request");

    check_first_request(&mut client, &transaction_id);

    // Send unauthenticated error response
    let instant = instant + std::time::Duration::from_millis(10);
    let flags: BitFlags<StunSecurityFeatures> =
        make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms | UserNameAnonymity});
    // An unsuported algorithm must be rejected and not retried
    let algorithms = vec![AlgorithmId::Unassigned(35)];
    let buffer = create_auth_error_response(transaction_id, Some(&algorithms), Some(flags));
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to receive buffer");

    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::TransactionFailed((id, error)) = iter.next().expect("Expected event")
    else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(transaction_id, *id);
    assert_eq!(error, &StunTransactionError::DoNotRetry);
    assert!(iter.next().is_none());
}
