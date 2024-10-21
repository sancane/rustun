use stun_agent::{
    RttConfig, StunAgentError, StunAttributes, StunClient, StunClienteBuilder, StuntClientEvent,
    TransportReliability,
};
use stun_rs::{
    attributes::stun::Fingerprint, methods::BINDING, MessageClass, MessageDecoderBuilder,
    MessageEncoderBuilder, StunMessageBuilder, TransactionId,
};

const CAPACITY: usize = 1024;

fn init_logging() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pool_buffer() -> Vec<u8> {
    vec![0; CAPACITY]
}

fn check_fingerprint_paramaters(
    client: &mut StunClient,
    transaction_id: &TransactionId,
    class: MessageClass,
) {
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket(packet) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let decoder = MessageDecoderBuilder::default().build();

    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    // No attributes must be set for the first request
    assert!(!msg.attributes().is_empty());
    let mut attr_iter = msg.attributes().iter();
    let attr = attr_iter.next().expect("Expected an attribute");
    assert!(attr.is_fingerprint());
    assert!(attr_iter.next().is_none());
    assert_eq!(transaction_id, msg.transaction_id());

    if class == MessageClass::Request {
        let StuntClientEvent::RestransmissionTimeOut((id, _)) =
            iter.next().expect("Expected event")
        else {
            panic!("Expected RestransmissionTimeOut event");
        };

        assert_eq!(transaction_id, id);
    }

    assert!(iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), class);
}

fn create_response(
    class: MessageClass,
    transaction_id: TransactionId,
    with_fingerprint: bool,
) -> Vec<u8> {
    let mut buffer = pool_buffer();
    let mut builder = StunMessageBuilder::new(BINDING, class).with_transaction_id(transaction_id);

    if with_fingerprint {
        builder = builder.with_attribute(Fingerprint::default());
    }
    let enc_msg = builder.build();

    let encoder = MessageEncoderBuilder::default().build();
    encoder
        .encode(&mut buffer, &enc_msg)
        .expect("Failed to encode message");

    buffer
}

#[test]
fn test_stun_client_send_request() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_fingerprint()
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");

    check_fingerprint_paramaters(&mut client, &transaction_id, MessageClass::Request);
}

#[test]
fn test_stun_client_send_indication() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_fingerprint()
            .build()
            .expect("Failed to build");

    let transaction_id = client
        .send_indication(BINDING, StunAttributes::default(), pool_buffer())
        .expect("Failed to create indication");

    check_fingerprint_paramaters(&mut client, &transaction_id, MessageClass::Indication);
}

#[test]
fn test_stun_client_no_fingerprint_in_response() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_fingerprint()
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");

    check_fingerprint_paramaters(&mut client, &transaction_id, MessageClass::Request);

    let response = create_response(MessageClass::SuccessResponse, transaction_id, false);
    let instant = instant + std::time::Duration::from_millis(10);
    let error = client
        .on_buffer_recv(&response, instant)
        .expect_err("Expected an error");
    assert_eq!(error, StunAgentError::StunCheckFailed);
}

#[test]
fn test_stun_client_bad_fingerprint_in_response() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_fingerprint()
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");

    check_fingerprint_paramaters(&mut client, &transaction_id, MessageClass::Request);

    let mut response = create_response(MessageClass::SuccessResponse, transaction_id, true);
    // Modify the fingerprint payload to make the fingerprint check fail
    response[26] += 1;
    let instant = instant + std::time::Duration::from_millis(10);
    let error = client
        .on_buffer_recv(&response, instant)
        .expect_err("Expected an error");
    assert_eq!(error, StunAgentError::Discarded);
}

#[test]
fn test_stun_client_with_fingerprint_in_response() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .with_fingerprint()
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let transaction_id = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");

    check_fingerprint_paramaters(&mut client, &transaction_id, MessageClass::Request);

    let response = create_response(MessageClass::SuccessResponse, transaction_id, true);

    let instant = instant + std::time::Duration::from_millis(10);
    client
        .on_buffer_recv(&response, instant)
        .expect("Expected an error");
}
