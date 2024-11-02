use std::time::{Duration, Instant};
use stun_agent::{
    CredentialMechanism, RttConfig, StunAgentError, StunAttributes, StunClient, StunClienteBuilder,
    StuntClientEvent, TransportReliability,
};
use stun_rs::attributes::stun::Software;
use stun_rs::methods::BINDING;
use stun_rs::MessageClass::{Indication, Request, SuccessResponse};
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

fn create_decoder(key: Option<HMACKey>) -> MessageDecoder {
    let ctx_builder = DecoderContextBuilder::default();
    let ctx = if let Some(key) = key {
        ctx_builder.with_key(key).with_validation().build()
    } else {
        ctx_builder.build()
    };
    MessageDecoderBuilder::default().with_context(ctx).build()
}

#[test]
fn test_stun_client_no_events() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // No events at this point
    let events = client.events();
    assert!(events.is_empty());
}

#[test]
fn test_create_stun_client() {
    init_logging();

    let _client = StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
        .build()
        .expect("Failed to build");

    // Control characters like TAB `U+0009` are disallowed for UserNAme and Password
    let _client = StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
        .with_mechanism(
            "bad\u{0009}name",
            PASSWORD,
            CredentialMechanism::ShortTerm(None),
        )
        .build()
        .expect_err("Should fail to build");

    let _client = StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
        .with_mechanism(
            USERNAME,
            "bad\u{0009}password",
            CredentialMechanism::ShortTerm(None),
        )
        .build()
        .expect_err("Should fail to build");
}

#[test]
fn test_stun_client_send_request() {
    init_logging();

    let decoder = create_decoder(None);

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create request");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((id, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(id, msg.transaction_id());
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
    // No aditional attributes must be set
    assert!(msg.attributes().is_empty())
}

fn create_client_with_max_retransmissions(max: Option<usize>) -> StunClient {
    let mut builder =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()));
    if let Some(max) = max {
        builder = builder.with_max_transactions(max);
    }
    builder.build().expect("Failed to build")
}

fn check_max_outstanding_requests(client: &mut StunClient, n: usize) {
    let instant = std::time::Instant::now();

    for _i in 0..n {
        // Send a request every 10ms
        let instant = instant + Duration::from_millis(10);
        client
            .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
            .expect("Failed to send request");
        // consume the events
        let _events = client.events();
    }

    // The Nth request should fail
    let instant = instant + Duration::from_millis(10);
    let error = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect_err("Expected MaxOutstandingRequestsReached error");
    assert_eq!(error, StunAgentError::MaxOutstandingRequestsReached);
}

#[test]
fn test_stun_client_send_max_request() {
    init_logging();

    // Check default max outstanding requests
    let mut client = create_client_with_max_retransmissions(None);
    check_max_outstanding_requests(&mut client, 10);
    // Check with a custom max outstanding requests
    let mut client = create_client_with_max_retransmissions(Some(5));
    check_max_outstanding_requests(&mut client, 5);
}

#[test]
fn test_stun_client_allow_send_request_after_max_request_error() {
    init_logging();

    // Check with a custom max outstanding requests
    let mut client = create_client_with_max_retransmissions(Some(1));

    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to send request");
    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };

    // Another try to send a request should fail
    let instant = instant + Duration::from_millis(10);
    let error = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect_err("Expected MaxOutstandingRequestsReached error");
    assert_eq!(error, StunAgentError::MaxOutstandingRequestsReached);
    // Events should be empty
    assert!(client.events().is_empty());

    // Reception of a response should allow to send a new request
    let response = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_transaction_id(*id)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");
    let instant = instant + Duration::from_millis(10);
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to process buffer");
    // consume the events
    let _events = client.events();

    // Now we can send a new request
    let buffer = pool_buffer();
    let instant = instant + Duration::from_millis(10);
    client
        .send_request(BINDING, StunAttributes::default(), buffer, instant)
        .expect("Failed to send request");
}

#[test]
fn test_stun_client_send_indication() {
    init_logging();

    let decoder = create_decoder(None);

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    client
        .send_indication(BINDING, StunAttributes::default(), pool_buffer())
        .expect("Failed to send indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    // No more events
    assert!(iter.next().is_none());

    // Another call to events should return an empty list of events
    assert!(client.events().is_empty());

    // Check the message sent
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Indication);
    // No aditional attributes must be set
    assert!(msg.attributes().is_empty());
    assert_eq!(msg.transaction_id(), tid);
}

#[test]
fn test_stun_client_send_unlimited_indications() {
    init_logging();

    const N: usize = 5;
    let mut client = create_client_with_max_retransmissions(Some(N));

    // Send N*2 indications
    for _i in 0..=N * 2 {
        client
            .send_indication(BINDING, StunAttributes::default(), pool_buffer())
            .expect("Failed to send indication");
        // consume the events
        let _events = client.events();
    }
}

#[test]
fn test_stun_client_send_indications_after_send_max_requests() {
    init_logging();

    let decoder = create_decoder(None);
    const N: usize = 5;
    let mut client = create_client_with_max_retransmissions(Some(N));
    check_max_outstanding_requests(&mut client, 5);

    // We can not send more requests, but we can send indications
    client
        .send_indication(BINDING, StunAttributes::default(), pool_buffer())
        .expect("Failed to send indication");
    // consume the events
    let events = client.events();
    // There must only be one OutputBuffer event with the indicatino itself
    assert_eq!(events.len(), 1);

    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket((tid, packet)) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    // No more events
    assert!(iter.next().is_none());

    // Check the message sent
    let (msg, _) = decoder.decode(packet).expect("Failed to decode message");
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Indication);
    // No aditional attributes must be set
    assert!(msg.attributes().is_empty());
    assert_eq!(msg.transaction_id(), tid);
}

#[test]
fn test_stun_client_recv_unexpected_transaction_id() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // Reception of a response without a matching transaction id should be ignored
    let response = StunMessageBuilder::new(BINDING, SuccessResponse).build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");

    let instant = std::time::Instant::now();
    let res = client.on_buffer_recv(&buffer, instant);
    assert_eq!(res, Err(StunAgentError::Discarded));
}

#[test]
fn test_stun_client_recv_request() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // Reception of a request should be discarded
    let response = StunMessageBuilder::new(BINDING, Request).build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");

    let instant = std::time::Instant::now();
    let res = client.on_buffer_recv(&buffer, instant);
    assert_eq!(res, Err(StunAgentError::Discarded));
}

#[test]
fn test_stun_client_recv_indication() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // Reception of an indication muste be notified
    let response = StunMessageBuilder::new(BINDING, Indication).build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");

    let instant = std::time::Instant::now();
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to process buffer");

    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::StunMessageReceived(msg) = iter.next().expect("Expected event") else {
        panic!("Expected StunMessageReceived event");
    };
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), Indication);
    // No more events
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_recv_unexpected_data() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // Reception of a buffer that has the same size of the stun header
    // but is not a STUN message should be discarded
    let buffer = [
        0x53, 0xAF, 0xC4, 0xFF, 0x56, 0x01, 0xFC, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];

    let instant = std::time::Instant::now();
    let res = client.on_buffer_recv(&buffer, instant);
    assert!(matches!(res, Err(StunAgentError::InternalError(_))));
}

#[test]
fn test_stun_client_transaction_finished_sucess_response() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to send request");
    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StuntClientEvent::RestransmissionTimeOut((id, _)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };

    // Reception of a success response should fire a transaction finished event
    let response = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_transaction_id(*id)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");
    let instant = instant + Duration::from_millis(10);
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to process buffer");
    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StuntClientEvent::StunMessageReceived(msg) = iter.next().expect("Expected event") else {
        panic!("Expected TransactionFinished event");
    };
    // No more events
    assert!(iter.next().is_none());

    // Check response
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), SuccessResponse);
    // No aditional attributes must be set
    assert!(msg.attributes().is_empty());
}

#[test]
fn test_stun_client_send_request_small_buffer_failure() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    let buffer = vec![0; MESSAGE_HEADER_SIZE - 1];
    let error = client
        .send_request(BINDING, StunAttributes::default(), buffer, instant)
        .expect_err("Expected InternalError");
    assert!(matches!(error, StunAgentError::InternalError(_)));
}

#[test]
fn test_stun_client_send_indication_small_buffer_failure() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let buffer = vec![0; MESSAGE_HEADER_SIZE - 1];
    let error = client
        .send_indication(BINDING, StunAttributes::default(), buffer)
        .expect_err("Expected InternalError");
    assert!(matches!(error, StunAgentError::InternalError(_)));
}

#[test]
fn test_stun_client_recv_small_buffer_failure() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // Create a SuccessResponse message with software attribute to skip the header length validation
    let software = Software::new("STUN test client").expect("Can not create a Sofware attribute");
    let response = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_attribute(software)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");
    let instant = Instant::now();
    let error = client
        .on_buffer_recv(&buffer[..MESSAGE_HEADER_SIZE + 2], instant)
        .expect_err("Expected InternalError");
    println!("error: {:?}", error);
    assert!(matches!(error, StunAgentError::InternalError(_)));
}
