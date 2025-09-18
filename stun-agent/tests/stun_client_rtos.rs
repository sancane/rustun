use log::info;
use std::time::{Duration, Instant};
use stun_agent::{
    RttConfig, StunAgentError, StunAttributes, StunClient, StunClienteBuilder,
    StunTransactionError, StunClientEvent, TransportReliability,
};
use stun_rs::methods::BINDING;
use stun_rs::MessageClass::SuccessResponse;
use stun_rs::{
    MessageDecoder, MessageDecoderBuilder, MessageEncoderBuilder, StunMessageBuilder, TransactionId,
};

const CAPACITY: usize = 1024;

fn init_logging() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pool_buffer() -> Vec<u8> {
    vec![0; CAPACITY]
}

#[test]
fn test_stun_client_no_reliable_first_rto() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    // send a request
    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((_, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout of the first rto must be 500 ms
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // No mor event must be pulled
    assert!(client.events().is_empty());
}

fn test_rto_after_duration(
    from: Instant,
    duration: Duration,
    expected: Duration,
    msg_id: &TransactionId,
    client: &mut StunClient,
    decoder: &MessageDecoder,
) {
    let instant = from + duration;
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    assert_eq!(msg_id, msg.transaction_id());
    let StunClientEvent::RestransmissionTimeOut((id, timeout)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(msg_id, id);
    assert_eq!(expected, *timeout);
    assert!(iter.next().is_none());
}

fn test_all_rtos(client: &mut StunClient, decoder: &MessageDecoder) {
    // Send an indication
    let now = Instant::now();
    let instant = now;
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), now)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    let msg_id = msg.transaction_id();
    let StunClientEvent::RestransmissionTimeOut((id, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(msg_id, id);
    assert_eq!(duration, &Duration::from_millis(500));
    assert!(iter.next().is_none());

    info!("Calling on_timeout after 500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(500),
        Duration::from_millis(1000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 1500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(1500),
        Duration::from_millis(2000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 3500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(3500),
        Duration::from_millis(4000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 7500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(7500),
        Duration::from_millis(8000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 15500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(15500),
        Duration::from_millis(16000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 31500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(31500),
        Duration::from_millis(8000),
        msg_id,
        client,
        decoder,
    );

    // Another timeout after 8000 ms must make the transaction fail
    let instant = instant + Duration::from_millis(39500);
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::TransactionFailed((id, error)) = iter.next().expect("Expected event")
    else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(msg_id, id);
    assert_eq!(StunTransactionError::TimedOut, *error);
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_no_reliable_all_rtos() {
    init_logging();

    let decoder = MessageDecoderBuilder::default().build();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    test_all_rtos(&mut client, &decoder);
}

#[test]
fn test_stun_client_no_reliable_skip_intermediate_rtos_on_delayed_call() {
    init_logging();

    let decoder = MessageDecoderBuilder::default().build();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    let msg_id = msg.transaction_id();
    let StunClientEvent::RestransmissionTimeOut((id, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout must be 500 ms after instant
    assert_eq!(msg_id, id);
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // Call on_timeout after 7500 ms, we expect the next timeout to be 8000 ms
    info!("Calling on_timeout after 7500 ms");
    test_rto_after_duration(
        instant,
        Duration::from_millis(7500),
        Duration::from_millis(8000),
        msg_id,
        &mut client,
        &decoder,
    );
}

#[test]
fn test_stun_client_no_reliable_rtt() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((id, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };

    // Timeout must be 500 ms after instant
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // Send response 100 ms after the request.
    let instant = instant + Duration::from_millis(100);
    let response = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_transaction_id(*id)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to process buffer");
    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::StunMessageReceived(msg) = iter.next().expect("Expected event") else {
        panic!("Expected TransactionFinished event");
    };
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // A new request should have an rto = 300 ms
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((_, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };

    // Timeout must be 300 ms after instant
    assert_eq!(*duration, std::time::Duration::from_millis(300));
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_no_reliable_reset_rtt_after_10_mins() {
    init_logging();

    let mut client =
        StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
            .build()
            .expect("Failed to build");

    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((id, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };

    // Timeout must be 500 ms after instant
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // Send response 100 ms after the request. this should lower the current RTT to 300ms
    let instant = instant + Duration::from_millis(100);
    let response = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_transaction_id(*id)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to process buffer");
    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::StunMessageReceived(msg) = iter.next().expect("Expected event") else {
        panic!("Expected TransactionFinished event");
    };
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // A new request should have an rto = 300 ms
    let buffer = pool_buffer();
    client
        .send_request(BINDING, StunAttributes::default(), buffer, instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((id, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout must be 300 ms after instant
    assert_eq!(*duration, std::time::Duration::from_millis(300));
    assert!(iter.next().is_none());

    // Send response 100 ms after the request.
    let instant = instant + Duration::from_millis(100);
    let response = StunMessageBuilder::new(BINDING, SuccessResponse)
        .with_transaction_id(*id)
        .build();
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = pool_buffer();
    encoder
        .encode(&mut buffer, &response)
        .expect("msg encoding failed");
    client
        .on_buffer_recv(&buffer, instant)
        .expect("Failed to process buffer");
    // consume the events
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::StunMessageReceived(msg) = iter.next().expect("Expected event") else {
        panic!("Expected TransactionFinished event");
    };
    assert_eq!(msg.transaction_id(), id);
    // No more events
    assert!(iter.next().is_none());

    // ten minutes of inactivity must be reset the RTT
    let instant = instant + Duration::from_secs(600);
    // A new request should have an rto = 500 ms (reset to default)
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((_, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout must be 500 ms
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_reliable_rtt() {
    init_logging();

    const DEFAULT_RTO: Duration = Duration::from_millis(39500);
    let mut client = StunClienteBuilder::new(TransportReliability::Reliable(DEFAULT_RTO))
        .build()
        .expect("Failed to build");

    // send a request
    let instant = std::time::Instant::now();
    client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::OutputPacket(_) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StunClientEvent::RestransmissionTimeOut((_, duration)) =
        iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(*duration, DEFAULT_RTO);
    assert!(iter.next().is_none());

    // Timeout on a reliable channel must be the default RTO and no more retransmissions must be issues
    let instant = instant + DEFAULT_RTO;
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StunClientEvent::TransactionFailed((_, error)) = iter.next().expect("Expected event")
    else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(StunTransactionError::TimedOut, *error);
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_can_not_set_timeout() {
    init_logging();

    let mut client = StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig {
        rto: Duration::from_millis(1000),
        granularity: Duration::from_millis(8000),
        rm: 0,
        rc: 0,
    }))
    .build()
    .expect("Failed to build");

    // send a request
    let instant = std::time::Instant::now();
    let error = client
        .send_request(BINDING, StunAttributes::default(), pool_buffer(), instant)
        .expect_err("Expected error");

    assert!(matches!(error, StunAgentError::InternalError(_)));
}
