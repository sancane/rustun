use log::info;
use std::time::{Duration, Instant};
use stun_agent::client::{StunClient, StunClienteBuilder};
use stun_agent::events::{StunTransactionError, StuntEvent};
use stun_agent::message::StunAttributes;
use stun_rs::methods::BINDING;
use stun_rs::MessageClass::{Indication, Request};
use stun_rs::{
    DecoderContextBuilder, HMACKey, MessageClass, MessageDecoder, MessageDecoderBuilder,
    MessageMethod, StunMessage, TransactionId,
};

const USERNAME: &str = "test-username";
const PASSWORD: &str = "test-password";

fn check_stun_message(
    msg: &StunMessage,
    method: MessageMethod,
    class: MessageClass,
    with_msg_integrity: bool,
    with_msg_integrity_sha256: bool,
    with_fingerprint: bool,
) {
    assert_eq!(msg.method(), method);
    assert_eq!(msg.class(), class);

    let attributes = msg.attributes();
    let mut iter = attributes.iter();
    let attr = iter.next().expect("Expected attribute UserName");
    let username = attr.expect_user_name();
    assert_eq!(username, USERNAME);

    if with_msg_integrity {
        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());
    }

    if with_msg_integrity_sha256 {
        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());
    }

    if with_fingerprint {
        let attr = iter.next().expect("Expected attribute Fingerprint");
        assert!(attr.is_fingerprint());
    }

    assert!(iter.next().is_none());
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
fn test_stun_client_with_short_term_auth_with_fingerprint_no_reliable() {
    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
    let decoder = create_decoder(Some(key));

    let mut client = StunClienteBuilder::new(USERNAME, PASSWORD).unwrap().build();

    // No events at this point
    let events = client.events();
    assert!(events.is_empty());

    // Send an indication
    client
        .create_indication(BINDING, StunAttributes::default())
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    assert!(iter.next().is_none());

    // Check message
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    check_stun_message(&msg, BINDING, Indication, true, true, false);

    // No mor event must be pulled
    assert!(client.events().is_empty());

    // Now send a request
    let instant = std::time::Instant::now();
    client
        .create_request(BINDING, StunAttributes::default(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StuntEvent::RestransmissionTimeOut((_, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout must be 500 ms after instant
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // Check message
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    check_stun_message(&msg, BINDING, Request, true, true, false);

    // No mor event must be pulled
    assert!(client.events().is_empty());
}

#[test]
fn test_stun_client_with_short_term_auth_with_fingerprint_no_reliable_retransmission() {
    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
    let decoder = create_decoder(Some(key));

    let mut client = StunClienteBuilder::new(USERNAME, PASSWORD).unwrap().build();

    // Send a first request
    let instant = std::time::Instant::now();
    client
        .create_request(BINDING, StunAttributes::default(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout must be 500 ms after instant
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());
    // Check message
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    check_stun_message(&msg, BINDING, Request, true, true, false);
    let msg1_id = msg.transaction_id();
    assert_eq!(msg1_id, id);

    // If we call on timeout now, we  must get the next time out
    // that should match to the first one
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(msg1_id, id);
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // Send a second request 300 ms after the first one
    let instant = instant + std::time::Duration::from_millis(300);
    client
        .create_request(BINDING, StunAttributes::default(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The next timeout must match the first one, and after 300 ms there must
    // expire after 200ms
    assert_eq!(msg1_id, id);
    assert_eq!(*duration, std::time::Duration::from_millis(200));
    assert!(iter.next().is_none());
    // Check message
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    check_stun_message(&msg, BINDING, Request, true, true, false);
    let msg2_id = msg.transaction_id();

    // If we call on timeout now, we  must get the next time out
    // that should expire in 200 ms
    client.on_timeout(instant);
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(msg1_id, id);
    assert_eq!(*duration, std::time::Duration::from_millis(200));
    assert!(iter.next().is_none());

    // Advance time to 500 ms after the first request
    let instant = instant + std::time::Duration::from_millis(200);
    client.on_timeout(instant);
    let events = client.events();
    // After 500 ms the first transaction must be retransmitted
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    // this must be the first message which must be retransmitted∫
    assert_eq!(msg1_id, msg.transaction_id());

    // We must get the next timeout for the next transaction pending
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // The next timeout must match the second one (300 ms after the first one), and after 500 ms
    // it must expire after 300ms
    assert_eq!(msg2_id, id);
    assert_eq!(*duration, std::time::Duration::from_millis(300));
}

fn test_timout_after_duration(
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
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    assert_eq!(msg_id, msg.transaction_id());
    let StuntEvent::RestransmissionTimeOut((id, timeout)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(msg_id, id);
    assert_eq!(expected, *timeout);
    assert!(iter.next().is_none());
}

fn test_timeout(client: &mut StunClient, decoder: &MessageDecoder) {
    // Send an indication
    let now = Instant::now();
    let instant = now;
    client
        .create_request(BINDING, StunAttributes::default(), now)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    let msg_id = msg.transaction_id();
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    assert_eq!(msg_id, id);
    assert_eq!(duration, &Duration::from_millis(500));
    assert!(iter.next().is_none());

    info!("Calling on_timeout after 500 ms");
    test_timout_after_duration(
        instant,
        Duration::from_millis(500),
        Duration::from_millis(1000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 1500 ms");
    test_timout_after_duration(
        instant,
        Duration::from_millis(1500),
        Duration::from_millis(2000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 3500 ms");
    test_timout_after_duration(
        instant,
        Duration::from_millis(3500),
        Duration::from_millis(4000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 7500 ms");
    test_timout_after_duration(
        instant,
        Duration::from_millis(7500),
        Duration::from_millis(8000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 15500 ms");
    test_timout_after_duration(
        instant,
        Duration::from_millis(15500),
        Duration::from_millis(16000),
        msg_id,
        client,
        decoder,
    );

    info!("Calling on_timeout after 31500 ms");
    test_timout_after_duration(
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
    let StuntEvent::TransactionFailed((id, error)) = iter.next().expect("Expected event") else {
        panic!("Expected TransactionFailed event");
    };
    assert_eq!(msg_id, id);
    assert_eq!(StunTransactionError::TimedOut, *error);
    assert!(iter.next().is_none());
}

#[test]
fn test_stun_client_with_short_term_auth_with_fingerprint_no_reliable_timeout() {
    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
    let decoder = create_decoder(Some(key));

    let mut client = StunClienteBuilder::new(USERNAME, PASSWORD).unwrap().build();

    test_timeout(&mut client, &decoder);
}

// Enable next tests when transmission over reliable channel is implemented
#[test]
#[ignore]
fn test_stun_client_with_short_term_auth_with_fingerprint_reliable_timeout() {
    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
    let decoder = create_decoder(Some(key));

    let mut client = StunClienteBuilder::new(USERNAME, PASSWORD)
        .unwrap()
        .reliable()
        .build();

    test_timeout(&mut client, &decoder);
}

#[test]
fn test_stun_client_delayed_on_timeout_callback() {
    let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
    let decoder = create_decoder(Some(key));

    let mut client = StunClienteBuilder::new(USERNAME, PASSWORD).unwrap().build();

    let instant = std::time::Instant::now();
    client
        .create_request(BINDING, StunAttributes::default(), instant)
        .expect("Failed to create indication");
    let events = client.events();
    let mut iter = events.iter();
    let StuntEvent::OutputBuffer(buffer) = iter.next().expect("Expected event") else {
        panic!("Expected OutputBuffer event");
    };
    let (msg, _) = decoder.decode(buffer).expect("Failed to decode message");
    let msg_id = msg.transaction_id();
    let StuntEvent::RestransmissionTimeOut((id, duration)) = iter.next().expect("Expected event")
    else {
        panic!("Expected RestransmissionTimeOut event");
    };
    // Timeout must be 500 ms after instant
    assert_eq!(msg_id, id);
    assert_eq!(*duration, std::time::Duration::from_millis(500));
    assert!(iter.next().is_none());

    // Call on_timeout after 7500 ms
    info!("Calling on_timeout after 7500 ms");
    test_timout_after_duration(
        instant,
        Duration::from_millis(7500),
        Duration::from_millis(8000),
        msg_id,
        &mut client,
        &decoder,
    );
}
