use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use stun_rs::attributes::ice::{IceControlled, Priority, UseCandidate};
use stun_rs::attributes::stun::{
    Fingerprint, MessageIntegrity, MessageIntegritySha256, Nonce, Realm, Software, UserHash,
    UserName, XorMappedAddress,
};
use stun_rs::error::StunErrorLevel;
use stun_rs::methods::BINDING;
use stun_rs::{
    Algorithm, AlgorithmId, AttributeType, EncoderContextBuilder, HMACKey, MessageClass,
    MessageEncoderBuilder, StunErrorType, StunMessageBuilder, StunPadding, TransactionId,
};
use stun_vectors::{
    SAMPLE_IPV4_RESPONSE, SAMPLE_IPV6_RESPONSE, SAMPLE_REQUEST, SAMPLE_REQUEST_LONG_TERM_AUTH,
    SAMPLE_REQUEST_LONG_TERM_AUTH_SHA256,
};

// 2.1.  Sample Request
#[test]
fn test_sample_request() {
    let transaction_id = TransactionId::from([
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ]);
    let software = Software::new("STUN test client").expect("Could not create Software attribute");
    let priority = Priority::from(0x6e0001ffu32);
    let ice_controlled = IceControlled::from(0x932ff9b151263b36u64);
    let user_name = UserName::try_from("evtj:h6vY").expect("Can not create USERNAME attribute");
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let key = HMACKey::new_short_term(password).expect("Could not create HMACKey");
    let integrity = MessageIntegrity::new(key);
    let fingerprint = Fingerprint::default();

    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_transaction_id(transaction_id)
        .with_attribute(software)
        .with_attribute(priority)
        .with_attribute(ice_controlled)
        .with_attribute(user_name)
        .with_attribute(integrity)
        .with_attribute(fingerprint)
        .build();

    let mut buffer: [u8; 150] = [0x00; 150];

    // This example of the rfc5769 uses ASCII white spaces (U+0020)
    // as padding which affects the message integrity fingerprint and CRC
    let ctx = EncoderContextBuilder::default()
        .with_custom_padding(StunPadding::Custom(0x20))
        .build();

    // Create a encoder that uses our custom context
    let encoder = MessageEncoderBuilder::default().with_context(ctx).build();
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(size, 108);

    // Check that both vectors are equal
    assert_eq!(buffer[..size], SAMPLE_REQUEST)
}

// 2.2.  Sample IPv4 Response
#[test]
fn test_sample_ipv4_response() {
    let transaction_id = TransactionId::from([
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ]);
    let software = Software::new("test vector").expect("Could not create Software attribute");
    let mapped_address = XorMappedAddress::from(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        32853,
    ));
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let key = HMACKey::new_short_term(password).expect("Could not create HMACKey");
    let integrity = MessageIntegrity::new(key);
    let fingerprint = Fingerprint::default();

    let msg = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
        .with_transaction_id(transaction_id)
        .with_attribute(software)
        .with_attribute(mapped_address)
        .with_attribute(integrity)
        .with_attribute(fingerprint)
        .build();

    let mut buffer: [u8; 80] = [0x00; 80];

    // This example of the rfc5769 uses ASCII white spaces (U+0020)
    // as padding which affects the message integrity fingerprint and CRC
    let ctx = EncoderContextBuilder::default()
        .with_custom_padding(StunPadding::Custom(0x20))
        .build();

    // Create a encoder that uses our custom context
    let encoder = MessageEncoderBuilder::default().with_context(ctx).build();
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(size, 80);

    // Check that both vectors are equal
    assert_eq!(buffer[..size], SAMPLE_IPV4_RESPONSE)
}

// 2.3.  Sample IPv6 Response
#[test]
fn test_sample_ipv6_response() {
    let transaction_id = TransactionId::from([
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ]);
    let software = Software::new("test vector").expect("Could not create Software attribute");
    let addr = SocketAddr::from_str("[2001:db8:1234:5678:11:2233:4455:6677]:32853")
        .expect("Can not parse SocketAddress");
    let mapped_address = XorMappedAddress::from(addr);
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let key = HMACKey::new_short_term(password).expect("Could not create HMACKey");
    let integrity = MessageIntegrity::new(key);
    let fingerprint = Fingerprint::default();

    let msg = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
        .with_transaction_id(transaction_id)
        .with_attribute(software)
        .with_attribute(mapped_address)
        .with_attribute(integrity)
        .with_attribute(fingerprint)
        .build();

    let mut buffer: [u8; 150] = [0x00; 150];

    // This example of the rfc5769 uses ASCII white spaces (U+0020)
    // as padding which affects the message integrity fingerprint and CRC
    let ctx = EncoderContextBuilder::default()
        .with_custom_padding(StunPadding::Custom(0x20))
        .build();

    // Create a encoder that uses our custom context
    let encoder = MessageEncoderBuilder::default().with_context(ctx).build();
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(size, 92);

    // Check that both vectors are equal
    assert_eq!(buffer[..size], SAMPLE_IPV6_RESPONSE)
}

// 2.4. Sample Request with Long-Term Authentication
#[test]
fn test_sample_request_with_long_term() {
    let transaction_id = TransactionId::from([
        0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
    ]);
    let username = UserName::try_from("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}")
        .expect("Can not creat USERNAME attribute");
    let nonce = Nonce::try_from("f//499k954d6OL34oL9FSTvy64sA").expect("Expected QuotedString");
    let realm = Realm::try_from("example.org").expect("Expected QuotedString");
    // Unicode codepoint {00AD} is disallowed in PRECIS, so we use the
    // result of applying SASLprep
    // let password = "The\u{00AD}M\u{00AA}tr\u{2168}";
    let password = "TheMatrIX";
    let algorithm = Algorithm::from(AlgorithmId::MD5);
    let key = HMACKey::new_long_term(&username, &realm, password, algorithm)
        .expect("Could not create HMACKey");
    let integrity = MessageIntegrity::new(key);

    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_transaction_id(transaction_id)
        .with_attribute(username)
        .with_attribute(nonce)
        .with_attribute(realm)
        .with_attribute(integrity)
        .build();

    let mut buffer: [u8; 150] = [0x00; 150];

    let encoder = MessageEncoderBuilder::default().build();
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(size, 116);

    // Check that both vectors are equal
    assert_eq!(buffer[..size], SAMPLE_REQUEST_LONG_TERM_AUTH)
}

// B.1.  Sample Request with Long-Term Authentication with MESSAGE-INTEGRITY-SHA256 and USERHASH.
#[test]
fn test_sample_request_with_long_term_sha256() {
    let transaction_id = TransactionId::from([
        0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
    ]);
    let username = UserName::try_from("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}")
        .expect("Can not creat USERNAME attribute");
    let realm = Realm::try_from("example.org").expect("Expected QuotedString");
    let user_hash = UserHash::new(&username, &realm).expect("Can not create UserHash");
    let nonce = Nonce::try_from("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA")
        .expect("Expected QuotedString");
    // Unicode codepoint {00AD} is disallowed in PRECIS, so we use the
    // result of applying SASLprep
    // let password = "The\u{00AD}M\u{00AA}tr\u{2168}";
    let password = "TheMatrIX";
    let algorithm = Algorithm::from(AlgorithmId::MD5);
    let key = HMACKey::new_long_term(&username, &realm, password, algorithm)
        .expect("Could not create HMACKey");
    let integrity = MessageIntegritySha256::new(key);

    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_transaction_id(transaction_id)
        .with_attribute(user_hash)
        .with_attribute(nonce)
        .with_attribute(realm)
        .with_attribute(integrity)
        .build();

    let mut buffer: [u8; 156] = [0x00; 156];

    let encoder = MessageEncoderBuilder::default().build();
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(size, 156);

    // Check that both vectors are equal
    assert_eq!(buffer[..size], SAMPLE_REQUEST_LONG_TERM_AUTH_SHA256)
}

#[test]
fn encode_request_error() {
    let nonce = Nonce::try_from("nonce").expect("Expected QuotedString");

    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_attribute(nonce)
        .build();

    let encoder = MessageEncoderBuilder::default().build();

    // No room for stun header
    let mut buffer: [u8; 10] = [0x00; 10];
    let error = encoder
        .encode(&mut buffer, &msg)
        .expect_err("Expected small buffer error");
    assert!(matches!(error.0, StunErrorLevel::Message(_)));
    assert!(match &error.0 {
        StunErrorLevel::Message(e) => e.0 == StunErrorType::SmallBuffer,
        _ => false,
    });

    // No room for Nonce attribute type
    let mut buffer: [u8; 21] = [0x00; 21];
    let error = encoder
        .encode(&mut buffer, &msg)
        .expect_err("Expected small buffer error");
    assert!(match &error.0 {
        StunErrorLevel::Attribute(e) => {
            e.attr_type == Some(AttributeType::new(0x0015))
                && e.position == 0
                && e.error == StunErrorType::SmallBuffer
        }
        _ => false,
    });

    // No room for padding (32 bytes required)
    let mut buffer: [u8; 31] = [0x00; 31];
    let error = encoder
        .encode(&mut buffer, &msg)
        .expect_err("Expected small buffer error");
    assert!(match &error.0 {
        StunErrorLevel::Attribute(e) => {
            e.attr_type == Some(AttributeType::new(0x0015))
                && e.position == 0
                && e.error == StunErrorType::SmallBuffer
        }
        _ => false,
    });
}

#[test]
fn encode_request() {
    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_attribute(UseCandidate::default())
        .build();

    let encoder = MessageEncoderBuilder::default().build();

    let mut buffer: [u8; 24] = [0x00; 24];
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Can not encode stun message");
    assert_eq!(size, 24);
}
