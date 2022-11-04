use std::convert::TryFrom;

use stun_rs::attributes::ice::{IceControlled, Priority, UseCandidate};
use stun_rs::attributes::stun::{
    Fingerprint, MessageIntegrity, MessageIntegritySha256, Nonce, Realm, Software, UserHash,
    UserName, XorMappedAddress,
};
use stun_rs::error::StunErrorLevel;
use stun_rs::methods::BINDING;
use stun_rs::{
    Algorithm, AlgorithmId, AttributeType, DecoderContextBuilder, HMACKey, MessageClass,
    MessageDecoderBuilder, MessageEncoderBuilder, StunAttributeType, StunErrorType, StunMessage,
    StunMessageBuilder,
};

// 2.1. Sample Request
#[test]
fn test_sample_request() {
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let ctx = DecoderContextBuilder::default()
        .with_key(HMACKey::new_short_term(password).expect("Can not create short term credential"))
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&stun_vectors::SAMPLE_REQUEST)
        .expect("Can not decode StunMessage");
    assert_eq!(size, 108);
    let attributes = msg.attributes();
    assert_eq!(attributes.len(), 6);

    let mut iter = attributes.iter();
    let attr = iter.next().expect("Expected attribute SOFTWARE");
    let software = attr.expect_software();
    assert_eq!(software.attribute_type(), Software::get_type());
    assert_eq!(software, "STUN test client");

    let attr = iter.next().expect("Expected attribute Priority");
    let priority = attr.expect_priority();
    assert_eq!(priority.attribute_type(), Priority::get_type());
    assert_eq!(priority.as_u32(), 1845494271);

    let attr = iter.next().expect("Expected attribute IceControlled");
    let ice_controlled = attr.expect_ice_controlled();
    assert_eq!(ice_controlled.attribute_type(), IceControlled::get_type());
    assert_eq!(ice_controlled.as_u64(), 10605970187446795062);

    let attr = iter.next().expect("Expected attribute Username");
    let username = attr.expect_user_name();
    assert_eq!(username.attribute_type(), UserName::get_type());
    assert_eq!(username, "evtj:h6vY");

    let attr = iter.next().expect("Expected attribute MessageIntegrity");
    let integrity = attr.expect_message_integrity();
    assert_eq!(integrity.attribute_type(), MessageIntegrity::get_type());

    let attr = iter.next().expect("Expected attribute Fingerprint");
    let fingerprint = attr.expect_fingerprint();
    assert_eq!(fingerprint.attribute_type(), Fingerprint::get_type());
}

// 2.2. Sample IPv4 Response
#[test]
fn test_sample_ipv4_response() {
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let ctx = DecoderContextBuilder::default()
        .with_key(HMACKey::new_short_term(password).expect("Can not create short term credential"))
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&stun_vectors::SAMPLE_IPV4_RESPONSE)
        .expect("Can not decode StunMessage");
    assert_eq!(size, 80);
    let attributes = msg.attributes();
    assert_eq!(attributes.len(), 4);

    let mut iter = attributes.iter();
    let attr = iter.next().expect("Expected attribute SOFTWARE");
    let software = attr.expect_software();
    assert_eq!(software.attribute_type(), Software::get_type());
    assert_eq!(software, "test vector");

    let attr = iter.next().expect("Expected attribute XorMappedAddress");
    let address = attr.expect_xor_mapped_address();
    assert_eq!(address.attribute_type(), XorMappedAddress::get_type());
    assert!(address.socket_address().is_ipv4());
    assert_eq!(address.socket_address().to_string(), "192.0.2.1:32853");

    let attr = iter.next().expect("Expected attribute MessageIntegrity");
    let integrity = attr.expect_message_integrity();
    assert_eq!(integrity.attribute_type(), MessageIntegrity::get_type());

    let attr = iter.next().expect("Expected attribute Fingerprint");
    let fingerprint = attr.expect_fingerprint();
    assert_eq!(fingerprint.attribute_type(), Fingerprint::get_type());
}

// 2.3. Sample IPv6 Response
#[test]
fn test_sample_ipv6_response() {
    let password = "VOkJxbRl1RmTxUk/WvJxBt";
    let ctx = DecoderContextBuilder::default()
        .with_key(HMACKey::new_short_term(password).expect("Can not create short term credential"))
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&stun_vectors::SAMPLE_IPV6_RESPONSE)
        .expect("Can not decode StunMessage");
    assert_eq!(size, 92);
    let attributes = msg.attributes();
    assert_eq!(attributes.len(), 4);

    let mut iter = attributes.iter();
    let attr = iter.next().expect("Expected attribute SOFTWARE");
    let software = attr.expect_software();
    assert_eq!(software.attribute_type(), Software::get_type());
    assert_eq!(software, "test vector");

    let attr = iter.next().expect("Expected attribute XorMappedAddress");
    let address = attr.expect_xor_mapped_address();
    assert_eq!(address.attribute_type(), XorMappedAddress::get_type());
    assert!(address.socket_address().is_ipv6());
    assert_eq!(
        address.socket_address().to_string(),
        "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
    );

    let attr = iter.next().expect("Expected attribute MessageIntegrity");
    let integrity = attr.expect_message_integrity();
    assert_eq!(integrity.attribute_type(), MessageIntegrity::get_type());

    let attr = iter.next().expect("Expected attribute Fingerprint");
    let fingerprint = attr.expect_fingerprint();
    assert_eq!(fingerprint.attribute_type(), Fingerprint::get_type());
}

// 2.4. Sample Request with Long-Term Authentication
#[test]
fn test_sample_request_with_long_term_auth() {
    let username_str = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
    let realm_str = "example.org";
    let algorithm = Algorithm::from(AlgorithmId::MD5);
    let ctx = DecoderContextBuilder::default()
        .with_key(
            HMACKey::new_long_term(username_str, realm_str, "TheMatrIX", algorithm)
                .expect("Can not create long term credential"),
        )
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&stun_vectors::SAMPLE_REQUEST_LONG_TERM_AUTH)
        .expect("Can not decode StunMessage");
    assert_eq!(size, 116);
    let attributes = msg.attributes();
    assert_eq!(attributes.len(), 4);

    let mut iter = attributes.iter();
    let attr = iter.next().expect("Expected attribute USERNAME");
    let username = attr.expect_user_name();
    assert_eq!(attr.attribute_type(), UserName::get_type());
    // Next comparation uses OpaqueString profile under the hood
    assert_eq!(username, username_str);

    let attr = iter.next().expect("Expected attribute Nonce");
    let nonce = attr.expect_nonce();
    assert_eq!(nonce.attribute_type(), Nonce::get_type());
    assert_eq!(nonce, "f//499k954d6OL34oL9FSTvy64sA");

    let attr = iter.next().expect("Expected attribute Realm");
    let realm = attr.expect_realm();
    assert_eq!(realm.attribute_type(), Realm::get_type());
    // Next comparation uses OpaqueString profile under the hood
    assert_eq!(realm, realm_str);

    let integrity = iter.next().expect("Expected attribute MessageIntegrity");
    assert_eq!(integrity.attribute_type(), MessageIntegrity::get_type());
}

// B.1.  Sample Request with Long-Term Authentication with MESSAGE-INTEGRITY-SHA256 and USERHASH.
#[test]
fn test_sample_request_with_long_term_auth_sha256() {
    let username_str = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
    let realm_str = "example.org";
    let algorithm = Algorithm::from(AlgorithmId::MD5);
    let ctx = DecoderContextBuilder::default()
        .with_key(
            HMACKey::new_long_term(username_str, realm_str, "TheMatrIX", algorithm)
                .expect("Can not create long term credential"),
        )
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&stun_vectors::SAMPLE_REQUEST_LONG_TERM_AUTH_SHA256)
        .expect("Can not decode StunMessage");
    assert_eq!(size, 156);
    let attributes = msg.attributes();
    assert_eq!(attributes.len(), 4);

    let mut iter = attributes.iter();
    let attr = iter.next().expect("Expected attribute UserHash");
    let userhash = attr.expect_user_hash();
    assert_eq!(userhash.attribute_type(), UserHash::get_type());
    let hash = [
        0x4a, 0x3c, 0xf3, 0x8f, // }
        0xef, 0x69, 0x92, 0xbd, // }
        0xa9, 0x52, 0xc6, 0x78, // }
        0x04, 0x17, 0xda, 0x0f, // }  `Userhash` value (32 bytes)
        0x24, 0x81, 0x94, 0x15, // }
        0x56, 0x9e, 0x60, 0xb2, // }
        0x05, 0xc4, 0x6e, 0x41, // }
        0x40, 0x7f, 0x17, 0x04, // }
    ];
    assert_eq!(userhash.hash(), hash);

    let attr = iter.next().expect("Expected attribute Nonce");
    let nonce = attr.expect_nonce();
    assert_eq!(nonce.attribute_type(), Nonce::get_type());
    assert_eq!(nonce, "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA");

    let attr = iter.next().expect("Expected attribute Realm");
    let realm = attr.expect_realm();
    assert_eq!(realm.attribute_type(), Realm::get_type());
    // Next comparation uses OpaqueString profile under the hood
    assert_eq!(realm, realm_str);

    let integrity = iter
        .next()
        .expect("Expected attribute MessageIntegritySha256");
    assert_eq!(
        integrity.attribute_type(),
        MessageIntegritySha256::get_type()
    );
}

#[test]
fn decode_request_error() {
    let mut buffer: [u8; 15] = [0x00; 15];
    buffer.copy_from_slice(&stun_vectors::SAMPLE_REQUEST[..15]);

    let decoder = MessageDecoderBuilder::default().build();
    let error = decoder.decode(&buffer).expect_err("Buffer is too small");
    assert!(match &error.0 {
        StunErrorLevel::Message(e) => e.0 == StunErrorType::SmallBuffer,
        _ => false,
    });

    let password = "wrong_password";
    let ctx = DecoderContextBuilder::default()
        .with_key(HMACKey::new_short_term(password).expect("Can not create short term credential"))
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let error = decoder
        .decode(&stun_vectors::SAMPLE_REQUEST)
        .expect_err("Validation must fail");
    assert!(match &error.0 {
        StunErrorLevel::Attribute(e) => {
            e.attr_type == Some(AttributeType::new(0x0008))
                && e.position == 4
                && e.error == StunErrorType::ValidationFailed
        }
        _ => false,
    });
}

#[test]
fn decode_request() {
    let simple_request = [
        0x00, 0x01, 0x00, 0x04, // Request type and message length
        0x21, 0x12, 0xa4, 0x42, // Magic cookie
        0xb7, 0xe7, 0xa7, 0x01, // }
        0xbc, 0x34, 0xd6, 0x86, // }  Transaction ID
        0xfa, 0x87, 0xdf, 0xae, // }
        0x00, 0x25, 0x00, 0x00, // } Use candidate
    ];

    let decoder = MessageDecoderBuilder::default().build();
    let (msg, size) = decoder
        .decode(&simple_request)
        .expect("Can not decode StunMessage");
    assert_eq!(size, simple_request.len());

    assert!(msg
        .get::<UseCandidate>()
        .ok_or("Use candidate attribute not found")
        .is_ok());
}

fn create_msg_with_ignorable_attributes(key: HMACKey) -> StunMessage {
    let software = Software::new("STUN test client").expect("Could not create Software attribute");
    let priority = Priority::from(0x6e0001ffu32);
    let ice_controlled = IceControlled::from(0x932ff9b151263b36u64);
    let user_name = UserName::try_from("evtj:h6vY").expect("Can not create USERNAME attribute");
    let integrity = MessageIntegrity::new(key);
    let fingerprint = Fingerprint::default();

    // Create a message and add some attributes after MessageIntegrity and Fingerprint, that MUST be ignored
    StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_attribute(software)
        .with_attribute(user_name)
        .with_attribute(integrity)
        .with_attribute(priority)
        .with_attribute(fingerprint)
        .with_attribute(ice_controlled)
        .build()
}

#[test]
fn decode_without_ignored_attributes() {
    let key = HMACKey::new_short_term("VOkJxbRl1RmTxUk/WvJxBt").expect("Could not create HMACKey");
    let msg = create_msg_with_ignorable_attributes(key.clone());

    let mut buffer: [u8; 150] = [0x00; 150];

    let encoder = MessageEncoderBuilder::default().build();
    let encoded_size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(encoded_size, 108);

    let ctx = DecoderContextBuilder::default()
        .with_key(key)
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, decoded_size) = decoder.decode(&buffer).expect("Can not decode StunMessage");
    assert_eq!(decoded_size, encoded_size);

    // Only Software, UserName, MessageIntegrity and Fingerprint
    // must be processed
    assert_eq!(msg.attributes().len(), 4);

    assert!(msg
        .get::<Software>()
        .ok_or("Software attribute not found")
        .is_ok());
    assert!(msg
        .get::<UserName>()
        .ok_or("UserName attribute not found")
        .is_ok());
    assert!(msg
        .get::<MessageIntegrity>()
        .ok_or("MessageIntegrity attribute not found")
        .is_ok());
    assert!(msg
        .get::<Fingerprint>()
        .ok_or("Fingerprint attribute not found")
        .is_ok());

    // Check that Priority and IceControlled attributes are ignored
    assert!(msg.get::<Priority>().is_none());
    assert!(msg.get::<IceControlled>().is_none());
}

#[test]
fn decode_with_ignored_attributes() {
    let key = HMACKey::new_short_term("VOkJxbRl1RmTxUk/WvJxBt").expect("Could not create HMACKey");
    let msg = create_msg_with_ignorable_attributes(key.clone());

    let mut buffer: [u8; 150] = [0x00; 150];

    let encoder = MessageEncoderBuilder::default().build();
    let encoded_size = encoder
        .encode(&mut buffer, &msg)
        .expect("Could not encode STUN message");
    assert_eq!(encoded_size, 108);

    let ctx = DecoderContextBuilder::default()
        .with_key(key)
        .with_validation()
        .not_ignore()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, decoded_size) = decoder.decode(&buffer).expect("Can not decode StunMessage");
    assert_eq!(decoded_size, encoded_size);

    // All attributes must be processed
    assert_eq!(msg.attributes().len(), 6);

    assert!(msg
        .get::<Software>()
        .ok_or("Software attribute not found")
        .is_ok());
    assert!(msg
        .get::<UserName>()
        .ok_or("UserName attribute not found")
        .is_ok());
    assert!(msg
        .get::<MessageIntegrity>()
        .ok_or("MessageIntegrity attribute not found")
        .is_ok());
    assert!(msg
        .get::<Priority>()
        .ok_or("Priority attribute not found")
        .is_ok());
    assert!(msg
        .get::<Fingerprint>()
        .ok_or("Fingerprint attribute not found")
        .is_ok());
    assert!(msg
        .get::<IceControlled>()
        .ok_or("IceControlled attribute not found")
        .is_ok());
}
