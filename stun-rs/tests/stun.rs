use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use stun_rs::attributes::stun::{
    AlternateServer, ErrorCode, Fingerprint, MappedAddress, MessageIntegrity,
    MessageIntegritySha256, Nonce, PasswordAlgorithm, PasswordAlgorithms, Realm, Software,
    UserHash, UserName, XorMappedAddress,
};

use stun_rs::methods::BINDING;
use stun_rs::{
    Algorithm, AlgorithmId, DecoderContextBuilder, HMACKey, MessageClass, MessageDecoderBuilder,
    MessageEncoderBuilder, StunMessageBuilder, TransactionId,
};

const RAW: [u8; 12] = [0x11; 12];

#[test]
fn test_stun_attributes_request() {
    const USERNAME: &str = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
    const SOFTWARE: &str = "STUN test";
    const NONCE: &str = "f//499k954d6OL34oL9FSTvy64sA";
    const REALM: &str = "example.org";

    // Create attributes
    let username = UserName::new(USERNAME).expect("Failed to create UserName");
    let nonce = Nonce::new(NONCE).expect("Failed to create Nonce");
    let realm = Realm::new(REALM).expect("Failed to create Realm");
    let user_hash = UserHash::new(&username, &realm).expect("Failed to create UserHash");
    let software = Software::new(SOFTWARE).expect("Failed to create Software");

    // TODO: Create PasswordAlgorithm from AlgorithmId
    let algorithms = vec![
        PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5)),
        PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256)),
    ];
    let password_algorithms = PasswordAlgorithms::from(algorithms);
    let password = "TheMatrIX";
    let algorithm = Algorithm::from(AlgorithmId::MD5);
    let key = HMACKey::new_long_term(&username, &realm, password, algorithm)
        .expect("Failed to create HMACKey");
    let integrity = MessageIntegrity::new(key.clone());
    let fingerprint = Fingerprint::default();

    // Create a message
    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_transaction_id(TransactionId::from(RAW))
        .with_attribute(username)
        .with_attribute(user_hash)
        .with_attribute(nonce)
        .with_attribute(realm)
        .with_attribute(software)
        .with_attribute(password_algorithms)
        .with_attribute(integrity)
        .with_attribute(fingerprint)
        .build();

    // Create an encoder to encode the message into a buffer
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = [0x00; 200];
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Failed to encode StunMessage");
    assert_eq!(size, 188);

    // Create a decoder to decode the message from the buffer
    let ctx = DecoderContextBuilder::default()
        .with_key(key)
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&buffer)
        .expect("Failed to decode StunMessage");
    assert_eq!(size, 188);

    // Check message method is a BINDING response
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), MessageClass::Request);

    let attribute = msg.get::<UserName>().unwrap();
    assert!(attribute.is_user_name());
    let username = attribute.as_user_name().unwrap();
    assert_eq!(username, USERNAME);

    // TODO: Allow to ref userhash as array
    let attribute = msg.get::<UserHash>().unwrap();
    assert!(attribute.is_user_hash());
    let userhash = attribute.as_user_hash().unwrap();
    assert_eq!(
        userhash.hash(),
        [
            74, 60, 243, 143, 239, 105, 146, 189, 169, 82, 198, 120, 4, 23, 218, 15, 36, 129, 148,
            21, 86, 158, 96, 178, 5, 196, 110, 65, 64, 127, 23, 4
        ]
    );

    let attribute = msg.get::<Nonce>().unwrap();
    assert!(attribute.is_nonce());
    let nonce = attribute.as_nonce().unwrap();
    assert_eq!(nonce, NONCE);

    let attribute = msg.get::<Realm>().unwrap();
    assert!(attribute.is_realm());
    let realm = attribute.as_realm().unwrap();
    assert_eq!(realm, REALM);

    let attribute = msg.get::<Software>().unwrap();
    assert!(attribute.is_software());
    let software = attribute.as_software().unwrap();
    assert_eq!(software, SOFTWARE);

    let attribute = msg.get::<PasswordAlgorithms>().unwrap();
    assert!(attribute.is_password_algorithms());
    let password_algorithms = attribute.as_password_algorithms().unwrap();
    let mut i = password_algorithms.iter();
    let attr = i.next().unwrap();
    assert_eq!(attr.algorithm(), AlgorithmId::MD5);
    assert!(attr.parameters().is_none());
    let attr = i.next().unwrap();
    assert_eq!(attr.algorithm(), AlgorithmId::SHA256);
    assert!(attr.parameters().is_none());
    assert!(i.next().is_none());

    let attribute = msg.get::<MessageIntegrity>().unwrap();
    assert!(attribute.is_message_integrity());
    let message_integrity = attribute.as_message_integrity().unwrap();
    match message_integrity {
        MessageIntegrity::Decodable(val) => assert_eq!(
            val.as_ref(),
            [
                217, 196, 241, 235, 205, 7, 148, 124, 89, 35, 36, 54, 161, 203, 33, 186, 207, 169,
                64, 137
            ]
        ),
        _ => panic!("Unexpected decodable type"),
    }

    let attribute = msg.get::<Fingerprint>().unwrap();
    assert!(attribute.is_fingerprint());
    let fingerprint = attribute.as_fingerprint().unwrap();
    match fingerprint {
        Fingerprint::Decodable(val) => assert_eq!(*val, 1457127838u32),
        _ => panic!("Unexpected decodable type"),
    }
}

#[test]
fn test_stun_attributes_response() {
    // Create attributes
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let alternate_server = AlternateServer::from(socket);
    let error =
        stun_rs::ErrorCode::new(420, "Unknown Attribute").expect("Failed to create ErrorCode");
    let error_code = ErrorCode::from(error);
    let mapped_address = MappedAddress::from(socket);
    let xor_mapped_address = XorMappedAddress::from(socket);
    let password_algorithm = PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5));
    let key = HMACKey::new_short_term("foo bar").expect("Failed to create HMACKey");
    let integrity = MessageIntegritySha256::new(key.clone());
    let fingerprint = Fingerprint::default();

    // Create a message
    let msg = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
        .with_transaction_id(TransactionId::from(RAW))
        .with_attribute(alternate_server)
        .with_attribute(mapped_address)
        .with_attribute(xor_mapped_address)
        .with_attribute(password_algorithm)
        .with_attribute(error_code)
        .with_attribute(integrity)
        .with_attribute(fingerprint)
        .build();

    // Create an encoder to encode the message into a buffer
    let encoder = MessageEncoderBuilder::default().build();
    let mut buffer = [0x00; 200];
    let size = encoder
        .encode(&mut buffer, &msg)
        .expect("Failed to encode StunMessage");
    assert_eq!(size, 136);

    // Create a decoder to decode the message from the buffer
    let ctx = DecoderContextBuilder::default()
        .with_key(key)
        .with_validation()
        .build();
    let decoder = MessageDecoderBuilder::default().with_context(ctx).build();

    let (msg, size) = decoder
        .decode(&buffer)
        .expect("Failed to decode StunMessage");
    assert_eq!(size, 136);

    // Check message method is a BINDING response
    assert_eq!(msg.method(), BINDING);
    assert_eq!(msg.class(), MessageClass::SuccessResponse);

    let mut iter = msg.attributes().iter();
    let attribute = iter.next().unwrap();
    assert!(attribute.is_alternate_server());
    let alternate_server = attribute.as_alternate_server().unwrap();
    assert_eq!(
        alternate_server.socket_address().to_string(),
        "127.0.0.1:8080"
    );

    let attribute = iter.next().unwrap();
    assert!(attribute.is_mapped_address());
    let mapped_address = attribute.as_mapped_address().unwrap();
    assert_eq!(
        mapped_address.socket_address().to_string(),
        "127.0.0.1:8080"
    );

    let attribute = iter.next().unwrap();
    assert!(attribute.is_xor_mapped_address());
    let xor_mapped_address = attribute.as_xor_mapped_address().unwrap();
    assert_eq!(
        xor_mapped_address.socket_address().to_string(),
        "127.0.0.1:8080"
    );

    let attribute = iter.next().unwrap();
    assert!(attribute.is_password_algorithm());
    let password_algorithm = attribute.as_password_algorithm().unwrap();
    assert_eq!(password_algorithm.algorithm(), AlgorithmId::MD5);
    assert!(password_algorithm.parameters().is_none());

    let attribute = iter.next().unwrap();
    assert!(attribute.is_error_code());
    let error_code = attribute.as_error_code().unwrap();
    assert_eq!(error_code.error_code().error_code(), 420);
    assert_eq!(error_code.error_code().reason(), "Unknown Attribute");

    let attribute = iter.next().unwrap();
    assert!(attribute.is_message_integrity_sha256());
    let message_integrity = attribute.as_message_integrity_sha256().unwrap();
    match message_integrity {
        MessageIntegritySha256::Decodable(val) => assert_eq!(
            val.as_ref(),
            [
                183, 224, 194, 222, 247, 1, 32, 156, 42, 13, 108, 152, 22, 111, 77, 56, 91, 48,
                174, 114, 97, 27, 11, 229, 186, 148, 192, 142, 224, 125, 109, 230
            ]
        ),
        _ => panic!("Unexpected decodable type"),
    }

    let attribute = iter.next().unwrap();
    assert!(attribute.is_fingerprint());
    let fingerprint = attribute.as_fingerprint().unwrap();
    match fingerprint {
        Fingerprint::Decodable(val) => assert_eq!(*val, 956942611),
        _ => panic!("Unexpected decodable type"),
    }

    // No more attributes
    assert!(iter.next().is_none());
}
