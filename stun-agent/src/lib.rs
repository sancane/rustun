//! STUN Agent library for Rust.
//!
//! This crate provides a STUN I/O-free protocol implementation.
//! An I/O-free protocol implementation, often referred to as a
//! [`sans-IO`](`https://sans-io.readthedocs.io/index.html`) implementation, is a
//! network protocol implementation that contains no code for network I/O or
//! asynchronous flow control. This means the protocol implementation is agnostic
//! to the underlying networking stack and can be used in any environment that provides
//! the necessary network I/O and asynchronous flow control.
//!
//! These STUN agents are designed for use in a client-server architecture where the
//! client sends a request and the server responds.
//!
//! This sans-IO protocol implementation is defined entirely in terms of synchronous
//! functions returning synchronous results, without blocking or waiting for any form
//! of I/O. This makes it suitable for a wide range of environments, enhancing testing,
//! flexibility, correctness, re-usability and simplicity.
//!
//! This library currently provides support for writing STUN clients. Support for
//! writing servers is not yet implemented. The main element of this library is:
//! - [`StunClient`](`crate::StunClient`): The STUN client that sends STUN requests and indications to a STUN server.
#![deny(missing_docs)]

use std::{ops::Deref, slice::Iter, sync::Arc};

use stun_rs::StunAttribute;

mod client;
mod events;
mod fingerprint;
mod integrity;
mod lt_cred_mech;
mod message;
mod rtt;
mod st_cred_mech;
mod timeout;

pub use crate::client::RttConfig;
pub use crate::client::StunClient;
pub use crate::client::StunClienteBuilder;
pub use crate::client::TransportReliability;
pub use crate::events::StunTransactionError;
pub use crate::events::StuntClientEvent;
pub use crate::message::StunAttributes;

/// Describes the error that can occur during the STUN agent operation.
#[derive(Debug, PartialEq, Eq)]
pub enum StunAgentError {
    /// Indicates that the STUN agent has discarded the buffer
    Discarded,
    /// Indicates that the STUN agent has received an invalid STUN packet
    FingerPrintValidationFailed,
    /// Indicates that the STUN agent has ignored the operation
    Ignored,
    /// Indicates that the STUN agent has reached the maximum number of outstanding requests
    MaxOutstandingRequestsReached,
    /// Indicates that the STUN agent has received an invalid STUN packet
    StunCheckFailed,
    /// Indicates that the STUN agent has detected an internal error, and the [`String`] contains the error message
    InternalError(String),
}

/// Describes the kind of integrity protection that can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// [`MessageInttegrity`](stun_rs::attributes::stun::MessageIntegrity) protection
    MessageIntegrity,
    /// [`MessageIntegritySha256`](stun_rs::attributes::stun::MessageIntegritySha256) protection
    MessageIntegritySha256,
}

/// Describes the kind of credential mechanism that can be used by the STUN agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMechanism {
    /// [Short-term credential mechanism](https://datatracker.ietf.org/doc/html/rfc8489#section-9.1)
    /// with the specified [`Integrity`] in case the agent knows from an external mechanism
    /// which message integrity algorithm is supported by both agents.
    ShortTerm(Option<Integrity>),
    /// [Long-term credential mechanism](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2)
    LongTerm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StunPacketInternal {
    buffer: Vec<u8>,
    size: usize,
}

/// A chunk of bytes that represents a STUN packet that can be cloned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunPacket(Arc<StunPacketInternal>);

impl StunPacket {
    /// Creates a STUN packet from a vector which is filled up to `size` bytes.
    pub(crate) fn new(buffer: Vec<u8>, size: usize) -> Self {
        let internal = StunPacketInternal { buffer, size };
        StunPacket(Arc::new(internal))
    }
}

impl Deref for StunPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.buffer[..self.0.size]
    }
}

impl AsRef<[u8]> for StunPacket {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[derive(Debug)]
struct ProtectedAttributeIteratorObject<'a> {
    iter: Iter<'a, StunAttribute>,
    integrity: bool,
    integrity_sha256: bool,
    fingerprint: bool,
}

trait ProtectedAttributeIterator<'a> {
    fn protected_iter(&self) -> ProtectedAttributeIteratorObject<'a>;
}

impl<'a> ProtectedAttributeIterator<'a> for &'a [StunAttribute] {
    fn protected_iter(&self) -> ProtectedAttributeIteratorObject<'a> {
        ProtectedAttributeIteratorObject {
            iter: self.iter(),
            integrity: false,
            integrity_sha256: false,
            fingerprint: false,
        }
    }
}

impl<'a> Iterator for ProtectedAttributeIteratorObject<'a> {
    type Item = &'a StunAttribute;

    fn next(&mut self) -> Option<Self::Item> {
        for attr in &mut self.iter {
            if attr.is_message_integrity() {
                if self.integrity || self.integrity_sha256 || self.fingerprint {
                    continue;
                }
                self.integrity = true;
            } else if attr.is_message_integrity_sha256() {
                if self.integrity_sha256 || self.fingerprint {
                    continue;
                }
                self.integrity_sha256 = true;
            } else if attr.is_fingerprint() {
                if self.fingerprint {
                    continue;
                }
                self.fingerprint = true;
            } else if self.integrity || self.integrity_sha256 || self.fingerprint {
                continue;
            }
            return Some(attr);
        }
        None
    }
}

#[cfg(test)]
mod tests_stun_packet {
    use super::*;

    #[test]
    fn test_stun_packet() {
        let buffer = vec![0; 10];
        assert_eq!(buffer.len(), 10);

        // Create a stun packet that is only filled up to 5 bytes.
        let packet = StunPacket::new(buffer, 5);
        assert_eq!(packet.as_ref().len(), 5);

        let buffer = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let packet = StunPacket::new(buffer, 5);
        assert_eq!(packet.len(), 5);
        assert_eq!(packet.as_ref(), &[0, 1, 2, 3, 4]);
    }
}

#[cfg(test)]
mod tests_protected_iterator {
    use super::*;
    use stun_rs::{
        attributes::stun::{
            Fingerprint, MessageIntegrity, MessageIntegritySha256, Nonce, Realm, UserName,
        },
        methods::BINDING,
        Algorithm, AlgorithmId, HMACKey, MessageClass, StunMessageBuilder,
    };

    const USERNAME: &str = "test-username";
    const NONCE: &str = "test-nonce";
    const REALM: &str = "test-realm";
    const PASSWORD: &str = "test-password";

    #[test]
    fn test_protected_iterator() {
        let username = UserName::new(USERNAME).expect("Failed to create username");
        let nonce = Nonce::new(NONCE).expect("Failed to create nonce");
        let realm = Realm::new(REALM).expect("Failed to create realm");
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm)
            .expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(username)
            .with_attribute(nonce)
            .with_attribute(realm)
            .with_attribute(integrity)
            .with_attribute(integrity_sha256)
            .with_attribute(Fingerprint::default())
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());

        let attr = iter.next().expect("Expected attribute Nonce");
        assert!(attr.is_nonce());

        let attr = iter.next().expect("Expected attribute Realm");
        assert!(attr.is_realm());

        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());

        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());

        let attr = iter.next().expect("Expected attribute FingerPrint");
        assert!(attr.is_fingerprint());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_protected_iterator_only_message_integrity() {
        let username = UserName::new(USERNAME).expect("Failed to create username");
        let nonce = Nonce::new(NONCE).expect("Failed to create nonce");
        let realm = Realm::new(REALM).expect("Failed to create realm");
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm)
            .expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(integrity)
            .with_attribute(username)
            .with_attribute(nonce)
            .with_attribute(realm)
            .with_attribute(integrity_sha256)
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());

        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_protected_iterator_skip_non_protected() {
        let username = UserName::new(USERNAME).expect("Failed to create username");
        let nonce = Nonce::new(NONCE).expect("Failed to create nonce");
        let realm = Realm::new(REALM).expect("Failed to create realm");
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm)
            .expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(username)
            .with_attribute(integrity)
            .with_attribute(nonce)
            .with_attribute(integrity_sha256)
            .with_attribute(realm)
            .with_attribute(Fingerprint::default())
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());

        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());

        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());

        let attr = iter.next().expect("Expected attribute FingerPrint");
        assert!(attr.is_fingerprint());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_protected_iterator_skip_message_integrity() {
        let username = UserName::new(USERNAME).expect("Failed to create username");
        let nonce = Nonce::new(NONCE).expect("Failed to create nonce");
        let realm = Realm::new(REALM).expect("Failed to create realm");
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm)
            .expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(username)
            .with_attribute(integrity_sha256)
            .with_attribute(nonce)
            .with_attribute(integrity)
            .with_attribute(realm)
            .with_attribute(Fingerprint::default())
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());

        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());

        // MessageIntegrity can not go after MessageIntegritySha256, so it must be skipped
        let attr = iter.next().expect("Expected attribute FingerPrint");
        assert!(attr.is_fingerprint());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_protected_iterator_skip_message_integrity_sha256() {
        let username = UserName::new(USERNAME).expect("Failed to create username");
        let nonce = Nonce::new(NONCE).expect("Failed to create nonce");
        let realm = Realm::new(REALM).expect("Failed to create realm");
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm)
            .expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(username)
            .with_attribute(Fingerprint::default())
            .with_attribute(nonce)
            .with_attribute(integrity_sha256)
            .with_attribute(integrity)
            .with_attribute(realm)
            .with_attribute(Fingerprint::default())
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());

        let attr = iter.next().expect("Expected attribute FingerPrint");
        assert!(attr.is_fingerprint());

        // All attributes after FingerPrint must be skipped
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_protected_iterator_skip_duplicated_integrity_attrs() {
        let username = UserName::new(USERNAME).expect("Failed to create username");
        let realm = Realm::new(REALM).expect("Failed to create realm");
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term(&username, realm, PASSWORD, algorithm)
            .expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(username)
            .with_attribute(integrity.clone())
            .with_attribute(integrity)
            .with_attribute(integrity_sha256.clone())
            .with_attribute(integrity_sha256)
            .with_attribute(Fingerprint::default())
            .with_attribute(Fingerprint::default())
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());

        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());

        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());

        let attr = iter.next().expect("Expected attribute FingerPrint");
        assert!(attr.is_fingerprint());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_protected_iterator_skip_corner_cases() {
        let username = UserName::new(USERNAME).expect("Failed to create username");

        let key = HMACKey::new_short_term("test-password").expect("Failed to create HMACKey");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key);

        let msg = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(integrity.clone())
            .with_attribute(integrity.clone())
            .with_attribute(integrity_sha256.clone())
            .with_attribute(integrity.clone())
            .with_attribute(integrity_sha256.clone())
            .with_attribute(Fingerprint::default())
            .with_attribute(integrity)
            .with_attribute(integrity_sha256)
            .with_attribute(Fingerprint::default())
            .with_attribute(username)
            .build();

        let mut iter = msg.attributes().protected_iter();
        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());
        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());
        let attr = iter.next().expect("Expected attribute FingerPrint");
        assert!(attr.is_fingerprint());

        assert!(iter.next().is_none());
    }
}
