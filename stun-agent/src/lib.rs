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

use stun_rs::MessageHeader;
use stun_rs::StunAttribute;
use stun_rs::MESSAGE_HEADER_SIZE;

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
pub use crate::events::StunClientEvent;
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

/// A STUN packet decoder that can be used to decode a STUN packet.
/// The [`StunPacketDecoder`] is helpful when reading bytes from a stream oriented connection,
/// such as a `TCP` stream, or even when reading bytes from a datagram oriented connection, such as
/// a `UDP` socket when the STUN packet is fragmented.
///```rust
/// # use stun_agent::StunPacketDecoder;
///
/// //let buffer = vec![0; 1024];
/// //let mut decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");
///```
#[derive(Debug)]
pub struct StunPacketDecoder {
    buffer: Vec<u8>,
    current_size: usize,
    expected_size: Option<usize>,
}

/// Describes the possible outcomes of the STUN packet decoding.
/// - If the STUN packet has been fully decoded, the method returns the decoded STUN packet
///   and the number of bytes consumed.
/// - If the STUN packet has not been fully decoded, the method returns the decoder and the
///   number of bytes still needed to complete the STUN packet, if known.
#[derive(Debug)]
pub enum StunPacketDecodedValue {
    /// Returns the decoded STUN packet and the number of bytes consumed from the input.
    Decoded((StunPacket, usize)),
    /// Returns the decoder and the number of bytes missing to complete the STUN packet if known.
    MoreBytesNeeded((StunPacketDecoder, Option<usize>)),
}

/// Describe the error type that can occur during the STUN packet decoding.
#[derive(Debug)]
pub enum StunPacketErrorType {
    /// The buffer is too small to hold the STUN packet.
    SmallBuffer,
    /// The buffer does not contain a valid STUN header.
    InvalidStunPacket,
}

/// Describes the error that can occur during the STUN packet decoding.
#[derive(Debug)]
pub struct StunPacketDecodedError {
    /// The type of error that occurred during the STUN packet decoding.
    pub error_type: StunPacketErrorType,
    /// The internal buffer filled with bytes.
    pub buffer: Vec<u8>,
    /// The size of the buffer that has been filled.
    pub size: usize,
    /// The number of bytes consumed from the input data.
    pub consumed: usize,
}

impl StunPacketDecoder {
    /// Creates a new STUN packet decoder using the provided buffer. The buffer must be
    /// at least 20 bytes long to accommodate the STUN message header. If the buffer is
    /// too small, an error is returned.
    pub fn new(buffer: Vec<u8>) -> Result<Self, StunPacketDecodedError> {
        if buffer.len() < MESSAGE_HEADER_SIZE {
            return Err(StunPacketDecodedError {
                error_type: StunPacketErrorType::SmallBuffer,
                buffer,
                size: 0,
                consumed: 0,
            });
        }
        Ok(StunPacketDecoder {
            buffer,
            current_size: 0,
            expected_size: None,
        })
    }

    /// Decodes the given data and returns the decoded STUN packet. This method takes the data
    /// read so far as an argument and returns one of the following outcomes:
    /// - If the STUN packet has been fully decoded, the method returns the decoded STUN packet
    ///   and the number of bytes consumed.
    /// - If the STUN packet has not been fully decoded, the method returns the decoder and the
    ///   number of bytes still needed to complete the STUN packet, if known.
    /// - If the buffer is too small or the header does not correspond to a STUN message, the
    ///   method returns an error.
    ///   Note: This method does not perform a full validation of the STUN message; it only checks
    ///   the header. Integrity checks and other validations will be performed by the STUN agent.
    pub fn decode(mut self, data: &[u8]) -> Result<StunPacketDecodedValue, StunPacketDecodedError> {
        match self.expected_size {
            Some(size) => {
                // At this point we know that the buffer is big enough to hold the message,
                // so we do not need to check bounds.
                let first = self.current_size;
                let remaining = size - first;
                if data.len() >= remaining {
                    // Copy only up to the message length
                    self.buffer[first..size].copy_from_slice(&data[..remaining]);
                    let packet = StunPacket::new(self.buffer, size);
                    Ok(StunPacketDecodedValue::Decoded((packet, remaining)))
                } else {
                    // Copy all the data
                    self.buffer[first..first + data.len()].copy_from_slice(&data[..data.len()]);
                    self.current_size += data.len();
                    Ok(StunPacketDecodedValue::MoreBytesNeeded((
                        self,
                        Some(remaining - data.len()),
                    )))
                }
            }
            None => {
                let header_length = self.current_size + data.len();
                if header_length >= MESSAGE_HEADER_SIZE {
                    let first = self.current_size;
                    let remaining = MESSAGE_HEADER_SIZE - first;

                    // Write the STUN message header
                    self.buffer[first..first + remaining].copy_from_slice(&data[..remaining]);

                    // We can decode the header now
                    let slice: &[u8; MESSAGE_HEADER_SIZE] =
                        self.buffer[..MESSAGE_HEADER_SIZE].try_into().unwrap();
                    let Ok(header) = MessageHeader::try_from(slice) else {
                        return Err(StunPacketDecodedError {
                            error_type: StunPacketErrorType::InvalidStunPacket,
                            buffer: self.buffer,
                            size: MESSAGE_HEADER_SIZE,
                            consumed: remaining,
                        });
                    };
                    let msg_length = header.msg_length as usize;

                    // Check if the buffer provided is big enough to hold the message
                    if self.buffer.len() < msg_length + MESSAGE_HEADER_SIZE {
                        return Err(StunPacketDecodedError {
                            error_type: StunPacketErrorType::SmallBuffer,
                            buffer: self.buffer,
                            size: MESSAGE_HEADER_SIZE,
                            consumed: remaining,
                        });
                    }

                    self.expected_size = Some(msg_length + MESSAGE_HEADER_SIZE);

                    if data.len() >= msg_length + remaining {
                        // Copy only up to the message length
                        self.buffer[MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + msg_length]
                            .copy_from_slice(&data[remaining..remaining + msg_length]);
                        let packet = StunPacket::new(self.buffer, msg_length + MESSAGE_HEADER_SIZE);
                        Ok(StunPacketDecodedValue::Decoded((
                            packet,
                            remaining + msg_length,
                        )))
                    } else {
                        // Copy all the remaining data
                        self.buffer
                            [MESSAGE_HEADER_SIZE..MESSAGE_HEADER_SIZE + data.len() - remaining]
                            .copy_from_slice(&data[remaining..data.len()]);
                        self.current_size += data.len();
                        let remaining = msg_length + MESSAGE_HEADER_SIZE - self.current_size;
                        Ok(StunPacketDecodedValue::MoreBytesNeeded((
                            self,
                            Some(remaining),
                        )))
                    }
                } else {
                    // The number of bytes is less than the header size, so we can safety copy all
                    // the data because the minimum size of the byte is 20 bytes.
                    let first = self.current_size;
                    let remaining = data.len();
                    self.buffer[first..first + remaining].copy_from_slice(&data[..remaining]);
                    self.current_size += data.len();

                    // We still don't know the message length
                    Ok(StunPacketDecodedValue::MoreBytesNeeded((self, None)))
                }
            }
        }
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

#[cfg(test)]
mod test_stun_packet_decoder {
    use super::*;
    use stun_vectors::SAMPLE_IPV4_RESPONSE;

    #[test]
    fn test_stun_packet_decoder_small_parts() {
        let buffer = vec![0; 1024];
        let decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");

        let mut index = 0;
        let data = &SAMPLE_IPV4_RESPONSE[index..10];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, remaining)) = decoded else {
            panic!("Expected more bytes needed");
        };
        // Message header is not processed, so we have no information about remaining bytes
        assert_eq!(remaining, None);
        assert_eq!(decoder.current_size, 10);
        assert!(decoder.expected_size.is_none());

        index = 10;
        let data = &SAMPLE_IPV4_RESPONSE[index..15];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, remaining)) = decoded else {
            panic!("Expected more bytes needed");
        };
        // Message header is not processed, so we have no information about remaining bytes
        assert_eq!(remaining, None);
        assert_eq!(decoder.current_size, 15);
        assert!(decoder.expected_size.is_none());
        assert_eq!(decoder.buffer[..15], SAMPLE_IPV4_RESPONSE[..15]);

        index = 15;
        let data = &SAMPLE_IPV4_RESPONSE[index..index + 5];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, remaining)) = decoded else {
            panic!("Expected more bytes needed");
        };
        // Header is processed and the msg length is 60 (0x3C)
        assert_eq!(remaining, Some(60));
        assert_eq!(decoder.current_size, 20);
        assert_eq!(decoder.expected_size, Some(60 + MESSAGE_HEADER_SIZE));
        assert_eq!(decoder.buffer[..20], SAMPLE_IPV4_RESPONSE[..20]);

        index = 20;
        let data = &SAMPLE_IPV4_RESPONSE[index..index + 30];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, remaining)) = decoded else {
            panic!("Expected more bytes needed");
        };
        assert_eq!(remaining, Some(30));
        assert_eq!(decoder.current_size, 50);
        assert_eq!(decoder.buffer[..50], SAMPLE_IPV4_RESPONSE[..50]);

        index = 50;
        let data = &SAMPLE_IPV4_RESPONSE[index..index + 29];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, remaining)) = decoded else {
            panic!("Expected more bytes needed");
        };
        assert_eq!(remaining, Some(1));
        assert_eq!(decoder.current_size, 79);
        assert_eq!(decoder.buffer[..79], SAMPLE_IPV4_RESPONSE[..79]);

        // Complete the byte remaining to complete the STUN packet
        index = 79;
        let data = &SAMPLE_IPV4_RESPONSE[index..index + 1];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::Decoded((packet, consumed)) = decoded else {
            panic!("Stun packed not decoded");
        };
        assert_eq!(consumed, 1);
        assert_eq!(&SAMPLE_IPV4_RESPONSE, packet.as_ref());
    }

    #[test]
    fn test_stun_packet_decoder_one_step() {
        let buffer = vec![0; 1024];
        let decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");

        // Read the buffer in one go
        let decoded = decoder
            .decode(&SAMPLE_IPV4_RESPONSE)
            .expect("Failed to decode");
        let StunPacketDecodedValue::Decoded((packet, consumed)) = decoded else {
            panic!("Stun packed not decoded");
        };
        assert_eq!(consumed, SAMPLE_IPV4_RESPONSE.len());
        assert_eq!(&SAMPLE_IPV4_RESPONSE, packet.as_ref());
    }

    #[test]
    fn test_stun_packet_decoder_two_step() {
        let buffer = vec![0; 1024];
        let decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");

        let data = &SAMPLE_IPV4_RESPONSE[..15];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, remaining)) = decoded else {
            panic!("Expected more bytes needed");
        };
        // Message header is not processed, so we have no information about remaining bytes
        assert_eq!(remaining, None);
        assert_eq!(decoder.current_size, 15);
        assert!(decoder.expected_size.is_none());

        // Read the rest of the packet
        let data = &SAMPLE_IPV4_RESPONSE[15..];
        let decoded = decoder.decode(data).expect("Failed to decode");
        let StunPacketDecodedValue::Decoded((packet, consumed)) = decoded else {
            panic!("Stun packed not decoded");
        };
        assert_eq!(consumed, data.len());
        assert_eq!(&SAMPLE_IPV4_RESPONSE, packet.as_ref());
    }

    #[test]
    fn test_stun_packet_decoder_byte_by_byte() {
        let buffer = vec![0; 1024];
        let mut decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");

        let total = SAMPLE_IPV4_RESPONSE.len();
        for index in 0..total {
            let data = &SAMPLE_IPV4_RESPONSE[index..index + 1];
            let decoded = decoder.decode(data).expect("Failed to decode");
            if index < total - 1 {
                let StunPacketDecodedValue::MoreBytesNeeded((deco, remaining)) = decoded else {
                    panic!("Expected more bytes needed");
                };
                if index >= MESSAGE_HEADER_SIZE - 1 {
                    assert_eq!(remaining, Some(total - 1 - index));
                } else {
                    assert_eq!(remaining, None);
                }
                decoder = deco;
            } else {
                let StunPacketDecodedValue::Decoded((packet, consumed)) = decoded else {
                    panic!("Stun packed not decoded");
                };
                assert_eq!(consumed, 1);
                assert_eq!(&SAMPLE_IPV4_RESPONSE, packet.as_ref());
                break;
            }
        }
    }

    #[test]
    fn test_stun_packet_decoder_small_buffer() {
        let buffer = vec![0; 10];
        let error = StunPacketDecoder::new(buffer).expect_err("Expected small buffer error");
        let StunPacketErrorType::SmallBuffer = error.error_type else {
            panic!("Expected small buffer error");
        };

        let buffer = vec![0; 50];
        let decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");

        let result = decoder
            .decode(&SAMPLE_IPV4_RESPONSE[..10])
            .expect("Failed to decode");
        // We could not read the whole header, so it won't fail
        let StunPacketDecodedValue::MoreBytesNeeded((decoder, None)) = result else {
            panic!("Expected more bytes needed");
        };

        let error = decoder
            .decode(&SAMPLE_IPV4_RESPONSE[10..])
            .expect_err("Expected error");
        // The header is read and the buffer is too small to hold the whole message
        let StunPacketErrorType::SmallBuffer = error.error_type else {
            panic!("Expected small buffer error");
        };

        // Test the same scenario but trying to decode the buffer in one go
        let buffer = vec![0; 50];
        let decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");
        let error = decoder
            .decode(&SAMPLE_IPV4_RESPONSE)
            .expect_err("Expected error");
        let StunPacketErrorType::SmallBuffer = error.error_type else {
            panic!("Expected small buffer error");
        };
    }

    #[test]
    fn test_stun_packet_decoder_invalid_stun_packet() {
        let buffer = vec![0; 1024];
        let decoder = StunPacketDecoder::new(buffer).expect("Failed to create decoder");

        let data = vec![0; 1024];
        let error = decoder.decode(&data).expect_err("Expected error");
        let StunPacketErrorType::InvalidStunPacket = error.error_type else {
            panic!("Expected invalid STUN packet error");
        };
    }
}
