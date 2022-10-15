use crate::common::{check_buffer_boundaries, sha256};
use crate::error::{StunError, StunErrorType};
use crate::strings::opaque_string_enforce;
use crate::{Algorithm, AlgorithmId, Encode};
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::ops::Deref;
use std::rc::Rc;

/// STUN magic cookie
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub(crate) const MAGIC_COOKIE_SIZE: usize = 4;
pub(crate) const TRANSACTION_ID_SIZE: usize = 12;

/// The transaction ID is a 96-bit identifier, used to uniquely identify
/// STUN transactions. It primarily serves to correlate requests with
/// responses, though it also plays a small role in helping to prevent
/// certain types of attacks. The server also uses the transaction ID as
/// a key to identify each transaction uniquely across all clients.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionId([u8; TRANSACTION_ID_SIZE]);
impl TransactionId {
    /// Returns a reference to the bytes that represents the identifier.
    pub fn as_bytes(&self) -> &[u8; TRANSACTION_ID_SIZE] {
        &self.0
    }
}

impl fmt::Debug for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TransactionId(0x")?;
        for b in self.as_ref() {
            write!(f, "{:02X}", b)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl Deref for TransactionId {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<&[u8; TRANSACTION_ID_SIZE]> for TransactionId {
    fn from(buff: &[u8; TRANSACTION_ID_SIZE]) -> Self {
        Self(*buff)
    }
}

impl From<[u8; TRANSACTION_ID_SIZE]> for TransactionId {
    fn from(buff: [u8; TRANSACTION_ID_SIZE]) -> Self {
        Self(buff)
    }
}

impl Distribution<TransactionId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TransactionId {
        let mut buffer = [0u8; TRANSACTION_ID_SIZE];
        rng.fill_bytes(&mut buffer);
        TransactionId::from(buffer)
    }
}

impl Default for TransactionId {
    /// Creates a cryptographically random transaction ID chosen from the interval 0 .. 2**96-1.
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        rng.gen()
    }
}

/// Authentication and message-integrity mechanisms.
/// The STUN [`RFC8489`](https://datatracker.ietf.org/doc/html/rfc8489)
/// defines two mechanisms for STUN that a client and server
/// can use to provide authentication and message integrity; these two
/// mechanisms are known as the short-term credential mechanism and the
/// long-term credential mechanism.  These two mechanisms are optional,
/// and each usage must specify if and when these mechanisms are used.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum CredentialMechanism {
    /// [short-term credential mechanism](https://datatracker.ietf.org/doc/html/rfc8489#section-9.1)
    ShortTerm,
    /// [long-term credential mechanism](https://datatracker.ietf.org/doc/html/rfc8489#section-9.2)
    LongTerm,
}

impl CredentialMechanism {
    /// Returns true if this is a short-term-credential mechanism
    pub fn is_short_term(&self) -> bool {
        matches!(self, CredentialMechanism::ShortTerm)
    }

    /// Returns true if this is a long-term-credential mechanism
    pub fn is_long_term(&self) -> bool {
        matches!(self, CredentialMechanism::LongTerm)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct HMACKeyPriv {
    mechanism: CredentialMechanism,
    key: Vec<u8>,
}

/// Key used for authentication and message integrity
///
/// # Examples:
///```rust
/// # use stun_rs::{Algorithm, AlgorithmId, CredentialMechanism, HMACKey};
/// # use std::error::Error;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// // Creates a new long term credential key using MD5 algorithm
/// let algorithm = Algorithm::from(AlgorithmId::MD5);
/// let key = HMACKey::new_long_term("user", "realm", "pass", algorithm)?;
/// assert_eq!(key.credential_mechanism(), CredentialMechanism::LongTerm);
///
/// let expected_hash = [
///     0x84, 0x93, 0xFB, 0xC5, 0x3B, 0xA5, 0x82, 0xFB,
///     0x4C, 0x04, 0x4C, 0x45, 0x6B, 0xDC, 0x40, 0xEB,
/// ];
/// assert_eq!(key.as_bytes(), expected_hash);
/// #
/// #   Ok(())
/// # }
///```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HMACKey(Rc<HMACKeyPriv>);

impl HMACKey {
    /// Creates a [`CredentialMechanism::ShortTerm`] key
    /// # Returns
    /// The new [`HMACKey`] used for short term credential mechanism, or a `StunError` if
    /// the password can not be processed using the opaque string profile.
    pub fn new_short_term<S>(password: S) -> Result<Self, StunError>
    where
        S: AsRef<str>,
    {
        let key = opaque_string_enforce(password.as_ref())?
            .as_ref()
            .as_bytes()
            .to_vec();
        let mechanism = CredentialMechanism::ShortTerm;
        Ok(HMACKey(Rc::new(HMACKeyPriv { mechanism, key })))
    }

    /// Creates a [`CredentialMechanism::LongTerm`] key.
    /// # Arguments:
    /// - `username` - The user name
    /// - `realm` - The realm.
    /// - `algorithm`- Optional value for the algorithm used to generate the key. If
    ///      algorithm is None, [`AlgorithmId::MD5`](crate::AlgorithmId::MD5) will be used.
    ///      The resulting key length is 16 bytes when `MD5` is used, or 32 bytes if
    ///      SHA-256 algorithm is used.
    /// # Returns
    /// The new [`HMACKey`] used for long term credential mechanism, or a `StunError` if
    /// `username`, `realm` or `password` can not be processed using the opaque string profile.
    pub fn new_long_term<A, B, C, T>(
        username: A,
        realm: B,
        password: C,
        algorithm: T,
    ) -> Result<Self, StunError>
    where
        A: AsRef<str>,
        B: AsRef<str>,
        C: AsRef<str>,
        T: AsRef<Algorithm>,
    {
        let realm = opaque_string_enforce(realm.as_ref())?;
        let password = opaque_string_enforce(password.as_ref())?;
        let key_str = format!("{}:{}:{}", username.as_ref(), realm, password);
        let key = HMACKey::get_key(&key_str, algorithm.as_ref())?;

        let mechanism = CredentialMechanism::LongTerm;
        Ok(HMACKey(Rc::new(HMACKeyPriv { mechanism, key })))
    }

    /// Gets the bytes representation of the key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.key
    }

    /// Gets the bytes representation of the key
    pub fn credential_mechanism(&self) -> CredentialMechanism {
        self.0.mechanism
    }

    fn get_key(key: &str, params: &Algorithm) -> Result<Vec<u8>, StunError> {
        match params.algorithm() {
            AlgorithmId::MD5 => {
                // Ignore the parameters argument (must be empty)
                let digest = md5::compute(key);
                Ok(digest.0.to_vec())
            }
            AlgorithmId::SHA256 => {
                // Ignore the parameters argument (must be empty)
                Ok(sha256(key))
            }
            _ => Err(StunError::new(
                StunErrorType::InvalidParam,
                format!("Invalid algorithm: {}", params.algorithm()),
            )),
        }
    }
}

const ADDRESS_FAMILY_SIZE: usize = 1;

/// Address family
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressFamily {
    /// IP version 4
    IPv4,
    /// IP version 6
    IPv6,
}

impl TryFrom<u8> for AddressFamily {
    type Error = StunError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddressFamily::IPv4),
            0x02 => Ok(AddressFamily::IPv6),
            _ => Err(StunError::new(
                StunErrorType::InvalidParam,
                format!("Invalid address family ({:#02x})", value),
            )),
        }
    }
}

impl<'a> crate::Decode<'a> for AddressFamily {
    fn decode(raw_value: &[u8]) -> Result<(Self, usize), StunError> {
        check_buffer_boundaries(raw_value, ADDRESS_FAMILY_SIZE)?;
        Ok((AddressFamily::try_from(raw_value[0])?, ADDRESS_FAMILY_SIZE))
    }
}

impl Encode for AddressFamily {
    fn encode(&self, raw_value: &mut [u8]) -> Result<usize, StunError> {
        check_buffer_boundaries(raw_value, ADDRESS_FAMILY_SIZE)?;
        raw_value[0] = match self {
            AddressFamily::IPv4 => 0x01,
            AddressFamily::IPv6 => 0x02,
        };
        Ok(ADDRESS_FAMILY_SIZE)
    }
}

const MIN_ERROR_CODE: u16 = 300;
const MAX_ERROR_CODE: u16 = 700;
const MAX_REASON_PHRASE_ENCODED_SIZE: usize = 509;
const MAX_REASON_PHRASE_DECODED_SIZE: usize = 763;

/// The `ErrorCode` contains a numeric error code value in the range of 300
/// to 699 plus a textual reason phrase encoded in UTF-8
/// [`RFC3629`](https://datatracker.ietf.org/doc/html/rfc3629); it is also
/// consistent in its code assignments and semantics with SIP
/// [`RFC3261`](https://datatracker.ietf.org/doc/html/rfc3261)
/// and HTTP [`RFC7231`](https://datatracker.ietf.org/doc/html/rfc7231).
/// The reason phrase is meant for diagnostic purposes and can be anything
/// appropriate for the error code.
/// Recommended reason phrases for the defined error codes are included
/// in the IANA registry for error codes.  The reason phrase MUST be a
/// UTF-8-encoded [`RFC3629`](https://datatracker.ietf.org/doc/html/rfc3629)
/// sequence of fewer than 128 characters (which can be as long as 509 bytes
/// when encoding them or 763 bytes when decoding them).
/// # Examples
///```rust
/// # use stun_rs::ErrorCode;
/// # use std::error::Error;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// let attr = ErrorCode::new(420, "Unknown Attribute")?;
/// assert_eq!(attr.class(), 4);
/// assert_eq!(attr.number(), 20);
/// assert_eq!(attr.error_code(), 420);
/// assert_eq!(attr.reason(), "Unknown Attribute");
/// #  Ok(())
/// # }
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorCode {
    error_code: u16,
    reason: String,
}

impl ErrorCode {
    /// Creates a new `ErrorCode` type.
    /// # Arguments:
    /// * `error_code` - The numeric error code.
    /// * `reason` - The reason phrase.
    /// # Return:
    /// The `ErrorCode` type or a [`StunError`] if the numeric
    /// error value is not in the range of 300 to 699.
    pub fn new(error_code: u16, reason: &str) -> Result<Self, StunError> {
        (MIN_ERROR_CODE..MAX_ERROR_CODE)
            .contains(&error_code)
            .then(|| Self {
                error_code,
                reason: String::from(reason),
            })
            .ok_or_else(|| {
                StunError::new(
                    StunErrorType::InvalidParam,
                    format!("Error code is not ({}..{})", MIN_ERROR_CODE, MAX_ERROR_CODE),
                )
            })
    }

    /// Returns the numeric error code value .
    pub fn error_code(&self) -> u16 {
        self.error_code
    }

    /// Returns the class of the error code (the hundreds digit).
    pub fn class(&self) -> u8 {
        ((self.error_code - self.number() as u16) / 100)
            .try_into()
            .unwrap()
    }

    /// Returns the binary encoding of the error code modulo 100.
    pub fn number(&self) -> u8 {
        (self.error_code % 100).try_into().unwrap()
    }

    /// Returns the reason phrase associated to this error.
    pub fn reason(&self) -> &str {
        self.reason.as_str()
    }
}

// ErrorCode format
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Reserved, should be 0         |Class|     Number    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Reason Phrase (variable)                                ..
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

impl<'a> crate::Decode<'a> for ErrorCode {
    fn decode(raw_value: &[u8]) -> Result<(Self, usize), StunError> {
        check_buffer_boundaries(raw_value, 4)?;

        let class = raw_value[2] & 0x07;
        if !(3..=6).contains(&class) {
            return Err(StunError::new(
                StunErrorType::InvalidParam,
                format!("Error class {} is not in the range (3..=6)", class),
            ));
        }

        let number = raw_value[3];
        if !(0..=99).contains(&number) {
            return Err(StunError::new(
                StunErrorType::InvalidParam,
                format!("Error number {} is not in the range (0..=99)", number),
            ));
        }

        let reason = std::str::from_utf8(&raw_value[4..])?;

        if reason.len() > MAX_REASON_PHRASE_DECODED_SIZE {
            return Err(StunError::new(
                StunErrorType::ValueTooLong,
                format!(
                    "Reason length ({}) > Max. decoded size ({})",
                    reason.len(),
                    MAX_REASON_PHRASE_DECODED_SIZE
                ),
            ));
        }

        let error_code = class as u16 * 100 + number as u16;
        Ok((ErrorCode::new(error_code, reason)?, raw_value.len()))
    }
}

impl Encode for ErrorCode {
    fn encode(&self, raw_value: &mut [u8]) -> Result<usize, StunError> {
        let mut len = 4; // (Reserved + class + number)
        let reason_len = self.reason.len();

        if reason_len > MAX_REASON_PHRASE_ENCODED_SIZE {
            return Err(StunError::new(
                StunErrorType::ValueTooLong,
                format!(
                    "Reason length ({}) > Max. encoded size ({})",
                    reason_len, MAX_REASON_PHRASE_ENCODED_SIZE
                ),
            ));
        }

        len += reason_len;

        check_buffer_boundaries(raw_value, len)?;

        raw_value[0] = 0;
        raw_value[1] = 0;
        raw_value[2] = self.class();
        raw_value[3] = self.number();
        raw_value[4..reason_len + 4].clone_from_slice(self.reason.as_bytes());
        Ok(len)
    }
}

#[cfg(test)]
mod error_code_tests {
    use super::*;
    use crate::Decode;

    #[test]
    fn constructor() {
        assert!(ErrorCode::new(299, "Invalid code").is_err());
        assert!(ErrorCode::new(300, "Try alternate").is_ok());
        assert!(ErrorCode::new(699, "Test error").is_ok());
        assert!(ErrorCode::new(700, "Invalid code").is_err());
    }

    #[test]
    fn check_properties() {
        let result = ErrorCode::new(300, "Try alternate");
        assert!(result.is_ok());
        let error_code = result.unwrap();
        assert_eq!(error_code.number(), 0);
        assert_eq!(error_code.class(), 3);

        let result = ErrorCode::new(512, "Try alternate");
        assert!(result.is_ok());
        let error_code = result.unwrap();
        assert_eq!(error_code.number(), 12);
        assert_eq!(error_code.class(), 5);

        let result = ErrorCode::new(699, "Try alternate");
        assert!(result.is_ok());
        let error_code = result.unwrap();
        assert_eq!(error_code.number(), 99);
        assert_eq!(error_code.class(), 6);
    }

    #[test]
    fn decode_error_code() {
        let buffer = [
            0xda, 0xa5, 0xfb, 0x12, 0x74, 0x65, 0x73, 0x74, 0x20, 0x72, 0x65, 0x61, 0x73, 0x6f,
            0x6e,
        ];
        let (error_code, size) = ErrorCode::decode(&buffer).expect("Can not decode ErrorCode");
        assert_eq!(size, 15);
        assert_eq!(error_code.error_code(), 318);
        assert_eq!(error_code.class(), 3);
        assert_eq!(error_code.number(), 18);
        assert_eq!(error_code.reason(), "test reason");

        let buffer = [0x00, 0x00, 0x03, 0x12];
        let (error_code, size) = ErrorCode::decode(&buffer).expect("Can not decode ERROR-CODE");
        assert_eq!(size, 4);
        assert_eq!(error_code.error_code(), 318);
        assert_eq!(error_code.class(), 3);
        assert_eq!(error_code.number(), 18);
        assert!(error_code.reason().is_empty());

        // short buffer
        let buffer = [0x00, 0x00, 0x03];
        let result = ErrorCode::decode(&buffer);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::SmallBuffer
        );

        // Wrong class: 2
        let buffer = [
            0x00, 0x00, 0x02, 0x12, 0x74, 0x65, 0x73, 0x74, 0x20, 0x72, 0x65, 0x61, 0x73, 0x6f,
            0x6e,
        ];
        let result = ErrorCode::decode(&buffer);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::InvalidParam
        );

        // Wrong number: 112
        let buffer = [
            0x00, 0x00, 0x03, 0x70, 0x74, 0x65, 0x73, 0x74, 0x20, 0x72, 0x65, 0x61, 0x73, 0x6f,
            0x6e,
        ];
        let result = ErrorCode::decode(&buffer);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::InvalidParam
        );

        // Test MAX_REASON_PHRASE_DECODED_SIZE
        const EXTRA_BYTES: usize = 4; //(Reserved + class + number)
        let mut buffer: [u8; MAX_REASON_PHRASE_DECODED_SIZE + EXTRA_BYTES] =
            [0x0; MAX_REASON_PHRASE_DECODED_SIZE + EXTRA_BYTES];
        buffer[..EXTRA_BYTES].clone_from_slice(&[0x00, 0x00, 0x03, 0x12]);
        buffer[EXTRA_BYTES..]
            .clone_from_slice("\u{0041}".repeat(MAX_REASON_PHRASE_DECODED_SIZE).as_bytes());
        let (error_code, size) = ErrorCode::decode(&buffer).expect("Can not decode ErrorCode");
        assert_eq!(size, MAX_REASON_PHRASE_DECODED_SIZE + EXTRA_BYTES);
        assert_eq!(error_code.error_code(), 318);
        assert_eq!(error_code.class(), 3);
        assert_eq!(error_code.number(), 18);
        assert_eq!(
            error_code.reason(),
            "\u{0041}".repeat(MAX_REASON_PHRASE_DECODED_SIZE)
        );

        // Test with reason phrase longer than MAX_REASON_PHRASE_DECODED_SIZE
        const REASON_SIZE: usize = MAX_REASON_PHRASE_DECODED_SIZE + 1;
        let mut buffer: [u8; REASON_SIZE + EXTRA_BYTES] = [0x0; REASON_SIZE + EXTRA_BYTES];
        buffer[..EXTRA_BYTES].clone_from_slice(&[0x00, 0x00, 0x03, 0x12]);
        buffer[EXTRA_BYTES..].clone_from_slice("\u{0041}".repeat(REASON_SIZE).as_bytes());
        let result = ErrorCode::decode(&buffer);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::ValueTooLong
        );
    }

    #[test]
    fn encode_error_code() {
        let error_code = ErrorCode::new(318, "test reason").expect("Can not encode ErroCode");

        let mut buffer: [u8; 14] = [0x0; 14];
        let result = error_code.encode(&mut buffer);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::SmallBuffer
        );

        let mut buffer: [u8; 15] = [0x0; 15];
        let result = error_code.encode(&mut buffer);
        assert_eq!(result, Ok(15));

        let cmp_buffer = [
            0x00, 0x00, 0x03, 0x12, 0x74, 0x65, 0x73, 0x74, 0x20, 0x72, 0x65, 0x61, 0x73, 0x6f,
            0x6e,
        ];
        assert_eq!(&buffer[..], &cmp_buffer[..]);

        // Test MAX_REASON_PHRASE_ENCODED_SIZE
        const EXTRA_BYTES: usize = 4; //(Reserved + class + number)
        let error_code = ErrorCode::new(318, "x".repeat(MAX_REASON_PHRASE_ENCODED_SIZE).as_str())
            .expect("Can not encode ErroCode");
        let mut buffer: [u8; MAX_REASON_PHRASE_ENCODED_SIZE + EXTRA_BYTES] =
            [0x0; MAX_REASON_PHRASE_ENCODED_SIZE + EXTRA_BYTES];
        let result = error_code.encode(&mut buffer);
        assert_eq!(result, Ok(MAX_REASON_PHRASE_ENCODED_SIZE + EXTRA_BYTES));

        // Test with reason phrase longer than MAX_REASON_PHRASE_ENCODED_SIZE
        const REASON_SIZE: usize = MAX_REASON_PHRASE_ENCODED_SIZE + 1;
        let error_code = ErrorCode::new(318, "\u{0041}".repeat(REASON_SIZE).as_str())
            .expect("Can not encode ErroCode");
        let mut buffer: [u8; REASON_SIZE + EXTRA_BYTES] = [0x0; REASON_SIZE + EXTRA_BYTES];
        let result = error_code.encode(&mut buffer);
        assert_eq!(
            result.expect_err("Error expected"),
            StunErrorType::ValueTooLong
        );
    }
}

#[cfg(test)]
mod transaction_id_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn constructor() {
        let tr1 = TransactionId::default();
        let tr2 = TransactionId::default();
        assert_ne!(tr1, tr2);

        let tr3 = TransactionId::from(tr1.as_bytes());
        assert_eq!(tr1, tr3);

        // Check deref
        let slice: &[u8] = &tr3;
        assert_eq!(slice, tr3.as_bytes());
    }

    #[test]
    fn check_random() {
        let mut transactions = HashSet::new();

        while transactions.len() < 1000 {
            let tr = TransactionId::default();
            assert!(!transactions.contains(&tr));
            transactions.insert(tr);
        }
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn short_term_credential() {
        let key = HMACKey::new_short_term("foo\u{1680}bar").expect("Could not create HMACKey");

        // `OGHAM` SPACE MARK (U+1680) is mapped to SPACE (U+0020)
        // thus, the full string is mapped to <foo bar>
        assert_eq!(key.credential_mechanism(), CredentialMechanism::ShortTerm);

        let expected = "foo bar".as_bytes();
        assert_eq!(key.as_bytes(), expected);
    }

    #[test]
    fn long_term_credential() {
        // Example taken from RFC5389 15.4
        let algorithm = Algorithm::from(AlgorithmId::MD5);
        let key = HMACKey::new_long_term("user", "realm", "pass", algorithm)
            .expect("Could not create HMACKey");

        assert_eq!(key.credential_mechanism(), CredentialMechanism::LongTerm);

        let md5_hash = [
            0x84, 0x93, 0xFB, 0xC5, 0x3B, 0xA5, 0x82, 0xFB, 0x4C, 0x04, 0x4C, 0x45, 0x6B, 0xDC,
            0x40, 0xEB,
        ];
        assert_eq!(key.as_bytes(), md5_hash);
        assert_eq!(key.as_bytes().len(), 16);

        let algorithm = Algorithm::from(AlgorithmId::SHA256);
        let key = HMACKey::new_long_term("user", "realm", "pass", algorithm)
            .expect("Could not create HMACKey");

        let sha256_hash = [
            0x07, 0xE9, 0x34, 0x11, 0x7A, 0xBD, 0x40, 0x83, 0x6E, 0x7C, 0x63, 0x29, 0xB5, 0x47,
            0x31, 0xB2, 0xB2, 0xD2, 0xA5, 0xF9, 0xA7, 0x1F, 0x54, 0x49, 0x22, 0xD7, 0x5E, 0x07,
            0x30, 0xD8, 0x25, 0x1B,
        ];
        assert_eq!(key.credential_mechanism(), CredentialMechanism::LongTerm);
        assert_eq!(key.as_bytes(), sha256_hash);
        assert_eq!(key.as_bytes().len(), 32);
    }
}
