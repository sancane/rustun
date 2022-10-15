/// [STUN Password Algorithms](https://datatracker.ietf.org/doc/html/rfc8489#section-18.5)
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AlgorithmId {
    /// Reserved
    Reserved,
    /// The `MD5` (message-digest algorithm) hashing algorithm is a one-way cryptographic function that accepts a message of any length as input and returns as output a fixed-length digest value to be used for authenticating the original message.
    MD5,
    /// `SHA256` is a part of the `SHA` 2 family of algorithms. It stands for Secure Hash Algorithm 256-bit and it is used for cryptographic security.
    SHA256,
    /// Unassigned
    Unassigned(u16),
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            AlgorithmId::Reserved => write!(f, "reserved"),
            AlgorithmId::MD5 => write!(f, "md5"),
            AlgorithmId::SHA256 => write!(f, "sha256"),
            AlgorithmId::Unassigned(val) => write!(f, "unassigned({})", val),
        }
    }
}

impl From<u16> for AlgorithmId {
    fn from(val: u16) -> Self {
        match val {
            0 => AlgorithmId::Reserved,
            1 => AlgorithmId::MD5,
            2 => AlgorithmId::SHA256,
            _ => AlgorithmId::Unassigned(val),
        }
    }
}

impl From<AlgorithmId> for u16 {
    fn from(val: AlgorithmId) -> Self {
        match val {
            AlgorithmId::Reserved => 0,
            AlgorithmId::MD5 => 1,
            AlgorithmId::SHA256 => 2,
            AlgorithmId::Unassigned(val) => val,
        }
    }
}

/// An algorithm is the combination of the [`AlgorithmId`] and its parameters.
#[derive(Debug, PartialEq, Eq)]
pub struct Algorithm {
    algorithm: AlgorithmId,
    params: Option<Vec<u8>>,
}
impl AsRef<Algorithm> for Algorithm {
    fn as_ref(&self) -> &Algorithm {
        self
    }
}

impl Algorithm {
    /// Creates a new algorithm with parameters.
    /// # Attributes:
    /// * `algorithm` - The [Algorithm].
    /// * `parameters` - Specific parameters for the algorithm, if any.
    pub fn new<'a, T>(algorithm: AlgorithmId, parameters: T) -> Self
    where
        T: Into<Option<&'a [u8]>>,
    {
        Self {
            algorithm,
            params: parameters.into().map(Vec::from),
        }
    }

    /// Returns the algorithm
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// Returns the parameters required by the algorithm.
    pub fn parameters(&self) -> Option<&[u8]> {
        match self.params.as_ref() {
            Some(buf) => Some(buf.as_slice()),
            None => None,
        }
    }
}

impl From<AlgorithmId> for Algorithm {
    fn from(algorithm: AlgorithmId) -> Self {
        Self {
            algorithm,
            params: None,
        }
    }
}
