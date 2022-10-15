//! Assigned Internet Protocol Numbers.
//! This module contains the protocol numbers specified in
//! [PROTOCOL-NUMBERS](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).

use crate::common::check_buffer_boundaries;
use crate::{Encode, StunError};

const PROTOCOL_NUMBER_SIZE: usize = 1;

/// The protocol number class represents a protocol defined in
/// [PROTOCOL-NUMBERS](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml).
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub struct ProtocolNumber(u8);

impl ProtocolNumber {
    // Creates a new ProtocolNumber from an unsigned `u8`
    pub(crate) fn new(value: u8) -> Self {
        Self(value)
    }
    /// Returns the `ProtocolNumber` as an `u8`
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// `UDP` protocol number
pub const UDP: ProtocolNumber = ProtocolNumber(17u8);

impl Encode for ProtocolNumber {
    fn encode(&self, raw_value: &mut [u8]) -> Result<usize, StunError> {
        check_buffer_boundaries(raw_value, PROTOCOL_NUMBER_SIZE)?;
        raw_value[0] = self.0;
        Ok(PROTOCOL_NUMBER_SIZE)
    }
}

impl<'a> crate::Decode<'a> for ProtocolNumber {
    fn decode(raw_value: &'a [u8]) -> Result<(Self, usize), StunError> {
        check_buffer_boundaries(raw_value, PROTOCOL_NUMBER_SIZE)?;
        Ok((ProtocolNumber(raw_value[0]), PROTOCOL_NUMBER_SIZE))
    }
}
