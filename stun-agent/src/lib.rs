use bytes::Bytes;
use log::debug;
use stun_rs::error::{StunDecodeError, StunEncodeError};
use stun_rs::{MessageHeader, MESSAGE_HEADER_SIZE};

pub mod client;
pub mod events;
pub mod message;

mod fingerprint;
mod short_term_auth;
mod timeout;

#[derive(Debug)]
pub enum StunAgentError {
    DecodeError(StunDecodeError),
    Discarded,
    EncodeError(StunEncodeError),
    FingerPrintValidationFailed,
    ProtectionViolated,
    StunCheckFailed,
    InternalError(String),
}

pub(crate) fn validate_stunt_header(buffer: &Bytes) -> Result<(), StunAgentError> {
    if buffer.len() < MESSAGE_HEADER_SIZE {
        debug!("Buffer is too small to contain a STUN message header.");
        return Err(StunAgentError::StunCheckFailed);
    }

    let val = <&[u8; MESSAGE_HEADER_SIZE]>::try_from(buffer.as_ref()).map_err(|_| {
        debug!("Failed to convert buffer to STUN message header.");
        StunAgentError::StunCheckFailed
    })?;

    let header = MessageHeader::try_from(val).map_err(|_| {
        debug!("Failed to crate STUN message header.");
        StunAgentError::StunCheckFailed
    })?;

    if header.bits & 0xC0 != 0 {
        debug!("First two bits in the header are not 0.");
        return Err(StunAgentError::StunCheckFailed);
    }

    if header.cookie != stun_rs::MAGIC_COOKIE {
        debug!("Cookie in the header is not the STUN magic cookie.");
        return Err(StunAgentError::StunCheckFailed);
    }

    Ok(())
}
