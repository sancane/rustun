use bytes::Bytes;
use std::time::Duration;
use stun_rs::{StunMessage, TransactionId};

#[derive(Debug)]
pub enum StuntEvent {
    OutputBuffer(Bytes),
    RestransmissionTimeOut((TransactionId, Duration)),
    TransactionFailed((TransactionId, StunTransactionError)),
    TransactionFinished(StunMessage),
}

#[derive(Debug, Eq, PartialEq)]
pub enum StunTransactionError {
    TimedOut,
    ProtectionViolated,
    NotFound,
}
