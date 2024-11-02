use crate::StunPacket;
use log::warn;
use std::collections::VecDeque;
use std::time::Duration;
use stun_rs::{StunMessage, TransactionId};

/// Stun client events
#[derive(Debug)]
pub enum StuntClientEvent {
    /// Notification used by the STUN client to send a STUN packet to the server
    OutputPacket(StunPacket),
    /// This event sets a timeout for a transaction identified by the [`TransactionId`].
    /// Once the timeout is reached, the client must call the [`on_timeout`](`crate::StunClient::on_timeout`) method on
    /// the [`StunClient`](`crate::StunClient`) instance.
    /// If multiple timeouts are scheduled for different outgoing transactions,
    /// the client will only be notified about the most recent timeout.
    RestransmissionTimeOut((TransactionId, Duration)),
    /// Notification used to retry a transaction identified by the [`TransactionId`].
    Retry(TransactionId),
    /// Event used by the STUN client to notify that a transaction identified by the [`TransactionId`]
    /// has failed. The [`StunTransactionError`] indicates the reason of the failure.
    TransactionFailed((TransactionId, StunTransactionError)),
    /// Event used by the STUN client to notify that a STUN message has been received.
    StunMessageReceived(StunMessage),
}

/// Errors that can be raised by the STUN client when a transaction fails.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StunTransactionError {
    /// The transaction has been canceled by the client.
    DoNotRetry,
    /// [`Fingerprint`](stun_rs::attributes::stun::Fingerprint) validation failed.
    InvalidFingerprint,
    /// Outgoing transaction not found.
    NotFound,
    /// The transaction has been canceled due to an integrity validation failure.
    ProtectionViolated,
    /// The transaction has timed out.
    TimedOut,
}

#[derive(Debug, Default)]
pub struct TransactionEventHandler {
    events: VecDeque<StuntClientEvent>,
}

impl TransactionEventHandler {
    pub fn init(&mut self) -> TransactionEvents {
        TransactionEvents {
            handler: self,
            events: VecDeque::new(),
        }
    }

    pub fn events(&mut self) -> VecDeque<StuntClientEvent> {
        std::mem::take(&mut self.events)
    }
}

#[derive(Debug)]
pub struct TransactionEvents<'a> {
    handler: &'a mut TransactionEventHandler,
    events: VecDeque<StuntClientEvent>,
}

impl TransactionEvents<'_> {
    pub fn push(&mut self, event: StuntClientEvent) {
        self.events.push_back(event);
    }
}

impl Drop for TransactionEvents<'_> {
    fn drop(&mut self) {
        if self.events.is_empty() {
            // No events to commit
            return;
        }

        std::mem::swap(&mut self.handler.events, &mut self.events);

        if !self.events.is_empty() {
            warn!(
                "Transaction events were committed without consuming {} the events.",
                self.events.len()
            );
        }
    }
}

#[cfg(test)]
mod stun_event_tests {
    use stun_rs::TransactionId;

    use super::*;

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_transaction_events_drop() {
        init_logging();

        let mut handler = TransactionEventHandler::default();

        let events = handler.events();
        assert!(events.is_empty());

        {
            let mut events = handler.init();

            events.push(StuntClientEvent::Retry(TransactionId::default()));
            events.push(StuntClientEvent::Retry(TransactionId::default()));
        }

        // Drop the events must commit the events
        let events = handler.events();
        assert_eq!(events.len(), 2);

        // No more events to consum
        let events = handler.events();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_transaction_events_drop_no_events() {
        init_logging();

        let mut handler = TransactionEventHandler::default();
        {
            let mut _events = handler.init();
        }

        let events = handler.events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_transaction_events_drop_no_commit() {
        init_logging();

        let mut handler = TransactionEventHandler::default();
        {
            let mut events = handler.init();
            events.push(StuntClientEvent::Retry(TransactionId::default()));
        }

        {
            // Init another transaction when there must be one event
            // that was not consumed previously, that event will be dropped
            let mut events = handler.init();
            events.push(StuntClientEvent::Retry(TransactionId::default()));
            events.push(StuntClientEvent::Retry(TransactionId::default()));
            events.push(StuntClientEvent::Retry(TransactionId::default()));
        }

        // There must be only three events
        let events = handler.events();
        assert_eq!(events.len(), 3);
    }
}
