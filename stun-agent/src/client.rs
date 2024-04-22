use crate::events::{StunTransactionError, StuntEvent};
use crate::fingerprint::{add_fingerprint_attribute, validate_fingerprint};
use crate::message::{create_stun_message, StunAttributes};
use crate::short_term_auth::{Integrity, ShortTermAuthClient};
use crate::timeout::{StunMessageTimeout, TimeoutManager};
use crate::{validate_stunt_header, StunAgentError};
use bytes::{Bytes, BytesMut};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use stun_rs::attributes::stun::UserName;
use stun_rs::error::StunEncodeError;
use stun_rs::{
    HMACKey, MessageClass, MessageDecoder, MessageEncoder, MessageMethod, StunError, StunMessage,
    TransactionId,
};

#[derive(Debug)]
struct StunClientParameters {
    user_name: UserName,
    key: HMACKey,
    integrity: Option<Integrity>,
    fingerprint: bool,
    reliable: bool,
}

#[derive(Debug)]
pub struct StunClienteBuilder(StunClientParameters);

impl StunClienteBuilder {
    pub fn new<U, P>(user_name: U, password: P) -> Result<StunClienteBuilder, StunError>
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        Ok(Self(StunClientParameters {
            user_name: UserName::new(user_name.as_ref())?,
            key: HMACKey::new_short_term(password.as_ref())?,
            integrity: None,
            fingerprint: false,
            reliable: false,
        }))
    }

    pub fn with_integrity(mut self, integrity: Integrity) -> Self {
        self.0.integrity = Some(integrity);
        self
    }

    pub fn use_fingerprint(mut self) -> Self {
        self.0.fingerprint = true;
        self
    }

    pub fn reliable(mut self) -> Self {
        self.0.reliable = true;
        self
    }

    pub fn build(self) -> StunClient {
        StunClient::new(self.0)
    }
}

pub struct StunClient {
    auth: ShortTermAuthClient,
    encoder: MessageEncoder,
    decoder: MessageDecoder,
    use_fingerprint: bool,
    timeouts: StunMessageTimeout,
    rtos: HashMap<TransactionId, TimeoutManager>,
    transactions: HashMap<TransactionId, Bytes>,
    events: Vec<StuntEvent>,
}

impl StunClient {
    fn new(params: StunClientParameters) -> Self {
        Self {
            auth: ShortTermAuthClient::new(
                params.user_name,
                params.key,
                params.integrity,
                params.reliable,
            ),
            encoder: Default::default(),
            decoder: Default::default(),
            use_fingerprint: params.fingerprint,
            timeouts: StunMessageTimeout::default(),
            rtos: Default::default(),
            transactions: Default::default(),
            events: Vec::new(),
        }
    }

    fn prepare_request_or_indication(&mut self, attributes: &mut StunAttributes) {
        self.auth.add_attributes(attributes);
        if self.use_fingerprint {
            add_fingerprint_attribute(attributes);
        }
    }

    fn set_timout(
        &mut self,
        transaction_id: TransactionId,
        instant: Instant,
    ) -> Result<(), StunAgentError> {
        let mut rto_manager = TimeoutManager::default();
        let timeout = rto_manager.next_rto(instant).ok_or_else(|| {
            StunAgentError::InternalError(String::from("Can not calculate next RTO"))
        })?;
        self.timeouts.add(instant, timeout, transaction_id);
        self.rtos.insert(transaction_id, rto_manager);
        debug!("set timeout {:?} for {:?}", timeout, transaction_id);
        Ok(())
    }

    fn add_timeout_event(&mut self, instant: Instant) {
        if let Some((id, left)) = self.timeouts.next_timeout(instant) {
            self.events
                .push(StuntEvent::RestransmissionTimeOut((id, left)));
        }
    }

    fn encode_buffer(&mut self, msg: &StunMessage) -> Result<Bytes, StunEncodeError> {
        let mut buffer = BytesMut::zeroed(1024);
        self.encoder.encode(buffer.as_mut(), msg)?;
        Ok(buffer.freeze())
    }

    fn transaction_finished(&mut self, transaction_id: &TransactionId) {
        self.timeouts.remove(transaction_id);
        self.rtos.remove(transaction_id);
        self.transactions.remove(transaction_id);
    }

    fn manage_retransmission(
        &mut self,
        transaction_id: TransactionId,
        instant: Instant,
        timeout: Duration,
    ) {
        let Some(buffer) = self.transactions.get(&transaction_id) else {
            debug!("Transaction {:?} not found", transaction_id);
            self.events.push(StuntEvent::TransactionFailed((
                transaction_id,
                StunTransactionError::NotFound,
            )));
            return;
        };

        self.timeouts.add(instant, timeout, transaction_id);
        debug!(
            "set timeout {:?} for transaction {:?}",
            timeout, transaction_id
        );
        self.events.push(StuntEvent::OutputBuffer(buffer.clone()));
    }

    pub fn create_request(
        &mut self,
        method: MessageMethod,
        mut attributes: StunAttributes,
        instant: Instant,
    ) -> Result<TransactionId, StunAgentError> {
        self.prepare_request_or_indication(&mut attributes);
        let msg = create_stun_message(method, MessageClass::Request, None, attributes);
        let buffer = self.encode_buffer(&msg)?;

        self.set_timout(*msg.transaction_id(), instant)?;
        self.transactions
            .insert(*msg.transaction_id(), buffer.clone());

        self.events.clear();
        self.events.push(StuntEvent::OutputBuffer(buffer));
        self.add_timeout_event(instant);

        Ok(*msg.transaction_id())
    }

    pub fn create_indication(
        &mut self,
        method: MessageMethod,
        mut attributes: StunAttributes,
    ) -> Result<TransactionId, StunAgentError> {
        self.prepare_request_or_indication(&mut attributes);
        let msg = create_stun_message(method, MessageClass::Indication, None, attributes);
        let buffer = self.encode_buffer(&msg)?;

        self.events.clear();
        self.events.push(StuntEvent::OutputBuffer(buffer));

        Ok(*msg.transaction_id())
    }

    pub fn on_buffer_recv(&mut self, buffer: Bytes) -> Result<(), StunAgentError> {
        validate_stunt_header(&buffer)?;
        let (msg, size) = self.decoder.decode(&buffer)?;

        if msg.class() == MessageClass::Request {
            debug!("Stun client received a request message. Discarding.");
            return Err(StunAgentError::Discarded);
        }

        if msg.class() != MessageClass::Indication
            && self.transactions.get(msg.transaction_id()).is_none()
        {
            debug!(
                "Received response with no matching transaction ID {}. Discarding.",
                msg.transaction_id()
            );
            return Err(StunAgentError::Discarded);
        }

        let raw_data = buffer.slice(0..size);
        if self.use_fingerprint && !validate_fingerprint(&raw_data, &msg) {
            return Err(StunAgentError::FingerPrintValidationFailed);
        }

        self.auth.recv_message(&raw_data, &msg)?;
        self.transaction_finished(msg.transaction_id());

        self.events.clear();
        self.events.push(StuntEvent::TransactionFinished(msg));

        Ok(())
    }

    pub fn on_timeout(&mut self, instant: Instant) {
        let timed_out = self.timeouts.check(instant);
        self.events.clear();

        for transaction_id in timed_out {
            if let Some(rto_manager) = self.rtos.get_mut(&transaction_id) {
                match rto_manager.next_rto(instant) {
                    Some(rto) => {
                        self.manage_retransmission(transaction_id, instant, rto);
                    }
                    None => {
                        let event = if self
                            .auth
                            .signal_protection_violated_on_timeout(&transaction_id)
                        {
                            StuntEvent::TransactionFailed((
                                transaction_id,
                                StunTransactionError::ProtectionViolated,
                            ))
                        } else {
                            StuntEvent::TransactionFailed((
                                transaction_id,
                                StunTransactionError::TimedOut,
                            ))
                        };
                        info!(
                            "Transaction {:?} timed out. Event: {:?}",
                            transaction_id, event
                        );
                        self.events.push(event);
                    }
                }
            } else {
                warn!("No rto manager set for transaction {}", transaction_id);
            }
        }

        // Add the most recent timout event if any
        self.add_timeout_event(instant);
    }

    pub fn events(&mut self) -> Vec<StuntEvent> {
        self.events.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_logging() {
        info!("Simple logging test");
    }

    #[test]
    fn test_logging_features() {
        env_logger::init();

        test_logging();
    }
}
