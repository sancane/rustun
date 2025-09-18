use crate::events::{StunClientEvent, StunTransactionError, TransactionEventHandler};
use crate::fingerprint::{add_fingerprint_attribute, validate_fingerprint};
use crate::integrity::IntegrityError;
use crate::lt_cred_mech::LongTermCredentialClient;
use crate::message::{create_stun_message, StunAttributes};
use crate::rtt::{RttCalcuator, DEFAULT_GRANULARITY};
use crate::st_cred_mech::ShortTermCredentialClient;
use crate::timeout::{RtoManager, StunMessageTimeout, DEFAULT_RC, DEFAULT_RM, DEFAULT_RTO};
use crate::{CredentialMechanism, StunAgentError, StunPacket};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use stun_rs::attributes::stun::UserName;
use stun_rs::error::StunEncodeError;
use stun_rs::{
    HMACKey, MessageClass, MessageDecoder, MessageEncoder, MessageMethod, StunMessage,
    TransactionId,
};

// Maximum number of outstanding transactions to the same server
pub const DEFAULT_MAX_TRANSACTIONS: usize = 10;

/// Description of the transport reliability, for STUN protocol
/// communication. It can be reliable or unreliable depending on
/// whether this is a `UDP` or `TCP` connection.
#[derive(Debug)]
pub enum TransportReliability {
    /// Reliable transport, such as `TCP`, where [`Duration`] represents the maximum
    /// time to wait for a response.
    Reliable(Duration),
    /// Unreliable transport, such as `UDP`, where the [`RttConfig`] contains the
    /// parameters to calculate the re-transmission timeout.
    Unreliable(RttConfig),
}

/// When using unreliable transport, such as `UDP`, the re-transmission timeout
/// is calculated using the following parameters.
/// The `RTO` is an estimate of the round-trip time (`RTT`) and is computed as described
/// in [`RFC6298`](`https://datatracker.ietf.org/doc/html/rfc6298`), with two exceptions.
/// First, the initial value for `RTO` SHOULD be greater than or equal to 500 ms.
/// Second, the value of `RTO` SHOULD NOT be rounded up to the nearest second. Rather,
/// a 1 ms accuracy SHOULD be maintained.
#[derive(Debug)]
pub struct RttConfig {
    /// Initial re-transmission timeout. Default is 500 ms.
    pub rto: Duration,
    /// The clock granularity to use for the `RTT` calculation. Default is 1 ms.
    pub granularity: Duration,
    /// The last re-transmission multiplier. Default is 16.
    pub rm: u32,
    /// Re-transmission counter. Default is 7.
    pub rc: u32,
}

impl Default for RttConfig {
    fn default() -> Self {
        Self {
            rto: DEFAULT_RTO,
            granularity: DEFAULT_GRANULARITY,
            rm: DEFAULT_RM,
            rc: DEFAULT_RC,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StunClientMessageClass {
    Request,
    Indication,
}

#[derive(Debug)]
struct StunClientParameters {
    user_name: Option<String>,
    password: Option<String>,
    mechanism: Option<CredentialMechanism>,
    reliability: TransportReliability,
    fingerprint: bool,
    max_transactions: usize,
}

/// Builder for the STUN client. It allows to configure the client
/// with the required parameters for the STUN usage.
/// ```rust
/// # use stun_agent::{CredentialMechanism, RttConfig, StunAgentError, StunClienteBuilder, TransportReliability};
/// # fn main() -> Result<(), StunAgentError> {
/// // Next example shows how to create a STUN client that uses
/// // long-term credentials to authenticate with the server over
/// // an unreliable transport and mandates the use of the FINGERPRINT
/// // attribute.
/// let client = StunClienteBuilder::new(
///     TransportReliability::Unreliable(RttConfig::default()))
///         .with_mechanism("user", "password", CredentialMechanism::LongTerm)
///         .with_fingerprint()
///         .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct StunClienteBuilder(StunClientParameters);

impl StunClienteBuilder {
    /// Creates a new STUN client builder with the given [`TransportReliability`].
    pub fn new(reliability: TransportReliability) -> StunClienteBuilder {
        Self(StunClientParameters {
            user_name: None,
            password: None,
            mechanism: None,
            reliability,
            fingerprint: false,
            max_transactions: DEFAULT_MAX_TRANSACTIONS,
        })
    }

    /// Sets the maximum number of outstanding transactions to the same server.
    /// The default value is 10.
    pub fn with_max_transactions(mut self, max_transactions: usize) -> Self {
        self.0.max_transactions = max_transactions;
        self
    }

    /// Sets the credentials for the STUN client.
    pub fn with_mechanism<U, P>(
        mut self,
        user_name: U,
        password: P,
        mechanism: CredentialMechanism,
    ) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        self.0.user_name = Some(user_name.into());
        self.0.password = Some(password.into());
        self.0.mechanism = Some(mechanism);
        self
    }

    /// Sets the use of the FINGERPRINT attribute in the STUN messages. The
    /// FINGERPRINT mechanism is not backwards compatible with
    /// [`RFC3489`](https://datatracker.ietf.org/doc/html/rfc3489) and
    /// cannot be used in environments where such compatibility is required.
    pub fn with_fingerprint(mut self) -> Self {
        self.0.fingerprint = true;
        self
    }

    /// Builds the STUN client with the given parameters.
    pub fn build(self) -> Result<StunClient, StunAgentError> {
        StunClient::new(self.0)
    }
}

#[derive(Debug)]
enum CredentialMechanismClient {
    ShortTerm(ShortTermCredentialClient),
    LongTerm(LongTermCredentialClient),
}

impl CredentialMechanismClient {
    fn prepare_request(&mut self, attributes: &mut StunAttributes) -> Result<(), StunAgentError> {
        match self {
            CredentialMechanismClient::ShortTerm(mechanism) => {
                mechanism.add_attributes(attributes);
                Ok(())
            }
            CredentialMechanismClient::LongTerm(mechanism) => mechanism.prepare_request(attributes),
        }
    }

    fn prepare_indication(
        &mut self,
        attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        match self {
            CredentialMechanismClient::ShortTerm(mechanism) => {
                mechanism.add_attributes(attributes);
                Ok(())
            }
            CredentialMechanismClient::LongTerm(mechanism) => {
                mechanism.prepare_indication(attributes)
            }
        }
    }

    fn recv_message(
        &mut self,
        raw_data: &[u8],
        message: &StunMessage,
    ) -> Result<(), IntegrityError> {
        match self {
            CredentialMechanismClient::ShortTerm(mechanism) => {
                mechanism.recv_message(raw_data, message)
            }
            CredentialMechanismClient::LongTerm(mechanism) => {
                mechanism.recv_message(raw_data, message)
            }
        }
    }

    fn signal_protection_violated_on_timeout(&mut self, transaction_id: &TransactionId) -> bool {
        match self {
            CredentialMechanismClient::ShortTerm(mechanism) => {
                mechanism.signal_protection_violated_on_timeout(transaction_id)
            }
            CredentialMechanismClient::LongTerm(mechanism) => {
                mechanism.signal_protection_violated_on_timeout(transaction_id)
            }
        }
    }
}

#[derive(Debug)]
struct StunTransaction {
    instant: Option<Instant>,
    packet: StunPacket,
    rtos: RtoManager,
}

#[derive(Debug)]
struct RttHandler {
    rtt: RttCalcuator,
    rm: u32,
    rc: u32,
    last_request: Option<Instant>,
}

#[derive(Debug)]
enum StunRttCalcuator {
    Reliable(Duration),
    Unreliable(RttHandler),
}

impl From<TransportReliability> for StunRttCalcuator {
    fn from(reliability: TransportReliability) -> Self {
        match reliability {
            TransportReliability::Reliable(timeout) => StunRttCalcuator::Reliable(timeout),
            TransportReliability::Unreliable(config) => StunRttCalcuator::Unreliable(RttHandler {
                rtt: RttCalcuator::new(config.rto, config.granularity),
                rm: config.rm,
                rc: config.rc,
                last_request: None,
            }),
        }
    }
}

/// A STUN client is an entity that sends STUN requests and receives STUN responses
/// and STUN indications. A STUN client can also send indications.
///
/// # [`StunClient`]
///
/// This is the main entity used to interact with the STUN server.
/// The [`StunClient`] provides the tools required to implement different
/// STUN [usages](https://datatracker.ietf.org/doc/html/rfc8489#section-13)
/// over the STUN protocol in an easy and efficient way.
///
/// # API considerations
///
/// Since the [`StunClient`] abstains from performing any I/O operations, the controller assumes
/// responsibility for managing input and output buffers, timeouts, and client-generated
/// events. The implementation of this controller is entirely at the user's discretion and
/// does not enforce the use of any specific I/O stack or asynchronous framework. This
/// abstraction imposes certain guidelines to ensure the protocol's proper functioning.
/// Consequently, users must consider the following technical aspects:
/// - The controller must capture and handle any events that the client may generate after
///   interacting with the library.
/// - The controller must handle the input and output buffers that the client will use to send and
///   receive data from the server.
/// - Timing management falls under the controller's jurisdiction, as the client lacks internal
///   time-handling mechanisms. The controller must define transaction timeouts and inform the client
///   upon their expiration. For supporting timed events, the API exposes an [`Instant`] parameter
///   to the controller, facilitating specification of event occurrence times.
///
/// # Design considerations
///
/// Most Sans I/O implementations are structured around a state machine that responds to events
/// generated by both the client and the server. Each event triggers the generation of output buffers,
/// timers, or additional events. This foundational concept is illustrated in the following API:
///
/// ```no_run
/// # use stun_agent::StunClientEvent;
/// # fn handle_data(in_bytes: &[u8]) -> Vec<StunClientEvent> { vec![] }
/// # fn perform_action() -> Vec<u8> { vec![] }
/// # let in_bytes = [];
/// let events = handle_data(&in_bytes);
/// let out_bytes = perform_action();
/// ```
///
/// However, the STUN requirements introduce complexity to the API. The aforementioned API alone
/// does not suffice to manage STUN intricacies. For instance, the `handle_data` function might fail
/// and trigger events even in case of failures. The STUN client needs to manage these events and
/// generate further events for the controller. This implementation could have been realized as follows:
///
/// ```no_run
/// # use stun_agent::StunClientEvent;
/// # use stun_agent::StunAgentError;
/// fn handle_data(in_bytes: &[u8])
///     -> Result<Vec<StunClientEvent>, (StunAgentError, Vec<StunClientEvent>)> {
///    // Implementation
/// #   Ok(vec![])
/// }
/// ```
///
/// The design of this API necessitates that the caller manages both errors and the events they generate.
/// This approach can lead to increased complexity and maintenance challenges in the caller's code.
/// For instance, the caller may employ a match expression when invoking the function to handle both
/// success outcomes and the errors and resulting events in case of failure:
///
/// ```no_run
/// # use stun_agent::StunClientEvent;
/// # use stun_agent::StunAgentError;
/// # fn handle_data(in_bytes: &[u8]) -> Result<Vec<StunClientEvent>, (StunAgentError, Vec<StunClientEvent>)> { Ok(vec![]) }
/// # fn handle_events(events: Vec<StunClientEvent>) {}
/// # fn handle_error(error: StunAgentError) {}
/// # let in_bytes = [];
/// let response = handle_data(&in_bytes);
/// match response {
///    Ok(events) => {
///       handle_events(events);
///   },
///   Err((error, events)) => {
///       handle_error(error);
///       handle_events(events);
///   },
/// }
/// ```
///
/// As observed, managing events in both success and failure scenarios indicates a sub-optimal design.
/// Consequently, the STUN client API is structured to enable the caller to pull [`events`](`Self::events`) generated by
/// the client. While this approach offers a more ergonomic event handling mechanism, it requires the
/// caller to actively retrieve and process events from the client.
///
/// ```no_run
/// # use stun_agent::StunAgentError;
/// # type ClientData = u8;
/// fn handle_data(in_bytes: &[u8]) -> Result<ClientData, StunAgentError> {
///   // Implementation
/// # Ok(ClientData::default())
/// }
/// ```
///
/// And the controller's code would look like this:
///
/// ```no_run
/// # use stun_agent::StunAgentError;
/// # type ClientData = u8;
/// # fn handle_data(in_bytes: &[u8]) -> Result<ClientData, StunAgentError> {Ok(ClientData::default())}
/// # fn pull_events() -> Vec<u8> { vec![] }
/// # fn main() -> Result<(), StunAgentError> {
/// # let in_bytes = [];
/// let data = handle_data(&in_bytes)?;
/// // Now we can pull events from the client
/// let events = pull_events();
/// # Ok(())
/// # }
/// ```
///
/// Moreover, this type of API not only facilitates the retrieval of events but also allows for the
/// retrieval of data generated by the client. For instance, the [`send_request`](`Self::send_request`)
/// method returns the [`TransactionId`] of the request, which the controller can use to manage outgoing
/// transactions.
///
/// <div class="warning">
///
/// Events are overwritten whenever a new operation is performed on the client. Therefore, the controller
/// must ensure that all events are processed before initiating any new operations. In multi-threaded
/// environments, the controller must also synchronize operations and event retrieval to maintain
/// consistency and prevent data loss.
///
/// </div>
///
/// ## Input and Output
///
/// The STUN client does not perform any I/O operations. Instead, the controller is responsible for
/// managing input and output buffers. Memory allocation is delegated to the controller, which must
/// provide the buffers used by the client. This approach reduces the client's memory footprint and
/// enhances performance by enabling more sophisticated memory management strategies, such as memory
/// pools, where buffers can be reused to minimize memory allocation overhead.
///
/// ## Timing Management
///
/// The STUN client does not manage timing internally. Instead, the controller is responsible for setting
/// timeouts and managing transaction timing. The API provides an [`Instant`] parameter to the controller,
/// allowing it to specify event occurrence times. Timing consistency across operations is crucial,
/// meaning that time must monotonically increase to ensure the proper functioning of the client.
///
/// Exposing the [`Instant`] parameter in the API might seem counter intuitive, as it requires the controller
/// to manage time. However, this design choice ensures that the client remains agnostic to time
/// management, granting the controller full control over the internal state machine. This approach
/// facilitates comprehensive testing of complex scenarios by enabling deterministic time control without
/// the need to mock time.
///
/// ## Timeouts
///
/// Timeouts specify the maximum duration the client will wait for an event to occur. The STUN client
/// uses timeouts to manage transactions and prevent indefinite waiting for responses. If a response
/// is not received within the designated timeout period, the client generates a timeout event, marking
/// the transaction as failed. Timeouts are also employed to manage re-transmissions of requests sent
/// over unreliable transports. When the client needs to set a timeout for a re-transmission, it generates
/// a [`RestransmissionTimeOut`](`crate::StunClientEvent::RestransmissionTimeOut`) event, which is then
/// notified to the controller when the events are pulled.
///
/// If multiple timeouts are scheduled, the client will only notify the controller of the most recent
/// timeout. This approach allows the controller to manage timeouts more efficiently, ensuring that
/// only one timeout needs to be handled at a time.
///
/// Managing timeouts is the responsibility of the controller; the STUN client will only provide the
/// timeout duration. If the timeout is not canceled, the controller must call the
/// [`on_timeout`](`crate::StunClient::on_timeout`) method to inform the client that the timeout
/// has been reached.
///
/// Timeouts are identified by a [`TransactionId`]. When a timeout is canceled for any reason, the
/// client will notify the controller either by setting a new timeout with a different [`TransactionId`]
/// or by not setting any timeout event at all.
///
/// # Usage
///
/// The following example demonstrates how to create a STUN client and send a
/// BINDING indication to a STUN server.
///
/// ```rust
/// # use stun_agent::{RttConfig, StunAttributes, StunClienteBuilder, StunClientEvent, TransportReliability};
/// # use stun_rs::methods::BINDING;
/// # use std::time::Instant;
///
/// // We use a client builder to create a STUN client, for this example,
/// // the client will be used over an unreliable transport such as UDP.
/// // This client will no use any credential mechanism nor the FINGERPRINT
/// // attributes. Besides, we configure the default parameters for the
/// // re-transmission timeout.
/// let mut client = StunClienteBuilder::new(
///     TransportReliability::Unreliable(RttConfig::default()))
///     .build()
///     .unwrap();
///
/// // We create a STUN BINDING indication to send to the server.
/// // According to the RFC8489, the BINDING indications does not require
/// // any attributes.
/// let mut attributes = StunAttributes::default();
///
/// // Since this is a library implementation without direct I/O operations,
/// // no input or output will be handled by the stack. Instead, we need to
/// // access the output buffer event provided by the client to send the data
/// // through the socket.
/// // Besides, no buffer allocations will be performed by the library, so the
/// // controller must provide the buffer that will be used to send the data.
/// // This allow the library to reduce the memory footprint and improve the
/// // performance, being flexible to allow more complex usages of memory such
/// // as memory pools where buffers can be reused to minimize the memory
/// // allocation overhead.
/// let buffer = vec![0; 1024];
/// client.send_indication(BINDING, attributes, buffer).unwrap();
///
/// // Pull events from the client
/// let events = client.events();
///
/// // Only one output packect event is expected. This event must contain the
/// // buffer that will be sent to the server. Because indications do not require
/// // a response, no timeouts will be set for this transaction.
/// assert_eq!(events.len(), 1);
/// let mut iter = events.iter();
///
/// // Next event already contains the buffer that needs to be send to the server.
/// let StunClientEvent::OutputPacket(buffer) = iter
///     .next()
///     .expect("Expected event")
/// else {
///     panic!("Expected OutputBuffer event");
/// };
/// ```
///
/// In the following example we are going to use the STUN client to send a BINDING request to a STUN server.
/// Requests require a response from the server, so the client will set a timeout for the transaction.
/// The response must arrive before the timeout is reached, otherwise the client will generate a timeout event
/// and will mark the transaction as failed.
/// ```rust
/// # use stun_agent::{RttConfig, StunAttributes, StunClienteBuilder, StunClientEvent, TransportReliability};
/// # use stun_rs::methods::BINDING;
/// # use std::time::Instant;
/// # let mut client = StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
/// #    .build().unwrap();
///
/// // We create a STUN BINDING request to send to the server.
/// // According to the RFC8489, the BINDING request does not require
/// // any attributes.
/// let instant = std::time::Instant::now();
/// let mut attributes = StunAttributes::default();
/// let buffer = vec![0; 1024];
/// let transaction_id = client
///     .send_request(BINDING, attributes, buffer, instant)
///     .unwrap();
///
/// // Pull events from the client
/// let events = client.events();
///
/// // Two events are expected, the first one is the output buffer event
/// // and the second one is the timeout event.
/// assert_eq!(events.len(), 2);
/// let mut iter = events.iter();
/// // Next event already contains the buffer that needs to be send to the server.
/// let StunClientEvent::OutputPacket(buffer) = iter
///     .next()
///     .expect("Expected event")
/// else {
///     panic!("Expected OutputBuffer event");
/// };
/// // Next event indicates that the user must set a timeout for the transaction
/// // identified by the transaction_id.
/// let StunClientEvent::RestransmissionTimeOut((id, duration)) = iter
///     .next()
///     .expect("Expected event")
/// else {
///     panic!("Expected RestransmissionTimeOut event");
/// };
/// assert_eq!(id, &transaction_id);
///
/// // Now the controller should set a timout of `duration` for the transaction
/// // identified by `id`. After the timeout is reached, the controller must call
/// // the `on_timeout` method to notify the client that the time has expired.
///
/// // We re going to simulate the timeout event by calling the `on_timeout` method.
/// let instant = instant + *duration;
/// client.on_timeout(instant);
///
/// // Pull events from the client
/// let events = client.events();
///
/// // Two events are expected, the first one is the retransmission of the requests,
/// // and the second one is the new timeout set for the transaction.
/// assert_eq!(events.len(), 2);
/// let mut iter = events.iter();
///
/// // Next event contains the buffer that needs to be retransmitted.
/// let StunClientEvent::OutputPacket(buffer) = iter
///     .next()
///     .expect("Expected event")
/// else {
///         panic!("Expected OutputBuffer event");
/// };
/// let StunClientEvent::RestransmissionTimeOut((id, duration)) = iter
///     .next()
///     .expect("Expected event")
/// else {
///    panic!("Expected RestransmissionTimeOut event");
/// };
/// assert_eq!(id, &transaction_id);
/// ```
///
/// When sending over an unreliable transport, the client SHOULD re-transmit a STUN request
/// message starting with an interval of `RTO` ("Re-transmission `TimeOut`"), doubling after
/// each re-transmission until a final timeout is reached. By default, if the controller does
/// not set a different value, the default timeout is 39500 ms for both, reliable and not
/// reliable transports. If the client has not received a response after that time, the client
/// will consider the transaction to have timed out, and an event of type
/// [`TransactionFailed`](crate::StunClientEvent::TransactionFailed) will be generated the
/// next time that events were pulled with the error
/// [`TimedOut`](crate::StunTransactionError::TimedOut) for the transaction.
///
/// To finish, the next example shows how to handle buffers received from the server. Raw buffers will
/// be processed by the client to generate events that can be pulled by the controller.
///```rust
/// # use stun_agent::{RttConfig, StunAttributes, StunClienteBuilder, StunClientEvent, TransportReliability};
/// # use stun_rs::methods::BINDING;
/// # use std::time::Instant;
/// # use stun_rs::MessageClass::Indication;
/// # let mut client = StunClienteBuilder::new(TransportReliability::Unreliable(RttConfig::default()))
/// #    .build().unwrap();
/// // Buffer received from the server
/// let buffer = [
///    0x00, 0x11, 0x00, 0x00, // BINDING Indication type and message length
///    0x21, 0x12, 0xA4, 0x42, // Magic cookie
///    0xB8, 0xC2, 0x8E, 0x1A, // }
///    0x41, 0x05, 0x18, 0x56, // }  Transaction ID
///    0x3E, 0xFC, 0xCF, 0x5D, // }
/// ];
///
/// // Process buffer
/// client.on_buffer_recv(&buffer, Instant::now()).unwrap();
///
/// // Pull events from the client
/// let events = client.events();
///
/// // There must be only one events with the STUN message received
/// assert_eq!(events.len(), 1);
///
/// let mut iter = events.iter();
/// let StunClientEvent::StunMessageReceived(msg) = iter
///     .next()
///     .expect("Expected event")
/// else {
///    panic!("Expected StunMessageReceived event");
/// };
/// assert_eq!(msg.method(), BINDING);
/// assert_eq!(msg.class(), Indication);
///
/// // No attributes in the message
/// assert_eq!(msg.attributes().len(), 0);
///```

#[derive(Debug)]
pub struct StunClient {
    mechanism: Option<CredentialMechanismClient>,
    encoder: MessageEncoder,
    decoder: MessageDecoder,
    use_fingerprint: bool,
    timeouts: StunMessageTimeout,
    rtt: StunRttCalcuator,
    transactions: HashMap<TransactionId, StunTransaction>,
    transaction_events: TransactionEventHandler,
    max_transactions: usize,
}

impl StunClient {
    fn new(params: StunClientParameters) -> Result<Self, StunAgentError> {
        let rtt = StunRttCalcuator::from(params.reliability);
        let is_reliable = matches!(rtt, StunRttCalcuator::Reliable(_));

        let mechanism = match params.mechanism {
            Some(value) => {
                let user_name = params.user_name.ok_or_else(|| {
                    StunAgentError::InternalError(String::from("User name is required"))
                })?;
                let password = params.password.ok_or_else(|| {
                    StunAgentError::InternalError(String::from("Password is required"))
                })?;
                let user_name = UserName::new(user_name).map_err(|e| {
                    StunAgentError::InternalError(format!("Failed to create user name: {}", e))
                })?;
                match value {
                    CredentialMechanism::ShortTerm(integrity) => Some(
                        CredentialMechanismClient::ShortTerm(ShortTermCredentialClient::new(
                            user_name,
                            HMACKey::new_short_term(password).map_err(|e| {
                                StunAgentError::InternalError(format!(
                                    "Failed to create HMAC key: {}",
                                    e
                                ))
                            })?,
                            integrity,
                            is_reliable,
                        )),
                    ),
                    CredentialMechanism::LongTerm => Some(CredentialMechanismClient::LongTerm(
                        LongTermCredentialClient::new(user_name, password, is_reliable),
                    )),
                }
            }
            None => None,
        };

        Ok(Self {
            mechanism,
            encoder: Default::default(),
            decoder: Default::default(),
            use_fingerprint: params.fingerprint,
            timeouts: StunMessageTimeout::default(),
            rtt,
            transactions: Default::default(),
            transaction_events: Default::default(),
            max_transactions: params.max_transactions,
        })
    }

    fn prepare_request(&mut self, attributes: &mut StunAttributes) -> Result<(), StunAgentError> {
        prepare_stun_message(
            StunClientMessageClass::Request,
            attributes,
            self.mechanism.as_mut(),
            self.use_fingerprint,
        )
    }

    fn prepare_indication(
        &mut self,
        attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        prepare_stun_message(
            StunClientMessageClass::Indication,
            attributes,
            self.mechanism.as_mut(),
            self.use_fingerprint,
        )
    }

    fn set_timeout(
        &mut self,
        transaction_id: TransactionId,
        instant: Instant,
    ) -> Result<RtoManager, StunAgentError> {
        let mut rto_manager = match self.rtt {
            StunRttCalcuator::Reliable(timeout) => RtoManager::new(timeout, 1, 1),
            StunRttCalcuator::Unreliable(ref mut handler) => {
                if let Some(last_request) = handler.last_request {
                    if instant - last_request > Duration::from_secs(600) {
                        debug!(
                            "Current RTT value {}ms staled caused by inactivity. Resetting.",
                            handler.rtt.rto().as_millis()
                        );
                        handler.rtt.reset();
                    }
                }
                handler.last_request = Some(instant);
                RtoManager::new(handler.rtt.rto(), handler.rm, handler.rc)
            }
        };

        let timeout = rto_manager.next_rto(instant).ok_or_else(|| {
            StunAgentError::InternalError(String::from("Can not calculate next RTO"))
        })?;
        self.timeouts.add(instant, timeout, transaction_id);
        debug!("[{:?}] Set timeout {:?}", transaction_id, timeout);
        Ok(rto_manager)
    }

    fn transaction_finished(&mut self, transaction_id: &TransactionId, instant: Instant) {
        self.timeouts.remove(transaction_id);
        let Some(transaction) = self.transactions.remove(transaction_id) else {
            debug!("[{:?}] Not found", transaction_id);
            return;
        };

        let Some(sent_instant) = transaction.instant else {
            // This means that there was a retransmission
            return;
        };
        if let StunRttCalcuator::Unreliable(handler) = &mut self.rtt {
            let new_rtt = instant - sent_instant;
            debug!(
                "[{:?}] RTT calculation: sent={:?}, recv={:?}, rtt={:?}",
                transaction_id, sent_instant, instant, new_rtt
            );
            handler.rtt.update(new_rtt);
        }
    }

    /// Creates a STUN request.
    ///
    /// # Arguments
    /// * `method` - The STUN [`MessageMethod`] to use.
    /// * `attributes` - The [`StunAttributes`] to include in the request.
    /// * `buffer` - The buffer to send with the request.
    /// * `instant` - The instant when the request is sent.
    /// # Returns
    /// The [`TransactionId`] of the request on success. Otherwise, a [`StunAgentError`] is returned.
    /// <div class="warning">
    ///
    /// After calling this method, the user should invoke [events](`Self::events`) to retrieve the events
    /// generated by the agent.
    ///
    /// </div>
    pub fn send_request(
        &mut self,
        method: MessageMethod,
        mut attributes: StunAttributes,
        buffer: Vec<u8>,
        instant: Instant,
    ) -> Result<TransactionId, StunAgentError> {
        if self.transactions.len() >= self.max_transactions {
            return Err(StunAgentError::MaxOutstandingRequestsReached);
        }

        self.prepare_request(&mut attributes)?;
        let msg = create_stun_message(method, MessageClass::Request, None, attributes);
        let packet = encode_buffer(&self.encoder, &msg, buffer).map_err(|e| {
            StunAgentError::InternalError(format!("Failed to encode request message: {}", e))
        })?;

        let transaction = StunTransaction {
            instant: Some(instant),
            packet: packet.clone(),
            rtos: self.set_timeout(*msg.transaction_id(), instant)?,
        };
        self.transactions.insert(*msg.transaction_id(), transaction);

        let mut events = self.transaction_events.init();
        events.push(StunClientEvent::OutputPacket(packet));

        // Add the most recent timout event if any
        if let Some((id, left)) = self.timeouts.next_timeout(instant) {
            events.push(StunClientEvent::RestransmissionTimeOut((id, left)));
        }

        Ok(*msg.transaction_id())
    }

    /// Creates a STUN indication.
    /// # Arguments
    /// * `method` - The STUN [`MessageMethod`] to use.
    /// * `attributes` - The [`StunAttributes`] to include in the indication.
    /// * `buffer` - The buffer to send with the indication.
    /// # Returns
    /// The [`TransactionId`] of the indication on success. Otherwise, a [`StunAgentError`] is returned.
    /// <div class="warning">
    ///
    /// After calling this method, the user should invoke [events](`Self::events`) to retrieve the events
    /// generated by the agent.
    ///
    /// </div>
    pub fn send_indication(
        &mut self,
        method: MessageMethod,
        mut attributes: StunAttributes,
        buffer: Vec<u8>,
    ) -> Result<TransactionId, StunAgentError> {
        self.prepare_indication(&mut attributes)?;
        let msg = create_stun_message(method, MessageClass::Indication, None, attributes);
        let packet = encode_buffer(&self.encoder, &msg, buffer).map_err(|e| {
            StunAgentError::InternalError(format!("Failed to encode indication message: {}", e))
        })?;

        let mut events = self.transaction_events.init();
        events.push(StunClientEvent::OutputPacket(packet));

        Ok(*msg.transaction_id())
    }

    /// Called when a buffer is received from the server.
    /// # Arguments
    /// * `buffer` - The buffer received from the server.
    /// * `instant` - The instant when the buffer was received.
    /// # Returns
    /// A [`StunAgentError`] if the buffer is invalid or the transaction is discarded.
    /// In the case when STUN is being    multiplexed with another protocol, an error
    /// may indicate that this is not really a STUN message; in this case, the agent
    /// should try to parse the message as a different protocol.
    /// <div class="warning">
    ///
    /// After calling this method, the user should invoke [events](`Self::events`) to retrieve the events
    /// generated by the agent.
    ///
    /// </div>
    pub fn on_buffer_recv(
        &mut self,
        buffer: &[u8],
        instant: Instant,
    ) -> Result<(), StunAgentError> {
        let (msg, _) = self.decoder.decode(buffer).map_err(|e| {
            StunAgentError::InternalError(format!("Failed to decode message: {}", e))
        })?;

        match msg.class() {
            MessageClass::Request => {
                // A STUN client can receive STUN responses and STUN indications.
                debug!(
                    "Received STUN request with {:?}. Discarding.",
                    msg.transaction_id()
                );
                return Err(StunAgentError::Discarded);
            }
            MessageClass::Indication => {
                debug!("Received STUN indication with {:?}", msg.transaction_id());
            }
            MessageClass::SuccessResponse | MessageClass::ErrorResponse => {
                // Check this is an outstanding transaction
                if !self.transactions.contains_key(msg.transaction_id()) {
                    debug!(
                        "Received response with no matching {:?}. Discarding.",
                        msg.transaction_id()
                    );
                    return Err(StunAgentError::Discarded);
                }
            }
        }

        // Validate fingerprint attribute
        if self.use_fingerprint && !validate_fingerprint(buffer, &msg)? {
            debug!(
                "[{:?}] Fingerprint validation failed. Discarding.",
                msg.transaction_id()
            );
            return Err(StunAgentError::Discarded);
        }

        // Validate message integrity
        let mut integrity_event = None;
        if let Some(mechanism) = &mut self.mechanism {
            if let Err(e) = mechanism.recv_message(buffer, &msg) {
                integrity_event = process_integrity_error(e, msg.transaction_id())?;
            }
        }

        if msg.class() != MessageClass::Indication {
            // finish outgoing transaction
            self.transaction_finished(msg.transaction_id(), instant);
        }

        let mut events = self.transaction_events.init();
        match integrity_event {
            Some(event) => {
                // notify the integrity issue
                events.push(event);
            }
            None => {
                // Notify the user about the received message
                events.push(StunClientEvent::StunMessageReceived(msg));
            }
        }

        Ok(())
    }

    /// Called when a timeout event occurs.
    /// # Arguments
    /// * `instant` - The instant when the timeout event occurred.
    /// <div class="warning">
    ///
    /// After calling this method, the user should invoke [events](`Self::events`) to retrieve the events
    /// generated by the agent.
    ///
    /// </div>
    pub fn on_timeout(&mut self, instant: Instant) {
        let timed_out = self.timeouts.check(instant);
        let mut events = self.transaction_events.init();

        for transaction_id in timed_out {
            if let Some(transaction) = self.transactions.get_mut(&transaction_id) {
                match transaction.rtos.next_rto(instant) {
                    Some(rto) => {
                        // Cancel rtt calculation on retransmission
                        transaction.instant = None;
                        self.timeouts.add(instant, rto, transaction_id);
                        debug!("set timeout {:?} for transaction {:?}", rto, transaction_id);
                        events.push(StunClientEvent::OutputPacket(transaction.packet.clone()));
                    }
                    None => {
                        let protection_violated = self.mechanism.as_mut().is_some_and(|m| {
                            m.signal_protection_violated_on_timeout(&transaction_id)
                        });
                        let event = if protection_violated {
                            StunClientEvent::TransactionFailed((
                                transaction_id,
                                StunTransactionError::ProtectionViolated,
                            ))
                        } else {
                            StunClientEvent::TransactionFailed((
                                transaction_id,
                                StunTransactionError::TimedOut,
                            ))
                        };
                        info!(
                            "Transaction {:?} timed out. Event: {:?}",
                            transaction_id, event
                        );
                        events.push(event);
                    }
                }
            } else {
                warn!("Transaction {:?} not found", transaction_id);
            }
        }

        // Add the most recent timout event if any
        if let Some((id, left)) = self.timeouts.next_timeout(instant) {
            events.push(StunClientEvent::RestransmissionTimeOut((id, left)));
        }
    }

    /// Returns the events generated by the agent.
    /// This method should be called after any interaction with the agent.
    /// The events notify the user about the status of the transactions.
    /// Note that no state is maintained between interactions with the agent.
    /// Therefore, the user should call this method to retrieve the events as
    /// soon as an operation is completed. Otherwise, the events may be lost
    /// if a new operation is performed.
    pub fn events(&mut self) -> Vec<StunClientEvent> {
        self.transaction_events.events()
    }
}

fn process_integrity_error(
    error: IntegrityError,
    transaction_id: &TransactionId,
) -> Result<Option<StunClientEvent>, StunAgentError> {
    match error {
        IntegrityError::ProtectionViolated => Ok(Some(StunClientEvent::TransactionFailed((
            *transaction_id,
            StunTransactionError::ProtectionViolated,
        )))),
        IntegrityError::Retry => Ok(Some(StunClientEvent::Retry(*transaction_id))),
        IntegrityError::NotRetryable => Ok(Some(StunClientEvent::TransactionFailed((
            *transaction_id,
            StunTransactionError::DoNotRetry,
        )))),
        IntegrityError::Discarded => {
            // Transaction was discarded. Retransmission will continue.
            Err(StunAgentError::Discarded)
        }
    }
}

fn prepare_stun_message(
    class: StunClientMessageClass,
    attributes: &mut StunAttributes,
    mechanism: Option<&mut CredentialMechanismClient>,
    use_fingerprint: bool,
) -> Result<(), StunAgentError> {
    if let Some(mechanism) = mechanism {
        match class {
            StunClientMessageClass::Request => mechanism.prepare_request(attributes)?,
            StunClientMessageClass::Indication => mechanism.prepare_indication(attributes)?,
        }
    }

    if use_fingerprint {
        add_fingerprint_attribute(attributes);
    }

    Ok(())
}

fn encode_buffer(
    encoder: &MessageEncoder,
    msg: &StunMessage,
    mut buffer: Vec<u8>,
) -> Result<StunPacket, StunEncodeError> {
    let size = encoder.encode(&mut buffer, msg)?;
    Ok(StunPacket::new(buffer, size))
}

#[cfg(test)]
mod stun_client_tests {
    use super::*;

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_stun_client_builder() {
        init_logging();

        let client =
            StunClienteBuilder::new(TransportReliability::Reliable(Duration::from_secs(5)))
                .with_max_transactions(5)
                .with_mechanism("user", "password", CredentialMechanism::ShortTerm(None))
                .with_fingerprint()
                .build()
                .expect("Could not create STUN client");

        assert_eq!(client.max_transactions, 5);
        assert!(matches!(
            client.mechanism,
            Some(CredentialMechanismClient::ShortTerm(_))
        ));
        assert!(client.use_fingerprint);

        let error = StunClienteBuilder::new(TransportReliability::Reliable(Duration::from_secs(5)))
            .with_max_transactions(5)
            .with_mechanism(
                "bad\u{0009}user",
                "password",
                CredentialMechanism::ShortTerm(None),
            )
            .with_fingerprint()
            .build()
            .expect_err("Should not create STUN client");
        assert!(matches!(error, StunAgentError::InternalError(_)));

        let error = StunClienteBuilder::new(TransportReliability::Reliable(Duration::from_secs(5)))
            .with_max_transactions(5)
            .with_mechanism(
                "user",
                "bad\u{0009}password",
                CredentialMechanism::ShortTerm(None),
            )
            .with_fingerprint()
            .build()
            .expect_err("Should not create STUN client");
        assert!(matches!(error, StunAgentError::InternalError(_)));
    }

    #[test]
    fn test_stun_client_constructor() {
        init_logging();

        let client = StunClient::new(StunClientParameters {
            user_name: Some(String::from("user")),
            password: Some(String::from("password")),
            mechanism: Some(CredentialMechanism::ShortTerm(None)),
            reliability: TransportReliability::Reliable(Duration::from_secs(5)),
            fingerprint: true,
            max_transactions: 5,
        })
        .expect("Could not create STUN client");
        assert_eq!(client.max_transactions, 5);
        assert!(matches!(
            client.mechanism,
            Some(CredentialMechanismClient::ShortTerm(_))
        ));
        assert!(client.use_fingerprint);

        let error = StunClient::new(StunClientParameters {
            user_name: Some(String::from("bad\u{0009}user")),
            password: Some(String::from("password")),
            mechanism: Some(CredentialMechanism::ShortTerm(None)),
            reliability: TransportReliability::Reliable(Duration::from_secs(5)),
            fingerprint: true,
            max_transactions: 5,
        })
        .expect_err("Should not create STUN client");
        assert!(matches!(error, StunAgentError::InternalError(_)));

        let error = StunClient::new(StunClientParameters {
            user_name: Some(String::from("user")),
            password: Some(String::from("bad\u{0009}password")),
            mechanism: Some(CredentialMechanism::ShortTerm(None)),
            reliability: TransportReliability::Reliable(Duration::from_secs(5)),
            fingerprint: true,
            max_transactions: 5,
        })
        .expect_err("Should not create STUN client");
        assert!(matches!(error, StunAgentError::InternalError(_)));

        let error = StunClient::new(StunClientParameters {
            user_name: None,
            password: Some(String::from("password")),
            mechanism: Some(CredentialMechanism::ShortTerm(None)),
            reliability: TransportReliability::Reliable(Duration::from_secs(5)),
            fingerprint: true,
            max_transactions: 5,
        })
        .expect_err("Should not create STUN client");
        assert!(matches!(error, StunAgentError::InternalError(_)));

        let error = StunClient::new(StunClientParameters {
            user_name: Some(String::from("user")),
            password: None,
            mechanism: Some(CredentialMechanism::ShortTerm(None)),
            reliability: TransportReliability::Reliable(Duration::from_secs(5)),
            fingerprint: true,
            max_transactions: 5,
        })
        .expect_err("Should not create STUN client");
        assert!(matches!(error, StunAgentError::InternalError(_)));
    }

    #[test]
    fn test_stun_client_transaction_finished_unknown_transaction_id() {
        init_logging();

        let mut client =
            StunClienteBuilder::new(TransportReliability::Reliable(Duration::from_secs(5)))
                .with_max_transactions(5)
                .with_mechanism("user", "password", CredentialMechanism::ShortTerm(None))
                .with_fingerprint()
                .build()
                .expect("Could not create STUN client");
        assert_eq!(client.transactions.len(), 0);

        let transanction_id = TransactionId::default();
        client.transaction_finished(&transanction_id, Instant::now());

        assert_eq!(client.transactions.len(), 0);
    }
}
