use crate::integrity::{IntegrityError, TransportIntegrity};
use crate::message::StunAttributes;
use crate::{Integrity, ProtectedAttributeIterator, StunAgentError};
use log::debug;
use stun_rs::attributes::stun::nonce_cookie::StunSecurityFeatures;
use stun_rs::attributes::stun::MessageIntegrity;
use stun_rs::attributes::stun::{
    MessageIntegritySha256, Nonce, PasswordAlgorithm, PasswordAlgorithms, Realm, UserHash, UserName,
};
use stun_rs::{
    Algorithm, AlgorithmId, HMACKey, MessageClass, StunAttribute, StunMessage, TransactionId,
};

const ERROR_CODE_UNAUTHENTICATED: u16 = 401;
const ERROR_CODE_STALE_NONCE: u16 = 438;

#[derive(Debug, Clone)]
struct LongTermCredentialAttributes {
    realm: Realm,
    nonce: Nonce,
    password_algorithms: Option<PasswordAlgorithms>,
    password_algorithm: Option<PasswordAlgorithm>,
    key: HMACKey,
    user_hash: Option<UserHash>,
    integrity: Integrity,
}

#[derive(Debug, PartialEq, Eq)]
enum RetryCause {
    Unauthenticated,
    StaleNonce,
}

#[derive(Debug, PartialEq, Eq)]
enum LongTermCredentialState {
    FirstRequest,
    Retry(RetryCause),
    SubsequentRequest,
}
#[derive(Debug)]
pub struct LongTermCredentialClient {
    user_name: UserName,
    password: String,
    params: Option<LongTermCredentialAttributes>,
    validator: TransportIntegrity,
    state: LongTermCredentialState,
}

impl LongTermCredentialClient {
    pub fn new<P>(user_name: UserName, password: P, is_reliable: bool) -> Self
    where
        P: Into<String>,
    {
        Self {
            user_name,
            password: password.into(),
            params: None,
            validator: TransportIntegrity::new(is_reliable),
            state: LongTermCredentialState::FirstRequest,
        }
    }

    fn change_state(&mut self, new_state: LongTermCredentialState) {
        if self.state != new_state {
            debug!(
                "Changing long-term credential state from {:?} to {:?}",
                self.state, new_state
            );
            self.state = new_state;
        }
    }

    // 9.2.3.1.  First Request
    // If the client has not completed a successful request/response
    // transaction with the server, it MUST omit the USERNAME, USERHASH,
    // MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256, REALM, NONCE, PASSWORD-
    // ALGORITHMS, and PASSWORD-ALGORITHM attributes.  In other words, the
    // first request is sent as if there were no authentication or message
    // integrity applied.
    fn first_request(&mut self, attributes: &mut StunAttributes) -> Result<(), StunAgentError> {
        remove_auth_and_integrity_attrs(attributes);

        // Ready to send the request
        Ok(())
    }

    // 9.2.3.2.  Subsequent Requests
    // Once a request/response transaction has completed, the client will
    // have been presented a realm and nonce by the server and selected a
    // username and password with which it authenticated.  The client SHOULD
    // cache the username, password, realm, and nonce for subsequent
    // communications with the server.  When the client sends a subsequent
    // request, it MUST include either the USERNAME or USERHASH, REALM,
    // NONCE, and PASSWORD-ALGORITHM attributes with these cached values.
    // It MUST include a MESSAGE-INTEGRITY attribute or a MESSAGE-INTEGRITY-
    // SHA256 attribute, computed as described in Sections 14.5 and 14.6
    // using the cached password.  The choice between the two attributes
    // depends on the attribute received in the response to the first
    // request.
    fn subsequent_request(
        &mut self,
        attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        let Some(params) = &self.params else {
            return Err(StunAgentError::InternalError(
                "No authentication parameters found".to_string(),
            ));
        };
        remove_auth_and_integrity_attrs(attributes);

        if let Some(user_hash) = &params.user_hash {
            attributes.add(user_hash.clone());
        } else {
            attributes.add(self.user_name.clone());
        }

        attributes.add(params.realm.clone());
        attributes.add(params.nonce.clone());

        if let Some(password_algorithms) = &params.password_algorithms {
            attributes.add(password_algorithms.clone());
        }

        if let Some(password_algorithm) = &params.password_algorithm {
            attributes.add(password_algorithm.clone());
        }

        match params.integrity {
            Integrity::MessageIntegrity => {
                attributes.add(MessageIntegrity::new(params.key.clone()))
            }
            Integrity::MessageIntegritySha256 => {
                attributes.add(MessageIntegritySha256::new(params.key.clone()))
            }
        }

        Ok(())
    }

    // 9.2.5.  Receiving a Response
    // If the response is an error response with an error code of 401
    // (Unauthenticated), the client SHOULD retry the request with a new
    // transaction.  This request MUST contain a USERNAME or a USERHASH,
    // determined by the client as the appropriate username for the REALM
    // from the error response.  If the "nonce cookie" is present and has
    // the STUN Security Feature "Username anonymity" bit set to 1, then the
    // USERHASH attribute MUST be used; else, the USERNAME attribute MUST be
    // used.  The request MUST contain the REALM, copied from the error
    // response.  The request MUST contain the NONCE, copied from the error
    // response.  If the response contains a PASSWORD-ALGORITHMS attribute,
    // the request MUST contain the PASSWORD-ALGORITHMS attribute with the
    // same content.  If the response contains a PASSWORD-ALGORITHMS
    // attribute, and this attribute contains at least one algorithm that is
    // supported by the client, then the request MUST contain a PASSWORD-
    // ALGORITHM attribute with the first algorithm supported on the list.
    fn retry_from_unauthenticated_error_response(
        &mut self,
        attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        let Some(params) = &self.params else {
            return Err(StunAgentError::InternalError(
                "No authentication parameters found".to_string(),
            ));
        };
        remove_auth_and_integrity_attrs(attributes);

        if let Some(user_hash) = &params.user_hash {
            attributes.add(user_hash.clone());
        } else {
            attributes.add(self.user_name.clone());
        }

        attributes.add(params.realm.clone());
        attributes.add(params.nonce.clone());

        if let Some(password_algorithms) = &params.password_algorithms {
            attributes.add(password_algorithms.clone());
        }

        if let Some(password_algorithm) = &params.password_algorithm {
            attributes.add(password_algorithm.clone());
        }

        Ok(())
    }

    // 9.2.5.  Receiving a Response
    // If the response is an error response with an error code of 438 (Stale
    // Nonce), the client MUST retry the request, using the new NONCE
    // attribute supplied in the 438 (Stale Nonce) response.  This retry
    // MUST also include either the USERNAME or USERHASH, the REALM, and
    // either the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute.
    fn retry_from_stale_nonce_error_response(
        &mut self,
        attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        let Some(params) = &self.params else {
            return Err(StunAgentError::InternalError(
                "No authentication parameters found".to_string(),
            ));
        };
        remove_auth_and_integrity_attrs(attributes);

        if let Some(user_hash) = &params.user_hash {
            attributes.add(user_hash.clone());
        } else {
            attributes.add(self.user_name.clone());
        }

        attributes.add(params.realm.clone());
        attributes.add(params.nonce.clone());

        match params.integrity {
            Integrity::MessageIntegrity => {
                attributes.add(MessageIntegrity::new(params.key.clone()))
            }
            Integrity::MessageIntegritySha256 => {
                attributes.add(MessageIntegritySha256::new(params.key.clone()))
            }
        }

        Ok(())
    }

    pub fn prepare_request(
        &mut self,
        attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        match &self.state {
            LongTermCredentialState::FirstRequest => self.first_request(attributes),
            LongTermCredentialState::Retry(cause) => match cause {
                RetryCause::Unauthenticated => {
                    self.retry_from_unauthenticated_error_response(attributes)
                }
                RetryCause::StaleNonce => self.retry_from_stale_nonce_error_response(attributes),
            },
            LongTermCredentialState::SubsequentRequest => self.subsequent_request(attributes),
        }
    }

    pub fn prepare_indication(
        &mut self,
        _attributes: &mut StunAttributes,
    ) -> Result<(), StunAgentError> {
        debug!("long-term credential mechanism cannot be used to protect indications. Ignoring");
        Err(StunAgentError::Ignored)
    }

    fn process_unauthenticated_error_response(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
        auth_params: LongTermCredentialAttributes,
        message_integrity: Option<&StunAttribute>,
        message_integrity_sha256: Option<&StunAttribute>,
    ) -> Result<(), IntegrityError> {
        if message_integrity.is_some() || message_integrity_sha256.is_some() {
            // The response contains a MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
            // attribute, this is a response to a subsequent request that was not
            // authenticated by the server.
            authenticate_message(
                &mut self.validator,
                raw_buffer,
                &auth_params.key,
                auth_params.integrity,
                msg,
                message_integrity,
                message_integrity_sha256,
            )?;
        }
        // Update auth parameters and retry with a new transaction
        self.params = Some(auth_params);
        self.change_state(LongTermCredentialState::Retry(RetryCause::Unauthenticated));
        Err(IntegrityError::Retry)
    }

    fn process_stale_nonce_error_response(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
        nonce: Option<Nonce>,
        message_integrity: Option<&StunAttribute>,
        message_integrity_sha256: Option<&StunAttribute>,
    ) -> Result<(), IntegrityError> {
        let nonce = nonce.ok_or_else(|| {
            debug!(
                "[{:?}] No Nonce attribute found in error response.",
                msg.transaction_id()
            );
            IntegrityError::Discarded
        })?;
        let Some(params) = self.params.as_mut() else {
            debug!(
                "[{:?}] No authentication parameters were set yet.",
                msg.transaction_id()
            );
            return Err(IntegrityError::Discarded);
        };

        // The response MAY include a MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
        // attribute, using the previous NONCE to calculate it
        if message_integrity.is_some() || message_integrity_sha256.is_some() {
            authenticate_message(
                &mut self.validator,
                raw_buffer,
                &params.key,
                params.integrity,
                msg,
                message_integrity,
                message_integrity_sha256,
            )?;
        }

        // Update Nonce and retry with a new transaction
        params.nonce = nonce;
        self.change_state(LongTermCredentialState::Retry(RetryCause::StaleNonce));
        Err(IntegrityError::Retry)
    }

    fn process_error(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
        message_integrity: Option<&StunAttribute>,
        message_integrity_sha256: Option<&StunAttribute>,
    ) -> Result<(), IntegrityError> {
        let (key, integrity) = match self.params.as_ref() {
            Some(params) => (&params.key, params.integrity),
            None => {
                debug!(
                    "[{:?}] No authentication parameters were set yet.",
                    msg.transaction_id()
                );
                return Err(IntegrityError::Discarded);
            }
        };
        authenticate_message(
            &mut self.validator,
            raw_buffer,
            key,
            integrity,
            msg,
            message_integrity,
            message_integrity_sha256,
        )
    }

    fn process_error_response(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
    ) -> Result<(), IntegrityError> {
        let mut error_code = None;
        let mut nonce = None;
        let mut realm = None;
        let mut password_algorithm = None;
        let mut password_algorithms = None;
        let mut integrity = None;
        let mut integrity_sha256 = None;
        let mut set_password_algorithms = false;
        let mut set_user_anonymity = false;

        for attribute in msg.attributes().protected_iter() {
            match attribute {
                StunAttribute::ErrorCode(attr) => {
                    if error_code.is_none() {
                        error_code = Some(attr);
                    } else {
                        debug!(
                            "[{:?}] Multiple ErrorCode attributes found in error response.",
                            msg.transaction_id()
                        );
                    }
                }
                StunAttribute::Realm(attr) => {
                    if realm.is_none() {
                        realm = Some(attr.clone());
                    } else {
                        debug!(
                            "[{:?}] Multiple Realm attributes found in error response.",
                            msg.transaction_id()
                        );
                    }
                }
                StunAttribute::Nonce(attr) => {
                    if nonce.is_some() {
                        debug!(
                            "[{:?}] Multiple Nonce attributes found in error response.",
                            msg.transaction_id()
                        );
                        continue;
                    }
                    if attr.is_nonce_cookie() {
                        if let Ok(flags) = attr.security_features() {
                            set_user_anonymity =
                                flags.contains(StunSecurityFeatures::UserNameAnonymity);
                            set_password_algorithms =
                                flags.contains(StunSecurityFeatures::PasswordAlgorithms);
                        }
                    }
                    nonce = Some(attr.clone());
                }
                StunAttribute::PasswordAlgorithms(attr) => {
                    if password_algorithms.is_some() {
                        debug!(
                            "[{:?}] Multiple PasswordAlgorithms attributes found in error response.",
                            msg.transaction_id()
                        );
                        continue;
                    }
                    for algorithm in attr.iter() {
                        // We preffer SHA256 over MD5
                        match algorithm.algorithm() {
                            AlgorithmId::MD5 => {
                                password_algorithm = Some(algorithm.clone());
                            }
                            AlgorithmId::SHA256 => {
                                password_algorithm = Some(algorithm.clone());
                                break;
                            }
                            _ => debug!(
                                "[{:?}] Ignoring unsupported password algorithm: {:?}",
                                msg.transaction_id(),
                                algorithm.algorithm()
                            ),
                        }
                    }
                    if password_algorithm.is_none() {
                        debug!(
                            "[{:?}] No supported password algorithm found in error response. Do not retry",
                            msg.transaction_id()
                        );
                        return Err(IntegrityError::NotRetryable);
                    }
                    password_algorithms = Some(attr.clone());
                }
                StunAttribute::MessageIntegrity(_) => integrity = Some(attribute),
                StunAttribute::MessageIntegritySha256(_) => integrity_sha256 = Some(attribute),
                _ => {}
            }
        }

        if set_password_algorithms && password_algorithms.is_none() {
            // For all responses, if the NONCE attribute starts with the
            // "nonce cookie" with the STUN Security Feature "Password algorithms"
            // bit set to 1 but PASSWORD-ALGORITHMS is not present, the response
            // MUST be ignored.
            debug!(
                "[{:?}] STUN Security Feature \"Password algorithms\" bit set to 1 \
                but PASSWORD-ALGORITHMS is not present. Do not retry.",
                msg.transaction_id()
            );
            return Err(IntegrityError::NotRetryable);
        }

        let error = error_code.ok_or_else(|| {
            debug!(
                "[{:?}] No error code attribute found in error response.",
                msg.transaction_id()
            );
            IntegrityError::Discarded
        })?;

        let code = error.error_code().error_code();
        if code == ERROR_CODE_UNAUTHENTICATED {
            debug!(
                "[{:?}] Received 401 Unauthenticated error response.",
                msg.transaction_id()
            );
            let attrs = LongTermAttributes {
                realm,
                nonce,
                password_algorithms,
                password_algorithm,
            };
            let params = create_long_term_auth_attrs(
                msg.transaction_id(),
                &self.user_name,
                &self.password,
                attrs,
                set_user_anonymity,
            )?;
            self.process_unauthenticated_error_response(
                raw_buffer,
                msg,
                params,
                integrity,
                integrity_sha256,
            )
        } else if code == ERROR_CODE_STALE_NONCE {
            debug!(
                "[{:?}] Received 438 Stale Nonce error response.",
                msg.transaction_id()
            );
            self.process_stale_nonce_error_response(
                raw_buffer,
                msg,
                nonce,
                integrity,
                integrity_sha256,
            )
        } else {
            debug!(
                "[{:?}] Received error response with error code: {}",
                msg.transaction_id(),
                error.error_code().error_code()
            );
            self.process_error(raw_buffer, msg, integrity, integrity_sha256)
        }
    }

    fn process_success_response(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
    ) -> Result<(), IntegrityError> {
        let (key, integrity) = self.params.as_ref().map_or_else(
            || {
                debug!(
                    "[{:?}] No authentication parameters were set yet.",
                    msg.transaction_id()
                );
                Err(IntegrityError::Discarded)
            },
            |params| Ok((params.key.clone(), params.integrity)),
        )?;

        let mut message_integrity = None;
        let mut message_integrity_sha256 = None;

        for attribute in msg.attributes().protected_iter() {
            if attribute.is_message_integrity() {
                match integrity {
                    Integrity::MessageIntegrity => message_integrity = Some(attribute),
                    Integrity::MessageIntegritySha256 => {
                        debug!(
                            "[{:?}] MessageIntegrity attribute found in response, \
                            only expected MessageIntegritySha256.",
                            msg.transaction_id()
                        );
                        return Err(IntegrityError::Discarded);
                    }
                }
            } else if attribute.is_message_integrity_sha256() {
                match integrity {
                    Integrity::MessageIntegritySha256 => message_integrity_sha256 = Some(attribute),
                    Integrity::MessageIntegrity => {
                        debug!(
                            "[{:?}] MessageIntegritySha256 attribute found in response, \
                            only expected MessageIntegrity.",
                            msg.transaction_id()
                        );
                        return Err(IntegrityError::Discarded);
                    }
                }
            }
        }

        authenticate_message(
            &mut self.validator,
            raw_buffer,
            &key,
            integrity,
            msg,
            message_integrity,
            message_integrity_sha256,
        )
    }

    pub fn recv_message(
        &mut self,
        raw_buffer: &[u8],
        msg: &StunMessage,
    ) -> Result<(), IntegrityError> {
        match msg.class() {
            MessageClass::Request => {
                debug!("Received a request message, discarding it");
                Err(IntegrityError::Discarded)
            }
            MessageClass::Indication => {
                debug!("long-term credential mechanism cannot be used to protect indications, discarding it");
                Err(IntegrityError::Discarded)
            }
            MessageClass::ErrorResponse => self.process_error_response(raw_buffer, msg),
            MessageClass::SuccessResponse => self.process_success_response(raw_buffer, msg),
        }?;
        // If no error happened the request/response transaction has completed
        self.change_state(LongTermCredentialState::SubsequentRequest);
        Ok(())
    }

    pub fn signal_protection_violated_on_timeout(
        &mut self,
        transaction_id: &TransactionId,
    ) -> bool {
        self.validator
            .signal_protection_violated_on_timeout(transaction_id)
    }
}

#[derive(Debug, Default)]
struct LongTermAttributes {
    realm: Option<Realm>,
    nonce: Option<Nonce>,
    password_algorithms: Option<PasswordAlgorithms>,
    password_algorithm: Option<PasswordAlgorithm>,
}

fn create_user_hash_attr<A, B>(
    transaction_id: &TransactionId,
    user_name: A,
    realm: B,
) -> Result<UserHash, IntegrityError>
where
    A: AsRef<str>,
    B: AsRef<str>,
{
    UserHash::new(user_name, realm).map_err(|e| {
        debug!("[{:?}] Failed to create UserHash: {:?}", transaction_id, e);
        IntegrityError::Discarded
    })
}

fn create_long_term_auth_attrs(
    transaction_id: &TransactionId,
    user_name: &UserName,
    password: &str,
    attrs: LongTermAttributes,
    user_anonymity: bool,
) -> Result<LongTermCredentialAttributes, IntegrityError> {
    let realm = attrs.realm.ok_or_else(|| {
        debug!(
            "[{:?}] No Realm attribute found in error response.",
            transaction_id
        );
        IntegrityError::Discarded
    })?;
    let nonce = attrs.nonce.ok_or_else(|| {
        debug!(
            "[{:?}] No Nonce attribute found in error response.",
            transaction_id
        );
        IntegrityError::Discarded
    })?;

    let user_hash = if user_anonymity {
        Some(create_user_hash_attr(transaction_id, user_name, &realm)?)
    } else {
        None
    };

    // If password algorithm is not found, use MD5
    let algorithm = match &attrs.password_algorithm {
        Some(attr) => attr.as_ref().clone(),
        None => Algorithm::from(AlgorithmId::MD5),
    };

    let key = HMACKey::new_long_term(user_name, &realm, password, algorithm).map_err(|e| {
        debug!("[{:?}] Failed to create HMACKey: {:?}", transaction_id, e);
        IntegrityError::Discarded
    })?;

    // If the response contains a PASSWORD-ALGORITHMS attribute, all the
    // subsequent requests MUST be authenticated using MESSAGE-INTEGRITY-
    // SHA256 only.
    let integrity = if attrs.password_algorithms.is_some() {
        Integrity::MessageIntegritySha256
    } else {
        Integrity::MessageIntegrity
    };

    Ok(LongTermCredentialAttributes {
        realm,
        nonce,
        password_algorithms: attrs.password_algorithms,
        password_algorithm: attrs.password_algorithm,
        key,
        user_hash,
        integrity,
    })
}

// Remove authentication or message integrity attributes
fn remove_auth_and_integrity_attrs(attributes: &mut StunAttributes) {
    attributes.remove::<UserName>();
    attributes.remove::<UserHash>();
    attributes.remove::<Realm>();
    attributes.remove::<Nonce>();
    attributes.remove::<PasswordAlgorithm>();
    attributes.remove::<PasswordAlgorithms>();
    attributes.remove::<MessageIntegrity>();
    attributes.remove::<MessageIntegritySha256>();
}

fn authenticate_message(
    validator: &mut TransportIntegrity,
    raw_buffer: &[u8],
    key: &HMACKey,
    integrity: Integrity,
    msg: &StunMessage,
    message_integrity: Option<&StunAttribute>,
    message_integrity_sha256: Option<&StunAttribute>,
) -> Result<(), IntegrityError> {
    match integrity {
        Integrity::MessageIntegrity => {
            validator.compute_message_integrity(key, message_integrity, raw_buffer, msg)
        }
        Integrity::MessageIntegritySha256 => {
            validator.compute_message_integrity(key, message_integrity_sha256, raw_buffer, msg)
        }
    }
}

#[cfg(test)]
mod long_term_cred_mech_tests {
    use enumflags2::{make_bitflags, BitFlags};
    use stun_rs::{
        attributes::stun::ErrorCode, methods::BINDING, DecoderContextBuilder,
        MessageDecoderBuilder, MessageEncoderBuilder, StunMessageBuilder,
    };

    use crate::message;

    use super::*;

    const USERNAME: &str = "test-username";
    const REALM: &str = "test-realm";
    const NONCE: &str = "test-nonce";
    const PASSWORD: &str = "test-password";

    const CAPACITY: usize = 1024;

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn pool_buffer() -> Vec<u8> {
        vec![0; CAPACITY]
    }

    fn create_stun_encoded_message(
        buffer: &mut [u8],
        class: MessageClass,
        attributes: StunAttributes,
    ) -> (StunMessage, usize) {
        let msg = message::create_stun_message(BINDING, class, None, attributes);
        let encoder = MessageEncoderBuilder::default().build();
        let size = encoder
            .encode(buffer, &msg)
            .expect("Failed to encode message");
        (msg, size)
    }

    fn create_stun_decoded_message(
        buffer: &mut [u8],
        key: Option<&HMACKey>,
        class: MessageClass,
        attributes: StunAttributes,
    ) -> (StunMessage, usize) {
        let (_, size) = create_stun_encoded_message(buffer, class, attributes);
        let decoder = match key {
            Some(key) => {
                let ctx = DecoderContextBuilder::default()
                    .with_key(key.clone())
                    .with_validation()
                    .build();
                MessageDecoderBuilder::default().with_context(ctx).build()
            }
            None => MessageDecoderBuilder::default().build(),
        };
        decoder
            .decode(&buffer[..size])
            .expect("Failed to decode message")
    }

    #[derive(Debug, Default)]
    struct StunAttributesConfig {
        with_realm: bool,
        with_username: bool,
        with_userhash: bool,
        with_integrity: bool,
        with_integrity_sha256: bool,
        nonce: Option<Nonce>,
        error: Option<stun_rs::ErrorCode>,
        algorithm: Option<Algorithm>,
        algorithms: Option<PasswordAlgorithms>,
    }

    fn create_attributes(config: StunAttributesConfig) -> StunAttributes {
        let mut attributes = StunAttributes::default();
        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        let realm = Realm::new(REALM).expect("Failed to create Realm");
        let user_hash = UserHash::new(&username, &realm).expect("Failed to create UserHash");

        let key = match &config.algorithm {
            Some(algorithm) => {
                HMACKey::new_long_term(&username, &realm, PASSWORD, algorithm.clone())
                    .expect("Failed to create HMACKey")
            }
            None => HMACKey::new_long_term(
                &username,
                &realm,
                PASSWORD,
                Algorithm::from(AlgorithmId::MD5),
            )
            .expect("Failed to create HMACKey"),
        };

        if config.with_realm {
            attributes.add(realm);
        }
        if let Some(nonce) = config.nonce {
            attributes.add(nonce);
        }
        if config.with_username {
            attributes.add(username);
        }
        if config.with_userhash {
            attributes.add(user_hash);
        }
        if let Some(algorithm) = config.algorithm {
            attributes.add(PasswordAlgorithm::new(algorithm));
        }
        if let Some(algorithms) = config.algorithms {
            attributes.add(algorithms);
        }
        if let Some(error) = config.error {
            attributes.add(ErrorCode::from(error));
        }
        if config.with_integrity {
            attributes.add(MessageIntegrity::new(key.clone()));
        }
        if config.with_integrity_sha256 {
            attributes.add(MessageIntegritySha256::new(key.clone()));
        }

        attributes
    }

    fn create_long_term_client(reliable: bool) -> LongTermCredentialClient {
        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        LongTermCredentialClient::new(username, PASSWORD, reliable)
    }

    #[test]
    fn test_long_ter_cred_mech_remove_attrs() {
        init_logging();

        let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        let realm = Realm::new(REALM).expect("Failed to create Realm");
        let nonce = Nonce::new(NONCE).expect("Failed to create Nonce");
        let user_hash = UserHash::new(&username, &realm).expect("Failed to create UserHash");
        let palgorithm = PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5));
        let palgorithms = PasswordAlgorithms::default();
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key.clone());

        let mut attributes = StunAttributes::default();
        attributes.add(nonce);
        attributes.add(integrity_sha256);
        attributes.add(username);
        attributes.add(palgorithms);
        attributes.add(realm);
        attributes.add(integrity);
        attributes.add(palgorithm);
        attributes.add(user_hash);

        remove_auth_and_integrity_attrs(&mut attributes);

        let vec: Vec<StunAttribute> = attributes.into();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_creation_of_long_term_auth_attrs() {
        init_logging();

        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        let transaction_id = TransactionId::default();

        // long term attributes are empty so this must be discarded
        let error = create_long_term_auth_attrs(
            &transaction_id,
            &username,
            PASSWORD,
            LongTermAttributes::default(),
            false,
        )
        .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        let lt_attrs = LongTermAttributes {
            nonce: Some(Nonce::new(NONCE).expect("Failed to create Nonce")),
            password_algorithm: Some(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5))),
            password_algorithms: Some(PasswordAlgorithms::default()),
            ..Default::default()
        };
        // realm is missing so this must be discarded
        let error =
            create_long_term_auth_attrs(&transaction_id, &username, PASSWORD, lt_attrs, false)
                .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        let lt_attrs = LongTermAttributes {
            realm: Some(Realm::new(REALM).expect("Failed to create Realm")),
            password_algorithm: Some(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5))),
            password_algorithms: Some(PasswordAlgorithms::default()),
            ..Default::default()
        };
        // nonce is missing so this must be discarded
        let error =
            create_long_term_auth_attrs(&transaction_id, &username, PASSWORD, lt_attrs, false)
                .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        let lt_attrs = LongTermAttributes {
            nonce: Some(Nonce::new(NONCE).expect("Failed to create Nonce")),
            realm: Some(Realm::new(REALM).expect("Failed to create Realm")),
            ..Default::default()
        };
        let lt_cred_attrs =
            create_long_term_auth_attrs(&transaction_id, &username, PASSWORD, lt_attrs, false)
                .expect("Failed to create long term auth attributes");
        assert!(lt_cred_attrs.password_algorithm.is_none());
        assert!(lt_cred_attrs.password_algorithms.is_none());
        assert!(lt_cred_attrs.user_hash.is_none());
        assert_eq!(lt_cred_attrs.integrity, Integrity::MessageIntegrity);

        // Check user anonymity
        let lt_attrs = LongTermAttributes {
            nonce: Some(Nonce::new(NONCE).expect("Failed to create Nonce")),
            realm: Some(Realm::new(REALM).expect("Failed to create Realm")),
            ..Default::default()
        };
        let lt_cred_attrs =
            create_long_term_auth_attrs(&transaction_id, &username, PASSWORD, lt_attrs, true)
                .expect("Failed to create long term auth attributes");
        assert!(lt_cred_attrs.password_algorithm.is_none());
        assert!(lt_cred_attrs.password_algorithms.is_none());
        assert!(lt_cred_attrs.user_hash.is_some());
        assert_eq!(lt_cred_attrs.integrity, Integrity::MessageIntegrity);

        // Check MESSAGE-INTEGRITY-SHA256
        let lt_attrs = LongTermAttributes {
            nonce: Some(Nonce::new(NONCE).expect("Failed to create Nonce")),
            realm: Some(Realm::new(REALM).expect("Failed to create Realm")),
            password_algorithm: Some(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256))),
            password_algorithms: Some(PasswordAlgorithms::default()),
        };
        let lt_cred_attrs =
            create_long_term_auth_attrs(&transaction_id, &username, PASSWORD, lt_attrs, true)
                .expect("Failed to create long term auth attributes");
        assert!(lt_cred_attrs.password_algorithm.is_some());
        assert!(lt_cred_attrs.password_algorithms.is_some());
        assert!(lt_cred_attrs.user_hash.is_some());
        assert_eq!(lt_cred_attrs.integrity, Integrity::MessageIntegritySha256);

        let lt_attrs = LongTermAttributes {
            nonce: Some(Nonce::new(NONCE).expect("Failed to create Nonce")),
            realm: Some(Realm::new(REALM).expect("Failed to create Realm")),
            password_algorithm: Some(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256))),
            password_algorithms: Some(PasswordAlgorithms::default()),
        };
        // Use a password that should make HMACKKey creation fail
        let password = "bad\u{0009}password";
        let error =
            create_long_term_auth_attrs(&transaction_id, &username, password, lt_attrs, true)
                .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_create_user_hash_attr() {
        create_user_hash_attr(&TransactionId::default(), USERNAME, REALM)
            .expect("Failed to create UserHash");
        let error = create_user_hash_attr(&TransactionId::default(), "bad\u{0009}username", REALM)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_prepare_indication() {
        init_logging();

        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        let mut client = LongTermCredentialClient::new(username, PASSWORD, false);
        let mut attributes = StunAttributes::default();
        let error = client
            .prepare_indication(&mut attributes)
            .expect_err("Expected error");
        assert_eq!(error, StunAgentError::Ignored);
    }

    #[test]
    fn test_prepare_first_request() {
        init_logging();

        let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        let realm = Realm::new(REALM).expect("Failed to create Realm");
        let nonce = Nonce::new(NONCE).expect("Failed to create Nonce");
        let user_hash = UserHash::new(&username, &realm).expect("Failed to create UserHash");
        let palgorithm = PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5));
        let palgorithms = PasswordAlgorithms::default();
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key.clone());

        let mut client: LongTermCredentialClient =
            LongTermCredentialClient::new(username.clone(), PASSWORD, false);

        let mut attributes = StunAttributes::default();
        attributes.add(nonce);
        attributes.add(integrity_sha256);
        attributes.add(username);
        attributes.add(palgorithms);
        attributes.add(realm);
        attributes.add(integrity);
        attributes.add(palgorithm);
        attributes.add(user_hash);

        client
            .prepare_request(&mut attributes)
            .expect("Failed to prepare request");

        let vec: Vec<StunAttribute> = attributes.into();
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn test_prepare_subsequent_request_internal_error() {
        init_logging();

        let username = UserName::new(USERNAME).expect("Failed to create UserName");

        let mut client: LongTermCredentialClient =
            LongTermCredentialClient::new(username.clone(), PASSWORD, false);

        // Subsequent request without credential attributes must fail
        let mut attributes = StunAttributes::default();
        let error = client
            .subsequent_request(&mut attributes)
            .expect_err("Expected error");
        assert!(matches!(error, StunAgentError::InternalError(_)));
    }

    #[test]
    fn test_prepare_retry_from_unauthenticated_internal_error() {
        init_logging();

        let username = UserName::new(USERNAME).expect("Failed to create UserName");

        let mut client: LongTermCredentialClient =
            LongTermCredentialClient::new(username.clone(), PASSWORD, false);

        // Retry from unatuhenticated error without credential attributes must fail
        let mut attributes = StunAttributes::default();
        let error = client
            .retry_from_unauthenticated_error_response(&mut attributes)
            .expect_err("Expected error");
        assert!(matches!(error, StunAgentError::InternalError(_)));
    }

    #[test]
    fn test_prepare_retry_from_stale_nonce_internal_error() {
        init_logging();

        let username = UserName::new(USERNAME).expect("Failed to create UserName");

        let mut client: LongTermCredentialClient =
            LongTermCredentialClient::new(username.clone(), PASSWORD, false);

        // Retry from stale nonce error without credential attributes must fail
        let mut attributes = StunAttributes::default();
        let error = client
            .retry_from_stale_nonce_error_response(&mut attributes)
            .expect_err("Expected error");
        assert!(matches!(error, StunAgentError::InternalError(_)));
    }

    #[test]
    fn test_receive_request() {
        init_logging();

        let mut client = create_long_term_client(false);
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_encoded_message(
            &mut buffer,
            MessageClass::Request,
            StunAttributes::default(),
        );

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_receive_indication() {
        init_logging();

        let mut client = create_long_term_client(false);
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_encoded_message(
            &mut buffer,
            MessageClass::Indication,
            StunAttributes::default(),
        );

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_receive_success_response_without_credentials() {
        init_logging();

        let mut client = create_long_term_client(false);
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_encoded_message(
            &mut buffer,
            MessageClass::SuccessResponse,
            StunAttributes::default(),
        );

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_receive_error_response_without_error_code() {
        init_logging();

        let mut client = create_long_term_client(false);
        let mut buffer = pool_buffer();
        let attrs = create_attributes(StunAttributesConfig::default());

        let (msg, size) =
            create_stun_encoded_message(&mut buffer, MessageClass::ErrorResponse, attrs);

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn test_receive_error_response_without_password_algorithms() {
        init_logging();

        let mut client = create_long_term_client(false);
        let mut buffer = pool_buffer();
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let nonce =
            Nonce::new_nonce_cookie(NONCE, Some(flags)).expect("Can not create nonce cookie");
        let attrs = create_attributes(StunAttributesConfig {
            with_realm: false,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: Some(nonce),
            error: None,
            algorithm: None,
            algorithms: None,
        });

        let (msg, size) =
            create_stun_encoded_message(&mut buffer, MessageClass::ErrorResponse, attrs);

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::NotRetryable);
    }

    fn process_unauthenticated_response(
        client: &mut LongTermCredentialClient,
        algorithms: Option<&[AlgorithmId]>,
        flags: Option<BitFlags<StunSecurityFeatures>>,
    ) {
        let nonce = Nonce::new_nonce_cookie(NONCE, flags).expect("Can not create nonce cookie");
        let error =
            stun_rs::ErrorCode::new(401, "Unauthenticated").expect("Failed to create error");
        let palgorithms = if let Some(algorithms) = algorithms {
            let mut palgorithms = PasswordAlgorithms::default();
            for i in algorithms {
                palgorithms.add(PasswordAlgorithm::new(Algorithm::from(*i)));
            }
            Some(palgorithms)
        } else {
            None
        };

        let attrs = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: Some(nonce),
            error: Some(error),
            algorithm: None,
            algorithms: palgorithms,
        });

        let mut buffer = pool_buffer();
        let (msg, size) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attrs);

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Retry);

        assert_eq!(
            client.state,
            LongTermCredentialState::Retry(RetryCause::Unauthenticated)
        );

        if algorithms.is_some() {
            // Because the response had a PasswordAlgorithms attribute, the client should use MessageIntegritySha256
            assert_eq!(
                client.params.as_ref().unwrap().integrity,
                Integrity::MessageIntegritySha256
            );
        } else {
            // Because the response did not have a PasswordAlgorithms attribute, the client should use MessageIntegrity
            assert_eq!(
                client.params.as_ref().unwrap().integrity,
                Integrity::MessageIntegrity
            );
        }
    }

    fn process_stale_nonce_response(
        nonce_value: &str,
        client: &mut LongTermCredentialClient,
        algorithms: Option<&[AlgorithmId]>,
        flags: Option<BitFlags<StunSecurityFeatures>>,
        with_integrity: bool,
    ) {
        let old_key = client.params.as_ref().unwrap().key.clone();
        let nonce =
            Nonce::new_nonce_cookie(nonce_value, flags).expect("Can not create nonce cookie");
        let error = stun_rs::ErrorCode::new(438, "Stale Nonce").expect("Failed to create error");
        let palgorithms = if let Some(algorithms) = algorithms {
            let mut palgorithms = PasswordAlgorithms::default();
            for i in algorithms {
                palgorithms.add(PasswordAlgorithm::new(Algorithm::from(*i)));
            }
            Some(palgorithms)
        } else {
            None
        };

        let mut attr = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: Some(nonce),
            error: Some(error),
            algorithm: None,
            algorithms: palgorithms,
        });

        if with_integrity {
            match client.params.as_ref().unwrap().integrity {
                Integrity::MessageIntegrity => attr.add(MessageIntegrity::new(old_key.clone())),
                Integrity::MessageIntegritySha256 => {
                    attr.add(MessageIntegritySha256::new(old_key.clone()))
                }
            };
        }

        let mut buffer = pool_buffer();
        let (msg, size) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attr);
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Retry);

        // A Stale Nonce error must make the client change to Retry state
        assert_eq!(
            client.state,
            LongTermCredentialState::Retry(RetryCause::StaleNonce)
        );
    }

    #[test]
    fn test_authentication_error_no_common_password_algorithm() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let nonce =
            Nonce::new_nonce_cookie(NONCE, Some(flags)).expect("Can not create nonce cookie");
        let error =
            stun_rs::ErrorCode::new(401, "Unauthenticated").expect("Failed to create error");
        let mut palgorithms = PasswordAlgorithms::default();
        palgorithms.add(PasswordAlgorithm::new(Algorithm::from(
            AlgorithmId::Unassigned(25),
        )));

        let attrs = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: Some(nonce),
            error: Some(error),
            algorithm: None,
            algorithms: Some(palgorithms),
        });

        let mut buffer = pool_buffer();
        let (msg, size) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attrs);

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::NotRetryable);
    }

    #[test]
    fn test_authenticate_from_success_reponse_with_message_integrity_sha256() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let algorithms = vec![AlgorithmId::MD5, AlgorithmId::SHA256];
        process_unauthenticated_response(&mut client, Some(&algorithms), Some(flags));

        // Retry the request
        let mut attributes = StunAttributes::default();
        client
            .prepare_request(&mut attributes)
            .expect("Failed to prepare request");
        let attr_vec: Vec<StunAttribute> = attributes.into();
        let mut iter = attr_vec.iter();
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_nonce());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_password_algorithms());
        let algorithms = attr
            .as_password_algorithms()
            .expect("Expected PasswordAlgorithms");
        {
            // Check password algorithms is MD5 and SHA256
            // Algorithms must be in the same order as in the response
            let mut iter = algorithms.iter();
            let algorithm = iter.next().expect("Expected an algorithm");
            assert_eq!(algorithm.algorithm(), AlgorithmId::MD5);
            let algorithm = iter.next().expect("Expected an algorithm");
            assert_eq!(algorithm.algorithm(), AlgorithmId::SHA256);
            assert!(iter.next().is_none());
        }
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_password_algorithm());
        // Check that password algorithm is SHA256 (preferred over MD5)
        let algorithm = attr
            .as_password_algorithm()
            .expect("Expected PasswordAlgorithm");
        assert_eq!(algorithm.algorithm(), AlgorithmId::SHA256);
        // No message integrity must be set after an unauthenticated error
        assert!(iter.next().is_none());

        // A susccess response using MessageIntegrity must be discarded
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        attrs.add(MessageIntegrity::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        // A susccess response using MessageIntegritySha256 and wrong key must be discarded
        let mut attrs = StunAttributes::default();
        let key = HMACKey::new_short_term("wrong-password").expect("Failed to create HMACKey");
        attrs.add(MessageIntegritySha256::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        // A susccess response using MessageIntegritySha256 must make the client
        // change to SubsequentRequest state
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        attrs.add(MessageIntegritySha256::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Expected success");

        assert_eq!(client.state, LongTermCredentialState::SubsequentRequest);
    }

    #[test]
    fn test_authenticate_from_success_reponse_with_message_integrity() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        process_unauthenticated_response(&mut client, None, None);

        // Retry the request
        let mut attributes = StunAttributes::default();
        client
            .prepare_request(&mut attributes)
            .expect("Failed to prepare request");
        let attr_vec: Vec<StunAttribute> = attributes.into();
        let mut iter = attr_vec.iter();
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_nonce());

        // A susccess response using MessageIntegritySha256 must be discarded
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        attrs.add(MessageIntegritySha256::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        // A susccess response using MessageIntegrity and wrong key must be discarded
        let mut attrs = StunAttributes::default();
        let key = HMACKey::new_short_term("wrong-password").expect("Failed to create HMACKey");
        attrs.add(MessageIntegrity::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        // A susccess response using MessageIntegrity must make the client
        // change to SubsequentRequest state
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        attrs.add(MessageIntegrity::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Expected success");

        assert_eq!(client.state, LongTermCredentialState::SubsequentRequest);
    }

    #[test]
    fn test_authenticate_from_error_reponse() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let algorithms = vec![AlgorithmId::MD5, AlgorithmId::SHA256];
        process_unauthenticated_response(&mut client, Some(&algorithms), Some(flags));

        // An error response using MessageIntegritySha256 must be accepted
        // and make the client change to SubsequentRequest state
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        let error =
            stun_rs::ErrorCode::new(420, "Unknown Attribute").expect("Failed to create error");
        attrs.add(MessageIntegritySha256::new(key.clone()));
        attrs.add(ErrorCode::from(error));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::ErrorResponse,
            attrs,
        );
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Expected success");

        assert_eq!(client.state, LongTermCredentialState::SubsequentRequest);
    }

    fn authenticate(
        client: &mut LongTermCredentialClient,
        algorithms: Option<&[AlgorithmId]>,
        flags: Option<BitFlags<StunSecurityFeatures>>,
    ) {
        process_unauthenticated_response(client, algorithms, flags);

        // A SuccessResponse must make the client change to SubsequentRequest state
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        match client.params.as_ref().unwrap().integrity {
            Integrity::MessageIntegrity => attrs.add(MessageIntegrity::new(key.clone())),
            Integrity::MessageIntegritySha256 => {
                attrs.add(MessageIntegritySha256::new(key.clone()))
            }
        };
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Expected success");

        assert_eq!(client.state, LongTermCredentialState::SubsequentRequest);
    }

    #[test]
    fn test_prepare_subsequent_request_sha256() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let algorithms = vec![AlgorithmId::SHA256];
        authenticate(&mut client, Some(&algorithms), Some(flags));

        // Check that the client is ready to send a subsequent request
        let mut attributes = StunAttributes::default();
        client
            .prepare_request(&mut attributes)
            .expect("Failed to prepare request");
        let attr_vec: Vec<StunAttribute> = attributes.into();
        let mut iter = attr_vec.iter();
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_nonce());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_password_algorithms());
        let algorithms = attr
            .as_password_algorithms()
            .expect("Expected PasswordAlgorithms");
        {
            // Check password algorithms is SHA256
            let mut iter = algorithms.iter();
            let algorithm = iter.next().expect("Expected an algorithm");
            assert_eq!(algorithm.algorithm(), AlgorithmId::SHA256);
            assert!(iter.next().is_none());
        }
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_password_algorithm());
        // Check that password algorithm is SHA256
        let algorithm = attr
            .as_password_algorithm()
            .expect("Expected PasswordAlgorithm");
        assert_eq!(algorithm.algorithm(), AlgorithmId::SHA256);
        // Message integrity must be set
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_message_integrity_sha256());
    }

    #[test]
    fn test_prepare_subsequent_request_md5() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let algorithms = vec![AlgorithmId::MD5];
        authenticate(&mut client, Some(&algorithms), Some(flags));

        // Check that the client is ready to send a subsequent request
        let mut attributes = StunAttributes::default();
        client
            .prepare_request(&mut attributes)
            .expect("Failed to prepare request");
        let attr_vec: Vec<StunAttribute> = attributes.into();
        let mut iter = attr_vec.iter();
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_nonce());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_password_algorithms());
        let algorithms = attr
            .as_password_algorithms()
            .expect("Expected PasswordAlgorithms");
        {
            // Check password algorithms is MD5
            let mut iter = algorithms.iter();
            let algorithm = iter.next().expect("Expected an algorithm");
            assert_eq!(algorithm.algorithm(), AlgorithmId::MD5);
            assert!(iter.next().is_none());
        }
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_password_algorithm());
        // Check that password algorithm is MD5
        let algorithm = attr
            .as_password_algorithm()
            .expect("Expected PasswordAlgorithm");
        assert_eq!(algorithm.algorithm(), AlgorithmId::MD5);
        // Message integrity must be set
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_message_integrity_sha256());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_prepare_subsequent_with_message_integrity() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        authenticate(&mut client, None, None);

        // Check that the client is using MessageIntegrity
        assert_eq!(
            client.params.as_ref().unwrap().integrity,
            Integrity::MessageIntegrity
        );

        // Check that the client is ready to send a subsequent request
        let mut attributes = StunAttributes::default();
        client
            .prepare_request(&mut attributes)
            .expect("Failed to prepare request");
        let attr_vec: Vec<StunAttribute> = attributes.into();
        let mut iter = attr_vec.iter();
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_nonce());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_message_integrity());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_process_unauthenticated_with_integrity_attributes_cached() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        authenticate(&mut client, None, None);

        // Check that the client is using MessageIntegrity
        assert_eq!(
            client.params.as_ref().unwrap().integrity,
            Integrity::MessageIntegrity
        );

        let nonce = Nonce::new_nonce_cookie(NONCE, None).expect("Can not create nonce cookie");
        let error =
            stun_rs::ErrorCode::new(401, "Unauthenticated").expect("Failed to create error");

        let attrs = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: true,
            with_integrity_sha256: false,
            nonce: Some(nonce),
            error: Some(error),
            algorithm: None,
            algorithms: None,
        });

        let mut buffer = pool_buffer();
        let (msg, size) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attrs);

        let error = client
            .recv_message(&buffer[..size], &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Retry);
    }

    #[test]
    fn test_stale_error_after_authenticated_no_integrty() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let algorithms = vec![AlgorithmId::SHA256];

        // Authenticate client
        authenticate(&mut client, Some(&algorithms), Some(flags));

        // process a stale error response
        process_stale_nonce_response(
            "new-nonce",
            &mut client,
            Some(&algorithms),
            Some(flags),
            false,
        );

        // Check parameters set by the client
        let mut attrs = StunAttributes::default();
        client
            .prepare_request(&mut attrs)
            .expect("Failed to prepare request");
        let attr_vec: Vec<StunAttribute> = attrs.into();
        let mut iter = attr_vec.iter();
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_nonce());
        assert_eq!(attr.as_nonce().unwrap().as_str(), "obMatJos2gAAAnew-nonce");
        let attr = iter.next().expect("Expected an attribute");
        assert!(attr.is_message_integrity_sha256());

        assert!(iter.next().is_none());

        // A SuccessResponse must make the client change to SubsequentRequest state
        let mut attrs = StunAttributes::default();
        let key = client.params.as_ref().unwrap().key.clone();
        attrs.add(MessageIntegritySha256::new(key.clone()));
        let mut buffer = pool_buffer();
        let (msg, size) = create_stun_decoded_message(
            &mut buffer,
            Some(&key),
            MessageClass::SuccessResponse,
            attrs,
        );
        client
            .recv_message(&buffer[..size], &msg)
            .expect("Expected success");

        assert_eq!(client.state, LongTermCredentialState::SubsequentRequest);
    }

    #[test]
    fn test_stale_error_after_authenticated_with_integrty() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        let flags: BitFlags<StunSecurityFeatures> =
            make_bitflags!(StunSecurityFeatures::{PasswordAlgorithms});
        let algorithms = vec![AlgorithmId::SHA256];

        // Authenticate client
        authenticate(&mut client, Some(&algorithms), Some(flags));

        // process a stale error response
        process_stale_nonce_response(
            "new-nonce",
            &mut client,
            Some(&algorithms),
            Some(flags),
            true,
        );

        // The client should have cached the new nonce
        assert_eq!(
            client.params.as_ref().unwrap().nonce,
            "obMatJos2gAAAnew-nonce"
        );
    }

    #[test]
    fn process_stale_nonce_error_response_no_nonce() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);

        let error = stun_rs::ErrorCode::new(438, "Stale Nonce").expect("Failed to create error");
        let mut palgorithms = PasswordAlgorithms::default();
        palgorithms.add(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256)));

        let attr = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: None,
            error: Some(error),
            algorithm: None,
            algorithms: Some(palgorithms),
        });

        let mut buffer = pool_buffer();
        let (msg, _) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attr);

        let error = client
            .process_stale_nonce_error_response(&buffer, &msg, None, None, None)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn process_stale_nonce_error_response_without_auth_attributes() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);

        let nonce = Nonce::new_nonce_cookie(NONCE, None).expect("Can not create nonce cookie");
        let error = stun_rs::ErrorCode::new(438, "Stale Nonce").expect("Failed to create error");
        let mut palgorithms = PasswordAlgorithms::default();
        palgorithms.add(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256)));

        let attr = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: Some(nonce.clone()),
            error: Some(error),
            algorithm: None,
            algorithms: Some(palgorithms),
        });

        let mut buffer = pool_buffer();
        let (msg, _) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attr);

        let error = client
            .process_stale_nonce_error_response(&buffer, &msg, Some(nonce), None, None)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn process_error_response_without_auth_attributes() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);

        let nonce = Nonce::new_nonce_cookie(NONCE, None).expect("Can not create nonce cookie");
        let error = stun_rs::ErrorCode::new(438, "Stale Nonce").expect("Failed to create error");
        let mut palgorithms = PasswordAlgorithms::default();
        palgorithms.add(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256)));

        let attr = create_attributes(StunAttributesConfig {
            with_realm: true,
            with_username: false,
            with_userhash: false,
            with_integrity: false,
            with_integrity_sha256: false,
            nonce: Some(nonce.clone()),
            error: Some(error),
            algorithm: None,
            algorithms: Some(palgorithms),
        });

        let mut buffer = pool_buffer();
        let (msg, _) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attr);

        let error = client
            .process_error(&buffer, &msg, None, None)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);
    }

    #[test]
    fn process_error_response_discard_duplicated_attributes() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);

        let nonce_1 = Nonce::new(NONCE).expect("Can not create nonce cookie");
        let nonce_2 = Nonce::new("NONCE-IGNORED").expect("Can not create nonce cookie");
        let error_1 =
            stun_rs::ErrorCode::new(401, "Ignored Error").expect("Failed to create error");
        let error_2 = stun_rs::ErrorCode::new(438, "Stale Nonce").expect("Failed to create error");
        let realm_1 = Realm::new(REALM).expect("Failed to create Realm");
        let realm_2 = Realm::new("REALM_IGNORED").expect("Failed to create Realm");
        let mut palgorithms_1 = PasswordAlgorithms::default();
        palgorithms_1.add(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::SHA256)));
        let mut palgorithms_2 = PasswordAlgorithms::default();
        palgorithms_2.add(PasswordAlgorithm::new(Algorithm::from(AlgorithmId::MD5)));

        let msg = StunMessageBuilder::new(BINDING, MessageClass::ErrorResponse)
            .with_attribute(nonce_1)
            .with_attribute(realm_1)
            .with_attribute(ErrorCode::new(error_1))
            .with_attribute(palgorithms_1)
            .with_attribute(nonce_2)
            .with_attribute(realm_2)
            .with_attribute(ErrorCode::new(error_2))
            .with_attribute(palgorithms_2)
            .build();
        let mut buffer = pool_buffer();
        let encoder = MessageEncoderBuilder::default().build();
        let _ = encoder
            .encode(&mut buffer, &msg)
            .expect("Failed to encode message");

        let error = client
            .process_error_response(&buffer, &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Retry);

        // Check client processed the error unauthorized by going to state Retry Unauthenticated
        assert_eq!(
            client.state,
            LongTermCredentialState::Retry(RetryCause::Unauthenticated)
        );
        // Check that the client has cached the first nonce
        assert_eq!(client.params.as_ref().unwrap().nonce, NONCE);
        // Check that the client has cached the first realm
        assert_eq!(client.params.as_ref().unwrap().realm, REALM);
        // Chekc that the algortithm is SHA256
        assert_eq!(
            client
                .params
                .as_ref()
                .unwrap()
                .password_algorithm
                .as_ref()
                .unwrap()
                .algorithm(),
            AlgorithmId::SHA256
        );
    }

    #[test]
    fn protection_violated() {
        init_logging();

        let mut client: LongTermCredentialClient = create_long_term_client(false);
        authenticate(&mut client, None, None);

        let key = HMACKey::new_short_term("wrong-passwpord").expect("Failed to create HMACKey");
        let realm = client.params.as_ref().unwrap().realm.clone();
        let message_integrity = MessageIntegrity::new(key);
        let nonce = client.params.as_ref().unwrap().nonce.clone();
        let error = stun_rs::ErrorCode::new(401, "Ignored Error").expect("Failed to create error");

        let mut attrs = StunAttributes::default();
        attrs.add(realm);
        attrs.add(nonce);
        attrs.add(ErrorCode::from(error));
        attrs.add(message_integrity);

        let mut buffer = pool_buffer();
        let (msg, _) =
            create_stun_decoded_message(&mut buffer, None, MessageClass::ErrorResponse, attrs);

        // Check that this message does not violate the protection
        assert!(!client.signal_protection_violated_on_timeout(msg.transaction_id()));

        // Inetgrity failed, the client must discard the message and be prepared to
        // signal a protection violation
        let error = client
            .recv_message(&buffer, &msg)
            .expect_err("Expected error");
        assert_eq!(error, IntegrityError::Discarded);

        assert!(client.signal_protection_violated_on_timeout(msg.transaction_id()));
    }
}
