use stun_rs::{
    MessageClass, MessageMethod, StunAttribute, StunAttributeType, StunMessage, StunMessageBuilder,
    TransactionId,
};

/// Even though the STUN message is a collection of attributes, The [`StunAttribute`] is used to
/// simplify the addition and removal of attributes. The
/// [`RFC8489`](https://datatracker.ietf.org/doc/html/rfc8489) does not set neither a
/// limit nor a specific order for the attributes that can be added to a message, nevertheless,
/// there are certain restrictions that must be followed for the integrity and fingerprint
/// attributes. The [`StunAttribute`] eases the manipulation of attributes
/// while ensuring that the above restrictions are met.
#[derive(Debug, Default, Clone)]
pub struct StunAttributes {
    attributes: Vec<StunAttribute>,
    integrity: Option<StunAttribute>,
    integrity_sha256: Option<StunAttribute>,
    fingerprint: Option<StunAttribute>,
}

impl StunAttributes {
    /// Adds a STUN attribute to the collection. If the attribute is already present,
    /// it will be replaced.
    pub fn add<T>(&mut self, attribute: T)
    where
        T: Into<StunAttribute>,
    {
        let attr = attribute.into();

        if attr.is_message_integrity() {
            self.integrity = Some(attr);
        } else if attr.is_message_integrity_sha256() {
            self.integrity_sha256 = Some(attr);
        } else if attr.is_fingerprint() {
            self.fingerprint = Some(attr);
        } else if let Some(index) = self
            .attributes
            .iter()
            .position(|a| a.attribute_type() == attr.attribute_type())
        {
            // If this kind of attribute is already present, replace it
            self.attributes[index] = attr;
        } else {
            self.attributes.push(attr);
        }
    }

    /// Removes a STUN attribute from the collection.
    /// # Returns
    /// The removed attribute if it was present.
    pub fn remove<T>(&mut self) -> Option<StunAttribute>
    where
        T: StunAttributeType,
    {
        if let Some(attr) = &self.integrity {
            if attr.attribute_type() == T::get_type() {
                return self.integrity.take();
            }
        }
        if let Some(attr) = &self.integrity_sha256 {
            if attr.attribute_type() == T::get_type() {
                return self.integrity_sha256.take();
            }
        }
        if let Some(attr) = &self.fingerprint {
            if attr.attribute_type() == T::get_type() {
                return self.fingerprint.take();
            }
        }
        if let Some(index) = self
            .attributes
            .iter()
            .position(|a| a.attribute_type() == T::get_type())
        {
            return Some(self.attributes.remove(index));
        }

        None
    }
}

impl From<StunAttributes> for Vec<StunAttribute> {
    fn from(val: StunAttributes) -> Self {
        let mut attributes = val.attributes;
        if let Some(attr) = val.integrity {
            attributes.push(attr);
        }
        if let Some(attr) = val.integrity_sha256 {
            attributes.push(attr);
        }
        if let Some(attr) = val.fingerprint {
            attributes.push(attr);
        }
        attributes
    }
}

pub fn create_stun_message(
    method: MessageMethod,
    class: MessageClass,
    transaction_id: Option<TransactionId>,
    attributes: StunAttributes,
) -> StunMessage {
    let mut builder = StunMessageBuilder::new(method, class);
    if let Some(transaction_id) = transaction_id {
        builder = builder.with_transaction_id(transaction_id);
    }

    let attributes: Vec<StunAttribute> = attributes.into();
    for attr in attributes {
        builder = builder.with_attribute(attr);
    }

    builder.build()
}

#[cfg(test)]
mod stun_message_tests {
    use super::*;
    use stun_rs::attributes::stun::{
        ErrorCode, Fingerprint, MessageIntegrity, MessageIntegritySha256, Nonce, Realm, Software,
        UserName,
    };
    use stun_rs::methods::BINDING;
    use stun_rs::HMACKey;

    const USERNAME: &str = "test-username";
    const REALM: &str = "test-realm";
    const NONCE: &str = "test-nonce";
    const PASSWORD: &str = "test-password";

    #[test]
    fn test_add_stun_attribute() {
        let mut attributes = StunAttributes::default();

        attributes.add(UserName::try_from("test-username-1").expect("Failed to create username"));
        attributes.add(UserName::try_from("test-username-2").expect("Failed to create username"));
        attributes.add(Software::try_from("test-software-1").expect("Failed to create software"));
        attributes.add(Software::try_from("test-software-2").expect("Failed to create software"));

        let mut iter = attributes.attributes.iter();
        let attr = iter.next().expect("Expected attribute UserName");
        let username = attr.expect_user_name();
        assert_eq!(username, "test-username-2");

        let attr = iter.next().expect("Expected attribute Software");
        let username = attr.expect_software();
        assert_eq!(username, "test-software-2");

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_remove_stun_attribute() {
        let mut attributes = StunAttributes::default();

        attributes.add(UserName::try_from("test-username-1").expect("Failed to create username"));
        attributes.add(UserName::try_from("test-username-2").expect("Failed to create username"));
        attributes.add(Software::try_from("test-software-1").expect("Failed to create software"));
        attributes.add(Software::try_from("test-software-2").expect("Failed to create software"));

        let attr = attributes
            .remove::<UserName>()
            .expect("Expected attribute UserName");
        let username = attr.expect_user_name();
        assert_eq!(username, "test-username-2");

        assert!(attributes.remove::<ErrorCode>().is_none());

        let mut iter = attributes.attributes.iter();
        let attr = iter.next().expect("Expected attribute Software");
        let username = attr.expect_software();
        assert_eq!(username, "test-software-2");
        assert!(iter.next().is_none());

        let key = HMACKey::new_short_term("foo bar").expect("Failed to create HMACKey");
        let mut attributes = StunAttributes::default();
        attributes.add(MessageIntegrity::new(key.clone()));
        attributes.add(MessageIntegritySha256::new(key));
        attributes.add(Fingerprint::default());
        attributes.add(UserName::try_from("test-username-1").expect("Failed to create username"));
        attributes.add(Software::try_from("test-software-1").expect("Failed to create software"));
        attributes.add(ErrorCode::from(
            stun_rs::ErrorCode::new(420, "Unknown Attribute").expect("Failed to create error"),
        ));

        assert!(attributes.remove::<MessageIntegrity>().is_some());
        assert!(attributes.remove::<MessageIntegritySha256>().is_some());
        assert!(attributes.remove::<Fingerprint>().is_some());
        assert!(attributes.remove::<Software>().is_some());
        assert!(attributes.remove::<ErrorCode>().is_some());
        assert!(attributes.remove::<UserName>().is_some());

        assert!(attributes.attributes.is_empty());
    }

    #[test]
    fn test_stun_attribute_position() {
        let key = HMACKey::new_short_term(PASSWORD).expect("Failed to create HMACKey");
        let username = UserName::new(USERNAME).expect("Failed to create UserName");
        let realm = Realm::new(REALM).expect("Failed to create Realm");
        let nonce = Nonce::new(NONCE).expect("Failed to create Nonce");
        let integrity = MessageIntegrity::new(key.clone());
        let integrity_sha256 = MessageIntegritySha256::new(key.clone());
        let fingerprint = Fingerprint::default();

        let mut attributes = StunAttributes::default();
        attributes.add(integrity);
        attributes.add(username);
        attributes.add(fingerprint);
        attributes.add(realm);
        attributes.add(integrity_sha256);
        attributes.add(nonce);

        let vector: Vec<StunAttribute> = Vec::from(attributes);
        let mut iter = vector.iter();
        let attr = iter.next().expect("Expected attribute UserName");
        assert!(attr.is_user_name());
        let attr = iter.next().expect("Expected attribute Realm");
        assert!(attr.is_realm());
        let attr = iter.next().expect("Expected attribute Nonce");
        assert!(attr.is_nonce());
        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());
        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());
        let attr = iter.next().expect("Expected attribute Fingerprint");
        assert!(attr.is_fingerprint());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_create_stun_message() {
        let key = HMACKey::new_short_term("foo bar").expect("Failed to create HMACKey");
        let transaction_id = TransactionId::default();

        let mut attributes = StunAttributes::default();

        attributes.add(Fingerprint::default());
        attributes.add(UserName::try_from("test-username-1").expect("Failed to create username"));
        attributes.add(MessageIntegritySha256::new(key.clone()));
        attributes.add(UserName::try_from("test-username-2").expect("Failed to create username"));
        attributes.add(MessageIntegrity::new(key));
        attributes.add(Software::try_from("test-software-1").expect("Failed to create software"));
        attributes.add(Software::try_from("test-software-2").expect("Failed to create software"));

        let message = create_stun_message(
            BINDING,
            MessageClass::Request,
            Some(transaction_id),
            attributes,
        );

        assert_eq!(message.method(), BINDING);
        assert_eq!(message.class(), MessageClass::Request);
        assert_eq!(message.transaction_id(), &transaction_id);

        let attributes = message.attributes();
        assert_eq!(attributes.len(), 5);

        let mut iter = attributes.iter();
        let attr = iter.next().expect("Expected attribute UserName");
        let username = attr.expect_user_name();
        assert_eq!(username, "test-username-2");

        let attr = iter.next().expect("Expected attribute Software");
        let username = attr.expect_software();
        assert_eq!(username, "test-software-2");

        let attr = iter.next().expect("Expected attribute MessageIntegrity");
        assert!(attr.is_message_integrity());

        let attr = iter
            .next()
            .expect("Expected attribute MessageIntegritySha256");
        assert!(attr.is_message_integrity_sha256());

        let attr = iter.next().expect("Expected attribute Fingerprint");
        assert!(attr.is_fingerprint());

        assert!(iter.next().is_none());
    }
}
