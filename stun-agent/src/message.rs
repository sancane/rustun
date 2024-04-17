use stun_rs::{
    MessageClass, MessageMethod, StunAttribute, StunAttributeType, StunMessage, StunMessageBuilder,
    TransactionId,
};

#[derive(Debug, Default)]
pub struct StunAttributes {
    attributes: Vec<StunAttribute>,
    integrity: Option<StunAttribute>,
    integrite_sha256: Option<StunAttribute>,
    fingerprint: Option<StunAttribute>,
}

impl StunAttributes {
    pub fn add<T>(&mut self, attribute: T)
    where
        T: Into<StunAttribute>,
    {
        let attr = attribute.into();

        if attr.is_message_integrity() {
            self.integrity = Some(attr);
        } else if attr.is_message_integrity_sha256() {
            self.integrite_sha256 = Some(attr);
        } else if attr.is_fingerprint() {
            self.fingerprint = Some(attr);
        } else {
            if let Some(index) = self
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
    }
}

impl Into<Vec<StunAttribute>> for StunAttributes {
    fn into(self) -> Vec<StunAttribute> {
        let mut attributes = self.attributes;
        if let Some(attr) = self.integrity {
            attributes.push(attr);
        }
        if let Some(attr) = self.integrite_sha256 {
            attributes.push(attr);
        }
        if let Some(attr) = self.fingerprint {
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
mod tests {
    use super::*;
    use stun_rs::attributes::stun::{
        Fingerprint, MessageIntegrity, MessageIntegritySha256, Software, UserName,
    };
    use stun_rs::methods::BINDING;
    use stun_rs::HMACKey;

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
            Some(transaction_id.clone()),
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
