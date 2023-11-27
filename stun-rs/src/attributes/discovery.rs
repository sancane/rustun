//! NAT Behavior Discovery attributes defined for STUN
//! [`RFC5780`](https://datatracker.ietf.org/doc/html/rfc5780)

mod other_address;
mod response_origin;
mod response_port;

use crate::registry::DecoderRegistry;
pub use other_address::OtherAddress;
pub use response_origin::ResponseOrigin;
pub use response_port::ResponsePort;

pub(crate) fn discovery_register_attributes(registry: &mut DecoderRegistry) {
    registry.register::<OtherAddress>();
    registry.register::<ResponseOrigin>();
    registry.register::<ResponsePort>();
}
