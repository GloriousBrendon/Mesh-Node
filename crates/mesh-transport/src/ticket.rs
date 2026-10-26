//! Test tickets (SPEC-transport D10): `mesh://node/<device key>?relay=<url>`.
//! Enough to reach one device through its relay, and no IP addresses, so a
//! pasted ticket doesn't carry anyone's home address. People will reach each
//! other by ID once `routing` lands; this is for testing until then.

use crate::MeshAddr;

const PREFIX: &str = "mesh://node/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("that isn't a Mesh test ticket: it should start with {PREFIX}")]
    WrongScheme,
    #[error("the ticket's device key is damaged")]
    BadKey,
    #[error("the ticket has no relay")]
    NoRelay,
    #[error("the ticket's relay address is damaged")]
    BadRelay,
}

impl MeshAddr {
    /// This address as a ticket to paste.
    pub fn ticket(&self) -> String {
        format!("{PREFIX}{}?relay={}", self.device, self.relay)
    }

    /// Reads a pasted ticket; each failure says what's wrong with it.
    pub fn from_ticket(text: &str) -> Result<Self, TicketError> {
        let rest = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(TicketError::WrongScheme)?;
        let (key, relay) = rest.split_once("?relay=").ok_or(TicketError::NoRelay)?;
        let device = key.parse().map_err(|_| TicketError::BadKey)?;
        let relay: iroh::RelayUrl = relay.parse().map_err(|_| TicketError::BadRelay)?;
        // Relays are reached over HTTP(S) only.
        if !matches!(relay.scheme(), "https" | "http") {
            return Err(TicketError::BadRelay);
        }
        Ok(Self { device, relay })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> MeshAddr {
        MeshAddr {
            device: iroh::SecretKey::from_bytes(&[3; 32]).public(),
            relay: "https://euc1-1.relay.n0.iroh.link./".parse().unwrap(),
        }
    }

    #[test]
    fn round_trips() {
        let ticket = addr().ticket();
        assert!(ticket.starts_with(PREFIX));
        assert_eq!(MeshAddr::from_ticket(&ticket), Ok(addr()));
        assert_eq!(
            MeshAddr::from_ticket(&format!("  {ticket}\n")),
            Ok(addr()),
            "pasted with spaces"
        );
    }

    #[test]
    fn each_mistake_has_its_own_error() {
        let ticket = addr().ticket();
        let key = addr().device.to_string();
        let cases = [
            (
                ticket.replace("mesh://node/", "mesh://id/"),
                TicketError::WrongScheme,
            ),
            (ticket.replace("?relay=", "?r="), TicketError::NoRelay),
            (ticket.replace(&key, &key[1..]), TicketError::BadKey),
            (ticket.replace(&key, &"z".repeat(64)), TicketError::BadKey),
            (
                ticket.replace("https://", "nonsense"),
                TicketError::BadRelay,
            ),
            (ticket.replace("https://", "file://"), TicketError::BadRelay),
        ];
        for (text, error) in cases {
            assert_eq!(MeshAddr::from_ticket(&text), Err(error), "{text}");
        }
    }
}
