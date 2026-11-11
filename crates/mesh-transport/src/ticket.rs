//! Test tickets (SPEC-transport D10): `mesh://node/<device key>?relay=<url>`.
//! Enough to reach one device through its relay, and no IP addresses, so a
//! pasted ticket doesn't carry anyone's home address. People will reach each
//! other by ID once `routing` lands; this is for testing until then.

use crate::MeshAddr;

const PREFIX: &str = "mesh://node/";
/// Direct addresses a ticket may carry: a seed's fixed IPv4 and IPv6, and
/// room to spare.
pub const MAX_DIRECT: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("that isn't a Mesh test ticket: it should start with {PREFIX}")]
    WrongScheme,
    #[error("the ticket's device key is damaged")]
    BadKey,
    #[error("the ticket has no relay or address")]
    NoRelay,
    #[error("the ticket's address is damaged")]
    BadAddr,
    #[error("the ticket's relay address is damaged")]
    BadRelay,
}

/// `mesh://node/<key>?relay=<url>&addr=<ip:port>…`: the relay, and for a
/// seed with a fixed address its direct addresses (SPEC-seed D8c). Tickets
/// with only a relay read as they always have.
impl MeshAddr {
    /// Key and relay only, as tickets always were: what people paste around
    /// never carries an IP (SPEC-transport D10).
    pub fn ticket(&self) -> Result<String, TicketError> {
        let relay = self.relay.as_ref().ok_or(TicketError::NoRelay)?;
        Ok(format!("{PREFIX}{}?relay={relay}", self.device))
    }

    /// With the direct addresses too: only for a seed's public address
    /// (SPEC-seed D8c).
    pub fn ticket_with_direct(&self) -> Result<String, TicketError> {
        if self.relay.is_none() && self.direct.is_empty() {
            return Err(TicketError::NoRelay);
        }
        if self.direct.len() > MAX_DIRECT {
            return Err(TicketError::BadAddr);
        }
        let mut params: Vec<String> = self.relay.iter().map(|r| format!("relay={r}")).collect();
        params.extend(self.direct.iter().map(|a| format!("addr={a}")));
        Ok(format!("{PREFIX}{}?{}", self.device, params.join("&")))
    }

    pub fn from_ticket(text: &str) -> Result<Self, TicketError> {
        let rest = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(TicketError::WrongScheme)?;
        let (key, query) = rest.split_once('?').ok_or(TicketError::NoRelay)?;
        let device = key.parse().map_err(|_| TicketError::BadKey)?;
        let (mut relay, mut direct) = (None, Vec::new());
        for param in query.split('&') {
            if let Some(url) = param.strip_prefix("relay=") {
                let url: iroh::RelayUrl = url.parse().map_err(|_| TicketError::BadRelay)?;
                if !matches!(url.scheme(), "https" | "http") {
                    return Err(TicketError::BadRelay);
                }
                relay = Some(url);
            } else if let Some(addr) = param.strip_prefix("addr=") {
                direct.push(addr.parse().map_err(|_| TicketError::BadAddr)?);
                if direct.len() > MAX_DIRECT {
                    return Err(TicketError::BadAddr);
                }
            }
        }
        if relay.is_none() && direct.is_empty() {
            return Err(TicketError::NoRelay);
        }
        Ok(Self {
            device,
            relay,
            direct,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> MeshAddr {
        MeshAddr {
            device: iroh::SecretKey::from_bytes(&[3; 32]).public(),
            relay: Some("https://euc1-1.relay.n0.iroh.link./".parse().unwrap()),
            direct: Vec::new(),
        }
    }

    #[test]
    fn round_trips() {
        let ticket = addr().ticket().unwrap();
        assert!(ticket.starts_with(PREFIX));
        // ticket() never carries an IP, even when the address has one: it's
        // what people paste around (D10).
        let lan = MeshAddr {
            direct: vec!["192.168.1.2:4000".parse().unwrap()],
            ..addr()
        };
        assert_eq!(lan.ticket(), Ok(ticket.clone()));
        // A seed's fixed address goes in only by asking, and comes back out.
        let with_ip = MeshAddr {
            direct: vec![
                "203.0.113.5:7400".parse().unwrap(),
                "[2001:db8::5]:7400".parse().unwrap(),
            ],
            ..addr()
        };
        let fixed = with_ip.ticket_with_direct().unwrap();
        assert!(
            fixed.contains("&addr=203.0.113.5:7400&addr=[2001:db8::5]:7400"),
            "{fixed}"
        );
        assert_eq!(MeshAddr::from_ticket(&fixed), Ok(with_ip.clone()));
        // An address alone is enough; so is a relay alone, as tickets were.
        let direct_only = MeshAddr {
            relay: None,
            ..with_ip
        };
        assert_eq!(
            MeshAddr::from_ticket(&direct_only.ticket_with_direct().unwrap()),
            Ok(direct_only)
        );
        assert_eq!(
            MeshAddr {
                relay: None,
                ..addr()
            }
            .ticket(),
            Err(TicketError::NoRelay)
        );
        assert_eq!(MeshAddr::from_ticket(&ticket), Ok(addr()));
        assert_eq!(
            MeshAddr::from_ticket(&format!("  {ticket}\n")),
            Ok(addr()),
            "pasted with spaces"
        );
    }

    #[test]
    fn each_mistake_has_its_own_error() {
        let ticket = addr().ticket().unwrap();
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
            (format!("{ticket}&addr=203.0.113.5"), TicketError::BadAddr),
            (format!("{ticket}&addr=nowhere:7400"), TicketError::BadAddr),
            (
                format!("{ticket}{}", "&addr=203.0.113.5:1".repeat(MAX_DIRECT + 1)),
                TicketError::BadAddr,
            ),
        ];
        for (text, error) in cases {
            assert_eq!(MeshAddr::from_ticket(&text), Err(error), "{text}");
        }
    }
}
