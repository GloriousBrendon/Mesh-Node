//! `mesh-transport`: encrypted connections between Mesh devices, dialled by the
//! device's public key (design/mesh/SPEC-transport.md, in Mesh-Voice). iroh
//! does the QUIC, hole punching and relay fallback; this crate adds Mesh's
//! handshake, framing and limits on top.

mod endpoint;
pub mod frame;
mod handshake;
pub mod ticket;

pub use endpoint::Node;
pub use handshake::{ALPN, HandshakeError};
pub use iroh::RelayUrl;

use mesh_identity::{DeviceKey, MeshId};
use std::net::SocketAddr;
use std::sync::Arc;

/// Where to reach one device (SPEC-transport D3): its key, the relay it's
/// connected to, and any direct addresses. A relay alone is enough; direct
/// paths are found from there by hole punching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAddr {
    pub device: iroh::PublicKey,
    pub relay: Option<iroh::RelayUrl>,
    pub direct: Vec<SocketAddr>,
}

impl MeshAddr {
    /// A device key and its relay, as an address record carries them
    /// (SPEC-routing D3). `None` if either isn't valid.
    pub fn from_parts(device: &[u8; 32], relay: &str) -> Option<Self> {
        Some(Self {
            device: iroh::PublicKey::from_bytes(device).ok()?,
            relay: Some(relay.parse().ok()?),
            direct: Vec::new(),
        })
    }

    fn endpoint_addr(&self) -> iroh::EndpointAddr {
        let mut addr = iroh::EndpointAddr::new(self.device);
        if let Some(relay) = &self.relay {
            addr = addr.with_relay_url(relay.clone());
        }
        self.direct
            .iter()
            .fold(addr, |addr, ip| addr.with_ip_addr(*ip))
    }
}

/// Another device, authenticated by the handshake: whose it is, which device,
/// and the name its owner gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: MeshId,
    pub device: iroh::PublicKey,
    pub name: String,
}

/// Which relays the node uses (SPEC-transport D4).
#[derive(Debug, Clone, Default)]
pub enum Relays {
    /// n0's public relays, until `seed` runs our own.
    #[default]
    Default,
    Custom(Vec<iroh::RelayUrl>),
    /// None at all: direct addresses only (tests on one machine).
    Disabled,
}

/// How the node is set up.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub relays: Relays,
    pub limits: Limits,
    /// Service tags this node answers besides `ping`; their streams come out
    /// of `Node::next_stream`.
    pub services: Vec<String>,
    /// Whose devices may connect to this node; everyone by default.
    pub allow: Allow,
    #[cfg(feature = "test-utils")]
    pub test: TestOptions,
}

/// Settings only tests can reach: the `test-utils` feature is never on in
/// `mesh-node`.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, Default)]
pub struct TestOptions {
    /// Accept a relay's self-signed certificate (iroh's in-process test relay).
    pub trust_any_relay: bool,
    /// No direct paths at all, so traffic has to go through the relay.
    pub relay_only: bool,
}

#[cfg(feature = "test-utils")]
impl TestOptions {
    fn apply(self, mut builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
        if self.trust_any_relay {
            builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
        }
        if self.relay_only {
            builder = builder.clear_ip_transports();
        }
        builder
    }
}

/// Who may connect: checked in the handshake, before this node shows its
/// certificate (SPEC-routing D9: only contacts and your own devices).
#[derive(Clone, Default)]
pub struct Allow(Option<Arc<AllowFn>>);

type AllowFn = dyn Fn(&MeshId) -> bool + Send + Sync;

impl Allow {
    pub fn only(check: impl Fn(&MeshId) -> bool + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(check)))
    }

    pub fn allows(&self, id: &MeshId) -> bool {
        self.0.as_ref().is_none_or(|check| check(id))
    }
}

impl std::fmt::Debug for Allow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "Allow(only)"
        } else {
            "Allow(anyone)"
        })
    }
}

/// Caps on what others can make this node hold (SPEC-transport D9). Who is
/// *allowed* to connect is `social`'s decision; these only bound the cost.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Open connections; new incoming ones are refused past this.
    pub connections: usize,
    /// Incoming connections still in their handshake.
    pub handshakes: usize,
    /// Streams open at once on one connection.
    pub streams: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 256,
            handshakes: 32,
            streams: 32,
        }
    }
}

/// What the node reports to the UI: no IP addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// A home relay is connected.
    pub online: bool,
    pub relay: Option<iroh::RelayUrl>,
    /// At least one open connection is on a direct path.
    pub direct: bool,
    pub connections: usize,
}

/// A connection's current path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relay,
}

/// A stream another device opened for one of `Config::services`, its tag
/// already read.
#[derive(Debug)]
pub struct ServiceStream {
    pub peer: Peer,
    pub service: String,
    pub send: iroh::endpoint::SendStream,
    pub recv: iroh::endpoint::RecvStream,
    /// The other side's IP while the connection is direct, for rate limits;
    /// `None` through a relay. Never log it.
    pub direct_ip: Option<std::net::IpAddr>,
}

/// A ping's answer.
#[derive(Debug, Clone)]
pub struct Pong {
    pub peer: Peer,
    pub rtt: std::time::Duration,
    pub path: Path,
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("the certificate given isn't for this device's key")]
    CertNotOurs,
    #[error("couldn't start networking: {0}")]
    Bind(String),
    #[error("couldn't reach that device: {0}")]
    Unreachable(String),
    #[error("that device didn't answer in time")]
    Timeout,
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
}

/// The device key as iroh's endpoint key: the same Ed25519 key (identity D1),
/// so the iroh endpoint id is the device's public key.
pub fn secret_key(device: &DeviceKey) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&device.secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_id_is_the_device_key() {
        let device = DeviceKey::generate().expect("randomness");
        assert_eq!(
            secret_key(&device).public().as_bytes(),
            device.public().as_bytes()
        );
    }
}
