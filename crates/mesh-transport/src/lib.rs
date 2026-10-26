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

use mesh_identity::{DeviceKey, MeshId};
use std::net::SocketAddr;

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
#[derive(Debug, Clone)]
pub enum Relays {
    /// n0's public relays, until `seed` runs our own.
    Default,
    Custom(Vec<iroh::RelayUrl>),
    /// None at all: direct addresses only (tests on one machine).
    Disabled,
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
