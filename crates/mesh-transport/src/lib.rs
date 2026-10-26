//! `mesh-transport`: encrypted connections between Mesh devices, dialled by the
//! device's public key (design/mesh/SPEC-transport.md, in Mesh-Voice). iroh
//! does the QUIC, hole punching and relay fallback; this crate adds Mesh's
//! handshake, framing and limits on top.

pub mod frame;
pub mod ticket;

use mesh_identity::DeviceKey;

/// Where to reach one device: its key, and the relay it's connected to
/// (SPEC-transport D3). Direct paths are found from there by hole punching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAddr {
    pub device: iroh::PublicKey,
    pub relay: iroh::RelayUrl,
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
