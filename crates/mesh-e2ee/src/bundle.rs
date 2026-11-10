//! The e2ee bundle (D3): a device's Olm keys, signed by its device key. It
//! counts only while that device is current in the person's newest
//! `DeviceList`, so the safety number, built from root IDs, vouches for it.
//!
//! Layout (big-endian):
//!
//! ```text
//! version u8 | device [32] | curve25519 [32] | ed25519 [32] | created_at u64
//!            | device signature [64]
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use mesh_identity::{DeviceKey, DeviceList, verify_device};

use crate::E2eeError;

const DOMAIN: &str = "mesh/v1/e2ee-bundle";
const FORMAT_V1: u8 = 1;
const BODY_LEN: usize = 1 + 32 + 32 + 32 + 8;
/// A bundle's length.
pub const MAX_BUNDLE_LEN: usize = BODY_LEN + 64;

/// A checked bundle: which device it belongs to and its Olm keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bundle {
    pub device: VerifyingKey,
    /// The Olm identity key (Curve25519).
    pub curve: [u8; 32],
    /// The Olm signing key (Ed25519).
    pub ed25519: [u8; 32],
    pub created_at: u64,
}

impl Bundle {
    /// Signs `curve` and `ed25519` as `device`'s Olm keys.
    pub fn sign(device: &DeviceKey, curve: [u8; 32], ed25519: [u8; 32], now: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_BUNDLE_LEN);
        out.push(FORMAT_V1);
        out.extend_from_slice(device.public().as_bytes());
        out.extend_from_slice(&curve);
        out.extend_from_slice(&ed25519);
        out.extend_from_slice(&now.to_be_bytes());
        let signature = device.sign(DOMAIN, &out);
        out.extend_from_slice(&signature.to_bytes());
        out
    }

    /// Opens a bundle and checks it against `devices`, the newest list seen
    /// for the person it should belong to.
    pub fn open(bytes: &[u8], devices: &DeviceList) -> Result<Self, E2eeError> {
        if bytes.len() != MAX_BUNDLE_LEN || bytes[0] != FORMAT_V1 {
            return Err(E2eeError::Malformed);
        }
        let (body, signature) = bytes.split_at(BODY_LEN);
        let key = |at: usize| -> [u8; 32] { body[at..at + 32].try_into().expect("32 bytes") };
        let device = VerifyingKey::from_bytes(&key(1)).map_err(|_| E2eeError::Malformed)?;
        if !devices.is_current(&device) {
            return Err(E2eeError::RevokedDevice);
        }
        let signature = Signature::from_bytes(signature.try_into().expect("64 bytes"));
        if !verify_device(&device, DOMAIN, body, &signature) {
            return Err(E2eeError::BadSignature);
        }
        Ok(Self {
            device,
            curve: key(33),
            ed25519: key(65),
            created_at: u64::from_be_bytes(body[97..105].try_into().expect("8 bytes")),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mesh_identity::{DeviceCert, RootKey};

    pub const NOW: u64 = 1_800_000_000;

    /// A person with one device.
    pub struct Person {
        pub root: RootKey,
        pub device: DeviceKey,
        pub devices: DeviceList,
    }

    pub fn person() -> Person {
        let root = RootKey::generate().unwrap();
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&root, &device.public(), "pc", NOW).unwrap();
        let devices = DeviceList::first(&root, cert).unwrap();
        Person {
            root,
            device,
            devices,
        }
    }

    #[test]
    fn round_trip() {
        let alice = person();
        let bytes = Bundle::sign(&alice.device, [1; 32], [2; 32], NOW);
        let bundle = Bundle::open(&bytes, &alice.devices).unwrap();
        assert_eq!(bundle.device, alice.device.public());
        assert_eq!((bundle.curve, bundle.ed25519), ([1; 32], [2; 32]));
        assert_eq!(bundle.created_at, NOW);
    }

    #[test]
    fn refusals() {
        let (alice, eve) = (person(), person());
        let bytes = Bundle::sign(&alice.device, [1; 32], [2; 32], NOW);
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            assert!(Bundle::open(&tampered, &alice.devices).is_err(), "byte {i}");
        }
        assert!(Bundle::open(&bytes[1..], &alice.devices).is_err());
        // Another root's list doesn't vouch for Alice's device.
        assert_eq!(
            Bundle::open(&bytes, &eve.devices).unwrap_err(),
            E2eeError::RevokedDevice
        );

        // A device removed from the newest list is refused.
        let laptop = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&alice.root, &laptop.public(), "laptop", NOW).unwrap();
        let two = alice.devices.with_device(&alice.root, cert).unwrap();
        let bytes = Bundle::sign(&laptop, [3; 32], [4; 32], NOW);
        assert!(Bundle::open(&bytes, &two).is_ok());
        let one = two.without_device(&alice.root, &laptop.public()).unwrap();
        assert_eq!(
            Bundle::open(&bytes, &one).unwrap_err(),
            E2eeError::RevokedDevice
        );
    }
}
