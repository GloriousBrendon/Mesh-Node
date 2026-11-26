//! The direct key (SPEC-connection-privacy P3): a second key per device that
//! runs the endpoint with direct paths, told only to friends and own devices.
//! The device key certifies it (`DirectCert`), so a friend can check it's
//! yours.
//!
//! The key is derived from the device secret and its issue time, so nothing
//! new is stored in the keystore: the helper keeps only the issue time.
//! Rotating (P4) is issuing at a new time. A lost issue time means a fresh
//! key at the next start, which is the safe side.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::id::{DeviceKey, verify_device};

const DOMAIN: &str = "mesh/v1/direct-cert";
const DERIVE: &str = "mesh/v1 direct key 2026-11-26";
const FORMAT_V1: u8 = 1;
/// A cert's length: format, device, direct key, issue time, signature.
pub const DIRECT_CERT_LEN: usize = 1 + 32 + 32 + 8 + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DirectError {
    #[error("the direct key's certificate is damaged or in an unknown format")]
    Malformed,
    #[error("the direct key's certificate isn't signed by that device")]
    BadSignature,
}

/// A device key's statement that `direct` is its direct key, from `issued_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectCert {
    device: VerifyingKey,
    direct: VerifyingKey,
    /// Unix seconds.
    issued_at: u64,
    signature: Signature,
}

impl DirectCert {
    /// The direct key `device` has for `issued_at`, and its certificate. The
    /// same inputs always give the same key.
    pub fn issue(device: &DeviceKey, issued_at: u64) -> (DeviceKey, Self) {
        let mut input = zeroize::Zeroizing::new([0u8; 40]);
        input[..32].copy_from_slice(device.secret_bytes().as_ref());
        input[32..].copy_from_slice(&issued_at.to_be_bytes());
        let direct = DeviceKey::from_secret_bytes(blake3::derive_key(DERIVE, input.as_ref()));
        let body = body(&device.public(), &direct.public(), issued_at);
        let cert = Self {
            device: device.public(),
            direct: direct.public(),
            issued_at,
            signature: device.sign(DOMAIN, &body),
        };
        (direct, cert)
    }

    pub fn device(&self) -> &VerifyingKey {
        &self.device
    }

    pub fn direct(&self) -> &VerifyingKey {
        &self.direct
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = body(&self.device, &self.direct, self.issued_at);
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    /// Parses and verifies a certificate: holding one means `device` signed it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DirectError> {
        if bytes.len() != DIRECT_CERT_LEN || bytes[0] != FORMAT_V1 {
            return Err(DirectError::Malformed);
        }
        let key = |at: usize| {
            VerifyingKey::from_bytes(bytes[at..at + 32].try_into().expect("32 bytes"))
                .map_err(|_| DirectError::Malformed)
        };
        let (device, direct) = (key(1)?, key(33)?);
        let issued_at = u64::from_be_bytes(bytes[65..73].try_into().expect("8 bytes"));
        let signature = Signature::from_bytes(bytes[73..].try_into().expect("64 bytes"));
        if !verify_device(&device, DOMAIN, &bytes[..73], &signature) {
            return Err(DirectError::BadSignature);
        }
        Ok(Self {
            device,
            direct,
            issued_at,
            signature,
        })
    }
}

fn body(device: &VerifyingKey, direct: &VerifyingKey, issued_at: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(DIRECT_CERT_LEN);
    body.push(FORMAT_V1);
    body.extend_from_slice(device.as_bytes());
    body.extend_from_slice(direct.as_bytes());
    body.extend_from_slice(&issued_at.to_be_bytes());
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_check() {
        let device = DeviceKey::generate().unwrap();
        let (direct, cert) = DirectCert::issue(&device, 1_000);
        let read = DirectCert::from_bytes(&cert.to_bytes()).unwrap();
        assert_eq!(read, cert);
        assert_eq!(read.device(), &device.public());
        assert_eq!(read.direct(), &direct.public());
        assert_eq!(read.issued_at(), 1_000);
        assert_ne!(direct.public(), device.public());
    }

    #[test]
    fn same_time_same_key_new_time_new_key() {
        let device = DeviceKey::generate().unwrap();
        let (a, _) = DirectCert::issue(&device, 1_000);
        let (b, _) = DirectCert::issue(&device, 1_000);
        let (c, _) = DirectCert::issue(&device, 1_001);
        assert_eq!(a.public(), b.public());
        assert_ne!(a.public(), c.public());
        // Another device at the same time gets its own key.
        let (d, _) = DirectCert::issue(&DeviceKey::generate().unwrap(), 1_000);
        assert_ne!(a.public(), d.public());
    }

    #[test]
    fn a_cert_from_another_signer_is_refused() {
        let (device, other) = (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        );
        let (_, cert) = DirectCert::issue(&device, 1_000);
        // Claim another device signed it: the signature no longer checks.
        let mut bytes = cert.to_bytes();
        bytes[1..33].copy_from_slice(other.public().as_bytes());
        assert_eq!(
            DirectCert::from_bytes(&bytes),
            Err(DirectError::BadSignature)
        );
    }

    #[test]
    fn a_damaged_cert_is_refused() {
        let (_, cert) = DirectCert::issue(&DeviceKey::generate().unwrap(), 1_000);
        let bytes = cert.to_bytes();
        let mut flipped = bytes.clone();
        flipped[40] ^= 1;
        assert!(DirectCert::from_bytes(&flipped).is_err());
        assert_eq!(
            DirectCert::from_bytes(&bytes[..bytes.len() - 1]),
            Err(DirectError::Malformed)
        );
        let mut format = bytes;
        format[0] = 2;
        assert_eq!(DirectCert::from_bytes(&format), Err(DirectError::Malformed));
    }
}
