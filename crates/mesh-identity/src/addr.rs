//! Address records (SPEC-routing D3): "this device of mine is on this relay",
//! encrypted for one contact and left on the seeds. The seed sees the lookup
//! ID, the slot and the expiry (so it can store, find and sweep), and nothing
//! else. The contact checks the sender's signed device list, that the device
//! is current in it, and the device's signature. No IP addresses.
//!
//! Layout (big-endian); the outer part is the AEAD's associated data:
//!
//! ```text
//! lookup [16] | slot [8] | expires_at u64 | nonce [24]
//!             | encrypted (body | device signature [64]) + 16 tag
//! body = version u8 | lookup [16] | slot [8] | device [32] | created_at u64
//!        | expires_at u64 | relay len u16 | relay | list len u16 | list
//!        | e2ee len u16 | e2ee                        (version 2 only)
//! ```
//!
//! Version 2 (SPEC-e2ee D4) adds an opaque e2ee field: the device's e2ee
//! bundle and the keys it keeps for this contact. Version 1 still opens,
//! with an empty field.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::device::DeviceList;
use crate::id::{DeviceKey, MeshId, verify_device};
use crate::pair::{PairKeys, day_of};

const DOMAIN: &str = "mesh/v1/addr-record";
const FORMAT_V1: u8 = 1;
const FORMAT_V2: u8 = 2;
/// The e2ee field's limit, in bytes. SPEC-e2ee D4 allows up to 1 KiB, but
/// the biggest record (16 devices with the longest names, the longest relay)
/// is 3,797 bytes before it, and the seed takes 4,096. The field e2ee sends
/// is 201 bytes.
pub const MAX_E2EE_FIELD: usize = 256;
pub(crate) const OUTER_LEN: usize = 16 + 8 + 8;
pub(crate) const NONCE_LEN: usize = 24;
/// A relay URL's limit, in bytes.
pub const MAX_RELAY_LEN: usize = 255;
/// A sealed record's limit; the seed refuses anything bigger.
pub const MAX_RECORD_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddrError {
    #[error("the record is damaged or in an unknown format")]
    Malformed,
    #[error("the record isn't for this pair")]
    WrongPair,
    #[error("the record belongs to another identity")]
    WrongIdentity,
    #[error("the record's device isn't one of that identity's devices")]
    NotCurrent,
    #[error("the record isn't signed by its device")]
    BadSignature,
    #[error("the record has expired")]
    Expired,
    #[error("the relay URL or device list is too long")]
    TooLong,
    #[error("couldn't get randomness from the system")]
    Random,
}

/// An opened, checked record.
#[derive(Debug, Clone)]
pub struct AddrRecord {
    pub device: VerifyingKey,
    pub relay: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// The sender's device list, verified and rooted in the expected ID.
    pub devices: DeviceList,
    /// The e2ee field, opaque here; empty in a version 1 record.
    pub e2ee: Vec<u8>,
}

/// What the seed reads from a sealed record: lookup ID, slot, expiry.
pub fn addr_outer(bytes: &[u8]) -> Option<([u8; 16], [u8; 8], u64)> {
    if bytes.len() < OUTER_LEN + NONCE_LEN || bytes.len() > MAX_RECORD_LEN {
        return None;
    }
    Some((
        bytes[..16].try_into().ok()?,
        bytes[16..24].try_into().ok()?,
        u64::from_be_bytes(bytes[24..32].try_into().ok()?),
    ))
}

/// Seals `device`'s address for the pair `keys`, from the identity `devices`
/// belongs to, valid from `now` for `ttl` seconds, carrying `e2ee`.
pub fn seal_addr(
    keys: &PairKeys,
    device: &DeviceKey,
    devices: &DeviceList,
    relay: &str,
    e2ee: &[u8],
    now: u64,
    ttl: u64,
) -> Result<Vec<u8>, AddrError> {
    let list = devices.to_bytes();
    if relay.len() > MAX_RELAY_LEN || list.len() > u16::MAX as usize || e2ee.len() > MAX_E2EE_FIELD
    {
        return Err(AddrError::TooLong);
    }
    let public = device.public();
    let lookup = keys.lookup(&devices.root(), day_of(now));
    let slot = keys.slot(&public);
    let expires_at = now + ttl;

    let mut body = vec![FORMAT_V2];
    body.extend_from_slice(&lookup);
    body.extend_from_slice(&slot);
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&now.to_be_bytes());
    body.extend_from_slice(&expires_at.to_be_bytes());
    body.extend_from_slice(&(relay.len() as u16).to_be_bytes());
    body.extend_from_slice(relay.as_bytes());
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend_from_slice(&list);
    body.extend_from_slice(&(e2ee.len() as u16).to_be_bytes());
    body.extend_from_slice(e2ee);
    let signature = device.sign(DOMAIN, &body);
    body.extend_from_slice(&signature.to_bytes());

    let mut out = Vec::with_capacity(OUTER_LEN + NONCE_LEN + body.len() + 16);
    out.extend_from_slice(&lookup);
    out.extend_from_slice(&slot);
    out.extend_from_slice(&expires_at.to_be_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| AddrError::Random)?;
    let sealed = cipher(keys)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &body,
                aad: &out,
            },
        )
        .map_err(|_| AddrError::Malformed)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    if out.len() > MAX_RECORD_LEN {
        return Err(AddrError::TooLong);
    }
    Ok(out)
}

/// Opens a record that `sender` left for the pair `keys`, and checks it.
pub fn open_addr(
    keys: &PairKeys,
    sender: &MeshId,
    bytes: &[u8],
    now: u64,
) -> Result<AddrRecord, AddrError> {
    let (lookup, slot, expires_at) = addr_outer(bytes).ok_or(AddrError::Malformed)?;
    let (outer, rest) = bytes.split_at(OUTER_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("24 bytes");
    let plain = cipher(keys)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: sealed,
                aad: outer,
            },
        )
        .map_err(|_| AddrError::WrongPair)?;
    let (body, signature) = plain.split_last_chunk::<64>().ok_or(AddrError::Malformed)?;

    let mut r = Reader(body);
    let malformed = AddrError::Malformed;
    let version = r.take(1)?[0];
    if ![FORMAT_V1, FORMAT_V2].contains(&version) || r.take(16)? != lookup || r.take(8)? != slot {
        return Err(malformed);
    }
    let device = VerifyingKey::from_bytes(r.take(32)?.try_into().map_err(|_| malformed)?)
        .map_err(|_| malformed)?;
    let created_at = r.u64()?;
    if r.u64()? != expires_at {
        return Err(malformed);
    }
    let relay_len = r.u16()?;
    let relay = String::from_utf8(r.take(relay_len)?.to_vec()).map_err(|_| malformed)?;
    let list_len = r.u16()?;
    let devices = DeviceList::from_bytes(r.take(list_len)?).map_err(|_| malformed)?;
    let e2ee = match version {
        FORMAT_V2 => {
            let len = r.u16()?;
            if len > MAX_E2EE_FIELD {
                return Err(malformed);
            }
            r.take(len)?.to_vec()
        }
        _ => Vec::new(),
    };
    if !r.0.is_empty() {
        return Err(malformed);
    }

    if devices.root() != *sender {
        return Err(AddrError::WrongIdentity);
    }
    if !devices.is_current(&device) || keys.slot(&device) != slot {
        return Err(AddrError::NotCurrent);
    }
    if !verify_device(&device, DOMAIN, body, &Signature::from_bytes(signature)) {
        return Err(AddrError::BadSignature);
    }
    if expires_at <= now {
        return Err(AddrError::Expired);
    }
    Ok(AddrRecord {
        device,
        relay,
        created_at,
        expires_at,
        devices,
        e2ee,
    })
}

pub(crate) fn cipher(keys: &PairKeys) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*keys.record_key()))
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], AddrError> {
        if self.0.len() < n {
            return Err(AddrError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    pub(crate) fn u16(&mut self) -> Result<usize, AddrError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")) as usize)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, AddrError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceCert;
    use crate::id::RootKey;

    const NOW: u64 = 1_800_000_000;
    const RELAY: &str = "https://relay.example/";

    struct Person {
        root: RootKey,
        device: DeviceKey,
        devices: DeviceList,
    }

    fn person() -> Person {
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

    fn sealed(from: &Person, to: &Person) -> Vec<u8> {
        let keys = PairKeys::new(&from.root, &to.root.id()).unwrap();
        seal_addr(
            &keys,
            &from.device,
            &from.devices,
            RELAY,
            b"e2ee",
            NOW,
            7200,
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let (alice, bob) = (person(), person());
        let bytes = sealed(&alice, &bob);
        let keys = PairKeys::new(&bob.root, &alice.root.id()).unwrap();
        let record = open_addr(&keys, &alice.root.id(), &bytes, NOW + 60).unwrap();
        assert_eq!(record.device, alice.device.public());
        assert_eq!(record.relay, RELAY);
        assert_eq!((record.created_at, record.expires_at), (NOW, NOW + 7200));
        assert_eq!(record.devices.root(), alice.root.id());
        assert_eq!(record.e2ee, b"e2ee");

        let (lookup, slot, expires) = addr_outer(&bytes).unwrap();
        assert_eq!(lookup, keys.lookup(&alice.root.id(), day_of(NOW)));
        assert_eq!(slot, keys.slot(&alice.device.public()));
        assert_eq!(expires, NOW + 7200);
    }

    #[test]
    fn refusals() {
        let (alice, bob, eve) = (person(), person(), person());
        let bytes = sealed(&alice, &bob);
        let keys = PairKeys::new(&bob.root, &alice.root.id()).unwrap();
        let alice_id = alice.root.id();

        for i in [0, 20, 30, 40, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            assert!(
                open_addr(&keys, &alice_id, &tampered, NOW).is_err(),
                "byte {i}"
            );
        }
        let eves = PairKeys::new(&eve.root, &alice_id).unwrap();
        assert_eq!(
            open_addr(&eves, &alice_id, &bytes, NOW).unwrap_err(),
            AddrError::WrongPair
        );
        assert_eq!(
            open_addr(&keys, &alice_id, &bytes, NOW + 7200).unwrap_err(),
            AddrError::Expired
        );
        assert_eq!(
            open_addr(&keys, &eve.root.id(), &bytes, NOW).unwrap_err(),
            AddrError::WrongIdentity
        );
    }

    #[test]
    fn a_device_not_in_the_list_is_refused() {
        let (alice, bob) = (person(), person());
        let stranger = DeviceKey::generate().unwrap();
        let keys = PairKeys::new(&alice.root, &bob.root.id()).unwrap();
        let bytes = seal_addr(&keys, &stranger, &alice.devices, RELAY, &[], NOW, 7200).unwrap();
        assert_eq!(
            open_addr(&keys, &alice.root.id(), &bytes, NOW).unwrap_err(),
            AddrError::NotCurrent
        );

        // A removed device's records stop opening once the newer list is in them.
        let second = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&alice.root, &second.public(), "laptop", NOW).unwrap();
        let two = alice.devices.with_device(&alice.root, cert).unwrap();
        let one = two.without_device(&alice.root, &second.public()).unwrap();
        let bytes = seal_addr(&keys, &second, &one, RELAY, &[], NOW, 7200).unwrap();
        assert_eq!(
            open_addr(&keys, &alice.root.id(), &bytes, NOW).unwrap_err(),
            AddrError::NotCurrent
        );
    }

    #[test]
    fn long_relays_are_refused() {
        let (alice, bob) = (person(), person());
        let keys = PairKeys::new(&alice.root, &bob.root.id()).unwrap();
        let relay = "x".repeat(MAX_RELAY_LEN + 1);
        assert_eq!(
            seal_addr(&keys, &alice.device, &alice.devices, &relay, &[], NOW, 60).unwrap_err(),
            AddrError::TooLong
        );
        let field = [0; MAX_E2EE_FIELD + 1];
        assert_eq!(
            seal_addr(&keys, &alice.device, &alice.devices, RELAY, &field, NOW, 60).unwrap_err(),
            AddrError::TooLong
        );
    }

    #[test]
    fn the_biggest_record_fits() {
        // 16 devices with the longest names, the longest relay, a full field.
        let (mut alice, bob) = (person(), person());
        for i in 1..crate::MAX_DEVICES {
            let device = DeviceKey::generate().unwrap();
            let name = format!("{i:0>width$}", width = crate::MAX_DEVICE_NAME);
            let cert = DeviceCert::issue(&alice.root, &device.public(), &name, NOW).unwrap();
            alice.devices = alice.devices.with_device(&alice.root, cert).unwrap();
        }
        let keys = PairKeys::new(&alice.root, &bob.root.id()).unwrap();
        let relay = "r".repeat(MAX_RELAY_LEN);
        let field = [9; MAX_E2EE_FIELD];
        let bytes = seal_addr(
            &keys,
            &alice.device,
            &alice.devices,
            &relay,
            &field,
            NOW,
            60,
        );
        assert!(bytes.unwrap().len() <= MAX_RECORD_LEN);
    }

    /// A version 1 record, as routing made them before e2ee, still opens.
    #[test]
    fn version_1_still_opens() {
        let (alice, bob) = (person(), person());
        let keys = PairKeys::new(&alice.root, &bob.root.id()).unwrap();
        let public = alice.device.public();
        let lookup = keys.lookup(&alice.root.id(), day_of(NOW));
        let slot = keys.slot(&public);
        let list = alice.devices.to_bytes();
        let mut body = vec![FORMAT_V1];
        body.extend_from_slice(&lookup);
        body.extend_from_slice(&slot);
        body.extend_from_slice(public.as_bytes());
        body.extend_from_slice(&NOW.to_be_bytes());
        body.extend_from_slice(&(NOW + 60).to_be_bytes());
        body.extend_from_slice(&(RELAY.len() as u16).to_be_bytes());
        body.extend_from_slice(RELAY.as_bytes());
        body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        body.extend_from_slice(&list);
        let signature = alice.device.sign(DOMAIN, &body);
        body.extend_from_slice(&signature.to_bytes());
        let mut out = lookup.to_vec();
        out.extend_from_slice(&slot);
        out.extend_from_slice(&(NOW + 60).to_be_bytes());
        let nonce = [3u8; NONCE_LEN];
        let payload = Payload {
            msg: &body,
            aad: &out,
        };
        let sealed = cipher(&keys)
            .encrypt(&XNonce::from(nonce), payload)
            .unwrap();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);

        let theirs = PairKeys::new(&bob.root, &alice.root.id()).unwrap();
        let record = open_addr(&theirs, &alice.root.id(), &out, NOW).unwrap();
        assert_eq!(record.device, public);
        assert!(record.e2ee.is_empty());
    }
}
