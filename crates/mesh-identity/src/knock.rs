//! Friend requests (SPEC-social D1, D4, D5): a request sealed to the owner of
//! a friend code and left on the seed under that code's lookup ID. Only the
//! owner's root key opens it. Inside, signed by the sender's device: their
//! device list, the owner's ID and the lookup ID (so it can't be replayed
//! under another code), their name, a note and when it was made.
//!
//! Layout (big-endian); the outer part is the AEAD's associated data:
//!
//! ```text
//! lookup_id [16] | slot [8] | throwaway key [32] | nonce [24]
//!                | encrypted (body | device signature [64]) + 16 tag
//! body = version u8 | owner [32] | lookup_id [16] | device [32] | created_at u64
//!        | name len u8 | name | note len u16 | note | list len u16 | list
//! ```

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::device::DeviceList;
use crate::id::{DeviceKey, MeshId, RootKey, verify_device};
use crate::pair::PairKeys;

const DOMAIN: &str = "mesh/v1/knock";
const KEY_CONTEXT: &str = "mesh/v1/knock-key";
const FORMAT_V1: u8 = 1;
const OUTER_LEN: usize = 16 + 8;
const HEAD_LEN: usize = OUTER_LEN + 32 + 24;
/// A sealed request's limit; the seed refuses anything bigger.
pub const MAX_KNOCK_LEN: usize = 4096;
/// A request's note, in UTF-8 bytes.
pub const MAX_NOTE: usize = 280;
/// A sender's display name, in UTF-8 bytes.
pub const MAX_KNOCK_NAME: usize = 64;
/// How far ahead a request's clock may be, and how old a request may get.
const AHEAD: u64 = 24 * 3600;
const OLDEST: u64 = 8 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KnockError {
    #[error("the request is damaged or in an unknown format")]
    Malformed,
    #[error("the request isn't for this identity or code")]
    NotForUs,
    #[error("the request's device isn't one of the sender's devices")]
    NotCurrent,
    #[error("the request isn't signed by its device")]
    BadSignature,
    #[error("the request is too old, or dated in the future")]
    OutOfDate,
    #[error("the name or note is too long")]
    TooLong,
    #[error("that ID can't be sent a request")]
    WeakKey,
    #[error("couldn't get randomness from the system")]
    Random,
}

/// An opened, checked request.
#[derive(Debug, Clone)]
pub struct Knock {
    pub sender: MeshId,
    /// The sender's device list, verified and rooted in `sender`.
    pub devices: DeviceList,
    pub name: String,
    pub note: String,
    pub created_at: u64,
}

/// What the seed reads from a sealed request: the lookup ID and slot.
pub fn knock_outer(bytes: &[u8]) -> Option<([u8; 16], [u8; 8])> {
    if bytes.len() < HEAD_LEN || bytes.len() > MAX_KNOCK_LEN {
        return None;
    }
    Some((bytes[..16].try_into().ok()?, bytes[16..24].try_into().ok()?))
}

/// What the sender puts in a request.
pub struct KnockFrom<'a> {
    pub root: &'a RootKey,
    pub device: &'a DeviceKey,
    pub devices: &'a DeviceList,
    pub name: &'a str,
}

/// Seals a request from `from` to the owner of the code behind `lookup_id`.
pub fn seal_knock(
    from: &KnockFrom,
    owner: &MeshId,
    lookup_id: &[u8; 16],
    note: &str,
    now: u64,
) -> Result<Vec<u8>, KnockError> {
    let list = from.devices.to_bytes();
    if from.name.len() > MAX_KNOCK_NAME || note.len() > MAX_NOTE || list.len() > u16::MAX as usize {
        return Err(KnockError::TooLong);
    }
    let slot = PairKeys::new(from.root, owner)
        .ok_or(KnockError::WeakKey)?
        .knock_slot(lookup_id);
    let throwaway = RootKey::generate().map_err(|_| KnockError::Random)?;
    let key = seal_key(&throwaway, owner, &throwaway.id(), owner).ok_or(KnockError::WeakKey)?;

    let public = from.device.public();
    let mut body = vec![FORMAT_V1];
    body.extend_from_slice(&owner.to_bytes());
    body.extend_from_slice(lookup_id);
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&now.to_be_bytes());
    body.push(from.name.len() as u8);
    body.extend_from_slice(from.name.as_bytes());
    body.extend_from_slice(&(note.len() as u16).to_be_bytes());
    body.extend_from_slice(note.as_bytes());
    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
    body.extend_from_slice(&list);
    let signature = from.device.sign(DOMAIN, &body);
    body.extend_from_slice(&signature.to_bytes());

    let mut out = Vec::with_capacity(HEAD_LEN + body.len() + 16);
    out.extend_from_slice(lookup_id);
    out.extend_from_slice(&slot);
    out.extend_from_slice(&throwaway.id().to_bytes());
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| KnockError::Random)?;
    out.extend_from_slice(&nonce);
    let sealed = cipher(&key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &body,
                aad: &out[..HEAD_LEN],
            },
        )
        .map_err(|_| KnockError::Malformed)?;
    out.extend_from_slice(&sealed);
    if out.len() > MAX_KNOCK_LEN {
        return Err(KnockError::TooLong);
    }
    Ok(out)
}

/// Opens a request found under `lookup_id`, with the owner's root key.
pub fn open_knock(
    root: &RootKey,
    lookup_id: &[u8; 16],
    bytes: &[u8],
    now: u64,
) -> Result<Knock, KnockError> {
    let (lookup, slot) = knock_outer(bytes).ok_or(KnockError::Malformed)?;
    if lookup != *lookup_id {
        return Err(KnockError::NotForUs);
    }
    let throwaway = MeshId::from_bytes(bytes[24..56].try_into().expect("32"))
        .map_err(|_| KnockError::Malformed)?;
    let owner = root.id();
    let key = seal_key(root, &throwaway, &throwaway, &owner).ok_or(KnockError::Malformed)?;
    let nonce: [u8; 24] = bytes[56..HEAD_LEN].try_into().expect("24 bytes");
    let plain = cipher(&key)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &bytes[HEAD_LEN..],
                aad: &bytes[..HEAD_LEN],
            },
        )
        .map_err(|_| KnockError::NotForUs)?;
    let (body, signature) = plain
        .split_last_chunk::<64>()
        .ok_or(KnockError::Malformed)?;

    let mut r = Reader(body);
    let bad = KnockError::Malformed;
    if r.take(1)? != [FORMAT_V1] {
        return Err(bad);
    }
    if r.take(32)? != owner.to_bytes() || r.take(16)? != lookup {
        return Err(KnockError::NotForUs);
    }
    let device =
        VerifyingKey::from_bytes(r.take(32)?.try_into().map_err(|_| bad)?).map_err(|_| bad)?;
    let created_at = u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes"));
    let name_len = r.take(1)?[0] as usize;
    let name = text(r.take(name_len)?)?;
    let note_len = r.u16()?;
    let note = text(r.take(note_len)?)?;
    let list_len = r.u16()?;
    let devices = DeviceList::from_bytes(r.take(list_len)?).map_err(|_| bad)?;
    if !r.0.is_empty() || name.len() > MAX_KNOCK_NAME || note.len() > MAX_NOTE {
        return Err(bad);
    }

    let sender = devices.root();
    if !devices.is_current(&device) {
        return Err(KnockError::NotCurrent);
    }
    if !verify_device(&device, DOMAIN, body, &Signature::from_bytes(signature)) {
        return Err(KnockError::BadSignature);
    }
    // The slot is the pair's, so a sender can't spread one person's requests
    // over many slots.
    let pair = PairKeys::new(root, &sender).ok_or(KnockError::NotForUs)?;
    if pair.knock_slot(&lookup) != slot {
        return Err(KnockError::Malformed);
    }
    if created_at > now + AHEAD || created_at + OLDEST < now {
        return Err(KnockError::OutOfDate);
    }
    Ok(Knock {
        sender,
        devices,
        name,
        note,
        created_at,
    })
}

/// The request key: X25519 between one side's secret and the other's public
/// key, bound to the throwaway key and the owner.
fn seal_key(
    mine: &RootKey,
    their: &MeshId,
    throwaway: &MeshId,
    owner: &MeshId,
) -> Option<Zeroizing<[u8; 32]>> {
    let shared = mine.diffie_hellman(their)?;
    let mut hasher = blake3::Hasher::new_derive_key(KEY_CONTEXT);
    hasher.update(shared.as_ref());
    hasher.update(&throwaway.to_bytes());
    hasher.update(&owner.to_bytes());
    Some(Zeroizing::new(*hasher.finalize().as_bytes()))
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key))
}

fn text(bytes: &[u8]) -> Result<String, KnockError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| KnockError::Malformed)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KnockError> {
        if self.0.len() < n {
            return Err(KnockError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<usize, KnockError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceCert;

    const NOW: u64 = 1_800_000_000;
    const LOOKUP: [u8; 16] = [7; 16];

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

    fn from(p: &Person) -> KnockFrom<'_> {
        KnockFrom {
            root: &p.root,
            device: &p.device,
            devices: &p.devices,
            name: "Alice",
        }
    }

    #[test]
    fn round_trip() {
        let (alice, bob) = (person(), person());
        let bytes = seal_knock(&from(&alice), &bob.root.id(), &LOOKUP, "hi, it's me", NOW).unwrap();
        let knock = open_knock(&bob.root, &LOOKUP, &bytes, NOW + 60).unwrap();
        assert_eq!(knock.sender, alice.root.id());
        assert_eq!(
            (knock.name.as_str(), knock.note.as_str()),
            ("Alice", "hi, it's me")
        );
        assert_eq!(knock.created_at, NOW);
        assert_eq!(knock.devices.root(), alice.root.id());

        let (lookup, slot) = knock_outer(&bytes).unwrap();
        assert_eq!(lookup, LOOKUP);
        let pair = PairKeys::new(&bob.root, &alice.root.id()).unwrap();
        assert_eq!(slot, pair.knock_slot(&LOOKUP));
        // A resend lands in the same slot; another code's doesn't.
        let again = seal_knock(&from(&alice), &bob.root.id(), &LOOKUP, "", NOW).unwrap();
        assert_eq!(knock_outer(&again).unwrap().1, slot);
        assert_ne!(pair.knock_slot(&[8; 16]), slot);
    }

    #[test]
    fn refusals() {
        let (alice, bob, eve) = (person(), person(), person());
        let bytes = seal_knock(&from(&alice), &bob.root.id(), &LOOKUP, "", NOW).unwrap();

        for i in [0, 20, 30, 60, 90, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            assert!(
                open_knock(&bob.root, &LOOKUP, &tampered, NOW).is_err(),
                "byte {i}"
            );
        }
        assert_eq!(
            open_knock(&eve.root, &LOOKUP, &bytes, NOW).unwrap_err(),
            KnockError::NotForUs
        );
        // Moved under another code by whoever holds it.
        let mut moved = bytes.clone();
        moved[..16].copy_from_slice(&[8; 16]);
        assert_eq!(
            open_knock(&bob.root, &[8; 16], &moved, NOW).unwrap_err(),
            KnockError::NotForUs
        );
        assert_eq!(
            open_knock(&bob.root, &[8; 16], &bytes, NOW).unwrap_err(),
            KnockError::NotForUs
        );
        assert_eq!(
            open_knock(&bob.root, &LOOKUP, &bytes, NOW + OLDEST + 1).unwrap_err(),
            KnockError::OutOfDate
        );
        assert_eq!(
            open_knock(&bob.root, &LOOKUP, &bytes, NOW - AHEAD - 1).unwrap_err(),
            KnockError::OutOfDate
        );
    }

    #[test]
    fn a_device_not_in_the_list_is_refused() {
        let (alice, bob) = (person(), person());
        let stranger = DeviceKey::generate().unwrap();
        let knock = KnockFrom {
            device: &stranger,
            ..from(&alice)
        };
        let bytes = seal_knock(&knock, &bob.root.id(), &LOOKUP, "", NOW).unwrap();
        assert_eq!(
            open_knock(&bob.root, &LOOKUP, &bytes, NOW).unwrap_err(),
            KnockError::NotCurrent
        );
    }

    #[test]
    fn long_notes_are_refused() {
        let (alice, bob) = (person(), person());
        let note = "x".repeat(MAX_NOTE + 1);
        assert_eq!(
            seal_knock(&from(&alice), &bob.root.id(), &LOOKUP, &note, NOW).unwrap_err(),
            KnockError::TooLong
        );
    }
}
