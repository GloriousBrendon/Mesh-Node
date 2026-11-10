//! The envelope (D2, D8, D9, D10): one format for every path. The inside is
//! padded and then encrypted by a session or chain; the envelope says which.
//! Anything a third party holds is sealed again to the reader's device key,
//! so the holder sees only the carrier's address, a throwaway key and a
//! padded length.
//!
//! Layout (big-endian):
//!
//! ```text
//! envelope = version u8 | type u8 | payload
//!   type 1 = olm first message, 2 = olm message, 3 = group message
//! sealed   = address [carrier-defined] | throwaway key [32] | nonce [24]
//!          | XChaCha20-Poly1305(envelope) + 16 tag
//!   key = blake3::derive_key("mesh/v1/seal-key",
//!                            X25519(throwaway, reader) | throwaway | reader)
//!   associated data = address | throwaway key | nonce
//! inside   = version u8 | conversation [16] | kind u8 | sender list seq u64
//!          | body len u32 | body | zero padding
//!   kind 1 = message, 2 = key share, 3 = key request, 4 = secret, 5 = test note
//! ```

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::VerifyingKey;
use mesh_identity::DeviceKey;
use zeroize::Zeroizing;

use crate::E2eeError;

const FORMAT_V1: u8 = 1;
const SEAL_CONTEXT: &str = "mesh/v1/seal-key";
const INSIDE_HEAD: usize = 1 + 16 + 1 + 8 + 4;
const SEAL_HEAD: usize = 32 + 24;
/// The padded sizes of the inside, before 16 KiB steps (D9).
const SMALL_SIZES: [usize; 3] = [256, 1024, 4096];
const STEP: usize = 16 * 1024;
/// The largest padded inside.
pub const MAX_INSIDE: usize = 64 * 1024;
/// The longest body an inside can carry.
pub const MAX_BODY: usize = MAX_INSIDE - INSIDE_HEAD;

/// Which session or chain encrypted an envelope's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeType {
    OlmFirst = 1,
    Olm = 2,
    Group = 3,
}

/// What an inside carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The caller's message (`dm`, `spaces`).
    Message = 1,
    KeyShare = 2,
    KeyRequest = 3,
    /// A secret for calls.
    Secret = 4,
    TestNote = 5,
}

impl Kind {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Message,
            2 => Self::KeyShare,
            3 => Self::KeyRequest,
            4 => Self::Secret,
            5 => Self::TestNote,
            _ => return None,
        })
    }
}

/// An envelope: its type and the encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: EnvelopeType,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.payload.len());
        out.extend_from_slice(&[FORMAT_V1, self.kind as u8]);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, E2eeError> {
        let kind = match bytes {
            [FORMAT_V1, 1, ..] => EnvelopeType::OlmFirst,
            [FORMAT_V1, 2, ..] => EnvelopeType::Olm,
            [FORMAT_V1, 3, ..] => EnvelopeType::Group,
            _ => return Err(E2eeError::Malformed),
        };
        Ok(Self {
            kind,
            payload: bytes[2..].to_vec(),
        })
    }
}

/// What goes inside the encryption: never outside it (D10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inside {
    pub conversation: [u8; 16],
    pub kind: Kind,
    /// The sender's device list `seq` when they sent it.
    pub seq: u64,
    pub body: Vec<u8>,
}

impl Inside {
    /// The padded bytes, sized to one of D9's buckets.
    pub fn to_bytes(&self) -> Result<Vec<u8>, E2eeError> {
        if self.body.len() > MAX_BODY {
            return Err(E2eeError::TooLong);
        }
        let mut out = Vec::with_capacity(padded_len(INSIDE_HEAD + self.body.len()));
        out.push(FORMAT_V1);
        out.extend_from_slice(&self.conversation);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out.resize(padded_len(out.len()), 0);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, E2eeError> {
        let bad = E2eeError::Malformed;
        if bytes.len() < INSIDE_HEAD || bytes.len() != padded_len(bytes.len()) {
            return Err(bad);
        }
        if bytes[0] != FORMAT_V1 {
            return Err(bad);
        }
        let kind = Kind::from_byte(bytes[17]).ok_or(bad)?;
        let len = u32::from_be_bytes(bytes[26..30].try_into().expect("4 bytes")) as usize;
        let body = bytes.get(INSIDE_HEAD..INSIDE_HEAD + len).ok_or(bad)?;
        if bytes[INSIDE_HEAD + len..].iter().any(|&b| b != 0) {
            return Err(bad);
        }
        Ok(Self {
            conversation: bytes[1..17].try_into().expect("16 bytes"),
            kind,
            seq: u64::from_be_bytes(bytes[18..26].try_into().expect("8 bytes")),
            body: body.to_vec(),
        })
    }
}

/// The bucket a plaintext of `len` bytes is padded to (D9).
fn padded_len(len: usize) -> usize {
    match SMALL_SIZES.iter().find(|&&size| len <= size) {
        Some(&size) => size,
        None => len.div_ceil(STEP) * STEP,
    }
}

/// Seals `envelope` to `reader`'s device key, behind the carrier's
/// `address` (D8).
pub fn seal_for(
    reader: &VerifyingKey,
    address: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let throwaway = DeviceKey::generate().map_err(|_| E2eeError::Random)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| E2eeError::Random)?;
    seal_with(&throwaway, nonce, reader, address, envelope)
}

pub(crate) fn seal_with(
    throwaway: &DeviceKey,
    nonce: [u8; 24],
    reader: &VerifyingKey,
    address: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let public = throwaway.public();
    let shared = throwaway
        .diffie_hellman(reader)
        .ok_or(E2eeError::Malformed)?;
    let mut out = Vec::with_capacity(address.len() + SEAL_HEAD + envelope.len() + 16);
    out.extend_from_slice(address);
    out.extend_from_slice(public.as_bytes());
    out.extend_from_slice(&nonce);
    let sealed = cipher(&shared, &public, reader)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: envelope,
                aad: &out,
            },
        )
        .map_err(|_| E2eeError::Malformed)?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a sealed envelope with this device's key. The first `address_len`
/// bytes are the carrier's address.
pub fn open_sealed(
    device: &DeviceKey,
    address_len: usize,
    bytes: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let head = address_len + SEAL_HEAD;
    if bytes.len() < head + 16 {
        return Err(E2eeError::Malformed);
    }
    let throwaway = &bytes[address_len..address_len + 32];
    let throwaway = VerifyingKey::from_bytes(throwaway.try_into().expect("32 bytes"))
        .map_err(|_| E2eeError::Malformed)?;
    let shared = device
        .diffie_hellman(&throwaway)
        .ok_or(E2eeError::Malformed)?;
    let nonce: [u8; 24] = bytes[address_len + 32..head].try_into().expect("24 bytes");
    cipher(&shared, &throwaway, &device.public())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &bytes[head..],
                aad: &bytes[..head],
            },
        )
        .map_err(|_| E2eeError::NotForUs)
}

fn cipher(
    shared: &Zeroizing<[u8; 32]>,
    throwaway: &VerifyingKey,
    reader: &VerifyingKey,
) -> XChaCha20Poly1305 {
    let mut material = Zeroizing::new([0u8; 96]);
    material[..32].copy_from_slice(shared.as_ref());
    material[32..64].copy_from_slice(throwaway.as_bytes());
    material[64..].copy_from_slice(reader.as_bytes());
    let key = Zeroizing::new(blake3::derive_key(SEAL_CONTEXT, material.as_ref()));
    XChaCha20Poly1305::new(&Key::from(*key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inside(len: usize) -> Inside {
        Inside {
            conversation: [7; 16],
            kind: Kind::TestNote,
            seq: 3,
            body: vec![b'x'; len],
        }
    }

    #[test]
    fn every_padded_size() {
        let cases = [
            (0, 256),
            (256 - INSIDE_HEAD, 256),
            (256 - INSIDE_HEAD + 1, 1024),
            (1024 - INSIDE_HEAD + 1, 4096),
            (4096 - INSIDE_HEAD + 1, 16384),
            (16384 - INSIDE_HEAD + 1, 32768),
            (32768, 49152),
            (49152, MAX_INSIDE),
            (MAX_BODY, MAX_INSIDE),
        ];
        for (body, size) in cases {
            let bytes = inside(body).to_bytes().unwrap();
            assert_eq!(bytes.len(), size, "body {body}");
            assert_eq!(Inside::from_bytes(&bytes).unwrap(), inside(body));
        }
        assert_eq!(
            inside(MAX_BODY + 1).to_bytes().unwrap_err(),
            E2eeError::TooLong
        );
    }

    #[test]
    fn damaged_insides_are_refused() {
        let bytes = inside(10).to_bytes().unwrap();
        let mut bad = vec![
            bytes[..255].to_vec(),             // not a bucket size
            [bytes.clone(), vec![0]].concat(), // nor this
        ];
        for (at, value) in [(0, 2), (17, 9), (26, 0xff), (200, 1)] {
            let mut b = bytes.clone();
            b[at] = value;
            bad.push(b);
        }
        for b in bad {
            assert_eq!(Inside::from_bytes(&b).unwrap_err(), E2eeError::Malformed);
        }
        assert!(Envelope::from_bytes(&[1, 4, 0]).is_err());
        assert!(Envelope::from_bytes(&[2, 1, 0]).is_err());
    }

    #[test]
    fn seal_round_trip() {
        let reader = DeviceKey::generate().unwrap();
        let envelope = Envelope {
            kind: EnvelopeType::Group,
            payload: vec![9; 300],
        }
        .to_bytes();
        let sealed = seal_for(&reader.public(), b"addr", &envelope).unwrap();
        assert_eq!(&sealed[..4], b"addr");
        assert_eq!(sealed.len(), 4 + SEAL_HEAD + envelope.len() + 16);
        assert_eq!(open_sealed(&reader, 4, &sealed).unwrap(), envelope);
        // A fresh throwaway key each time: two seals of one envelope differ.
        assert_ne!(
            seal_for(&reader.public(), b"addr", &envelope).unwrap(),
            sealed
        );
    }

    #[test]
    fn seal_refusals() {
        let (reader, other) = (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        );
        let sealed = seal_for(&reader.public(), b"addr", b"envelope").unwrap();
        assert_eq!(
            open_sealed(&other, 4, &sealed).unwrap_err(),
            E2eeError::NotForUs
        );
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(open_sealed(&reader, 4, &tampered).is_err(), "byte {i}");
        }
        assert!(open_sealed(&reader, 4, &sealed[..40]).is_err());
        assert!(open_sealed(&reader, 3, &sealed).is_err());
    }

    #[test]
    fn a_seal_shows_no_sender_session_or_conversation() {
        let (reader, sender) = (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        );
        let conversation = [0x5a; 16];
        let chain = [0xc3; 32];
        // Worst case: the payload carries all three in the clear.
        let inside = Inside {
            conversation,
            kind: Kind::Message,
            seq: 1,
            body: b"hi".to_vec(),
        };
        let mut payload = sender.public().as_bytes().to_vec();
        payload.extend_from_slice(&chain);
        payload.extend_from_slice(&inside.to_bytes().unwrap());
        let envelope = Envelope {
            kind: EnvelopeType::Group,
            payload,
        }
        .to_bytes();
        let sealed = seal_for(&reader.public(), &[0; 16], &envelope).unwrap();
        for needle in [&sender.public().as_bytes()[..], &chain, &conversation] {
            assert!(!contains(&sealed, needle));
        }
    }

    pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }
}
