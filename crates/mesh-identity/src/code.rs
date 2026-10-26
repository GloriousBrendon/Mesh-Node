//! Friend codes: short codes like `K7QM-3XPA` that point to an ID, shared by
//! hand the way Discord invites are. A code is only a pointer; trust comes
//! from the safety number.
//!
//! The code derives (Argon2id) a `lookup_id`, which the record is stored and
//! found under, and a `record_key`, which encrypts it. Whoever holds records
//! (a seed in v1) sees neither the code nor the ID. It does see the expiry and
//! use limit, which it enforces, and a revoke tag: revoking reveals the secret
//! behind that tag, which only the owner's root key can derive, so revoking
//! doesn't reveal the ID either.
//!
//! Held record layout (big-endian), the part before the nonce authenticated
//! as associated data:
//!
//! ```text
//! lookup_id [16] | expires_at u64 | max_uses u32 | revoke_tag [32]
//!                | nonce [24] | encrypted (body | signature [64]) + 16 tag
//! body = version u8 | root [32] | lookup_id [16] | created_at u64
//!        | expires_at u64 | max_uses u32
//! ```
//!
//! `expires_at = 0` means never; `max_uses = 0` means unlimited.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::id::{MeshId, RootKey};

/// Crockford base32: no I, L, O or U, so codes read aloud unambiguously.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 8;
const KDF_SALT: &[u8] = b"mesh/v1/code";
/// Fixed for good: every client must derive the same lookup ID from a code.
/// About 100 ms; with seed rate limits, guessing 40-bit codes is hopeless.
const KDF_M_KIB: u32 = 64 * 1024;
const KDF_T: u32 = 5;
const RECORD_DOMAIN: &str = "mesh/v1/code-record";
const REVOKE_CONTEXT: &str = "mesh/v1/code-revoke";
const FORMAT_V1: u8 = 1;
const BODY_LEN: usize = 1 + 32 + 16 + 8 + 8 + 4;
const OUTER_LEN: usize = 16 + 8 + 4 + 32;
const NONCE_LEN: usize = 24;
/// Outer part, nonce, body, signature and the AEAD tag.
const HELD_LEN: usize = OUTER_LEN + NONCE_LEN + BODY_LEN + 64 + 16;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
/// How long a code can last, in seconds; `None` is never (only when chosen).
pub const EXPIRY_CHOICES: [Option<u64>; 7] = [
    Some(30 * MINUTE),
    Some(HOUR),
    Some(6 * HOUR),
    Some(12 * HOUR),
    Some(DAY),
    Some(7 * DAY),
    None,
];
pub const DEFAULT_EXPIRY: Option<u64> = Some(7 * DAY);
/// How many times a code can be looked up; `None` is unlimited.
pub const USE_CHOICES: [Option<u32>; 5] = [Some(1), Some(5), Some(10), Some(25), None];
pub const DEFAULT_USES: Option<u32> = Some(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    #[error("a friend code is 8 characters, like K7QM-3XPA")]
    Length,
    #[error("'{0}' can't be in a friend code")]
    BadCharacter(char),
    #[error("that expiry or use limit isn't one of the choices")]
    NotAChoice,
    #[error("that code doesn't match this record")]
    WrongCode,
    #[error("the record isn't signed by the ID inside it")]
    BadSignature,
    #[error("that friend code has expired")]
    Expired,
    #[error("the record is damaged or in an unknown format")]
    Malformed,
    #[error("couldn't get randomness from the system")]
    Random,
}

/// A friend code: 40 random bits, shown as `XXXX-XXXX`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
pub struct FriendCode([u8; 5]);

impl FriendCode {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 5];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Lenient, for codes typed by hand: any case, hyphens and spaces
    /// ignored, `I`/`L` read as `1` and `O` as `0`.
    pub fn parse(text: &str) -> Result<Self, CodeError> {
        let mut n = 0u64;
        let mut len = 0;
        for c in text.chars().filter(|c| *c != '-' && !c.is_whitespace()) {
            let c = match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                c => c,
            };
            let value = ALPHABET
                .iter()
                .position(|&a| char::from(a) == c)
                .ok_or(CodeError::BadCharacter(c))?;
            n = n << 5 | value as u64;
            len += 1;
            if len > CODE_LEN {
                return Err(CodeError::Length);
            }
        }
        if len != CODE_LEN {
            return Err(CodeError::Length);
        }
        Ok(Self(n.to_be_bytes()[3..].try_into().expect("5 bytes")))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }

    /// `mesh://code/K7QM-3XPA`.
    pub fn link(&self) -> String {
        format!("mesh://code/{self}")
    }

    /// What a holder files this code's record under. Runs the Argon2id
    /// derivation (about 100 ms), so call it off any UI or async thread.
    pub fn lookup_id(&self) -> [u8; 16] {
        self.keys().0
    }

    /// The lookup ID and record key (Argon2id, fixed settings).
    fn keys(&self) -> ([u8; 16], Zeroizing<[u8; 32]>) {
        let params = argon2::Params::new(KDF_M_KIB, KDF_T, 1, Some(48)).expect("valid settings");
        let mut out = Zeroizing::new([0u8; 48]);
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(&self.0, KDF_SALT, out.as_mut())
            .expect("valid lengths");
        let lookup_id = out[..16].try_into().expect("16 bytes");
        let record_key = Zeroizing::new(out[16..].try_into().expect("32 bytes"));
        (lookup_id, record_key)
    }
}

impl fmt::Display for FriendCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0.iter().fold(0u64, |n, &b| n << 8 | u64::from(b));
        for i in 0..CODE_LEN {
            if i == 4 {
                f.write_str("-")?;
            }
            let value = (n >> (5 * (CODE_LEN - 1 - i))) & 31;
            write!(f, "{}", char::from(ALPHABET[value as usize]))?;
        }
        Ok(())
    }
}

impl fmt::Debug for FriendCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FriendCode({self})")
    }
}

/// A verified record: the ID a code points to, and its limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRecord {
    root: MeshId,
    created_at: u64,
    expires_at: u64,
    max_uses: u32,
}

impl CodeRecord {
    /// The ID the code points to.
    pub fn root(&self) -> MeshId {
        self.root
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Unix seconds; `None` never expires.
    pub fn expires_at(&self) -> Option<u64> {
        (self.expires_at != 0).then_some(self.expires_at)
    }

    /// `None` is unlimited.
    pub fn max_uses(&self) -> Option<u32> {
        (self.max_uses != 0).then_some(self.max_uses)
    }
}

/// A record as its holder stores it: encrypted under the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCode(Vec<u8>);

impl HeldCode {
    /// The owner's record for `code`, valid from `created_at` for `expiry`
    /// seconds and `uses` lookups (one of the choices above).
    pub fn new(
        root: &RootKey,
        code: &FriendCode,
        created_at: u64,
        expiry: Option<u64>,
        uses: Option<u32>,
    ) -> Result<Self, CodeError> {
        if !EXPIRY_CHOICES.contains(&expiry) || !USE_CHOICES.contains(&uses) {
            return Err(CodeError::NotAChoice);
        }
        let expires_at = expiry.map_or(0, |s| created_at + s);
        let max_uses = uses.unwrap_or(0);
        let (lookup_id, record_key) = code.keys();
        let body = record_body(&root.id(), &lookup_id, created_at, expires_at, max_uses);
        let mut plain = body.clone();
        plain.extend_from_slice(&root.sign(RECORD_DOMAIN, &body).to_bytes());

        let mut held = Vec::with_capacity(HELD_LEN);
        held.extend_from_slice(&lookup_id);
        held.extend_from_slice(&expires_at.to_be_bytes());
        held.extend_from_slice(&max_uses.to_be_bytes());
        held.extend_from_slice(blake3::hash(revoke_secret(root, &lookup_id).as_ref()).as_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| CodeError::Random)?;
        let sealed = XChaCha20Poly1305::new(&Key::from(*record_key))
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &held,
                },
            )
            .map_err(|_| CodeError::Malformed)?;
        held.extend_from_slice(&nonce);
        held.extend_from_slice(&sealed);
        Ok(Self(held))
    }

    /// Checks the length only; the rest is checked on opening.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodeError> {
        if bytes.len() != HELD_LEN {
            return Err(CodeError::Malformed);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// What the holder files the record under.
    pub fn lookup_id(&self) -> [u8; 16] {
        self.0[..16].try_into().expect("16 bytes")
    }

    /// Unix seconds, for the holder to enforce; `None` never expires.
    pub fn expires_at(&self) -> Option<u64> {
        let at = u64::from_be_bytes(self.0[16..24].try_into().expect("8 bytes"));
        (at != 0).then_some(at)
    }

    /// For the holder to count down; `None` is unlimited.
    pub fn max_uses(&self) -> Option<u32> {
        let uses = u32::from_be_bytes(self.0[24..28].try_into().expect("4 bytes"));
        (uses != 0).then_some(uses)
    }

    /// The hash of the owner's revoke secret: the same for every record the
    /// owner makes for this code, so a holder can tell a repeat hold by the
    /// owner from someone else's record under the same lookup ID.
    pub fn revoke_tag(&self) -> [u8; 32] {
        self.0[28..OUTER_LEN].try_into().expect("32 bytes")
    }

    /// Whether `revoke` is the owner revoking this record.
    pub fn is_revoked_by(&self, revoke: &CodeRevoke) -> bool {
        // blake3::Hash compares in constant time.
        revoke.lookup_id == self.lookup_id() && blake3::hash(&revoke.secret) == self.revoke_tag()
    }

    /// Decrypts and verifies the record with the code someone typed, refusing
    /// it if it expired before `now` (Unix seconds).
    pub fn open(&self, code: &FriendCode, now: u64) -> Result<CodeRecord, CodeError> {
        let (lookup_id, record_key) = code.keys();
        if lookup_id != self.lookup_id() {
            return Err(CodeError::WrongCode);
        }
        let (outer, rest) = self.0.split_at(OUTER_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let plain = XChaCha20Poly1305::new(&Key::from(*record_key))
            .decrypt(
                &XNonce::from(<[u8; NONCE_LEN]>::try_from(nonce).expect("nonce")),
                Payload {
                    msg: sealed,
                    aad: outer,
                },
            )
            .map_err(|_| CodeError::WrongCode)?;
        let (body, signature) = plain.split_at(BODY_LEN);
        if body[0] != FORMAT_V1 || body[33..49] != lookup_id {
            return Err(CodeError::Malformed);
        }
        let root = MeshId::from_bytes(body[1..33].try_into().expect("32 bytes"))
            .map_err(|_| CodeError::Malformed)?;
        let signature = Signature::from_bytes(signature.try_into().expect("64 bytes"));
        if !root.verify(RECORD_DOMAIN, body, &signature) {
            return Err(CodeError::BadSignature);
        }
        let record = CodeRecord {
            root,
            created_at: u64::from_be_bytes(body[49..57].try_into().expect("8 bytes")),
            expires_at: u64::from_be_bytes(body[57..65].try_into().expect("8 bytes")),
            max_uses: u32::from_be_bytes(body[65..69].try_into().expect("4 bytes")),
        };
        // The holder's copy of the limits must be the ones the owner signed.
        if record.expires_at() != self.expires_at() || record.max_uses() != self.max_uses() {
            return Err(CodeError::Malformed);
        }
        if record.expires_at().is_some_and(|at| at <= now) {
            return Err(CodeError::Expired);
        }
        Ok(record)
    }
}

/// The owner's instruction to a holder to delete a code's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRevoke {
    lookup_id: [u8; 16],
    secret: [u8; 32],
}

impl CodeRevoke {
    /// Any of the owner's devices can revoke any of their codes: it needs
    /// only the root key, not a record of having made the code.
    pub fn new(root: &RootKey, code: &FriendCode) -> Self {
        let (lookup_id, _) = code.keys();
        Self {
            lookup_id,
            secret: *revoke_secret(root, &lookup_id),
        }
    }

    pub fn lookup_id(&self) -> [u8; 16] {
        self.lookup_id
    }

    /// `lookup_id [16] | secret [32]`.
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[..16].copy_from_slice(&self.lookup_id);
        bytes[16..].copy_from_slice(&self.secret);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodeError> {
        let bytes: &[u8; 48] = bytes.try_into().map_err(|_| CodeError::Malformed)?;
        Ok(Self {
            lookup_id: bytes[..16].try_into().expect("16 bytes"),
            secret: bytes[16..].try_into().expect("32 bytes"),
        })
    }
}

/// A code the owner made on this device, kept in the keystore so they can see
/// and revoke it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct ActiveCode {
    pub code: FriendCode,
    pub created_at: u64,
    /// `None` never expires.
    pub expires_at: Option<u64>,
    /// `None` is unlimited.
    pub max_uses: Option<u32>,
}

fn record_body(
    root: &MeshId,
    lookup_id: &[u8; 16],
    created_at: u64,
    expires_at: u64,
    max_uses: u32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(BODY_LEN);
    body.push(FORMAT_V1);
    body.extend_from_slice(&root.to_bytes());
    body.extend_from_slice(lookup_id);
    body.extend_from_slice(&created_at.to_be_bytes());
    body.extend_from_slice(&expires_at.to_be_bytes());
    body.extend_from_slice(&max_uses.to_be_bytes());
    body
}

/// Only the root key can make this; the record holds just its hash.
fn revoke_secret(root: &RootKey, lookup_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        blake3::Hasher::new_derive_key(REVOKE_CONTEXT)
            .update(root.secret_bytes().as_ref())
            .update(lookup_id)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: u64 = 1_792_627_200;

    fn held(root: &RootKey, code: &FriendCode) -> HeldCode {
        HeldCode::new(root, code, NOW, DEFAULT_EXPIRY, DEFAULT_USES).unwrap()
    }

    #[test]
    fn typed_codes_are_read_leniently() {
        let code = FriendCode::parse("K7QM-3XPA").unwrap();
        assert_eq!(code.to_string(), "K7QM-3XPA");
        for typed in ["k7qm3xpa", " K7QM 3XPA ", "k7qm-3xpa", "K7QM--3XPA"] {
            assert_eq!(FriendCode::parse(typed), Ok(code), "{typed}");
        }
        assert_eq!(
            FriendCode::parse("I0LO-OOOO"),
            FriendCode::parse("1010-0000")
        );
        assert_eq!(
            FriendCode::parse("K7QM-3XPU"),
            Err(CodeError::BadCharacter('U'))
        );
        assert_eq!(FriendCode::parse("K7QM-3XP"), Err(CodeError::Length));
        assert_eq!(FriendCode::parse("K7QM-3XPAA"), Err(CodeError::Length));
        assert_eq!(FriendCode::parse(""), Err(CodeError::Length));
        assert_eq!(code.link(), "mesh://code/K7QM-3XPA");
    }

    #[test]
    fn the_right_code_opens_the_record() {
        let root = RootKey::generate().unwrap();
        let code = FriendCode::generate().unwrap();
        let held = held(&root, &code);
        let record = held.open(&code, NOW + 60).unwrap();
        assert_eq!(record.root(), root.id());
        assert_eq!(record.created_at(), NOW);
        assert_eq!(record.expires_at(), Some(NOW + 7 * DAY));
        assert_eq!(record.max_uses(), Some(1));
        assert_eq!(
            (held.expires_at(), held.max_uses()),
            (Some(NOW + 7 * DAY), Some(1))
        );
        assert_eq!(HeldCode::from_bytes(held.as_bytes()), Ok(held));
    }

    #[test]
    fn a_record_cant_be_read_without_its_code() {
        let root = RootKey::generate().unwrap();
        let code = FriendCode::generate().unwrap();
        let held = held(&root, &code);
        let other = FriendCode::generate().unwrap();
        assert_eq!(held.open(&other, NOW), Err(CodeError::WrongCode));
        // Nothing identifying is readable by the holder.
        let contains = |needle: &[u8]| held.as_bytes().windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&root.id().to_bytes()));
        assert!(!contains(&code.0));
        // Tampering anywhere stops it opening.
        for i in [0, 17, 25, 40, OUTER_LEN + 1, HELD_LEN - 1] {
            let mut bytes = held.as_bytes().to_vec();
            bytes[i] ^= 1;
            let tampered = HeldCode::from_bytes(&bytes).unwrap();
            assert!(tampered.open(&code, NOW).is_err(), "byte {i}");
        }
        assert_eq!(
            HeldCode::from_bytes(&held.as_bytes()[1..]),
            Err(CodeError::Malformed)
        );
    }

    #[test]
    fn a_record_signed_by_another_root_is_refused() {
        // Someone who knows the code re-seals the record claiming another ID.
        let (owner, liar) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let code = FriendCode::generate().unwrap();
        let (lookup_id, record_key) = code.keys();
        let body = record_body(&owner.id(), &lookup_id, NOW, 0, 0);
        let mut plain = body.clone();
        plain.extend_from_slice(&liar.sign(RECORD_DOMAIN, &body).to_bytes());
        let mut bytes = lookup_id.to_vec();
        bytes.extend_from_slice(&[0; 12]);
        bytes.extend_from_slice(&[0; 32]);
        let nonce = [7u8; NONCE_LEN];
        let sealed = XChaCha20Poly1305::new(&Key::from(*record_key))
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &bytes,
                },
            )
            .unwrap();
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&sealed);
        let forged = HeldCode::from_bytes(&bytes).unwrap();
        assert_eq!(forged.open(&code, NOW), Err(CodeError::BadSignature));
    }

    #[test]
    fn expiry_and_choices() {
        let root = RootKey::generate().unwrap();
        let code = FriendCode::generate().unwrap();
        let hour = HeldCode::new(&root, &code, NOW, Some(HOUR), None).unwrap();
        assert!(hour.open(&code, NOW + HOUR - 1).is_ok());
        assert_eq!(hour.open(&code, NOW + HOUR), Err(CodeError::Expired));
        assert_eq!(hour.max_uses(), None);
        let never = HeldCode::new(&root, &code, NOW, None, Some(5)).unwrap();
        let record = never.open(&code, u64::MAX).unwrap();
        assert_eq!((record.expires_at(), never.expires_at()), (None, None));
        assert_eq!(
            HeldCode::new(&root, &code, NOW, Some(2 * HOUR), None),
            Err(CodeError::NotAChoice)
        );
        assert_eq!(
            HeldCode::new(&root, &code, NOW, None, Some(0)),
            Err(CodeError::NotAChoice)
        );
    }

    #[test]
    fn only_the_owner_can_revoke() {
        let root = RootKey::generate().unwrap();
        let code = FriendCode::generate().unwrap();
        let held = held(&root, &code);
        let revoke = CodeRevoke::new(&root, &code);
        assert!(held.is_revoked_by(&revoke));
        assert_eq!(
            CodeRevoke::from_bytes(&revoke.to_bytes()),
            Ok(revoke.clone())
        );
        assert!(!held.is_revoked_by(&CodeRevoke::new(&RootKey::generate().unwrap(), &code)));
        let other = FriendCode::generate().unwrap();
        assert!(!held.is_revoked_by(&CodeRevoke::new(&root, &other)));
        // The revoke says nothing about the ID either.
        assert!(
            !revoke
                .to_bytes()
                .windows(32)
                .any(|w| w == root.id().to_bytes())
        );
    }

    proptest! {
        #[test]
        fn display_and_parse_round_trip(bytes in any::<[u8; 5]>()) {
            let code = FriendCode(bytes);
            let text = code.to_string();
            prop_assert_eq!(text.len(), 9);
            prop_assert_eq!(FriendCode::parse(&text), Ok(code));
            prop_assert_eq!(FriendCode::parse(&text.to_lowercase()), Ok(code));
        }
    }
}
