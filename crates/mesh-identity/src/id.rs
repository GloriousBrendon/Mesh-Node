//! Keys and the permanent ID. A person's ID is their root Ed25519 public key,
//! written `mesh1…` (bech32m: a checksum catches typos). Each install also has
//! its own device key, certified by the root key (see `device.rs`).

use std::fmt;

use bech32::Bech32m;
use bech32::primitives::decode::CheckedHrpstring;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::code::{CodeError, FriendCode};

const HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("mesh");
/// `mesh1` + 52 data characters (32 bytes) + a 6-character checksum.
const ID_TEXT_LEN: usize = 63;
const LINK_PREFIX: &str = "mesh://";

/// Why some text isn't a Mesh ID or link; each says what to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("that ID has a typo: its checksum doesn't match")]
    Checksum,
    #[error("that isn't a Mesh ID: Mesh IDs start with mesh1")]
    NotMesh,
    #[error("that ID is too short or too long")]
    Length,
    #[error("that ID mixes capital and small letters")]
    MixedCase,
    #[error("that ID isn't a valid key")]
    NotAKey,
    #[error("that isn't a Mesh link")]
    NotALink,
    #[error("{0}")]
    Code(#[from] CodeError),
}

/// A person's root key: their identity. It signs only identity records
/// (device certificates and lists, friend codes), never chat traffic.
pub struct RootKey(SigningKey);

/// One install's key. It is the device's transport identity (iroh's key).
pub struct DeviceKey(SigningKey);

impl RootKey {
    /// A new root key from the OS random number generator.
    pub fn generate() -> Result<Self, getrandom::Error> {
        Ok(Self(random_signing_key()?))
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&secret))
    }

    /// The secret, for the keystore; wiped when dropped.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn id(&self) -> MeshId {
        MeshId(self.0.verifying_key())
    }

    /// Signs `body` under a domain string (e.g. `mesh/v1/device-cert`), so a
    /// signature made for one kind of record can't be passed off as another.
    pub fn sign(&self, domain: &str, body: &[u8]) -> Signature {
        self.0.sign(&signed_bytes(domain, body))
    }
}

impl DeviceKey {
    /// A new device key from the OS random number generator.
    pub fn generate() -> Result<Self, getrandom::Error> {
        Ok(Self(random_signing_key()?))
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&secret))
    }

    /// The secret, for the keystore; wiped when dropped.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

fn random_signing_key() -> Result<SigningKey, getrandom::Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut())?;
    Ok(SigningKey::from_bytes(&secret))
}

/// What a domain-separated signature covers: the domain, a 0 byte, the body.
/// Domains are fixed ASCII strings without 0 bytes, so the split is unambiguous.
pub(crate) fn signed_bytes(domain: &str, body: &[u8]) -> Vec<u8> {
    debug_assert!(!domain.as_bytes().contains(&0));
    let mut bytes = Vec::with_capacity(domain.len() + 1 + body.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(body);
    bytes
}

/// A person's permanent ID: their root public key, shown as `mesh1…`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MeshId(VerifyingKey);

impl MeshId {
    /// Parses `mesh1…` text (surrounding spaces and all-capitals are fine, as
    /// QR codes use capitals); each failure says what's wrong, for the UI.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let text = text.trim();
        if text.chars().any(|c| c.is_ascii_uppercase())
            && text.chars().any(|c| c.is_ascii_lowercase())
        {
            return Err(IdError::MixedCase);
        }
        let text = text.to_ascii_lowercase();
        if !text.starts_with("mesh1") {
            return Err(IdError::NotMesh);
        }
        // Checked before the checksum, so a cut-off ID says "too short", not "typo".
        if text.len() != ID_TEXT_LEN {
            return Err(IdError::Length);
        }
        let checked = CheckedHrpstring::new::<Bech32m>(&text).map_err(|_| IdError::Checksum)?;
        let bytes: [u8; 32] = checked
            .byte_iter()
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| IdError::Length)?;
        Self::from_bytes(&bytes)
    }

    /// Rejects encodings that aren't valid keys, so a corrupted ID can't
    /// parse as somebody else's.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, IdError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| IdError::NotAKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Whether `signature` is this ID's root key signing `body` under `domain`.
    pub fn verify(&self, domain: &str, body: &[u8], signature: &Signature) -> bool {
        // Strict: rejects weak keys and malleable signatures.
        self.0
            .verify_strict(&signed_bytes(domain, body), signature)
            .is_ok()
    }

    /// `mesh://id/mesh1…`: what QR codes and shared links carry.
    pub fn link(&self) -> String {
        format!("{LINK_PREFIX}id/{self}")
    }
}

impl fmt::Display for MeshId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Can't fail: the prefix is valid and 32 bytes fit well under bech32's limit.
        let text =
            bech32::encode_lower::<Bech32m>(HRP, self.0.as_bytes()).map_err(|_| fmt::Error)?;
        f.write_str(&text)
    }
}

impl fmt::Debug for MeshId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MeshId({self})")
    }
}

/// Something shared by hand: an ID (a `mesh://id/` link or bare `mesh1…`
/// text) or a friend code (a `mesh://code/` link).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Id(MeshId),
    Code(FriendCode),
}

impl Link {
    /// Parses `mesh://id/mesh1…` or bare `mesh1…` (what people paste).
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let text = text.trim();
        match text.get(..LINK_PREFIX.len()) {
            Some(scheme) if scheme.eq_ignore_ascii_case(LINK_PREFIX) => {
                let rest = &text[LINK_PREFIX.len()..];
                match rest.split_once('/') {
                    Some((kind, id)) if kind.eq_ignore_ascii_case("id") => {
                        MeshId::parse(id).map(Link::Id)
                    }
                    Some((kind, code)) if kind.eq_ignore_ascii_case("code") => {
                        Ok(Link::Code(FriendCode::parse(code)?))
                    }
                    _ => Err(IdError::NotALink),
                }
            }
            _ => MeshId::parse(text).map(Link::Id),
        }
    }
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Link::Id(id) => f.write_str(&id.link()),
            Link::Code(code) => f.write_str(&code.link()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn some_id() -> MeshId {
        RootKey::generate().unwrap().id()
    }

    #[test]
    fn text_and_link_round_trip() {
        let id = some_id();
        let text = id.to_string();
        assert_eq!(text.len(), ID_TEXT_LEN);
        assert_eq!(MeshId::parse(&text), Ok(id));
        assert_eq!(
            MeshId::parse(&format!("  {}\n", text.to_ascii_uppercase())),
            Ok(id)
        );
        assert_eq!(Link::parse(&id.link()), Ok(Link::Id(id)));
        assert_eq!(Link::parse(&text), Ok(Link::Id(id)));
        assert_eq!(
            Link::parse(&format!("MESH://ID/{}", text.to_ascii_uppercase())),
            Ok(Link::Id(id))
        );
        assert_eq!(Link::Id(id).to_string(), id.link());
        let code = FriendCode::parse("K7QM-3XPA").unwrap();
        assert_eq!(Link::parse("mesh://code/k7qm-3xpa"), Ok(Link::Code(code)));
        assert_eq!(Link::Code(code).to_string(), "mesh://code/K7QM-3XPA");
    }

    #[test]
    fn each_mistake_has_its_own_error() {
        let text = some_id().to_string();
        // One changed character: the checksum catches it.
        let mut typo = text.clone().into_bytes();
        typo[20] = if typo[20] == b'q' { b'p' } else { b'q' };
        assert_eq!(
            MeshId::parse(std::str::from_utf8(&typo).unwrap()),
            Err(IdError::Checksum)
        );
        assert_eq!(MeshId::parse(&text[..40]), Err(IdError::Length));
        assert_eq!(MeshId::parse(&format!("{text}q")), Err(IdError::Length));
        assert_eq!(
            MeshId::parse(&text.replacen("mesh1", "npub1", 1)),
            Err(IdError::NotMesh)
        );
        assert_eq!(
            MeshId::parse(&format!("M{}", &text[1..])),
            Err(IdError::MixedCase)
        );
        assert_eq!(MeshId::parse(""), Err(IdError::NotMesh));
        assert_eq!(Link::parse("mesh://space/abc"), Err(IdError::NotALink));
        assert_eq!(Link::parse("mesh://id"), Err(IdError::NotALink));
        assert_eq!(
            Link::parse("mesh://code/K7QM-3XPU"),
            Err(IdError::Code(CodeError::BadCharacter('U')))
        );
    }

    #[test]
    fn a_well_formed_id_that_is_not_a_key_is_refused() {
        // Some 32-byte strings aren't points on the curve; find one and encode it.
        let bytes = (0u8..=255)
            .map(|b| [b; 32])
            .find(|b| VerifyingKey::from_bytes(b).is_err())
            .unwrap();
        let text = bech32::encode_lower::<Bech32m>(HRP, &bytes).unwrap();
        assert_eq!(MeshId::parse(&text), Err(IdError::NotAKey));
    }

    #[test]
    fn signatures_are_bound_to_their_domain_and_key() {
        let root = RootKey::generate().unwrap();
        let sig = root.sign("mesh/v1/test", b"hello");
        assert!(root.id().verify("mesh/v1/test", b"hello", &sig));
        assert!(!root.id().verify("mesh/v1/other", b"hello", &sig));
        assert!(!root.id().verify("mesh/v1/test", b"hellO", &sig));
        assert!(!some_id().verify("mesh/v1/test", b"hello", &sig));
        // The domain boundary can't be shifted into the body.
        assert_ne!(
            signed_bytes("mesh/v1/a", b"b"),
            signed_bytes("mesh/v1/ab", b"")
        );
    }

    #[test]
    fn keys_survive_their_secret_bytes() {
        let root = RootKey::generate().unwrap();
        assert_eq!(
            RootKey::from_secret_bytes(*root.secret_bytes()).id(),
            root.id()
        );
        let device = DeviceKey::generate().unwrap();
        assert_eq!(
            DeviceKey::from_secret_bytes(*device.secret_bytes()).public(),
            device.public()
        );
        assert_ne!(device.public().to_bytes(), root.id().to_bytes());
    }

    proptest! {
        #[test]
        fn any_key_round_trips(secret in any::<[u8; 32]>()) {
            let id = RootKey::from_secret_bytes(secret).id();
            prop_assert_eq!(MeshId::parse(&id.to_string()), Ok(id));
            prop_assert_eq!(Link::parse(&id.link()), Ok(Link::Id(id)));
        }
    }
}
