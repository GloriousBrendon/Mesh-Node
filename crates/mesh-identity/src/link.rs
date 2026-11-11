//! Device linking: an existing device E hands the identity to a new device N
//! after you type E's short link code on N. SPAKE2 turns the code into a
//! strong shared key, so an attacker gets one guess per code and E burns the
//! code after that one attempt.
//!
//! The messages, each a kind byte then its payload:
//!
//! ```text
//! 1 Hello     N → E  SPAKE2 message (role B)
//! 2 Reply     E → N  SPAKE2 message (role A) | confirm [32]
//! 3 Device    N → E  nonce [24] | sealed(device key [32] | name len u16 | name)
//! 4 Identity  E → N  nonce [24] | sealed(0 = cancelled
//!                                       | 1 | root secret [32] | username len u16
//!                                         | username | device list)
//! ```
//!
//! `confirm` proves to N that E derived the same key (so N knows a wrong code
//! at once); E learns it when N's Device message opens. Each direction's key
//! seals one message. Transport and rendezvous come with `transport`; this is
//! only the state machines.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::VerifyingKey;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::code::FriendCode;
use crate::device::{DeviceCert, DeviceError, DeviceList, MAX_DEVICE_NAME};
use crate::id::{DeviceKey, RootKey};
use crate::keystore::{Keystore, KeystoreError};

/// How long a link code works, in seconds.
pub const LINK_CODE_LIFETIME: u64 = 5 * 60;
const ID_EXISTING: &[u8] = b"mesh/v1/link-existing";
const ID_NEW: &[u8] = b"mesh/v1/link-new";
const CONFIRM_CONTEXT: &str = "mesh/v1/link-confirm";
const N_TO_E_CONTEXT: &str = "mesh/v1/link-new-to-existing";
const E_TO_N_CONTEXT: &str = "mesh/v1/link-existing-to-new";
const HELLO: u8 = 1;
const REPLY: u8 = 2;
const DEVICE: u8 = 3;
const IDENTITY: u8 = 4;
const NONCE_LEN: usize = 24;
/// The Argon2id salt for the link record's keys; friend codes use their own.
const LINK_SALT: &[u8] = b"mesh/v1/link-code";
/// The link record's slot: there's only ever one under its lookup ID.
const RECORD_SLOT: [u8; 8] = [0; 8];
const OUTER_LEN: usize = 16 + 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("that link code is wrong; make a new one on your other device")]
    WrongCode,
    #[error("that link code was already tried; make a new one")]
    CodeUsed,
    #[error("that link code has expired; make a new one")]
    Expired,
    #[error("linking was cancelled on your other device")]
    Cancelled,
    #[error("the other device sent something out of order")]
    Unexpected,
    #[error("the other device sent something damaged")]
    Malformed,
    #[error("{0}")]
    Code(#[from] crate::code::CodeError),
    #[error("{0}")]
    Device(#[from] DeviceError),
    #[error("couldn't get randomness from the system")]
    Random,
}

/// The keys both sides derive from the SPAKE2 secret.
struct Keys {
    confirm: Zeroizing<[u8; 32]>,
    new_to_existing: Zeroizing<[u8; 32]>,
    existing_to_new: Zeroizing<[u8; 32]>,
}

impl Keys {
    fn derive(secret: &[u8]) -> Self {
        let derive = |context| Zeroizing::new(blake3::derive_key(context, secret));
        Self {
            confirm: derive(CONFIRM_CONTEXT),
            new_to_existing: derive(N_TO_E_CONTEXT),
            existing_to_new: derive(E_TO_N_CONTEXT),
        }
    }

    /// Binds the confirmation to both SPAKE2 messages.
    fn confirmation(&self, hello: &[u8], reply: &[u8]) -> blake3::Hash {
        blake3::Hasher::new_keyed(&self.confirm)
            .update(&(hello.len() as u64).to_be_bytes())
            .update(hello)
            .update(reply)
            .finalize()
    }
}

/// A device N has asked to link, waiting for you to confirm on E.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDevice {
    pub key: VerifyingKey,
    pub name: String,
}

enum ExistingState {
    WaitingHello { code: FriendCode, expires_at: u64 },
    WaitingDevice(Keys),
    // Boxed: a verifying key is large, and this state is held only briefly.
    Confirming(Keys, Box<PendingDevice>),
    Done,
}

/// E's side: the device that already holds the identity.
pub struct LinkInitiator(ExistingState);

impl LinkInitiator {
    /// A new link code, valid from `now` for [`LINK_CODE_LIFETIME`]; show it
    /// to the user to type on the new device.
    pub fn new(now: u64) -> Result<(Self, FriendCode), LinkError> {
        let code = FriendCode::generate().map_err(|_| LinkError::Random)?;
        let state = ExistingState::WaitingHello {
            code,
            expires_at: now + LINK_CODE_LIFETIME,
        };
        Ok((Self(state), code))
    }

    /// N's Hello; returns the Reply. The code is burned whatever happens, so
    /// each code allows one guess.
    pub fn receive_hello(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>, LinkError> {
        // A message in the wrong state is refused and leaves the session as it was.
        let (code, expires_at) = match std::mem::replace(&mut self.0, ExistingState::Done) {
            ExistingState::WaitingHello { code, expires_at } => (code, expires_at),
            other => {
                self.0 = other;
                return Err(LinkError::CodeUsed);
            }
        };
        if now >= expires_at {
            return Err(LinkError::Expired);
        }
        let hello = payload(message, HELLO)?;
        let (spake, ours) = Spake2::<Ed25519Group>::start_a(
            &Password::new(code_bytes(&code)),
            &Identity::new(ID_EXISTING),
            &Identity::new(ID_NEW),
        );
        let secret = Zeroizing::new(spake.finish(hello).map_err(|_| LinkError::Malformed)?);
        let keys = Keys::derive(&secret);
        let mut reply = vec![REPLY];
        reply.extend_from_slice(&ours);
        reply.extend_from_slice(keys.confirmation(hello, &ours).as_bytes());
        self.0 = ExistingState::WaitingDevice(keys);
        Ok(reply)
    }

    /// N's Device message: the device to show the user ("Link *Laptop*?").
    /// If it doesn't open, N had the wrong code.
    pub fn receive_device(&mut self, message: &[u8]) -> Result<PendingDevice, LinkError> {
        let keys = match std::mem::replace(&mut self.0, ExistingState::Done) {
            ExistingState::WaitingDevice(keys) => keys,
            other => {
                self.0 = other;
                return Err(LinkError::Unexpected);
            }
        };
        let plain = open(&keys.new_to_existing, DEVICE, payload(message, DEVICE)?)
            .map_err(|_| LinkError::WrongCode)?;
        let mut r = Reader(&plain);
        let key = VerifyingKey::from_bytes(&r.array()?).map_err(|_| LinkError::Malformed)?;
        let name = r.string(MAX_DEVICE_NAME)?;
        r.end()?;
        let device = PendingDevice { key, name };
        self.0 = ExistingState::Confirming(keys, Box::new(device.clone()));
        Ok(device)
    }

    /// You confirmed: certifies N, adds it to the identity's device list
    /// (saved in `store`; publish the new list) and returns the Identity
    /// message carrying the root key to N.
    pub fn confirm(&mut self, store: &mut Keystore, now: u64) -> Result<Vec<u8>, KeystoreError> {
        let (keys, device) = match std::mem::replace(&mut self.0, ExistingState::Done) {
            ExistingState::Confirming(keys, device) => (keys, device),
            other => {
                self.0 = other;
                return Err(LinkError::Unexpected.into());
            }
        };
        let cert = DeviceCert::issue(store.root_key(), &device.key, &device.name, now)?;
        store.add_device(cert)?;
        let username = store.username().as_bytes();
        let mut plain = Zeroizing::new(vec![1]);
        plain.extend_from_slice(store.root_key().secret_bytes().as_ref());
        // Fits: usernames are checked at most 32 characters.
        plain.extend_from_slice(&(username.len() as u16).to_be_bytes());
        plain.extend_from_slice(username);
        plain.extend_from_slice(&store.devices().to_bytes());
        Ok(seal(&keys.existing_to_new, IDENTITY, &plain)?)
    }

    /// You said no: tells N, and sends nothing of the identity.
    pub fn cancel(&mut self) -> Result<Vec<u8>, LinkError> {
        let keys = match std::mem::replace(&mut self.0, ExistingState::Done) {
            ExistingState::Confirming(keys, _) => keys,
            other => {
                self.0 = other;
                return Err(LinkError::Unexpected);
            }
        };
        seal(&keys.existing_to_new, IDENTITY, &[0])
    }
}

enum NewState {
    WaitingReply {
        spake: Spake2<Ed25519Group>,
        hello: Vec<u8>,
        device: DeviceKey,
        name: String,
    },
    WaitingIdentity(Keys, DeviceKey, String),
    Done,
}

/// N's side: the new device.
pub struct LinkResponder(NewState);

impl LinkResponder {
    /// Starts with the link code as typed and this device's name; returns
    /// the Hello to send to E. Makes this device's key.
    pub fn new(code: &str, device_name: &str) -> Result<(Self, Vec<u8>), LinkError> {
        let code = FriendCode::parse(code)?;
        if device_name.len() > MAX_DEVICE_NAME {
            return Err(DeviceError::NameTooLong.into());
        }
        let device = DeviceKey::generate().map_err(|_| LinkError::Random)?;
        let (spake, ours) = Spake2::<Ed25519Group>::start_b(
            &Password::new(code_bytes(&code)),
            &Identity::new(ID_EXISTING),
            &Identity::new(ID_NEW),
        );
        let mut hello = vec![HELLO];
        hello.extend_from_slice(&ours);
        let state = NewState::WaitingReply {
            spake,
            hello: ours,
            device,
            name: device_name.to_owned(),
        };
        Ok((Self(state), hello))
    }

    /// E's Reply; returns the Device message. Fails here if the code was wrong.
    pub fn receive_reply(&mut self, message: &[u8]) -> Result<Vec<u8>, LinkError> {
        let (spake, hello, device, name) = match std::mem::replace(&mut self.0, NewState::Done) {
            NewState::WaitingReply {
                spake,
                hello,
                device,
                name,
            } => (spake, hello, device, name),
            other => {
                self.0 = other;
                return Err(LinkError::Unexpected);
            }
        };
        let reply = payload(message, REPLY)?;
        let (theirs, confirm) = reply.split_last_chunk::<32>().ok_or(LinkError::Malformed)?;
        let secret = Zeroizing::new(spake.finish(theirs).map_err(|_| LinkError::Malformed)?);
        let keys = Keys::derive(&secret);
        // blake3::Hash compares in constant time.
        if keys.confirmation(&hello, theirs) != *confirm {
            return Err(LinkError::WrongCode);
        }
        let mut plain = device.public().to_bytes().to_vec();
        plain.extend_from_slice(&(name.len() as u16).to_be_bytes());
        plain.extend_from_slice(name.as_bytes());
        let sent = seal(&keys.new_to_existing, DEVICE, &plain)?;
        self.0 = NewState::WaitingIdentity(keys, device, name);
        Ok(sent)
    }

    /// E's Identity message: the identity, ready for
    /// [`Keystore::create_from_link`], or `Cancelled`.
    pub fn receive_identity(&mut self, message: &[u8]) -> Result<LinkedIdentity, LinkError> {
        let (keys, device, name) = match std::mem::replace(&mut self.0, NewState::Done) {
            NewState::WaitingIdentity(keys, device, name) => (keys, device, name),
            other => {
                self.0 = other;
                return Err(LinkError::Unexpected);
            }
        };
        let plain = open(&keys.existing_to_new, IDENTITY, payload(message, IDENTITY)?)?;
        let mut r = Reader(&plain);
        if r.array::<1>()? == [0] {
            r.end()?;
            return Err(LinkError::Cancelled);
        }
        let root = RootKey::from_secret_bytes(r.array()?);
        let username = r.string(4 * crate::password::MAX_USERNAME_LEN)?;
        let devices = DeviceList::from_bytes(r.0)?;
        if devices.root() != root.id() {
            return Err(DeviceError::WrongIdentity.into());
        }
        // E must have certified this device, under the name we sent.
        let ours = devices
            .devices()
            .iter()
            .find(|c| c.device() == &device.public())
            .ok_or(DeviceError::NotLinked)?;
        if ours.name() != name {
            return Err(LinkError::Malformed);
        }
        Ok(LinkedIdentity {
            root,
            device,
            username,
            devices,
        })
    }
}

/// What N receives: everything for its own keystore.
pub struct LinkedIdentity {
    pub(crate) root: RootKey,
    pub(crate) device: DeviceKey,
    pub(crate) username: String,
    pub(crate) devices: DeviceList,
}

impl LinkedIdentity {
    pub fn id(&self) -> crate::id::MeshId {
        self.root.id()
    }

    /// The identity's username, to ask for before saving the keystore.
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// Where E leaves its link node's address for N (PLAN-link L1): an ordinary
/// address record to the seed, filed under a lookup ID and sealed with a key
/// that both come from the link code through Argon2id, as friend codes' do.
/// A fast hash would let the seed's operator try all 2^40 codes within the
/// code's 5 minutes. About 100 ms: make it off any async thread.
pub struct LinkRendezvous {
    lookup: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

impl LinkRendezvous {
    pub fn new(code: &FriendCode) -> Self {
        let (lookup, key) = code.stretch(LINK_SALT);
        Self { lookup, key }
    }

    /// The lookup ID the record is filed and fetched under.
    pub fn lookup(&self) -> [u8; 16] {
        self.lookup
    }

    /// The record for `addr` (E's link node, as a ticket), lasting the code's
    /// life from `now`.
    pub fn seal(&self, addr: &[u8], now: u64) -> Result<Vec<u8>, LinkError> {
        let mut outer = self.lookup.to_vec();
        outer.extend_from_slice(&RECORD_SLOT);
        outer.extend_from_slice(&(now + LINK_CODE_LIFETIME).to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| LinkError::Random)?;
        let payload = Payload {
            msg: addr,
            aad: &outer,
        };
        let sealed = XChaCha20Poly1305::new(&Key::from(*self.key))
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| LinkError::Malformed)?;
        let record = [&outer[..], &nonce, &sealed].concat();
        if crate::addr::addr_outer(&record).is_none() {
            return Err(LinkError::Malformed);
        }
        Ok(record)
    }

    /// The address in a record from the seed; refused if it's for another
    /// code, damaged or expired.
    pub fn open(&self, record: &[u8], now: u64) -> Result<Vec<u8>, LinkError> {
        let (lookup, _, expires_at) =
            crate::addr::addr_outer(record).ok_or(LinkError::Malformed)?;
        if lookup != self.lookup {
            return Err(LinkError::WrongCode);
        }
        if now >= expires_at {
            return Err(LinkError::Expired);
        }
        let (outer, rest) = record.split_at(OUTER_LEN);
        let (nonce, sealed) = rest
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(LinkError::Malformed)?;
        let payload = Payload {
            msg: sealed,
            aad: outer,
        };
        XChaCha20Poly1305::new(&Key::from(*self.key))
            .decrypt(&XNonce::from(*nonce), payload)
            .map_err(|_| LinkError::Malformed)
    }
}

/// The 40 code bits are the SPAKE2 password.
fn code_bytes(code: &FriendCode) -> &[u8] {
    code.as_bytes()
}

fn payload(message: &[u8], kind: u8) -> Result<&[u8], LinkError> {
    match message.split_first() {
        Some((&k, rest)) if k == kind => Ok(rest),
        Some(_) => Err(LinkError::Unexpected),
        None => Err(LinkError::Malformed),
    }
}

fn seal(key: &[u8; 32], kind: u8, plain: &[u8]) -> Result<Vec<u8>, LinkError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| LinkError::Random)?;
    let sealed = XChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plain,
                aad: &[kind],
            },
        )
        .map_err(|_| LinkError::Malformed)?;
    Ok([&[kind][..], &nonce, &sealed].concat())
}

fn open(key: &[u8; 32], kind: u8, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, LinkError> {
    let (nonce, body) = sealed
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(LinkError::Malformed)?;
    XChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: body,
                aad: &[kind],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| LinkError::Malformed)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], LinkError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(LinkError::Malformed)?;
        self.0 = rest;
        Ok(*head)
    }

    /// A u16-length-prefixed UTF-8 string of at most `max` bytes.
    fn string(&mut self, max: usize) -> Result<String, LinkError> {
        let len = u16::from_be_bytes(self.array()?) as usize;
        if len > max || len > self.0.len() {
            return Err(LinkError::Malformed);
        }
        let (text, rest) = self.0.split_at(len);
        self.0 = rest;
        String::from_utf8(text.to_vec()).map_err(|_| LinkError::Malformed)
    }

    fn end(&self) -> Result<(), LinkError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(LinkError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KdfParams;

    #[test]
    fn the_link_record_opens_only_with_its_code() {
        let (_, code) = LinkInitiator::new(NOW).unwrap();
        let here = LinkRendezvous::new(&code);
        let ticket = b"mesh://node/abc?relay=https://relay.example/";
        let record = here.seal(ticket, NOW).unwrap();
        // The seed reads it as any address record, within its 3 hours ahead.
        let (lookup, _, expires_at) = crate::addr::addr_outer(&record).unwrap();
        assert_eq!(lookup, here.lookup());
        assert_eq!(expires_at, NOW + LINK_CODE_LIFETIME);
        const { assert!(LINK_CODE_LIFETIME <= 3 * 3600) };

        let there = LinkRendezvous::new(&FriendCode::parse(&code.to_string()).unwrap());
        assert_eq!(there.open(&record, NOW).unwrap(), ticket);
        let other = LinkRendezvous::new(&FriendCode::generate().unwrap());
        assert!(other.open(&record, NOW).is_err(), "another code");
        assert!(
            there.open(&record, NOW + LINK_CODE_LIFETIME).is_err(),
            "expired"
        );
        let mut bad = record.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(there.open(&bad, NOW).is_err(), "damaged");
    }

    /// The keys must cost what a friend code's do: Argon2id with the same
    /// settings, under the link salt (PLAN-link L1).
    #[test]
    fn the_link_record_keys_are_the_slow_derivation() {
        let code = FriendCode::generate().unwrap();
        let params = argon2::Params::new(64 * 1024, 5, 1, Some(48)).unwrap();
        let mut out = [0u8; 48];
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(code.as_bytes(), b"mesh/v1/link-code", &mut out)
            .unwrap();
        let rendezvous = LinkRendezvous::new(&code);
        assert_eq!(rendezvous.lookup(), out[..16]);
        assert_eq!(*rendezvous.key, out[16..]);
        assert_ne!(rendezvous.lookup(), code.lookup_id(), "not a friend code's");
    }

    const NOW: u64 = 1_792_627_200;
    const PASSWORD: &str = "Tundra-Gravel-Mosaic-41";
    const LAPTOP_PASSWORD: &str = "copper lantern drifts sideways";
    const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;

    fn existing(name: &str) -> Keystore {
        let dir = std::env::temp_dir().join(format!("mesh-link-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Keystore::create_with(&dir.join("e.mks"), "Brendon", PASSWORD, "Desktop", FAST).unwrap()
    }

    /// Runs Hello → Reply → Device; returns both sides with E confirming.
    fn up_to_confirm(code: &str) -> (LinkInitiator, LinkResponder, PendingDevice) {
        let (mut e, _) = LinkInitiator::new(NOW).unwrap();
        let ExistingState::WaitingHello { code: real, .. } = &e.0 else {
            unreachable!()
        };
        let code = if code.is_empty() {
            real.to_string()
        } else {
            code.to_owned()
        };
        let (mut n, hello) = LinkResponder::new(&code, "Laptop").unwrap();
        let reply = e.receive_hello(&hello, NOW + 10).unwrap();
        let device = n.receive_reply(&reply).unwrap();
        let pending = e.receive_device(&device).unwrap();
        (e, n, pending)
    }

    #[test]
    fn linking_gives_the_new_device_the_same_identity() {
        let mut store = existing("ok");
        let seq = store.devices().seq();
        let (mut e, mut n, pending) = up_to_confirm("");
        assert_eq!(pending.name, "Laptop");
        let identity = e.confirm(&mut store, NOW + 20).unwrap();
        // E saved the new list: one more device, seq + 1.
        assert_eq!(store.devices().seq(), seq + 1);
        assert!(store.devices().is_current(&pending.key));

        let linked = n.receive_identity(&identity).unwrap();
        assert_eq!(linked.id(), store.id());
        let laptop = store.path().with_file_name("n.mks");
        assert!(matches!(
            Keystore::create_from_link_with(&laptop, linked, "Brandon", LAPTOP_PASSWORD, FAST),
            Err(KeystoreError::CannotUnlock)
        ));
        let (mut e, mut n, _) = up_to_confirm("");
        let linked = n
            .receive_identity(&e.confirm(&mut store, NOW).unwrap())
            .unwrap();
        assert!(matches!(
            Keystore::create_from_link_with(&laptop, linked, "brendon", "password1234", FAST),
            Err(KeystoreError::WeakPassword(_))
        ));
        let (mut e, mut n, pending) = up_to_confirm("");
        let linked = n
            .receive_identity(&e.confirm(&mut store, NOW).unwrap())
            .unwrap();
        let new =
            Keystore::create_from_link_with(&laptop, linked, "brendon", LAPTOP_PASSWORD, FAST)
                .unwrap();
        assert_eq!((new.id(), new.username()), (store.id(), "Brendon"));
        assert_eq!(new.device_key().public(), pending.key);
        assert_ne!(new.device_key().public(), store.device_key().public());
        assert_eq!(new.devices(), store.devices());
        drop(new);
        assert!(Keystore::unlock(&laptop, "Brendon", LAPTOP_PASSWORD).is_ok());
    }

    #[test]
    fn a_wrong_code_fails_once_and_burns_the_code() {
        let (mut e, code) = LinkInitiator::new(NOW).unwrap();
        let wrong = FriendCode::generate().unwrap();
        assert_ne!(wrong, code);
        let (mut n, hello) = LinkResponder::new(&wrong.to_string(), "Laptop").unwrap();
        let reply = e.receive_hello(&hello, NOW).unwrap();
        assert_eq!(n.receive_reply(&reply), Err(LinkError::WrongCode));
        // The right code can't be tried afterwards.
        let (_, hello) = LinkResponder::new(&code.to_string(), "Laptop").unwrap();
        assert_eq!(e.receive_hello(&hello, NOW), Err(LinkError::CodeUsed));
    }

    #[test]
    fn a_device_message_under_the_wrong_code_is_refused_by_e() {
        // A modified N that ignores the failed confirmation and sends anyway.
        let (mut e, _) = LinkInitiator::new(NOW).unwrap();
        let wrong = FriendCode::generate().unwrap();
        let (_, hello) = LinkResponder::new(&wrong.to_string(), "Laptop").unwrap();
        e.receive_hello(&hello, NOW).unwrap();
        let keys = Keys::derive(&[9; 32]);
        let forged = seal(&keys.new_to_existing, DEVICE, &[0; 34]).unwrap();
        assert_eq!(e.receive_device(&forged), Err(LinkError::WrongCode));
    }

    #[test]
    fn cancelling_on_e_transfers_nothing() {
        let mut store = existing("cancel");
        let before = store.devices().clone();
        let (mut e, mut n, _) = up_to_confirm("");
        let message = e.cancel().unwrap();
        assert_eq!(
            n.receive_identity(&message).err(),
            Some(LinkError::Cancelled)
        );
        assert!(
            !message
                .windows(32)
                .any(|w| w == *store.root_key().secret_bytes())
        );
        assert!(matches!(
            e.confirm(&mut store, NOW),
            Err(KeystoreError::Link(LinkError::Unexpected))
        ));
        assert_eq!(store.devices(), &before);
    }

    #[test]
    fn replayed_and_out_of_order_messages_are_refused() {
        let (mut e, code) = LinkInitiator::new(NOW).unwrap();
        let (mut n, hello) = LinkResponder::new(&code.to_string(), "Laptop").unwrap();
        // A Hello where the Device message belongs, before any Hello.
        assert_eq!(e.receive_device(&hello), Err(LinkError::Unexpected));
        let (mut e, code) = LinkInitiator::new(NOW).unwrap();
        let (mut n2, hello2) = LinkResponder::new(&code.to_string(), "Laptop").unwrap();
        let reply = e.receive_hello(&hello2, NOW).unwrap();
        // A replayed Hello is refused without ending the real session.
        assert_eq!(e.receive_hello(&hello2, NOW), Err(LinkError::CodeUsed));
        assert_eq!(n.receive_reply(&hello), Err(LinkError::Unexpected));
        let device = n2.receive_reply(&reply).unwrap();
        assert_eq!(n2.receive_reply(&reply), Err(LinkError::Unexpected));
        e.receive_device(&device).unwrap();
        assert_eq!(e.receive_device(&device), Err(LinkError::Unexpected));
        assert_eq!(
            n2.receive_identity(&device).err(),
            Some(LinkError::Unexpected)
        );
    }

    /// The key schedule, computed with the Python `blake3` package.
    #[test]
    fn key_schedule_vector() {
        let keys = Keys::derive(&core::array::from_fn::<u8, 32, _>(|i| i as u8));
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(keys.new_to_existing.as_ref()),
            "b507349fc02947fc615fa4a72f76f0c04a790fd2dc7fc4c4d10a5775b497f59d"
        );
        assert_eq!(
            hex(keys.existing_to_new.as_ref()),
            "064f0b10123fbaf79013f047c6781e837962644c9ef414a685c65c06a446e9c6"
        );
        assert_eq!(
            keys.confirmation(&[0x41; 33], &[0x42; 33])
                .to_hex()
                .as_str(),
            "1f10a1c0e051af41b19858ef02095b2405c641dbdbc9d681aed57c3c201c5c22"
        );
    }

    #[test]
    fn an_expired_code_is_refused() {
        let (mut e, code) = LinkInitiator::new(NOW).unwrap();
        let (_, hello) = LinkResponder::new(&code.to_string(), "Laptop").unwrap();
        assert_eq!(
            e.receive_hello(&hello, NOW + LINK_CODE_LIFETIME),
            Err(LinkError::Expired)
        );
        assert_eq!(
            LinkResponder::new("K7QM-3XPU", "Laptop").err(),
            Some(LinkError::Code(crate::code::CodeError::BadCharacter('U')))
        );
    }
}
