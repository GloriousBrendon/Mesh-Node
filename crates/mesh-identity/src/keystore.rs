//! The keystore: everything secret about an identity, encrypted at rest; and
//! backups, which use the same sealing.
//!
//! The username and password go through Argon2id into a key-encryption key
//! (KEK). The KEK wraps a random data key (DEK), and the DEK encrypts the
//! contents. Changing the password re-wraps only the DEK, so later modules
//! can encrypt their own local stores with it. Neither the username nor the
//! ID is readable on disk, so a copied file says nothing about whose it is.
//!
//! File layout (big-endian); both layers authenticate the header before it:
//!
//! ```text
//! magic [4] | version u8 | m_kib u32 | t u32 | p u32 | salt [16]
//!           | wrap nonce [24] | wrapped DEK [32 + 16 tag]
//!           | contents nonce [24] | contents (postcard, + 16 tag)
//! ```
//!
//! The magic is `MKS1` for a keystore and `MKB1` for a backup. A backup holds
//! the username, the root key and the device list, but no device key: each
//! install needs its own, so a restored device makes a new one.
//!
//! Contacts (routing) follow the contents as a second postcard value, and
//! the account state (social) as a third, only when there are any: a file
//! without them is exactly the earlier format, and postcard ignores what
//! follows a value, so older Mesh still opens it.
//!
//! The account state is the source of who you know; routing's contacts are
//! kept in step with its `outgoing` and `friend` entries after every change.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use std::collections::HashSet;

use crate::account::{Account, Entry, Kind, Status};
use crate::code::{ActiveCode, CodeError, CodeRevoke, FriendCode, HeldCode};
use crate::contacts::{Contact, LastAddr, MAX_CONTACTS, clean_name};
use crate::device::{DeviceCert, DeviceList};
use crate::id::{DeviceKey, MeshId, RootKey};
use crate::knock::Knock;
use crate::link::{LinkError, LinkedIdentity};
use crate::pair::PairKeys;
use crate::password::{PasswordVerdict, check_password, normalize_username, valid_username};

const KEYSTORE_MAGIC: &[u8; 4] = b"MKS1";
const BACKUP_MAGIC: &[u8; 4] = b"MKB1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = NONCE_LEN + 32 + TAG_LEN;
/// Magic, version, three u32 parameters, salt.
const PARAMS_END: usize = 4 + 1 + 12 + SALT_LEN;
/// Plus the wrap nonce and the wrapped data key.
const HEADER_LEN: usize = PARAMS_END + WRAPPED_LEN;
/// IDs one identity can block (SPEC-social D10).
pub const MAX_BLOCKS: usize = 10_000;
/// How long a code stays listed after it expires, so the requests left with
/// it can still be collected (SPEC-social D6, D7).
const CODE_COLLECT: u64 = 8 * 24 * 3600;

/// Argon2id settings, kept in the header so they can be raised later without
/// breaking old files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane (spec; aims at under a second to unlock).
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
    /// Refused when read from a file, so a crafted header can't make
    /// unlocking eat the machine's memory or time.
    const MAX: KdfParams = KdfParams {
        m_kib: 4 * 1024 * 1024,
        t: 64,
        p: 16,
    };

    /// Tiny settings so tests stay fast; never used for a real keystore.
    #[cfg(test)]
    pub(crate) const FAST_FOR_TESTS: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn within_limits(&self) -> bool {
        self.m_kib <= Self::MAX.m_kib && self.t <= Self::MAX.t && self.p <= Self::MAX.p
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Wrong username, wrong password or a damaged file: deliberately one
    /// error, so a failure doesn't say which part was wrong.
    #[error("that username and password don't open this identity")]
    CannotUnlock,
    #[error("there's no identity on this device yet")]
    NotFound,
    #[error("there's already an identity on this device")]
    AlreadyExists,
    #[error("this identity was saved by a newer Mesh; update Mesh to open it")]
    NewerVersion,
    #[error("usernames are 1 to 32 characters")]
    BadUsername,
    #[error("{}", .0.message())]
    WeakPassword(PasswordVerdict),
    #[error("{0}")]
    Device(#[from] crate::device::DeviceError),
    #[error("{0}")]
    Code(#[from] CodeError),
    #[error("{0}")]
    Link(#[from] LinkError),
    #[error("that's your own ID")]
    OwnId,
    #[error("that ID is already a contact")]
    AlreadyContact,
    #[error("that ID isn't a contact")]
    NotAContact,
    #[error("a contact name is 1 to 64 characters")]
    BadContactName,
    #[error("you can have at most {MAX_CONTACTS} contacts")]
    TooManyContacts,
    #[error("you've blocked that ID; unblock them first")]
    Blocked,
    #[error("you can block at most {MAX_BLOCKS} IDs")]
    TooManyBlocks,
    #[error("there's no request from that ID")]
    NoRequest,
    #[error("couldn't use the system keyring: {0}")]
    Keyring(String),
    #[error("couldn't get randomness from the system: {0}")]
    Random(getrandom::Error),
    #[error("couldn't read or write the identity file: {0}")]
    Io(#[from] std::io::Error),
}

/// A keystore's contents: postcard, encrypted with the data key.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Contents {
    /// As typed at onboarding; unlocking compares the normalized form.
    username: String,
    root_secret: [u8; 32],
    device_secret: [u8; 32],
    device_list: Vec<u8>,
    /// Friend codes made on this device (not backed up: codes are short-lived).
    codes: Vec<ActiveCode>,
}

/// A backup's contents: no device key (see the module docs).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct BackupContents {
    username: String,
    root_secret: [u8; 32],
    device_list: Vec<u8>,
}

/// How a sealed file is opened.
#[derive(Clone, Copy)]
enum Opener<'a> {
    Password {
        username: &'a str,
        password: &'a str,
    },
    /// The data key itself, kept in the OS keyring ("keep unlocked").
    DataKey(&'a [u8; 32]),
}

/// One sealed file's header and its unwrapped data key.
struct Sealed {
    magic: &'static [u8; 4],
    params: KdfParams,
    salt: [u8; SALT_LEN],
    /// The KEK-wrapped data key as stored (re-wrapped on password change).
    wrapped: [u8; WRAPPED_LEN],
    data_key: Zeroizing<[u8; 32]>,
}

impl Sealed {
    /// A fresh random data key, wrapped under `username` and `password`.
    fn new(
        magic: &'static [u8; 4],
        params: KdfParams,
        username: &str,
        password: &str,
    ) -> Result<Self, KeystoreError> {
        let data_key = Zeroizing::new(random::<32>()?);
        let mut sealed = Self {
            magic,
            params,
            salt: [0; SALT_LEN],
            wrapped: [0; WRAPPED_LEN],
            data_key,
        };
        sealed.wrap(username, password)?;
        Ok(sealed)
    }

    /// Reads `path` and unwraps its data key; returns the decrypted contents.
    fn open(
        path: &Path,
        magic: &'static [u8; 4],
        with: Opener<'_>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), KeystoreError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound);
            }
            Err(e) => return Err(e.into()),
        };
        if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN || &bytes[..4] != magic {
            return Err(KeystoreError::CannotUnlock);
        }
        if bytes[4] > VERSION {
            return Err(KeystoreError::NewerVersion);
        }
        if bytes[4] != VERSION {
            return Err(KeystoreError::CannotUnlock);
        }
        let u32_at = |i: usize| u32::from_be_bytes(bytes[i..i + 4].try_into().expect("4 bytes"));
        let params = KdfParams {
            m_kib: u32_at(5),
            t: u32_at(9),
            p: u32_at(13),
        };
        if !params.within_limits() {
            return Err(KeystoreError::CannotUnlock);
        }
        let salt: [u8; SALT_LEN] = bytes[17..PARAMS_END].try_into().expect("salt");
        let wrapped: [u8; WRAPPED_LEN] = bytes[PARAMS_END..HEADER_LEN]
            .try_into()
            .expect("wrapped key");
        let data_key = match with {
            Opener::Password { username, password } => {
                let kek = derive_kek(username, password, &salt, params)?;
                Zeroizing::new(
                    open_bytes(&kek, &wrapped, &bytes[..PARAMS_END])?
                        .as_slice()
                        .try_into()
                        .map_err(|_| KeystoreError::CannotUnlock)?,
                )
            }
            // Wrong keys fail below: the contents only open with the real one.
            Opener::DataKey(key) => Zeroizing::new(*key),
        };
        let contents = open_bytes(&data_key, &bytes[HEADER_LEN..], &bytes[..HEADER_LEN])?;
        Ok((
            Self {
                magic,
                params,
                salt,
                wrapped,
                data_key,
            },
            contents,
        ))
    }

    /// Whether `username` and `password` unwrap this file's data key.
    fn opens_with(&self, username: &str, password: &str) -> bool {
        derive_kek(username, password, &self.salt, self.params)
            .and_then(|kek| open_bytes(&kek, &self.wrapped, &self.params_bytes()))
            .is_ok_and(|key| key.as_slice() == self.data_key.as_slice())
    }

    /// A new salt and KEK from `username` and `password`, wrapping the data key.
    fn wrap(&mut self, username: &str, password: &str) -> Result<(), KeystoreError> {
        self.salt = random::<SALT_LEN>()?;
        let kek = derive_kek(username, password, &self.salt, self.params)?;
        self.wrapped = seal_bytes(&kek, self.data_key.as_ref(), &self.params_bytes())?
            .try_into()
            .map_err(|_| std::io::Error::other("wrapped key has the wrong length"))?;
        Ok(())
    }

    fn params_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PARAMS_END);
        bytes.extend_from_slice(self.magic);
        bytes.push(VERSION);
        for v in [self.params.m_kib, self.params.t, self.params.p] {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        bytes.extend_from_slice(&self.salt);
        bytes
    }

    /// Encrypts `contents` under the data key and replaces the file atomically.
    fn save(&self, path: &Path, contents: &[u8]) -> Result<(), KeystoreError> {
        let mut bytes = self.params_bytes();
        bytes.extend_from_slice(&self.wrapped);
        let sealed = seal_bytes(&self.data_key, contents, &bytes)?;
        bytes.extend_from_slice(&sealed);
        write_atomically(path, &bytes)?;
        Ok(())
    }
}

/// An unlocked identity. Dropping it locks: the secrets are wiped.
pub struct Keystore {
    path: PathBuf,
    sealed: Sealed,
    username: String,
    root: RootKey,
    device: DeviceKey,
    devices: DeviceList,
    codes: Vec<ActiveCode>,
    contacts: Vec<Contact>,
    account: Account,
    /// Space members who aren't contacts: never saved (SPEC-spaces S2).
    peers: Vec<Contact>,
}

impl Keystore {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Makes a new identity (root key, this device's key and certificate)
    /// and saves it at `path`. Refuses weak passwords and never overwrites.
    pub fn create(
        path: &Path,
        username: &str,
        password: &str,
        device_name: &str,
    ) -> Result<Self, KeystoreError> {
        Self::create_with(path, username, password, device_name, KdfParams::DEFAULT)
    }

    pub(crate) fn create_with(
        path: &Path,
        username: &str,
        password: &str,
        device_name: &str,
        params: KdfParams,
    ) -> Result<Self, KeystoreError> {
        let root = RootKey::generate().map_err(KeystoreError::Random)?;
        let device = DeviceKey::generate().map_err(KeystoreError::Random)?;
        let cert = DeviceCert::issue(&root, &device.public(), device_name, unix_now())?;
        let devices = DeviceList::first(&root, cert)?;
        Self::save_new(path, username, password, params, root, device, devices)
    }

    /// The checks every new keystore passes (no overwrite, username rules,
    /// password policy), then its first save.
    fn save_new(
        path: &Path,
        username: &str,
        password: &str,
        params: KdfParams,
        root: RootKey,
        device: DeviceKey,
        devices: DeviceList,
    ) -> Result<Self, KeystoreError> {
        if Self::exists(path) {
            return Err(KeystoreError::AlreadyExists);
        }
        if !valid_username(username) {
            return Err(KeystoreError::BadUsername);
        }
        let verdict = check_password(username, password);
        if !verdict.is_ok() {
            return Err(KeystoreError::WeakPassword(verdict));
        }
        let store = Self {
            path: path.to_owned(),
            sealed: Sealed::new(KEYSTORE_MAGIC, params, username, password)?,
            username: username.trim().to_owned(),
            root,
            device,
            devices,
            codes: Vec::new(),
            contacts: Vec::new(),
            peers: Vec::new(),
            account: Account::default(),
        };
        store.save()?;
        Ok(store)
    }

    /// Opens the identity at `path` with its username and password.
    pub fn unlock(path: &Path, username: &str, password: &str) -> Result<Self, KeystoreError> {
        let (sealed, plain) = Sealed::open(
            path,
            KEYSTORE_MAGIC,
            Opener::Password { username, password },
        )?;
        Self::decode(path, sealed, &plain)
    }

    /// Opens the identity with its data key (from the OS keyring).
    pub(crate) fn open_with_data_key(
        path: &Path,
        data_key: &[u8; 32],
    ) -> Result<Self, KeystoreError> {
        let (sealed, plain) = Sealed::open(path, KEYSTORE_MAGIC, Opener::DataKey(data_key))?;
        Self::decode(path, sealed, &plain)
    }

    fn decode(path: &Path, sealed: Sealed, plain: &[u8]) -> Result<Self, KeystoreError> {
        let (contents, contacts, account) = decode_with_contacts::<Contents>(plain)?;
        let root = RootKey::from_secret_bytes(contents.root_secret);
        let devices = DeviceList::from_bytes(&contents.device_list)
            .map_err(|_| KeystoreError::CannotUnlock)?;
        if devices.root() != root.id() {
            return Err(KeystoreError::CannotUnlock);
        }
        let mut store = Self {
            path: path.to_owned(),
            sealed,
            username: contents.username.clone(),
            root,
            device: DeviceKey::from_secret_bytes(contents.device_secret),
            devices,
            codes: contents.codes.clone(),
            contacts,
            peers: Vec::new(),
            account,
        };
        store.adopt_contacts();
        Ok(store)
    }

    /// Routing's contacts with no account entry (a keystore from before
    /// `social`) become `outgoing`: the first connection makes them friends.
    fn adopt_contacts(&mut self) {
        let by = self.by();
        for c in &self.contacts {
            if self.account.get(&c.id()).is_none() {
                self.account.change(&c.id(), by, c.added, |e| {
                    e.kind = Kind::Outgoing;
                    e.nick = c.name.clone();
                    e.at = c.added;
                });
            }
        }
    }

    /// Where this keystore lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Changes this device's password. The data key stays the same, so
    /// anything other modules encrypted with it stays readable.
    pub fn change_password(
        &mut self,
        username: &str,
        old: &str,
        new: &str,
    ) -> Result<(), KeystoreError> {
        if !self.sealed.opens_with(username, old) {
            return Err(KeystoreError::CannotUnlock);
        }
        let verdict = check_password(username, new);
        if !verdict.is_ok() {
            return Err(KeystoreError::WeakPassword(verdict));
        }
        self.sealed.wrap(username, new)?;
        self.save()
    }

    /// Writes a backup to `path`, opened later with this identity's username
    /// and `password` (which must pass the password policy).
    pub fn export(&self, path: &Path, password: &str) -> Result<(), KeystoreError> {
        self.export_with(path, password, KdfParams::DEFAULT)
    }

    pub(crate) fn export_with(
        &self,
        path: &Path,
        password: &str,
        params: KdfParams,
    ) -> Result<(), KeystoreError> {
        let verdict = check_password(&self.username, password);
        if !verdict.is_ok() {
            return Err(KeystoreError::WeakPassword(verdict));
        }
        let contents = BackupContents {
            username: self.username.clone(),
            root_secret: *self.root.secret_bytes(),
            device_list: self.devices.to_bytes(),
        };
        let plain = encode_with_contacts(&contents, &self.contacts, &self.account)?;
        Sealed::new(BACKUP_MAGIC, params, &self.username, password)?.save(path, &plain)
    }

    /// Restores a backup as a new device: same identity, a new device key
    /// and certificate, and this device's own `new_password`.
    pub fn import(
        backup: &Path,
        path: &Path,
        username: &str,
        backup_password: &str,
        new_password: &str,
        device_name: &str,
    ) -> Result<Self, KeystoreError> {
        Self::import_with(
            backup,
            path,
            username,
            backup_password,
            new_password,
            device_name,
            KdfParams::DEFAULT,
        )
    }

    pub(crate) fn import_with(
        backup: &Path,
        path: &Path,
        username: &str,
        backup_password: &str,
        new_password: &str,
        device_name: &str,
        params: KdfParams,
    ) -> Result<Self, KeystoreError> {
        let (_, plain) = Sealed::open(
            backup,
            BACKUP_MAGIC,
            Opener::Password {
                username,
                password: backup_password,
            },
        )?;
        let (contents, contacts, account) = decode_with_contacts::<BackupContents>(&plain)?;
        let root = RootKey::from_secret_bytes(contents.root_secret);
        let backed_up = DeviceList::from_bytes(&contents.device_list)
            .map_err(|_| KeystoreError::CannotUnlock)?;
        if backed_up.root() != root.id() {
            return Err(KeystoreError::CannotUnlock);
        }
        let device = DeviceKey::generate().map_err(KeystoreError::Random)?;
        let cert = DeviceCert::issue(&root, &device.public(), device_name, unix_now())?;
        let devices = backed_up.with_device(&root, cert)?;
        // The username as typed at onboarding, not as typed now.
        let mut store = Self::save_new(
            path,
            &contents.username,
            new_password,
            params,
            root,
            device,
            devices,
        )?;
        if !contacts.is_empty() || !account.is_empty() {
            store.contacts = contacts;
            store.account = account;
            store.adopt_contacts();
            store.save()?;
        }
        Ok(store)
    }

    /// Saves an identity received by linking as this device's keystore.
    /// `username` must be the identity's (you're asked to type it, as a
    /// check); `password` is this device's own, under the password policy.
    pub fn create_from_link(
        path: &Path,
        linked: LinkedIdentity,
        username: &str,
        password: &str,
    ) -> Result<Self, KeystoreError> {
        Self::create_from_link_with(path, linked, username, password, KdfParams::DEFAULT)
    }

    pub(crate) fn create_from_link_with(
        path: &Path,
        linked: LinkedIdentity,
        username: &str,
        password: &str,
        params: KdfParams,
    ) -> Result<Self, KeystoreError> {
        if normalize_username(username) != normalize_username(&linked.username) {
            return Err(KeystoreError::CannotUnlock);
        }
        let LinkedIdentity {
            root,
            device,
            username,
            devices,
        } = linked;
        Self::save_new(path, &username, password, params, root, device, devices)
    }

    /// Adds a newly linked device to the list (`seq + 1`) and saves.
    pub(crate) fn add_device(&mut self, cert: DeviceCert) -> Result<(), KeystoreError> {
        self.devices = self.devices.with_device(&self.root, cert)?;
        self.save()
    }

    /// Takes a newer list of our own devices, from another of them (a
    /// device restored from a backup adds itself). True if it was newer. A
    /// list that drops this device is left alone: it's for that device's
    /// other devices to act on.
    pub fn own_list_seen(&mut self, list: &DeviceList) -> Result<bool, KeystoreError> {
        if list.root() != self.id()
            || list.replaces(&self.devices).is_err()
            || list.seq() <= self.devices.seq()
            || !list.is_current(&self.device.public())
        {
            return Ok(false);
        }
        self.devices = list.clone();
        self.save()?;
        Ok(true)
    }

    /// Removes another of our devices (SPEC-identity, "Remove a device"): a
    /// new list, `seq + 1`, with it revoked. Not this device itself.
    pub fn remove_device(
        &mut self,
        device: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), KeystoreError> {
        if *device == self.device.public() {
            return Err(KeystoreError::Device(crate::device::DeviceError::NotLinked));
        }
        self.devices = self.devices.without_device(&self.root, device)?;
        self.save()
    }

    pub fn id(&self) -> MeshId {
        self.root.id()
    }

    /// The display form of the username (as typed at onboarding).
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn devices(&self) -> &DeviceList {
        &self.devices
    }

    pub fn device_key(&self) -> &DeviceKey {
        &self.device
    }

    pub fn root_key(&self) -> &RootKey {
        &self.root
    }

    /// A new friend code for this identity, and the record to hand to a
    /// holder. Expired codes are dropped from the list at the same time.
    pub fn create_code(
        &mut self,
        expiry: Option<u64>,
        uses: Option<u32>,
    ) -> Result<(FriendCode, HeldCode), KeystoreError> {
        let code = FriendCode::generate().map_err(KeystoreError::Random)?;
        let now = unix_now();
        let held = HeldCode::new(&self.root, &code, now, expiry, uses)?;
        self.codes
            .retain(|c| !expired(c, now.saturating_sub(CODE_COLLECT)));
        self.codes.push(ActiveCode {
            code,
            created_at: now,
            expires_at: held.expires_at(),
            max_uses: held.max_uses(),
        });
        self.save()?;
        Ok((code, held))
    }

    /// The record for one of this device's codes, built again (same lookup
    /// ID and revoke tag, a fresh nonce) to hand to a holder that missed it.
    pub fn held_record(&self, code: &ActiveCode) -> Result<HeldCode, KeystoreError> {
        let expiry = code.expires_at.map(|at| at.saturating_sub(code.created_at));
        Ok(HeldCode::new(
            &self.root,
            &code.code,
            code.created_at,
            expiry,
            code.max_uses,
        )?)
    }

    /// Codes made on this device that haven't expired.
    pub fn codes(&self) -> Vec<ActiveCode> {
        let now = unix_now();
        self.codes
            .iter()
            .filter(|c| !expired(c, now))
            .copied()
            .collect()
    }

    /// Every code still listed, expired or not: requests left with them may
    /// still be waiting (SPEC-social D7).
    pub fn collect_codes(&self) -> &[ActiveCode] {
        &self.codes
    }

    /// The revoke for one of this identity's codes, which also reads the
    /// requests left with it (SPEC-social D3).
    pub fn code_revoke(&self, code: &FriendCode) -> CodeRevoke {
        CodeRevoke::new(&self.root, code)
    }

    /// Takes a code off the list once its requests are collected.
    pub fn drop_code(&mut self, code: &FriendCode) -> Result<(), KeystoreError> {
        self.codes.retain(|c| c.code != *code);
        self.save()
    }

    /// Removes `code` from the list and returns the revoke to send to its
    /// holder. Works for codes made on another device too.
    pub fn revoke_code(&mut self, code: &FriendCode) -> Result<CodeRevoke, KeystoreError> {
        let before = self.codes.len();
        self.codes.retain(|c| c.code != *code);
        if self.codes.len() != before {
            self.save()?;
        }
        Ok(CodeRevoke::new(&self.root, code))
    }

    /// The key other modules use to encrypt their local stores.
    pub fn data_key(&self) -> &[u8; 32] {
        &self.sealed.data_key
    }

    fn save(&self) -> Result<(), KeystoreError> {
        let contents = Contents {
            username: self.username.clone(),
            root_secret: *self.root.secret_bytes(),
            device_secret: *self.device.secret_bytes(),
            device_list: self.devices.to_bytes(),
            codes: self.codes.clone(),
        };
        let plain = encode_with_contacts(&contents, &self.contacts, &self.account)?;
        self.sealed.save(&self.path, &plain)
    }

    pub fn contacts(&self) -> &[Contact] {
        &self.contacts
    }

    pub fn contact(&self, id: &MeshId) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.id() == *id)
    }

    /// Members of the Spaces held who aren't contacts (SPEC-spaces S2), in
    /// memory only: the caller works them out again after each unlock.
    pub fn peers(&self) -> &[Contact] {
        &self.peers
    }

    /// A contact or a peer: what routing needs to reach `id`.
    pub fn reachable_contact(&self, id: &MeshId) -> Option<&Contact> {
        self.contact(id)
            .or_else(|| self.peers.iter().find(|c| c.id() == *id))
    }

    /// Contacts, then peers: who routing, mail and the handshake reach.
    pub fn reachable(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.iter().chain(&self.peers)
    }

    /// Replaces the peers with `ids`, less ourselves, contacts and blocks,
    /// keeping each one's route if they were already a peer. Refused, and
    /// nothing changed, past `MAX_CONTACTS` with the contacts.
    pub fn set_peers(
        &mut self,
        ids: impl IntoIterator<Item = MeshId>,
    ) -> Result<(), KeystoreError> {
        let mut seen = HashSet::new();
        let ids: Vec<MeshId> = ids
            .into_iter()
            .filter(|id| self.is_peer_candidate(id) && seen.insert(*id))
            .collect();
        if self.contacts.len() + ids.len() > MAX_CONTACTS {
            return Err(KeystoreError::TooManyContacts);
        }
        let mut old = std::mem::take(&mut self.peers);
        self.peers = ids
            .into_iter()
            .map(|id| match old.iter().position(|c| c.id() == id) {
                Some(at) => old.swap_remove(at),
                None => Contact::new(id, String::new(), unix_now()),
            })
            .collect();
        Ok(())
    }

    /// Whether `ids` fit under `MAX_CONTACTS` with the contacts and peers,
    /// each person counted once.
    pub fn room_for(&self, ids: &[MeshId]) -> bool {
        let known =
            |id: &MeshId| self.contact(id).is_some() || self.peers.iter().any(|c| c.id() == *id);
        let mut seen = HashSet::new();
        let new = ids
            .iter()
            .filter(|id| **id != self.id() && !known(id) && seen.insert(**id))
            .count();
        self.contacts.len() + self.peers.len() + new <= MAX_CONTACTS
    }

    fn is_peer_candidate(&self, id: &MeshId) -> bool {
        *id != self.id()
            && self.contact(id).is_none()
            && self.account.kind(id) != Some(Kind::Blocked)
    }

    /// Who you know (SPEC-social D8).
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Adds `id` by ID, or after sending them a request: `outgoing` until
    /// they connect. If they'd asked you, this accepts. `nick` may be empty.
    pub fn add_contact(&mut self, id: MeshId, nick: &str) -> Result<(), KeystoreError> {
        if id == self.id() {
            return Err(KeystoreError::OwnId);
        }
        let nick = clean_nick(nick)?;
        match self.account.kind(&id) {
            Some(Kind::Outgoing | Kind::Friend) => return Err(KeystoreError::AlreadyContact),
            Some(Kind::Blocked) => return Err(KeystoreError::Blocked),
            Some(Kind::Incoming) => return self.accept(&id),
            _ => {}
        }
        if !self.room_for(&[id]) {
            return Err(KeystoreError::TooManyContacts);
        }
        // A weak key could never be reached; refuse it up front.
        PairKeys::new(&self.root, &id).ok_or(KeystoreError::BadContactName)?;
        let now = unix_now();
        self.set_kind(&id, Kind::Outgoing, |e| {
            e.nick = nick;
            e.at = now;
        })
    }

    /// A request arrived. Dropped if they're blocked or already a friend; if
    /// you'd asked them too, you're friends now. True if anything changed.
    pub fn knocked(&mut self, knock: &Knock) -> Result<bool, KeystoreError> {
        let id = knock.sender;
        let seen = |e: &Entry| e.at >= knock.created_at;
        match self.account.kind(&id) {
            _ if id == self.id() => Ok(false),
            Some(Kind::Blocked | Kind::Friend) => Ok(false),
            Some(Kind::Incoming) if self.account.get(&id).is_some_and(seen) => Ok(false),
            Some(Kind::Outgoing) => self.set_kind(&id, Kind::Friend, |_| {}).map(|()| true),
            _ => {
                let (name, note, at) = (knock.name.clone(), knock.note.clone(), knock.created_at);
                self.set_kind(&id, Kind::Incoming, |e| {
                    (e.name, e.note, e.at) = (name, note, at)
                })?;
                Ok(true)
            }
        }
    }

    pub fn accept(&mut self, id: &MeshId) -> Result<(), KeystoreError> {
        if self.account.kind(id) != Some(Kind::Incoming) {
            return Err(KeystoreError::NoRequest);
        }
        if !self.room_for(&[*id]) {
            return Err(KeystoreError::TooManyContacts);
        }
        self.set_kind(id, Kind::Friend, |_| {})
    }

    /// Drops their request; nothing tells them (SPEC-social D9).
    pub fn decline(&mut self, id: &MeshId) -> Result<(), KeystoreError> {
        if self.account.kind(id) != Some(Kind::Incoming) {
            return Err(KeystoreError::NoRequest);
        }
        self.set_kind(id, Kind::Removed, |_| {})
    }

    /// Removes a friend, or cancels a request you sent.
    pub fn remove_contact(&mut self, id: &MeshId) -> Result<(), KeystoreError> {
        if !matches!(self.account.kind(id), Some(Kind::Outgoing | Kind::Friend)) {
            return Err(KeystoreError::NotAContact);
        }
        self.set_kind(id, Kind::Removed, |_| {})
    }

    pub fn block(&mut self, id: &MeshId) -> Result<(), KeystoreError> {
        if *id == self.id() {
            return Err(KeystoreError::OwnId);
        }
        let blocks = self.account.entries().iter();
        let blocks = blocks.filter(|e| e.kind == Kind::Blocked).count();
        if self.account.kind(id) != Some(Kind::Blocked) && blocks >= MAX_BLOCKS {
            return Err(KeystoreError::TooManyBlocks);
        }
        let now = unix_now();
        self.set_kind(id, Kind::Blocked, |e| e.at = now)
    }

    /// Unblocking doesn't bring a friendship back.
    pub fn unblock(&mut self, id: &MeshId) -> Result<(), KeystoreError> {
        if self.account.kind(id) != Some(Kind::Blocked) {
            return Err(KeystoreError::NotAContact);
        }
        self.set_kind(id, Kind::Removed, |_| {})
    }

    /// Your name for them; empty clears it.
    pub fn rename_contact(&mut self, id: &MeshId, nick: &str) -> Result<(), KeystoreError> {
        let nick = clean_nick(nick)?;
        let kind = self.known(id)?;
        self.set_kind(id, kind, |e| e.nick = nick)
    }

    /// After comparing the safety number (SPEC-social D14).
    pub fn verify(&mut self, id: &MeshId, verified: bool) -> Result<(), KeystoreError> {
        let kind = self.known(id)?;
        self.set_kind(id, kind, |e| e.verified = verified)
    }

    pub fn set_status(&mut self, status: Status) -> Result<(), KeystoreError> {
        self.account.set_status(status, self.by(), unix_now());
        self.save()
    }

    /// A connection with `id` passed the handshake. Their device let us in,
    /// so an `outgoing` contact has added us too: friends now (D8). True if
    /// that changed anything.
    pub fn connected(&mut self, id: &MeshId) -> Result<bool, KeystoreError> {
        if self.account.kind(id) != Some(Kind::Outgoing) {
            return Ok(false);
        }
        self.set_kind(id, Kind::Friend, |_| {}).map(|()| true)
    }

    /// A friend's own name, as their presence carries it: the request only
    /// carried the sender's, so this is how the sender learns theirs. True if
    /// it changed.
    pub fn heard_name(&mut self, id: &MeshId, name: &str) -> Result<bool, KeystoreError> {
        let name = name.trim();
        let current = self.account.get(id).filter(|e| e.kind == Kind::Friend);
        if !crate::password::valid_username(name) || current.is_none_or(|e| e.name == name) {
            return Ok(false);
        }
        let name = name.to_owned();
        self.set_kind(id, Kind::Friend, |e| e.name = name)
            .map(|()| true)
    }

    /// Takes in another device's account state (SPEC-social D11). True if
    /// anything changed here.
    pub fn merge_account(&mut self, other: &Account) -> Result<bool, KeystoreError> {
        if !self.account.merge(other) {
            return Ok(false);
        }
        self.account.prune();
        self.follow_account();
        self.save()?;
        Ok(true)
    }

    /// Their kind, if they're in your lists as anything but a tombstone.
    fn known(&self, id: &MeshId) -> Result<Kind, KeystoreError> {
        match self.account.kind(id) {
            None | Some(Kind::Removed) => Err(KeystoreError::NotAContact),
            Some(kind) => Ok(kind),
        }
    }

    fn set_kind(
        &mut self,
        id: &MeshId,
        kind: Kind,
        f: impl FnOnce(&mut Entry),
    ) -> Result<(), KeystoreError> {
        let now = unix_now();
        self.account.change(id, self.by(), now, |e| {
            if kind != Kind::Incoming {
                e.note.clear();
            }
            if matches!(kind, Kind::Removed | Kind::Blocked) {
                e.verified = false;
            }
            e.kind = kind;
            f(e);
        });
        self.account.prune();
        self.follow_account();
        self.save()
    }

    /// Keeps routing's contacts to exactly the `outgoing` and `friend` entries.
    fn follow_account(&mut self) {
        let account = &self.account;
        let reachable =
            |id: &MeshId| matches!(account.kind(id), Some(Kind::Outgoing | Kind::Friend));
        self.contacts.retain(|c| reachable(&c.id()));
        for e in account.entries() {
            let id = e.id();
            if reachable(&id) {
                match self.contacts.iter_mut().find(|c| c.id() == id) {
                    Some(c) => c.name = e.nick.clone(),
                    None => self.contacts.push(Contact::new(id, e.nick.clone(), e.at)),
                }
            }
        }
        // A peer who's now a contact, or blocked, isn't a peer. One who stops
        // being a contact comes back when the caller next sets the peers.
        let blocked = |id: &MeshId| account.kind(id) == Some(Kind::Blocked);
        self.peers
            .retain(|p| !reachable(&p.id()) && !blocked(&p.id()));
    }

    /// This device, as the tie-breaker in account stamps.
    fn by(&self) -> [u8; 32] {
        *self.device.public().as_bytes()
    }

    /// A handshake with `id`'s device worked through `last`: cache it, and
    /// keep `list` if it's their newest.
    pub fn contact_reached(
        &mut self,
        id: &MeshId,
        last: LastAddr,
        list: Option<&DeviceList>,
    ) -> Result<(), KeystoreError> {
        // A peer's route lives in memory only (SPEC-spaces S2).
        if let Some(peer) = self.peer_mut(id) {
            peer.reached(last, list, unix_now());
            return Ok(());
        }
        self.contact_mut(id)?.reached(last, list, unix_now());
        self.save()
    }

    /// A handshake over a connection `id` opened (or one already open): seen
    /// now, with no address to keep.
    pub fn contact_seen(&mut self, id: &MeshId) -> Result<(), KeystoreError> {
        if let Some(peer) = self.peer_mut(id) {
            peer.seen = Some(unix_now());
            return Ok(());
        }
        self.contact_mut(id)?.seen = Some(unix_now());
        self.save()
    }

    /// The keys this identity shares with `id` (routing's pair keys).
    pub fn pair_keys(&self, id: &MeshId) -> Option<PairKeys> {
        PairKeys::new(&self.root, id)
    }

    fn contact_mut(&mut self, id: &MeshId) -> Result<&mut Contact, KeystoreError> {
        self.contacts
            .iter_mut()
            .find(|c| c.id() == *id)
            .ok_or(KeystoreError::NotAContact)
    }

    fn peer_mut(&mut self, id: &MeshId) -> Option<&mut Contact> {
        self.peers.iter_mut().find(|c| c.id() == *id)
    }
}

/// `value`, then the contacts and the account state if there are any (see
/// the module docs).
fn encode_with_contacts<T: Serialize>(
    value: &T,
    contacts: &[Contact],
    account: &Account,
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let to_io = |e: postcard::Error| std::io::Error::other(e.to_string());
    let mut plain = Zeroizing::new(postcard::to_allocvec(value).map_err(to_io)?);
    if !contacts.is_empty() || !account.is_empty() {
        plain.extend_from_slice(&postcard::to_allocvec(contacts).map_err(to_io)?);
    }
    if !account.is_empty() {
        plain.extend_from_slice(&account.to_bytes());
    }
    Ok(plain)
}

fn decode_with_contacts<T: serde::de::DeserializeOwned>(
    plain: &[u8],
) -> Result<(T, Vec<Contact>, Account), KeystoreError> {
    let bad = |_| KeystoreError::CannotUnlock;
    let (value, rest) = postcard::take_from_bytes::<T>(plain).map_err(bad)?;
    let (contacts, rest): (Vec<Contact>, &[u8]) = if rest.is_empty() {
        (Vec::new(), rest)
    } else {
        postcard::take_from_bytes(rest).map_err(bad)?
    };
    let account = if rest.is_empty() {
        Account::default()
    } else {
        Account::from_bytes(rest).ok_or(KeystoreError::CannotUnlock)?
    };
    if !contacts.iter().all(Contact::valid) {
        return Err(KeystoreError::CannotUnlock);
    }
    Ok((value, contacts, account))
}

/// A nickname, trimmed; empty is allowed (no nickname).
fn clean_nick(nick: &str) -> Result<String, KeystoreError> {
    match nick.trim() {
        "" => Ok(String::new()),
        n => clean_name(n).ok_or(KeystoreError::BadContactName),
    }
}

/// Argon2id over `normalize(username) || 0 || password`.
fn derive_kek(
    username: &str,
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let mut input = Zeroizing::new(normalize_username(username).into_bytes());
    input.push(0);
    input.extend_from_slice(password.as_bytes());
    let argon = argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| KeystoreError::CannotUnlock)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon)
        .hash_password_into(&input, salt, kek.as_mut())
        .map_err(|_| KeystoreError::CannotUnlock)?;
    Ok(kek)
}

/// A random nonce followed by `plain` encrypted under `key`, bound to `aad`.
fn seal_bytes(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let nonce = random::<NONCE_LEN>()?;
    let sealed = XChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| std::io::Error::other("encryption failed"))?;
    Ok([nonce.as_slice(), &sealed].concat())
}

/// The reverse of [`seal_bytes`]; any mismatch is `CannotUnlock`.
fn open_bytes(
    key: &[u8; 32],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let (nonce, body) = sealed
        .split_at_checked(NONCE_LEN)
        .ok_or(KeystoreError::CannotUnlock)?;
    let nonce = XNonce::from(<[u8; NONCE_LEN]>::try_from(nonce).expect("split at NONCE_LEN"));
    XChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&nonce, Payload { msg: body, aad })
        .map(Zeroizing::new)
        .map_err(|_| KeystoreError::CannotUnlock)
}

fn random<const N: usize>() -> Result<[u8; N], KeystoreError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(KeystoreError::Random)?;
    Ok(bytes)
}

fn expired(code: &ActiveCode, now: u64) -> bool {
    code.expires_at.is_some_and(|at| at <= now)
}

/// Seconds since 1970 (0 if the clock is before it), moved by the clock
/// offset if one was set.
pub fn unix_now() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    now.saturating_add_signed(CLOCK_OFFSET.load(std::sync::atomic::Ordering::Relaxed))
}

/// Seconds added to `unix_now`: 0, unless a test moved the clock.
static CLOCK_OFFSET: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
/// How far a test may move the clock (`--clock-offset`).
pub const MAX_CLOCK_OFFSET: i64 = 60 * 86_400;

/// Moves this process's clock by `secs`, for tests (`--clock-offset`,
/// SPEC-mailbox decided Q14). `false`, and nothing moved, past
/// `MAX_CLOCK_OFFSET`.
pub fn set_clock_offset(secs: i64) -> bool {
    if secs.abs() > MAX_CLOCK_OFFSET {
        return false;
    }
    CLOCK_OFFSET.store(secs, std::sync::atomic::Ordering::Relaxed);
    true
}

/// Writes `bytes` to a temporary file beside `path` (owner-only), syncs
/// it, renames it over `path`, then syncs the folder: after a crash or a
/// power cut there's the old file or the new one, never half of either.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    // The rename itself is durable only once the directory is synced (Unix).
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_devices_learn_and_remove_each_other() {
        let (desk_path, backup, laptop_path) = (
            temp_path("own-desk"),
            temp_path("own-backup"),
            temp_path("own-laptop"),
        );
        let mut desk = create(&desk_path);
        desk.export(&backup, PASSWORD).unwrap();
        let laptop = Keystore::import_with(
            &backup,
            &laptop_path,
            "Brendon",
            PASSWORD,
            PASSWORD,
            "Laptop",
            FAST,
        )
        .unwrap();
        let laptop_key = laptop.device_key().public();
        // The desk can't remove what it doesn't know of yet.
        assert!(desk.remove_device(&laptop_key).is_err());
        assert!(desk.own_list_seen(laptop.devices()).unwrap());
        assert!(!desk.own_list_seen(laptop.devices()).unwrap());
        desk.remove_device(&laptop_key).unwrap();
        assert!(!desk.devices().is_current(&laptop_key));
        assert_eq!(desk.devices().seq(), laptop.devices().seq() + 1);
        // An older list doesn't bring it back, and a device can't remove itself.
        assert!(!desk.own_list_seen(laptop.devices()).unwrap());
        let this = desk.device_key().public();
        assert!(desk.remove_device(&this).is_err());
        // The change was saved.
        let reopened = Keystore::unlock(&desk_path, "Brendon", PASSWORD).unwrap();
        assert!(!reopened.devices().is_current(&laptop_key));
        for p in [desk_path, backup, laptop_path] {
            let _ = fs::remove_dir_all(p.parent().unwrap());
        }
    }

    const PASSWORD: &str = "Tundra-Gravel-Mosaic-41";
    const OTHER_PASSWORD: &str = "copper lantern drifts sideways";
    const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-keystore-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("identity.mks")
    }

    fn create(path: &Path) -> Keystore {
        Keystore::create_with(path, "Brendon", PASSWORD, "Desktop", FAST).unwrap()
    }

    fn cannot(r: Result<Keystore, KeystoreError>) -> bool {
        matches!(r, Err(KeystoreError::CannotUnlock))
    }

    #[test]
    fn create_lock_and_unlock() {
        let path = temp_path("round-trip");
        let created = create(&path);
        let (id, device, data_key) = (
            created.id(),
            created.device_key().public(),
            *created.data_key(),
        );
        drop(created); // locked
        let opened = Keystore::unlock(&path, " brendon ", PASSWORD).unwrap();
        assert_eq!(
            (
                opened.id(),
                opened.device_key().public(),
                *opened.data_key()
            ),
            (id, device, data_key)
        );
        assert_eq!(opened.username(), "Brendon");
        assert!(opened.devices().is_current(&device));
        assert_eq!(opened.devices().devices()[0].name(), "Desktop");
        assert!(matches!(
            Keystore::create_with(&path, "Brendon", PASSWORD, "Desktop", FAST),
            Err(KeystoreError::AlreadyExists)
        ));
    }

    #[test]
    fn wrong_username_password_or_damage_all_fail_the_same() {
        let path = temp_path("failures");
        drop(create(&path));
        assert!(cannot(Keystore::unlock(
            &path,
            "Brendon",
            "Tundra-Gravel-Mosaic-42"
        )));
        assert!(cannot(Keystore::unlock(&path, "Brandon", PASSWORD)));
        let good = fs::read(&path).unwrap();
        // Any changed byte, in the header or the contents, stops it opening.
        for i in [
            0,
            6,
            20,
            PARAMS_END + 3,
            HEADER_LEN - 1,
            HEADER_LEN + 5,
            good.len() - 1,
        ] {
            let mut bad = good.clone();
            bad[i] ^= 1;
            fs::write(&path, &bad).unwrap();
            assert!(
                cannot(Keystore::unlock(&path, "Brendon", PASSWORD)),
                "byte {i}"
            );
        }
        fs::write(&path, &good[..40]).unwrap();
        assert!(cannot(Keystore::unlock(&path, "Brendon", PASSWORD)));
        let mut newer = good.clone();
        newer[4] = VERSION + 1;
        fs::write(&path, &newer).unwrap();
        assert!(matches!(
            Keystore::unlock(&path, "Brendon", PASSWORD),
            Err(KeystoreError::NewerVersion)
        ));
        assert!(matches!(
            Keystore::unlock(&temp_path("missing"), "Brendon", PASSWORD),
            Err(KeystoreError::NotFound)
        ));
    }

    #[test]
    fn nothing_identifying_is_readable_on_disk() {
        let path = temp_path("opaque");
        let store = create(&path);
        let backup = path.with_file_name("backup.mkb");
        store.export_with(&backup, OTHER_PASSWORD, FAST).unwrap();
        for file in [&path, &backup] {
            let bytes = fs::read(file).unwrap();
            let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
            for needle in [
                b"Brendon".as_slice(),
                b"brendon",
                &store.id().to_bytes(),
                store.id().to_string().as_bytes(),
                b"Desktop",
                &store.device_key().public().to_bytes(),
            ] {
                assert!(
                    !contains(needle),
                    "{needle:?} is readable in {}",
                    file.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn weak_passwords_and_bad_usernames_are_refused() {
        let path = temp_path("policy");
        let weak = Keystore::create_with(&path, "Brendon", "password1234", "Desktop", FAST);
        assert!(matches!(
            weak,
            Err(KeystoreError::WeakPassword(PasswordVerdict::Weak { .. }))
        ));
        let bad = Keystore::create_with(&path, "  ", PASSWORD, "Desktop", FAST);
        assert!(matches!(bad, Err(KeystoreError::BadUsername)));
        assert!(!Keystore::exists(&path));
    }

    #[test]
    fn crafted_huge_parameters_are_refused_before_hashing() {
        let path = temp_path("huge");
        drop(create(&path));
        let mut bytes = fs::read(&path).unwrap();
        bytes[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        let started = std::time::Instant::now();
        assert!(cannot(Keystore::unlock(&path, "Brendon", PASSWORD)));
        assert!(started.elapsed().as_secs() < 1);
    }

    #[test]
    fn changing_the_password_keeps_the_data_key() {
        let path = temp_path("change");
        let mut store = create(&path);
        let data_key = *store.data_key();
        assert!(matches!(
            store.change_password("Brendon", "Not-The-Password-77", OTHER_PASSWORD),
            Err(KeystoreError::CannotUnlock)
        ));
        assert!(matches!(
            store.change_password("Brendon", PASSWORD, "password1234"),
            Err(KeystoreError::WeakPassword(_))
        ));
        store
            .change_password("brendon", PASSWORD, OTHER_PASSWORD)
            .unwrap();
        drop(store);
        assert!(cannot(Keystore::unlock(&path, "Brendon", PASSWORD)));
        let reopened = Keystore::unlock(&path, "Brendon", OTHER_PASSWORD).unwrap();
        assert_eq!(*reopened.data_key(), data_key);
    }

    #[test]
    fn a_backup_restores_the_identity_as_a_new_device() {
        let path = temp_path("backup");
        let store = create(&path);
        let backup = path.with_file_name("backup.mkb");
        assert!(matches!(
            store.export_with(&backup, "password1234", FAST),
            Err(KeystoreError::WeakPassword(_))
        ));
        store.export_with(&backup, OTHER_PASSWORD, FAST).unwrap();

        let laptop = path.with_file_name("laptop.mks");
        let import = |user: &str, backup_pw: &str, new_pw: &str| {
            Keystore::import_with(&backup, &laptop, user, backup_pw, new_pw, "Laptop", FAST)
        };
        assert!(cannot(import("Brendon", PASSWORD, PASSWORD)));
        assert!(cannot(import("Brandon", OTHER_PASSWORD, PASSWORD)));
        assert!(matches!(
            import("Brendon", OTHER_PASSWORD, "qwertyuiop12"),
            Err(KeystoreError::WeakPassword(_))
        ));
        let restored = import("BRENDON", OTHER_PASSWORD, PASSWORD).unwrap();
        assert_eq!(
            (restored.id(), restored.username()),
            (store.id(), "Brendon")
        );
        assert_ne!(restored.device_key().public(), store.device_key().public());
        assert_eq!(restored.devices().seq(), store.devices().seq() + 1);
        assert!(
            restored
                .devices()
                .is_current(&restored.device_key().public())
        );
        assert_eq!(restored.devices().replaces(store.devices()), Ok(()));
        // A backup is not a keystore, nor the other way round.
        assert!(cannot(Keystore::unlock(&backup, "Brendon", OTHER_PASSWORD)));
        assert!(cannot(Keystore::import_with(
            &path,
            &temp_path("x"),
            "Brendon",
            PASSWORD,
            PASSWORD,
            "X",
            FAST
        )));
        drop(restored);
        assert!(Keystore::unlock(&laptop, "Brendon", PASSWORD).is_ok());
    }

    /// Space members (SPEC-spaces S2 as changed 2026-11-14): worked out by
    /// the caller, held here in memory beside the contacts, never saved.
    #[test]
    fn peers_are_worked_out_beside_the_contacts() {
        let path = temp_path("peers");
        let mut store = create(&path);
        let friend = RootKey::generate().unwrap().id();
        let blocked = RootKey::generate().unwrap().id();
        let peer = RootKey::generate().unwrap().id();
        store.add_contact(friend, "Alex").unwrap();
        store.block(&blocked).unwrap();
        let me = store.id();
        store.set_peers([me, friend, blocked, peer, peer]).unwrap();
        // Less ourselves, contacts and blocks, once each.
        let peers: Vec<MeshId> = store.peers().iter().map(|c| c.id()).collect();
        assert_eq!(peers, [peer]);
        let reachable: Vec<MeshId> = store.reachable().map(|c| c.id()).collect();
        assert_eq!(reachable, [friend, peer]);
        // Not a contact, so social sees nothing new.
        assert!(store.contact(&peer).is_none());
        assert_eq!(store.account().kind(&peer), None);
        // Reaching one keeps its route while it stays a peer.
        let last = LastAddr {
            device: [9; 32],
            relay: "https://relay.example/".into(),
        };
        store.contact_reached(&peer, last.clone(), None).unwrap();
        store.set_peers([peer]).unwrap();
        assert_eq!(store.peers()[0].last, Some(last));
        // Never saved: after a lock, there are none until worked out again.
        drop(store);
        let store = Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        assert!(store.peers().is_empty());
    }

    /// `MAX_CONTACTS` counts contacts and peers together, once per person.
    #[test]
    fn contacts_and_peers_share_one_cap() {
        let path = temp_path("peer-cap");
        let mut store = create(&path);
        let friend = RootKey::generate().unwrap().id();
        store.add_contact(friend, "").unwrap();
        let many: Vec<MeshId> = (0..MAX_CONTACTS - 1)
            .map(|_| RootKey::generate().unwrap().id())
            .collect();
        assert!(store.room_for(&many));
        let one_more = RootKey::generate().unwrap().id();
        let too_many: Vec<MeshId> = many.iter().copied().chain([one_more]).collect();
        assert!(!store.room_for(&too_many));
        // A friend already counted isn't counted twice.
        let with_friend: Vec<MeshId> = many.iter().copied().chain([friend]).collect();
        assert!(store.room_for(&with_friend));
        store.set_peers(many.iter().copied()).unwrap();
        assert!(matches!(
            store.set_peers(too_many.iter().copied()),
            Err(KeystoreError::TooManyContacts)
        ));
        assert_eq!(store.peers().len(), MAX_CONTACTS - 1, "kept as it was");
        // And a new contact can't push past it either.
        assert!(matches!(
            store.add_contact(one_more, ""),
            Err(KeystoreError::TooManyContacts)
        ));
    }

    /// Seen over a connection they opened (or one already open): no
    /// address to keep, but a handshake all the same (SPEC-routing `seen`).
    #[test]
    fn a_contact_is_seen_over_an_open_connection() {
        let path = temp_path("seen");
        let mut store = create(&path);
        let kim = RootKey::generate().unwrap().id();
        store.add_contact(kim, "Kim").unwrap();
        assert!(store.contact(&kim).unwrap().seen.is_none());
        store.contact_seen(&kim).unwrap();
        drop(store);
        let store = Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        let k = store.contact(&kim).unwrap();
        assert!(k.seen.is_some() && k.last.is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn contacts_are_kept_changed_and_backed_up() {
        let path = temp_path("contacts");
        let mut store = create(&path);
        // No contacts: the file is the earlier format, byte for byte.
        let before = fs::read(&path).unwrap();
        assert!(before.len() < HEADER_LEN + 400);

        let friend = RootKey::generate().unwrap().id();
        assert!(matches!(
            store.add_contact(store.id(), "me"),
            Err(KeystoreError::OwnId)
        ));
        assert!(matches!(
            store.add_contact(friend, &"x".repeat(65)),
            Err(KeystoreError::BadContactName)
        ));
        store.add_contact(friend, " Alex ").unwrap();
        assert!(matches!(
            store.add_contact(friend, "Alex"),
            Err(KeystoreError::AlreadyContact)
        ));
        store.rename_contact(&friend, "Alex P").unwrap();

        let device = DeviceKey::generate().unwrap();
        let friend_root = RootKey::generate().unwrap();
        let cert = DeviceCert::issue(&friend_root, &device.public(), "pc", 1).unwrap();
        let list = DeviceList::first(&friend_root, cert).unwrap();
        let other = friend_root.id();
        store.add_contact(other, "Sam").unwrap();
        let last = LastAddr {
            device: *device.public().as_bytes(),
            relay: "https://r/".into(),
        };
        store
            .contact_reached(&other, last.clone(), Some(&list))
            .unwrap();
        assert!(store.pair_keys(&other).is_some());

        let mut store = {
            drop(store);
            Keystore::unlock(&path, "Brendon", PASSWORD).unwrap()
        };
        assert_eq!(store.contacts().len(), 2);
        assert_eq!(store.contact(&friend).unwrap().name, "Alex P");
        let sam = store.contact(&other).unwrap();
        assert_eq!(sam.last.as_ref(), Some(&last));
        assert!(sam.seen.is_some());
        assert_eq!(sam.devices().unwrap().seq(), 1);

        store
            .change_password("Brendon", PASSWORD, OTHER_PASSWORD)
            .unwrap();
        let backup = path.with_file_name("backup.mkb");
        store.export_with(&backup, OTHER_PASSWORD, FAST).unwrap();
        let laptop = path.with_file_name("laptop.mks");
        let restored = Keystore::import_with(
            &backup,
            &laptop,
            "Brendon",
            OTHER_PASSWORD,
            PASSWORD,
            "Laptop",
            FAST,
        )
        .unwrap();
        assert_eq!(restored.contacts(), store.contacts());

        store.remove_contact(&friend).unwrap();
        assert!(matches!(
            store.remove_contact(&friend),
            Err(KeystoreError::NotAContact)
        ));
        drop(store);
        let store = Keystore::unlock(&path, "Brendon", OTHER_PASSWORD).unwrap();
        assert_eq!(store.contacts().len(), 1);
    }

    fn knock_from(root: &RootKey, at: u64) -> Knock {
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(root, &device.public(), "pc", 1).unwrap();
        Knock {
            sender: root.id(),
            devices: DeviceList::first(root, cert).unwrap(),
            name: "Sam".into(),
            note: "hi".into(),
            created_at: at,
        }
    }

    #[test]
    fn the_lists_follow_the_account_and_are_backed_up() {
        let path = temp_path("social");
        let mut store = create(&path);
        let (sam, eve, kim) = (
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
        );
        let now = unix_now();

        // A request isn't a contact: it isn't let in until accepted.
        assert!(store.knocked(&knock_from(&sam, now)).unwrap());
        assert!(!store.knocked(&knock_from(&sam, now)).unwrap());
        assert_eq!(store.account().kind(&sam.id()), Some(Kind::Incoming));
        assert_eq!(store.account().get(&sam.id()).unwrap().note, "hi");
        assert!(store.contacts().is_empty());
        store.accept(&sam.id()).unwrap();
        assert_eq!(store.account().kind(&sam.id()), Some(Kind::Friend));
        assert_eq!(store.contacts().len(), 1);
        assert!(!store.knocked(&knock_from(&sam, now + 1)).unwrap());

        // Blocked: never a contact, requests dropped.
        store.knocked(&knock_from(&eve, now)).unwrap();
        store.block(&eve.id()).unwrap();
        assert!(!store.knocked(&knock_from(&eve, now + 5)).unwrap());
        assert!(matches!(
            store.add_contact(eve.id(), ""),
            Err(KeystoreError::Blocked)
        ));
        assert!(matches!(
            store.accept(&eve.id()),
            Err(KeystoreError::NoRequest)
        ));
        assert_eq!(store.contacts().len(), 1);

        // Added by ID, then their device connects: friends.
        store.add_contact(kim.id(), "").unwrap();
        assert_eq!(store.account().kind(&kim.id()), Some(Kind::Outgoing));
        assert!(store.connected(&kim.id()).unwrap());
        assert!(!store.connected(&kim.id()).unwrap());
        assert_eq!(store.account().kind(&kim.id()), Some(Kind::Friend));
        store.verify(&kim.id(), true).unwrap();
        store.set_status(Status::Dnd).unwrap();

        // Backed up, and opened as a second device.
        let backup = path.with_file_name("social.mkb");
        store.export_with(&backup, OTHER_PASSWORD, FAST).unwrap();
        let laptop = path.with_file_name("social-laptop.mks");
        let mut second = Keystore::import_with(
            &backup,
            &laptop,
            "Brendon",
            OTHER_PASSWORD,
            PASSWORD,
            "Laptop",
            FAST,
        )
        .unwrap();
        assert_eq!(second.account(), store.account());
        assert_eq!(second.contacts().len(), 2);

        // The laptop removes Sam; the desktop takes the change in.
        second.remove_contact(&sam.id()).unwrap();
        assert!(store.merge_account(second.account()).unwrap());
        assert!(!store.merge_account(second.account()).unwrap());
        assert_eq!(store.account().kind(&sam.id()), Some(Kind::Removed));
        assert_eq!(store.contacts().len(), 1);
        store.unblock(&eve.id()).unwrap();
        assert_eq!(store.account().kind(&eve.id()), Some(Kind::Removed));

        let account = store.account().clone();
        drop(store);
        let store = Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        assert_eq!(store.account(), &account);
        assert_eq!(store.account().status(), Status::Dnd);
        assert!(store.account().get(&kim.id()).unwrap().verified);
    }

    #[test]
    fn routing_contacts_open_as_outgoing() {
        let path = temp_path("adopt");
        let mut store = create(&path);
        let friend = RootKey::generate().unwrap().id();
        store.add_contact(friend, "Alex").unwrap();
        // As a keystore from routing: contacts, but no account state.
        store.account = Account::default();
        store.save().unwrap();
        drop(store);
        let store = Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        let entry = store.account().get(&friend).unwrap();
        assert_eq!((entry.kind, entry.nick.as_str()), (Kind::Outgoing, "Alex"));
        assert_eq!(store.contacts().len(), 1);
    }

    #[test]
    fn friend_codes_are_kept_and_revoked() {
        let path = temp_path("codes");
        let mut store = create(&path);
        let (code, held) = store.create_code(Some(3600), Some(5)).unwrap();
        assert_eq!(held.open(&code, unix_now()).unwrap().root(), store.id());
        let (other, _) = store.create_code(None, None).unwrap();
        assert!(matches!(
            store.create_code(Some(1), None),
            Err(KeystoreError::Code(CodeError::NotAChoice))
        ));
        drop(store);
        let mut store = Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        let listed: Vec<_> = store.codes().iter().map(|c| c.code).collect();
        assert_eq!(listed, [code, other]);
        assert_eq!(store.codes()[0].max_uses, Some(5));
        assert_eq!(store.codes()[1].expires_at, None);
        // Built again for a holder: the same handle and owner, the same limits.
        let again = store.held_record(&store.codes()[0]).unwrap();
        assert_eq!(
            (
                again.lookup_id(),
                again.revoke_tag(),
                again.expires_at(),
                again.max_uses()
            ),
            (
                held.lookup_id(),
                held.revoke_tag(),
                held.expires_at(),
                held.max_uses()
            )
        );
        assert_eq!(again.open(&code, unix_now()).unwrap().root(), store.id());
        let revoke = store.revoke_code(&code).unwrap();
        assert!(held.is_revoked_by(&revoke));
        drop(store);
        let store = Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        assert_eq!(store.codes().len(), 1);
        assert_eq!(store.codes()[0].code, other);
    }

    /// Unlock time with the real settings: `cargo test --release -- --ignored unlock_time`.
    #[test]
    #[ignore]
    fn unlock_time() {
        let path = temp_path("timing");
        drop(Keystore::create(&path, "Brendon", PASSWORD, "Desktop").unwrap());
        let started = std::time::Instant::now();
        Keystore::unlock(&path, "Brendon", PASSWORD).unwrap();
        let elapsed = started.elapsed();
        eprintln!("unlock with {:?}: {elapsed:?}", KdfParams::DEFAULT);
        assert!(elapsed.as_secs_f64() < 1.0, "{elapsed:?}");
    }
}
