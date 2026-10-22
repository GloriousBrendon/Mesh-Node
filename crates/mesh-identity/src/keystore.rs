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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::device::{DeviceCert, DeviceList};
use crate::id::{DeviceKey, MeshId, RootKey};
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
}

/// A backup's contents: no device key (see the module docs).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct BackupContents {
    username: String,
    root_secret: [u8; 32],
    device_list: Vec<u8>,
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
        username: &str,
        password: &str,
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
        let kek = derive_kek(username, password, &salt, params)?;
        let data_key = Zeroizing::new(
            open_bytes(&kek, &wrapped, &bytes[..PARAMS_END])?
                .as_slice()
                .try_into()
                .map_err(|_| KeystoreError::CannotUnlock)?,
        );
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
        };
        store.save()?;
        Ok(store)
    }

    /// Opens the identity at `path` with its username and password.
    pub fn unlock(path: &Path, username: &str, password: &str) -> Result<Self, KeystoreError> {
        let (sealed, plain) = Sealed::open(path, KEYSTORE_MAGIC, username, password)?;
        let contents: Contents =
            postcard::from_bytes(&plain).map_err(|_| KeystoreError::CannotUnlock)?;
        let root = RootKey::from_secret_bytes(contents.root_secret);
        let devices = DeviceList::from_bytes(&contents.device_list)
            .map_err(|_| KeystoreError::CannotUnlock)?;
        if devices.root() != root.id() {
            return Err(KeystoreError::CannotUnlock);
        }
        Ok(Self {
            path: path.to_owned(),
            sealed,
            username: contents.username.clone(),
            root,
            device: DeviceKey::from_secret_bytes(contents.device_secret),
            devices,
        })
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
        let plain = Zeroizing::new(
            postcard::to_allocvec(&contents).map_err(|e| std::io::Error::other(e.to_string()))?,
        );
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
        let (_, plain) = Sealed::open(backup, BACKUP_MAGIC, username, backup_password)?;
        let contents: BackupContents =
            postcard::from_bytes(&plain).map_err(|_| KeystoreError::CannotUnlock)?;
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
        Self::save_new(
            path,
            &contents.username,
            new_password,
            params,
            root,
            device,
            devices,
        )
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
        };
        let plain = Zeroizing::new(
            postcard::to_allocvec(&contents).map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        self.sealed.save(&self.path, &plain)
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Temporary file beside `path`, owner-only, synced, then renamed over it:
/// a crash leaves the old file or the new one, never half of one.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
