//! The store (D12): `<data>/e2ee/account`, and one file per person (their
//! keys and our Olm sessions with their devices) and per group (its members
//! and sender chains). Each is sealed with XChaCha20-Poly1305 under a key
//! derived from the keystore's data key (`mesh/v1/e2ee-store`), with its file
//! name as associated data, so a file copied over another is refused. Names
//! are a keyed hash of what the file holds. Writes are atomic: a crash leaves
//! the old file or the new one.
//!
//! File layout: `nonce [24] | sealed JSON + 16 tag`. The JSON holds
//! vodozemac's pickles; they never leave the seal.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::E2eeError;

const STORE_CONTEXT: &str = "mesh/v1/e2ee-store";
/// The account's file name.
pub(crate) const ACCOUNT: &str = "account";

pub(crate) struct Store {
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

impl Store {
    pub(crate) fn new(dir: &Path, data_key: &[u8; 32]) -> Self {
        Self {
            dir: dir.to_owned(),
            key: Zeroizing::new(blake3::derive_key(STORE_CONTEXT, data_key)),
        }
    }

    /// A file's name: a keyed hash of its kind and ID, so names say nothing.
    pub(crate) fn name(&self, kind: &[u8], id: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(b"name").update(kind).update(id);
        let hash = hasher.finalize();
        hash.as_bytes()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub(crate) fn write(&self, name: &str, value: &impl Serialize) -> Result<(), E2eeError> {
        let json = Zeroizing::new(serde_json::to_vec(value).map_err(|_| E2eeError::Store)?);
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| E2eeError::Random)?;
        let sealed = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &json,
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| E2eeError::Store)?;
        let mut bytes = nonce.to_vec();
        bytes.extend_from_slice(&sealed);
        write_atomically(&self.dir.join(name), &bytes).map_err(|_| E2eeError::Store)
    }

    /// `None` when there's no such file; an error when it's damaged.
    pub(crate) fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, E2eeError> {
        let bytes = match fs::read(self.dir.join(name)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(E2eeError::Store),
        };
        if bytes.len() < 24 + 16 {
            return Err(E2eeError::Store);
        }
        let nonce: [u8; 24] = bytes[..24].try_into().expect("24 bytes");
        let json = self
            .cipher()
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[24..],
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| E2eeError::Store)?;
        let json = Zeroizing::new(json);
        serde_json::from_slice(&json)
            .map(Some)
            .map_err(|_| E2eeError::Store)
    }

    /// Removes every file: the state belonged to another device.
    pub(crate) fn clear(&self) -> Result<(), E2eeError> {
        match fs::remove_dir_all(&self.dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(E2eeError::Store),
            _ => Ok(()),
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(*self.key))
    }
}

/// Temporary file beside `path`, owner-only, synced, then renamed over it,
/// as the keystore does.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bundle::tests::{NOW, Person, person};
    use crate::{E2ee, E2eeError, Kind};
    use mesh_identity::MeshId;
    use std::path::{Path, PathBuf};

    const DATA_KEY: [u8; 32] = [7; 32];

    fn temp_dir() -> PathBuf {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name).unwrap();
        let name: String = name.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("mesh-e2ee-{name}"))
    }

    struct Stored {
        who: Person,
        dir: PathBuf,
        e2ee: E2ee,
    }

    impl Stored {
        fn new() -> Self {
            let (who, dir) = (person(), temp_dir());
            let e2ee = Self::open_at(&who, &dir).unwrap();
            Self { who, dir, e2ee }
        }

        fn open_at(who: &Person, dir: &Path) -> Result<E2ee, E2eeError> {
            E2ee::open(dir, &DATA_KEY, &who.root, &who.device, &who.devices, NOW)
        }

        /// Drops the state in memory (a crash) and opens it from disk.
        fn restart(&mut self) {
            self.e2ee = Self::open_at(&self.who, &self.dir).unwrap();
        }

        fn id(&self) -> MeshId {
            self.who.root.id()
        }
    }

    impl Drop for Stored {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// `x` learns `y`'s keys from the record `y` left for it.
    fn introduce(x: &mut Stored, y: &mut Stored) {
        let field = y.e2ee.record_field(&x.id(), NOW).unwrap();
        let device = y.who.device.public();
        x.e2ee
            .learn(&y.id(), &y.who.devices, &device, &field)
            .unwrap();
    }

    fn friends(a: &mut Stored, b: &mut Stored) {
        introduce(a, b);
        introduce(b, a);
    }

    fn refused(who: &Person, dir: &Path) -> E2eeError {
        Stored::open_at(who, dir).err().expect("refused")
    }

    fn one(out: Vec<(ed25519_dalek::VerifyingKey, Vec<u8>)>) -> Vec<u8> {
        assert_eq!(out.len(), 1);
        out.into_iter().next().unwrap().1
    }

    fn body(e2ee: &mut E2ee, bytes: &[u8]) -> Vec<u8> {
        let mut got = e2ee.decrypt(bytes, NOW).unwrap();
        got.opened.pop().unwrap().body
    }

    #[test]
    fn state_survives_a_restart() {
        let (mut alice, mut bob) = (Stored::new(), Stored::new());
        friends(&mut alice, &mut bob);
        let (alice_id, bob_id) = (alice.id(), bob.id());
        let note = one(alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"1")
            .unwrap());
        assert_eq!(body(&mut bob.e2ee, &note), b"1");
        let group = alice.e2ee.new_group(&[bob_id], NOW).unwrap();
        let out = alice
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"g1", NOW)
            .unwrap();
        for env in &out[0].1 {
            bob.e2ee.decrypt(env, NOW).unwrap();
        }

        alice.restart();
        bob.restart();
        let reply = one(bob
            .e2ee
            .encrypt_direct(&alice_id, Kind::TestNote, b"2")
            .unwrap());
        assert_eq!(body(&mut alice.e2ee, &reply), b"2");
        let out = alice
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"g2", NOW)
            .unwrap();
        assert_eq!(out[0].1.len(), 1, "the share was remembered");
        assert_eq!(body(&mut bob.e2ee, &out[0].1[0]), b"g2");
        // A replay stays refused after the restart.
        assert_eq!(bob.e2ee.decrypt(&note, NOW).unwrap_err(), E2eeError::Replay);
        assert_eq!(alice.e2ee.members(&group).unwrap().len(), 2);
    }

    #[test]
    fn a_crash_after_saving_never_reuses_a_message_key() {
        let (mut alice, mut bob) = (Stored::new(), Stored::new());
        friends(&mut alice, &mut bob);
        let bob_id = bob.id();
        let group = alice.e2ee.new_group(&[bob_id], NOW).unwrap();
        // Encrypted and saved, then the device dies before sending.
        let lost = one(alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"lost")
            .unwrap());
        let lost_group = alice
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"lost", NOW)
            .unwrap();
        alice.restart();
        let sent = one(alice
            .e2ee
            .encrypt_direct(&bob_id, Kind::TestNote, b"sent")
            .unwrap());
        let sent_group = alice
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"sent", NOW)
            .unwrap();
        // Both open: had the state rolled back, the second would reuse the
        // first's key and be refused as a replay.
        assert_eq!(body(&mut bob.e2ee, &sent), b"sent");
        assert_eq!(body(&mut bob.e2ee, &lost), b"lost");
        let share = &lost_group[0].1[0];
        bob.e2ee.decrypt(share, NOW).unwrap();
        assert_eq!(body(&mut bob.e2ee, &sent_group[0].1[0]), b"sent");
        assert_eq!(body(&mut bob.e2ee, &lost_group[0].1[1]), b"lost");
    }

    #[test]
    fn damaged_swapped_and_foreign_state() {
        let (mut alice, mut bob) = (Stored::new(), Stored::new());
        friends(&mut alice, &mut bob);
        let files: Vec<PathBuf> = std::fs::read_dir(alice.dir.join("e2ee"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let account = alice.dir.join("e2ee").join("account");
        let person = files.iter().find(|p| **p != account).unwrap().clone();
        // Names say nothing: 32 hex characters.
        assert_eq!(person.file_name().unwrap().len(), 32);

        let good = std::fs::read(&account).unwrap();
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(&account, &bad).unwrap();
        assert_eq!(refused(&alice.who, &alice.dir), E2eeError::Store);
        // Another file put in the account's place is refused too.
        std::fs::write(&account, std::fs::read(&person).unwrap()).unwrap();
        assert_eq!(refused(&alice.who, &alice.dir), E2eeError::Store);
        std::fs::write(&account, &good).unwrap();
        alice.restart();

        // A missing person file is a damaged store, not an empty one.
        std::fs::remove_file(&person).unwrap();
        assert_eq!(refused(&alice.who, &alice.dir), E2eeError::Store);

        // Another device key (a restored backup) starts fresh (Q5).
        let other = person_with_new_device(&alice.who);
        let fresh = Stored::open_at(&other, &alice.dir).unwrap();
        assert_eq!(
            fresh.encrypt_direct_count(&bob.id()),
            Err(E2eeError::NoKeys)
        );
    }

    fn person_with_new_device(who: &Person) -> Person {
        use mesh_identity::{DeviceCert, DeviceKey, RootKey};
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&who.root, &device.public(), "new", NOW).unwrap();
        let devices = who.devices.with_device(&who.root, cert).unwrap();
        Person {
            root: RootKey::from_secret_bytes(*who.root.secret_bytes()),
            device,
            devices,
        }
    }

    impl E2ee {
        fn encrypt_direct_count(mut self, peer: &MeshId) -> Result<usize, E2eeError> {
            self.encrypt_direct(peer, Kind::TestNote, b"x")
                .map(|o| o.len())
        }
    }
}
