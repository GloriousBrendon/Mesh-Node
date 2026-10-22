//! "Keep unlocked on this device" (opt-in, off by default): the keystore's
//! data key kept in the OS keyring (Windows Credential Manager, the Secret
//! Service on Linux), so Mesh opens without asking. It's only as safe as the
//! OS login; turning it off deletes the entry.
//!
//! The entry is named by a random value stored beside the keystore
//! (`identity.mks.keep`), which says nothing about whose identity it is.

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::keystore::{Keystore, KeystoreError};

/// The keyring service every entry is stored under.
const SERVICE: &str = "mesh-node";

/// Where secrets go: the OS keyring, or a map in tests.
pub(crate) trait Vault {
    fn set(&self, entry: &str, secret: &[u8]) -> Result<(), String>;
    /// `Ok(None)` when there's no such entry.
    fn get(&self, entry: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    fn delete(&self, entry: &str) -> Result<(), String>;
}

/// The OS keyring.
pub(crate) struct OsKeyring;

impl Vault for OsKeyring {
    fn set(&self, entry: &str, secret: &[u8]) -> Result<(), String> {
        keyring::Entry::new(SERVICE, entry)
            .and_then(|e| e.set_secret(secret))
            .map_err(|e| e.to_string())
    }

    fn get(&self, entry: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match keyring::Entry::new(SERVICE, entry).and_then(|e| e.get_secret()) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn delete(&self, entry: &str) -> Result<(), String> {
        match keyring::Entry::new(SERVICE, entry).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Whether this machine has a keyring to keep the key in; the reason if not,
/// for the UI to show next to the disabled toggle.
pub fn keyring_status() -> Result<(), String> {
    keyring::Entry::store_status()
        .as_ref()
        .map(|_| ())
        .map_err(|e| format!("no system keyring is available ({e})"))
}

fn marker(keystore: &Path) -> PathBuf {
    let mut path = keystore.as_os_str().to_owned();
    path.push(".keep");
    PathBuf::from(path)
}

/// Whether "keep unlocked" is on for the keystore at `path`.
pub fn is_kept(path: &Path) -> bool {
    marker(path).is_file()
}

impl Keystore {
    /// Turns "keep unlocked on this device" on or off.
    pub fn keep_unlocked(&self, on: bool) -> Result<(), KeystoreError> {
        self.keep_unlocked_in(&OsKeyring, on)
    }

    pub(crate) fn keep_unlocked_in(
        &self,
        vault: &dyn Vault,
        on: bool,
    ) -> Result<(), KeystoreError> {
        let marker = marker(self.path());
        // Whatever was kept before goes first, so turning it on twice leaves one entry.
        if let Ok(old) = fs::read_to_string(&marker) {
            vault.delete(old.trim()).map_err(KeystoreError::Keyring)?;
            fs::remove_file(&marker)?;
        }
        if on {
            let mut name = [0u8; 16];
            getrandom::fill(&mut name).map_err(KeystoreError::Random)?;
            let name: String = name.iter().map(|b| format!("{b:02x}")).collect();
            vault
                .set(&name, self.data_key())
                .map_err(KeystoreError::Keyring)?;
            fs::write(&marker, &name)?;
        }
        Ok(())
    }

    /// Opens the keystore at `path` without asking, if "keep unlocked" is on
    /// and the keyring still has its key; `Ok(None)` means ask for the
    /// username and password as usual.
    pub fn open_kept(path: &Path) -> Result<Option<Self>, KeystoreError> {
        Self::open_kept_in(&OsKeyring, path)
    }

    pub(crate) fn open_kept_in(
        vault: &dyn Vault,
        path: &Path,
    ) -> Result<Option<Self>, KeystoreError> {
        let Ok(name) = fs::read_to_string(marker(path)) else {
            return Ok(None);
        };
        // A keyring that's locked or gone means asking, not failing.
        let Ok(Some(secret)) = vault.get(name.trim()) else {
            return Ok(None);
        };
        let Ok(key) = <[u8; 32]>::try_from(secret.as_slice()) else {
            return Ok(None);
        };
        let key = Zeroizing::new(key);
        match Keystore::open_with_data_key(path, &key) {
            Ok(store) => Ok(Some(store)),
            // A stale entry (say, from before a restore): ask instead.
            Err(KeystoreError::CannotUnlock) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;
    use crate::keystore::KdfParams;

    #[derive(Default)]
    struct MemoryVault(RefCell<HashMap<String, Vec<u8>>>);

    impl Vault for MemoryVault {
        fn set(&self, entry: &str, secret: &[u8]) -> Result<(), String> {
            self.0
                .borrow_mut()
                .insert(entry.to_owned(), secret.to_vec());
            Ok(())
        }
        fn get(&self, entry: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self.0.borrow().get(entry).cloned().map(Zeroizing::new))
        }
        fn delete(&self, entry: &str) -> Result<(), String> {
            self.0.borrow_mut().remove(entry);
            Ok(())
        }
    }

    struct BrokenVault;

    impl Vault for BrokenVault {
        fn set(&self, _: &str, _: &[u8]) -> Result<(), String> {
            Err("no keyring".into())
        }
        fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Err("no keyring".into())
        }
        fn delete(&self, _: &str) -> Result<(), String> {
            Err("no keyring".into())
        }
    }

    fn create(name: &str) -> Keystore {
        let dir = std::env::temp_dir().join(format!("mesh-remember-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Keystore::create_with(
            &dir.join("identity.mks"),
            "Brendon",
            "Tundra-Gravel-Mosaic-41",
            "Desktop",
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap()
    }

    #[test]
    fn on_opens_without_asking_and_off_asks_again() {
        let vault = MemoryVault::default();
        let store = create("toggle");
        let (path, id) = (store.path().to_owned(), store.id());
        assert!(Keystore::open_kept_in(&vault, &path).unwrap().is_none());

        store.keep_unlocked_in(&vault, true).unwrap();
        store.keep_unlocked_in(&vault, true).unwrap(); // twice leaves one entry
        assert_eq!(vault.0.borrow().len(), 1);
        assert!(is_kept(&path));
        drop(store);
        let opened = Keystore::open_kept_in(&vault, &path)
            .unwrap()
            .expect("opens without a password");
        assert_eq!(opened.id(), id);

        opened.keep_unlocked_in(&vault, false).unwrap();
        assert!(vault.0.borrow().is_empty() && !is_kept(&path));
        assert!(Keystore::open_kept_in(&vault, &path).unwrap().is_none());
    }

    #[test]
    fn a_missing_or_wrong_key_means_asking() {
        let vault = MemoryVault::default();
        let store = create("stale");
        store.keep_unlocked_in(&vault, true).unwrap();
        let path = store.path().to_owned();
        // Someone wiped the keyring: ask.
        vault.0.borrow_mut().clear();
        assert!(Keystore::open_kept_in(&vault, &path).unwrap().is_none());
        // The entry holds some other key: ask, don't fail.
        let name = fs::read_to_string(marker(&path)).unwrap();
        vault.set(&name, &[7u8; 32]).unwrap();
        assert!(Keystore::open_kept_in(&vault, &path).unwrap().is_none());
    }

    #[test]
    fn no_keyring_is_an_error_to_show_not_a_crash() {
        let store = create("broken");
        assert!(matches!(
            store.keep_unlocked_in(&BrokenVault, true),
            Err(KeystoreError::Keyring(_))
        ));
        assert!(!is_kept(store.path()));
        assert!(
            Keystore::open_kept_in(&BrokenVault, store.path())
                .unwrap()
                .is_none()
        );
    }

    /// The real OS keyring: `cargo test -- --ignored os_keyring`.
    #[test]
    #[ignore]
    fn os_keyring() {
        match keyring_status() {
            Err(reason) => eprintln!("keyring unavailable: {reason}"),
            Ok(()) => {
                let store = create("os");
                store.keep_unlocked(true).unwrap();
                let path = store.path().to_owned();
                drop(store);
                let opened = Keystore::open_kept(&path)
                    .unwrap()
                    .expect("opens from the OS keyring");
                opened.keep_unlocked(false).unwrap();
                assert!(Keystore::open_kept(&path).unwrap().is_none());
                eprintln!("keyring works");
            }
        }
    }
}
