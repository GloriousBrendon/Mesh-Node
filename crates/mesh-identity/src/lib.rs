//! Mesh identity: a person's permanent ID (their root Ed25519 key, shown as
//! `mesh1…`), their devices, the password-encrypted keystore, friend codes,
//! safety numbers and device linking. See `design/mesh/SPEC-identity.md` in
//! Mesh-Voice. No networking here.

mod device;
mod id;
mod keystore;
mod password;
mod remember;

pub use device::{DeviceCert, DeviceError, DeviceList, MAX_DEVICE_NAME, MAX_DEVICES};
pub use id::{DeviceKey, IdError, Link, MeshId, RootKey};
pub use keystore::{KdfParams, Keystore, KeystoreError};
pub use password::{
    MAX_USERNAME_LEN, MIN_PASSWORD_LEN, PasswordVerdict, check_password, normalize_username,
    valid_username,
};
pub use remember::{is_kept, keyring_status};
