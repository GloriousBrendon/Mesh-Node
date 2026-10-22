//! Mesh identity: a person's permanent ID (their root Ed25519 key, shown as
//! `mesh1…`), their devices, the password-encrypted keystore, friend codes,
//! safety numbers and device linking. See `design/mesh/SPEC-identity.md` in
//! Mesh-Voice. No networking here.

mod device;
mod id;

pub use device::{DeviceCert, DeviceError, DeviceList, MAX_DEVICE_NAME, MAX_DEVICES};
pub use id::{DeviceKey, IdError, Link, MeshId, RootKey};
