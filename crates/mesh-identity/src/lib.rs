//! Mesh identity: a person's permanent ID (their root Ed25519 key, shown as
//! `mesh1…`), their devices, the password-encrypted keystore, friend codes,
//! safety numbers and device linking. See `design/mesh/SPEC-identity.md` in
//! Mesh-Voice. No networking here.

mod id;

pub use id::{DeviceKey, IdError, Link, MeshId, RootKey};
