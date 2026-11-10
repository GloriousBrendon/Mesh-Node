//! Mesh identity: a person's permanent ID (their root Ed25519 key, shown as
//! `mesh1…`), their devices, the password-encrypted keystore, friend codes,
//! safety numbers and device linking. See `design/mesh/SPEC-identity.md` in
//! Mesh-Voice. No networking here.

mod account;
mod addr;
mod code;
mod contacts;
mod device;
mod id;
mod keystore;
mod knock;
mod link;
mod pair;
mod password;
mod remember;
mod safety;

pub use account::{Account, Entry, Kind, Status, TOMBSTONE_LIFE};
pub use addr::{
    AddrError, AddrRecord, MAX_E2EE_FIELD, MAX_RECORD_LEN, MAX_RELAY_LEN, addr_outer, open_addr,
    seal_addr,
};
pub use code::{
    ActiveCode, CodeError, CodeRecord, CodeRevoke, DEFAULT_EXPIRY, DEFAULT_USES, EXPIRY_CHOICES,
    FriendCode, HeldCode, USE_CHOICES,
};
pub use contacts::{Contact, LastAddr, MAX_CONTACT_NAME, MAX_CONTACTS};
pub use device::{DeviceCert, DeviceError, DeviceList, MAX_DEVICE_NAME, MAX_DEVICES};
pub use id::{DeviceKey, IdError, Link, MeshId, RootKey, verify_device};
pub use keystore::{KdfParams, Keystore, KeystoreError, unix_now, write_atomically};
pub use knock::{
    Knock, KnockError, KnockFrom, MAX_KNOCK_LEN, MAX_KNOCK_NAME, MAX_NOTE, knock_outer, open_knock,
    seal_knock,
};
pub use link::{
    LINK_CODE_LIFETIME, LinkError, LinkInitiator, LinkResponder, LinkedIdentity, PendingDevice,
};
pub use pair::{PairKeys, day_of};
pub use password::{
    MAX_USERNAME_LEN, MIN_PASSWORD_LEN, PasswordVerdict, check_password, normalize_username,
    valid_username,
};
pub use remember::{is_kept, keyring_status};
pub use safety::SafetyNumber;
