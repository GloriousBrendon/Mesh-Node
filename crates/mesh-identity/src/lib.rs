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
mod mailrec;
mod pair;
mod password;
mod remember;
mod safety;
mod sealed;

pub use account::{Account, Entry, Kind, MAX_REMOVED, Status};
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
pub use ed25519_dalek::VerifyingKey;
pub use id::{DeviceKey, IdError, Link, MeshId, RootKey, mail_collect_tag, verify_device};
pub use keystore::{
    KdfParams, Keystore, KeystoreError, MAX_CLOCK_OFFSET, set_clock_offset, unix_now,
    write_atomically,
};
pub use knock::{
    Knock, KnockError, KnockFrom, MAX_KNOCK_LEN, MAX_KNOCK_NAME, MAX_NOTE, knock_outer, open_knock,
    seal_knock,
};
pub use link::{
    LINK_CODE_LIFETIME, LinkError, LinkInitiator, LinkRendezvous, LinkResponder, LinkedIdentity,
    PendingDevice,
};
pub use mailrec::{
    Holder, MAIL_RECORD_LIFE, MAX_HOLDERS, MailRecord, open_mail_record, seal_mail_record,
};
pub use pair::{PairKeys, day_of, week_of};
pub use password::{
    MAX_USERNAME_LEN, MIN_PASSWORD_LEN, PasswordVerdict, check_password, normalize_username,
    valid_username,
};
pub use remember::{is_kept, keyring_status};
pub use safety::SafetyNumber;
pub use sealed::{SealedError, read_sealed, write_sealed};
