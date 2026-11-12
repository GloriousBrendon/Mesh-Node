//! Mesh end-to-end encryption (SPEC-e2ee in Mesh-Voice's `design/mesh/`):
//! e2ee bundles chained to a person's ID, 1:1 Olm sessions, Megolm sender
//! chains for groups, the sealed envelope, and the store that keeps them.
//! vodozemac's types stay inside this crate. No networking here.

mod bundle;
mod envelope;
mod group;
mod session;
mod store;

pub use bundle::{Bundle, MAX_BUNDLE_LEN};
pub use envelope::{
    Envelope, EnvelopeType, Inside, Kind, MAIL, MAIL_FORMAT, MAX_BODY, MAX_INSIDE, MailHead,
    RECEIPT, open_mail, open_sealed, seal_for, seal_mail,
};
pub use group::{Deliveries, MAX_MEMBERS, ROTATE_AFTER, ROTATE_MESSAGES, WAIT_FOR_KEY};
pub use session::{
    Conversation, E2ee, FALLBACK_LIFE, FRESH_SESSION_MIN, MAX_FIELD_LEN, MAX_ONE_TIME_KEYS, Opened,
    Received,
};

/// Why something couldn't be encrypted or opened. Each is fixed text and
/// names nothing (D15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum E2eeError {
    #[error("the message or record is damaged or in an unknown format")]
    Malformed,
    #[error("that device isn't one of that identity's current devices")]
    RevokedDevice,
    #[error("the signature doesn't match")]
    BadSignature,
    #[error("that isn't for this device")]
    NotForUs,
    #[error("the e2ee store is damaged or can't be written")]
    Store,
    #[error("the message is too long")]
    TooLong,
    #[error("no keys have been seen for that person yet")]
    NoKeys,
    #[error("that message was already opened")]
    Replay,
    #[error("couldn't open that message")]
    CantOpen,
    #[error("that message is from a device we don't know")]
    UnknownSender,
    #[error("that message isn't for a conversation we're in")]
    NotMember,
    #[error("couldn't get randomness from the system")]
    Random,
}
