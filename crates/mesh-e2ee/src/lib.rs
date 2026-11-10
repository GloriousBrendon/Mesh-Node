//! Mesh end-to-end encryption (SPEC-e2ee in Mesh-Voice's `design/mesh/`):
//! e2ee bundles chained to a person's ID, 1:1 Olm sessions, Megolm sender
//! chains for groups, the sealed envelope, and the store that keeps them.
//! vodozemac's types stay inside this crate. No networking here.

mod bundle;
mod envelope;

pub use bundle::{Bundle, MAX_BUNDLE_LEN};
pub use envelope::{
    Envelope, EnvelopeType, Inside, Kind, MAX_BODY, MAX_INSIDE, open_sealed, seal_for,
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
    #[error("the message is too long")]
    TooLong,
    #[error("couldn't get randomness from the system")]
    Random,
}
