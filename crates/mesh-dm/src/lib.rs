//! Mesh direct messages (SPEC-dm): the pieces with no networking. `event`
//! is what a chat is made of, `chat` folds events into what a chat shows,
//! `store` keeps them sealed on disk, `sync` decides what each device gets
//! next, and `blob` encrypts files. The caller passes the time; the only
//! I/O is the store's own directory.

pub mod blob;
pub mod chat;
pub mod event;
pub mod store;
pub mod sync;

/// A person: their Mesh ID's 32 bytes.
pub type Person = [u8; 32];
/// One of a person's devices: its device key's 32 bytes.
pub type Device = [u8; 32];
/// Who sent an event, as e2ee checked it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sender {
    pub person: Person,
    pub device: Device,
}
