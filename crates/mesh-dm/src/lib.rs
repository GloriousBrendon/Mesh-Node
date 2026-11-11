//! Mesh direct messages (SPEC-dm): the pieces with no networking. `event`
//! is what a chat is made of, `chat` folds events into what a chat shows,
//! `store` keeps them sealed on disk, `sync` decides what each device gets
//! next, and `blob` encrypts files. The caller passes the time; the only
//! I/O is the store's own directory.

pub mod blob;
pub mod chat;
pub mod event;
pub mod group;
pub mod history;
pub mod store;
pub mod sync;

/// Where a 1:1 chat with `peer` (their ID's bytes) is kept on our devices.
pub fn direct_chat(peer: &Person) -> store::Conversation {
    let key = blake3::derive_key("mesh/v1/dm-chat", peer);
    key[..16].try_into().expect("16 bytes")
}

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
