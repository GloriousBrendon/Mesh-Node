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
pub mod space;
pub mod space_store;
pub mod store;
pub mod sync;

/// Which chat an event belongs to, as e2ee says: a 1:1 with a person, or a
/// group. Each kind's storage key comes from its own input, so no group ID
/// can name a 1:1 chat's files (and none reaches the log, store.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Where {
    Direct(Person),
    Group([u8; 16]),
}

impl Where {
    /// Where the chat is kept on this device.
    pub fn key(&self) -> store::Conversation {
        let input = match self {
            Where::Direct(person) => [&[1u8][..], person].concat(),
            Where::Group(id) => [&[2u8][..], id].concat(),
        };
        let key = blake3::derive_key("mesh/v1/dm-chat", &input);
        key[..16].try_into().expect("16 bytes")
    }
}

/// A group DM's ID: a hash of its creator and the random value its
/// creation carries (dm D7, e2ee D10), so nobody else can make a creation
/// that counts for it.
pub fn group_id(creator: &Person, nonce: &[u8; 16]) -> [u8; 16] {
    let key = blake3::derive_key("mesh/v1/dm-group", &[&creator[..], nonce].concat());
    key[..16].try_into().expect("16 bytes")
}

/// A new group's random value, and its ID with `creator` as the creator.
pub fn new_group(creator: &Person) -> Option<([u8; 16], [u8; 16])> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    Some((nonce, group_id(creator, &nonce)))
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
