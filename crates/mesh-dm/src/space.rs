//! Spaces (SPEC-spaces): the signed event (S1, S3, S5, S12). A Space event
//! is signed by its author's device and carries that device's certificate,
//! which the author's ID signs, so any member can pass it on and a reader
//! can tell who wrote it without asking them (history, S10). Its own layout,
//! not dm's `Event`, so group DMs' formats don't change.

use mesh_identity::{DeviceCert, DeviceKey, verify_device_bytes};
use serde::{Deserialize, Serialize};

use crate::event::{
    Attachment, EventError, EventId, MAX_ATTACHMENTS, MAX_EMOJI, MAX_NAME, MAX_PREVIEW,
    MAX_TEXT_CHARS,
};
use crate::{Person, Sender};

pub const SPACE_VERSION: u8 = 1;
/// People in a Space, the owner included (S1, Q1).
pub const MAX_SPACE_MEMBERS: usize = 50;
/// Channels in a Space (Limits).
pub const MAX_CHANNELS: usize = 100;
/// Categories in a Space (Limits).
pub const MAX_CATEGORIES: usize = 20;
/// A Space's, channel's or category's name, in bytes.
pub const MAX_SPACE_NAME: usize = 100;
/// The name a member joins with, in bytes (social D4's limit).
pub const MAX_DISPLAY_NAME: usize = 64;
/// People one line may mention (S12): everyone else in a full Space.
pub const MAX_MENTIONS: usize = MAX_SPACE_MEMBERS;
/// A whole event, in bytes: under e2ee's 64 KiB envelope with room for the
/// certificate and signature.
pub const MAX_SPACE_EVENT_LEN: usize = 60 * 1024;
/// A device certificate's bytes at most: format, root, device, time, name
/// length, the longest name, signature.
const MAX_CERT_LEN: usize = 1 + 32 + 32 + 8 + 2 + mesh_identity::MAX_DEVICE_NAME + 64;
/// The domain Space events are signed under.
pub const SPACE_SIGNATURE: &str = "mesh/v1/space-event";

pub type SpaceId = [u8; 16];
pub type ChannelId = [u8; 16];
pub type CategoryId = [u8; 16];

/// A Space's ID: a hash of its creator and the random value its creation
/// carries (S1), so nobody else can make a creation that counts for it.
pub fn space_id(creator: &Person, nonce: &[u8; 16]) -> SpaceId {
    let key = blake3::derive_key("mesh/v1/space", &[&creator[..], nonce].concat());
    key[..16].try_into().expect("16 bytes")
}

/// A channel's or category's ID, from its Space and the random value its
/// creation carries: two Spaces can't share one.
pub fn part_id(space: &SpaceId, nonce: &[u8; 16]) -> [u8; 16] {
    let key = blake3::derive_key("mesh/v1/space-part", &[&space[..], nonce].concat());
    key[..16].try_into().expect("16 bytes")
}

/// A fresh random value, for a Space, channel or category creation.
pub fn nonce() -> Option<[u8; 16]> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    Some(nonce)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceEvent {
    pub version: u8,
    pub space: SpaceId,
    pub id: EventId,
    /// The sender's clock, in milliseconds: for display only (dm D2).
    pub time: u64,
    /// The channel's order, or the chain's for a change (dm D2).
    pub seq: u64,
    /// The signing device's own count of its events in this Space.
    pub n: u64,
    pub body: SpaceBody,
    /// The signing device's `DeviceCert`, as its bytes.
    pub cert: Vec<u8>,
    /// The device's signature over everything above (64 bytes).
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaceBody {
    Post {
        channel: ChannelId,
        text: String,
        reply_to: Option<EventId>,
        attachments: Vec<Attachment>,
        mentions: Vec<Person>,
        /// `@everyone`: counts only from an admin (S12).
        everyone: bool,
    },
    Edit {
        channel: ChannelId,
        target: EventId,
        text: String,
    },
    /// The author's, or an admin's (S8).
    Delete {
        channel: ChannelId,
        target: EventId,
    },
    React {
        channel: ChannelId,
        target: EventId,
        emoji: String,
        on: bool,
    },
    /// "Read up to here", to your own devices only (dm D9).
    Read {
        channel: ChannelId,
        up_to: EventId,
    },
    Change(SpaceChange),
}

/// A change to a Space, naming the change it follows (S7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceChange {
    /// `None` only for the creation.
    pub after: Option<EventId>,
    pub change: Change,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change {
    /// `nonce` with the creator's ID hashes to the Space's ID (`space_id`).
    Create {
        name: String,
        nonce: [u8; 16],
        /// The creator's display name.
        display: String,
    },
    /// A friend of the adder, with the name they go by (S6).
    Add {
        who: Person,
        display: String,
    },
    Leave,
    Kick(Person),
    Ban(Person),
    Unban(Person),
    MakeAdmin(Person),
    Demote(Person),
    /// The owner hands the Space to a member.
    Transfer(Person),
    Rename(String),
    MembersMayAdd(bool),
    ChannelCreate {
        nonce: [u8; 16],
        name: String,
        category: Option<CategoryId>,
        admins_post: bool,
    },
    ChannelRename {
        channel: ChannelId,
        name: String,
    },
    /// Where a channel sits: under a category (or none), at a position.
    ChannelMove {
        channel: ChannelId,
        category: Option<CategoryId>,
        position: u16,
    },
    ChannelDelete(ChannelId),
    /// Who may post: everyone, or admins only (S3).
    ChannelPost {
        channel: ChannelId,
        admins_only: bool,
    },
    CategoryCreate {
        nonce: [u8; 16],
        name: String,
    },
    CategoryRename {
        category: CategoryId,
        name: String,
    },
    CategoryMove {
        category: CategoryId,
        position: u16,
    },
    CategoryDelete(CategoryId),
    /// The owner ends the Space.
    End,
}

/// The fields a device signs: everything but the signature.
fn signed_bytes(e: &SpaceEvent) -> Vec<u8> {
    let fields = (
        e.version, &e.space, &e.id, e.time, e.seq, e.n, &e.body, &e.cert,
    );
    postcard::to_stdvec(&fields).expect("to memory")
}

impl SpaceEvent {
    /// A new event, signed by `device` under its certificate `cert`.
    pub fn signed(
        space: SpaceId,
        id: EventId,
        (time, seq, n): (u64, u64, u64),
        body: SpaceBody,
        device: &DeviceKey,
        cert: &DeviceCert,
    ) -> Self {
        let mut e = Self {
            version: SPACE_VERSION,
            space,
            id,
            time,
            seq,
            n,
            body,
            cert: cert.to_bytes(),
            signature: Vec::new(),
        };
        e.signature = device
            .sign(SPACE_SIGNATURE, &signed_bytes(&e))
            .to_bytes()
            .to_vec();
        e
    }

    /// Who wrote it, if the certificate is its author's ID's and the
    /// signature is that device's (S5a). Says nothing about whether the
    /// device is still in use or the author may post: `check_live` and
    /// `check_history` do.
    pub fn author(&self) -> Option<Sender> {
        let cert = DeviceCert::from_bytes(&self.cert).ok()?;
        verify_device_bytes(
            cert.device(),
            SPACE_SIGNATURE,
            &signed_bytes(self),
            &self.signature,
        )
        .then(|| Sender {
            person: cert.root().to_bytes(),
            device: cert.device().to_bytes(),
        })
    }

    /// The event's bytes, once it's checked against the limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EventError> {
        self.check()?;
        let bytes = postcard::to_stdvec(self).map_err(|_| EventError::Malformed)?;
        if bytes.len() > MAX_SPACE_EVENT_LEN {
            return Err(EventError::TooLong("message"));
        }
        Ok(bytes)
    }

    /// An event from its bytes: refused if it doesn't parse, has bytes left
    /// over, is of another version, or breaks a limit. The signature is
    /// checked by `author`, not here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventError> {
        if bytes.len() > MAX_SPACE_EVENT_LEN {
            return Err(EventError::TooLong("message"));
        }
        match bytes.first() {
            None => return Err(EventError::Malformed),
            Some(&v) if v != SPACE_VERSION => return Err(EventError::UnknownVersion),
            Some(_) => {}
        }
        let (event, rest) =
            postcard::take_from_bytes::<Self>(bytes).map_err(|_| EventError::Malformed)?;
        if !rest.is_empty() {
            return Err(EventError::Malformed);
        }
        event.check()?;
        Ok(event)
    }

    fn check(&self) -> Result<(), EventError> {
        let long = |text: &str, max: usize, what| {
            if text.len() > max {
                Err(EventError::TooLong(what))
            } else {
                Ok(())
            }
        };
        let text = |text: &str| {
            if text.chars().count() > MAX_TEXT_CHARS {
                Err(EventError::TooLong("text"))
            } else {
                Ok(())
            }
        };
        if self.signature.len() > 64 || self.cert.len() > MAX_CERT_LEN {
            return Err(EventError::Malformed);
        }
        match &self.body {
            SpaceBody::Post {
                text: t,
                attachments,
                mentions,
                ..
            } => {
                text(t)?;
                if attachments.len() > MAX_ATTACHMENTS {
                    return Err(EventError::TooMany("attachments"));
                }
                if mentions.len() > MAX_MENTIONS {
                    return Err(EventError::TooMany("mentions"));
                }
                for a in attachments {
                    long(&a.name, MAX_NAME, "file name")?;
                    long(&a.mime, MAX_NAME, "file type")?;
                    if a.preview.as_ref().is_some_and(|p| p.len() > MAX_PREVIEW) {
                        return Err(EventError::TooLong("preview"));
                    }
                }
            }
            SpaceBody::Edit { text: t, .. } => text(t)?,
            SpaceBody::React { emoji, .. } => {
                long(emoji, MAX_EMOJI, "emoji")?;
                if emoji.is_empty() {
                    return Err(EventError::Malformed);
                }
            }
            SpaceBody::Change(SpaceChange { change, .. }) => match change {
                Change::Create { name, display, .. } => {
                    long(name, MAX_SPACE_NAME, "space name")?;
                    long(display, MAX_DISPLAY_NAME, "name")?;
                }
                Change::Add { display, .. } => long(display, MAX_DISPLAY_NAME, "name")?,
                Change::Rename(name) => long(name, MAX_SPACE_NAME, "space name")?,
                Change::ChannelCreate { name, .. }
                | Change::ChannelRename { name, .. }
                | Change::CategoryCreate { name, .. }
                | Change::CategoryRename { name, .. } => {
                    long(name, MAX_SPACE_NAME, "channel name")?
                }
                _ => {}
            },
            SpaceBody::Delete { .. } | SpaceBody::Read { .. } => {}
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mesh_identity::RootKey;

    /// A person with one device and its certificate.
    pub(crate) struct Someone {
        pub root: RootKey,
        pub device: DeviceKey,
        pub cert: DeviceCert,
    }

    impl Someone {
        pub(crate) fn new() -> Self {
            let root = RootKey::generate().unwrap();
            Self::with_root(root)
        }

        /// Another device of the same person.
        pub(crate) fn with_root(root: RootKey) -> Self {
            let device = DeviceKey::generate().unwrap();
            let cert = DeviceCert::issue(&root, &device.public(), "laptop", 1).unwrap();
            Self { root, device, cert }
        }

        pub(crate) fn id(&self) -> Person {
            self.root.id().to_bytes()
        }

        pub(crate) fn event(
            &self,
            space: SpaceId,
            id: u8,
            seq: u64,
            body: SpaceBody,
        ) -> SpaceEvent {
            SpaceEvent::signed(
                space,
                [id; 16],
                (seq, seq, seq),
                body,
                &self.device,
                &self.cert,
            )
        }
    }

    fn post(text: &str) -> SpaceBody {
        SpaceBody::Post {
            channel: [1; 16],
            text: text.into(),
            reply_to: None,
            attachments: vec![],
            mentions: vec![[9; 32]],
            everyone: false,
        }
    }

    #[test]
    fn a_signed_event_round_trips_and_names_its_author() {
        let alice = Someone::new();
        let e = alice.event([5; 16], 1, 10, post("hi"));
        let back = SpaceEvent::from_bytes(&e.to_bytes().unwrap()).unwrap();
        assert_eq!(back, e);
        let author = back.author().unwrap();
        assert_eq!(author.person, alice.id());
        assert_eq!(author.device, alice.device.public().to_bytes());
        let change = SpaceBody::Change(SpaceChange {
            after: Some([1; 16]),
            change: Change::ChannelCreate {
                nonce: [2; 16],
                name: "general".into(),
                category: None,
                admins_post: true,
            },
        });
        let e = alice.event([5; 16], 2, 11, change);
        assert_eq!(SpaceEvent::from_bytes(&e.to_bytes().unwrap()).unwrap(), e);
    }

    #[test]
    fn an_altered_byte_or_someone_elses_certificate_fails() {
        let alice = Someone::new();
        let bob = Someone::new();
        let e = alice.event([5; 16], 1, 10, post("hi"));
        let mut altered = e.clone();
        altered.body = post("bye");
        assert_eq!(altered.author(), None, "altered text");
        let mut later = e.clone();
        later.seq += 1;
        assert_eq!(later.author(), None, "moved in order");
        // Bob's certificate on Alice's signature: the device doesn't match.
        let mut theirs = e.clone();
        theirs.cert = bob.cert.to_bytes();
        assert_eq!(theirs.author(), None);
        // A certificate Alice's device made for itself, not her ID's.
        let mut forged = e;
        let fake_root = RootKey::generate().unwrap();
        let fake = DeviceCert::issue(&fake_root, &alice.device.public(), "x", 1).unwrap();
        let mut bytes = fake.to_bytes();
        bytes[1..33].copy_from_slice(&alice.id());
        forged.cert = bytes;
        assert_eq!(forged.author(), None, "a certificate not signed by the ID");
    }

    #[test]
    fn limits_are_refused_both_ways() {
        let alice = Someone::new();
        let long = alice.event([5; 16], 1, 1, post(&"a".repeat(MAX_TEXT_CHARS + 1)));
        assert_eq!(long.to_bytes(), Err(EventError::TooLong("text")));
        let bytes = postcard::to_stdvec(&long).unwrap();
        assert_eq!(
            SpaceEvent::from_bytes(&bytes),
            Err(EventError::TooLong("text"))
        );
        let crowd = SpaceBody::Post {
            channel: [1; 16],
            text: String::new(),
            reply_to: None,
            attachments: vec![],
            mentions: vec![[1; 32]; MAX_MENTIONS + 1],
            everyone: false,
        };
        let crowd = alice.event([5; 16], 2, 2, crowd);
        assert_eq!(crowd.to_bytes(), Err(EventError::TooMany("mentions")));
        let name = SpaceBody::Change(SpaceChange {
            after: None,
            change: Change::Rename("n".repeat(MAX_SPACE_NAME + 1)),
        });
        let name = alice.event([5; 16], 3, 3, name);
        assert_eq!(name.to_bytes(), Err(EventError::TooLong("space name")));
        let display = SpaceBody::Change(SpaceChange {
            after: Some([1; 16]),
            change: Change::Add {
                who: [2; 32],
                display: "d".repeat(MAX_DISPLAY_NAME + 1),
            },
        });
        let display = alice.event([5; 16], 4, 4, display);
        assert_eq!(display.to_bytes(), Err(EventError::TooLong("name")));
        // At the edges, fine.
        let edge = alice.event([5; 16], 5, 5, post(&"a".repeat(MAX_TEXT_CHARS)));
        assert!(edge.to_bytes().is_ok());
    }

    #[test]
    fn damaged_and_newer_events_are_refused() {
        let alice = Someone::new();
        let bytes = alice.event([5; 16], 1, 1, post("hi")).to_bytes().unwrap();
        assert_eq!(
            SpaceEvent::from_bytes(&bytes[..bytes.len() - 1]),
            Err(EventError::Malformed)
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(SpaceEvent::from_bytes(&extra), Err(EventError::Malformed));
        let mut newer = bytes;
        newer[0] = SPACE_VERSION + 1;
        assert_eq!(
            SpaceEvent::from_bytes(&newer),
            Err(EventError::UnknownVersion)
        );
    }

    #[test]
    fn ids_come_from_their_creator_and_space() {
        let (a, b) = ([1; 32], [2; 32]);
        assert_ne!(space_id(&a, &[3; 16]), space_id(&b, &[3; 16]));
        assert_ne!(part_id(&[1; 16], &[3; 16]), part_id(&[2; 16], &[3; 16]));
        assert_ne!(nonce(), nonce());
    }
}
