//! The event format (SPEC-dm D1, D14): the body of an e2ee message. The
//! envelope already says who sent it, from which device, in which chat, so
//! an event carries none of that. Encoded with postcard; anything that
//! doesn't parse, is too big, or is of an unknown kind is refused.

use serde::{Deserialize, Serialize};

use crate::Person;

pub const VERSION: u8 = 1;
/// Text a message may hold, in characters (D14).
pub const MAX_TEXT_CHARS: usize = 4000;
/// Attachments one message may carry (D14).
pub const MAX_ATTACHMENTS: usize = 10;
/// A picture's preview, in bytes (D12).
pub const MAX_PREVIEW: usize = 16 * 1024;
/// One emoji (with its modifiers), in bytes.
pub const MAX_EMOJI: usize = 32;
/// A file's name or type, in bytes.
pub const MAX_NAME: usize = 255;
/// A group's name, in bytes.
pub const MAX_GROUP_NAME: usize = 100;
/// People in a group DM, the creator included (D6).
pub const MAX_MEMBERS: usize = 10;
/// A whole event, in bytes: under e2ee's 64 KiB envelope.
pub const MAX_EVENT_LEN: usize = 60 * 1024;

pub type EventId = [u8; 16];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub version: u8,
    pub id: EventId,
    /// The sender's clock, in milliseconds: for display only (D2).
    pub time: u64,
    /// The chat's order (D2).
    pub seq: u64,
    /// The sending device's own count of its events in this chat (D2).
    pub n: u64,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Text {
        text: String,
        reply_to: Option<EventId>,
        attachments: Vec<Attachment>,
    },
    Edit {
        target: EventId,
        text: String,
    },
    /// `everyone` false is "delete for me": sent to your own devices only.
    Delete {
        target: EventId,
        everyone: bool,
    },
    React {
        target: EventId,
        emoji: String,
        on: bool,
    },
    /// "Read up to here", to your own devices only (D9).
    Read {
        up_to: EventId,
    },
    Group(GroupChange),
}

/// A file a message carries (D12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub key: [u8; 32],
    /// The encrypted file's blake3 hash.
    pub hash: [u8; 32],
    pub size: u64,
    pub name: String,
    pub mime: String,
    pub preview: Option<Vec<u8>>,
}

/// A change to a group, naming the change it follows (D7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupChange {
    /// `None` only for the creation.
    pub after: Option<EventId>,
    pub change: Change,
    /// Its author's signature, so any member can pass it on (D7). A change
    /// from the wire without one is refused.
    pub signed: Option<Signed>,
}

/// Who made a group change, signed with their ID key over the group, the
/// event's ID, `seq` and `n`, their device, and the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub author: Person,
    pub device: crate::Device,
    /// 64 bytes (a Vec: serde has no arrays past 32).
    pub signature: Vec<u8>,
}

/// The domain group-change signatures are made under.
pub const GROUP_SIGNATURE: &str = "mesh/v1/dm-group-change";

/// The bytes an author signs for group change `event` in group `group`.
pub fn group_signed_bytes(
    group: &[u8; 16],
    event: &Event,
    author: &Person,
    device: &crate::Device,
) -> Option<Vec<u8>> {
    let Body::Group(change) = &event.body else {
        return None;
    };
    let fields = (
        group,
        &event.id,
        event.seq,
        event.n,
        author,
        device,
        &change.after,
        &change.change,
    );
    Some(postcard::to_stdvec(&fields).expect("to memory"))
}

/// Who wrote group change `event` in `group`, if its signature checks out.
pub fn group_author(group: &[u8; 16], event: &Event) -> Option<crate::Sender> {
    let Body::Group(GroupChange {
        signed: Some(signed),
        ..
    }) = &event.body
    else {
        return None;
    };
    let id = mesh_identity::MeshId::from_bytes(&signed.author).ok()?;
    let bytes = group_signed_bytes(group, event, &signed.author, &signed.device)?;
    id.verify_bytes(GROUP_SIGNATURE, &bytes, &signed.signature)
        .then_some(crate::Sender {
            person: signed.author,
            device: signed.device,
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change {
    /// `nonce` with the creator's ID hashes to the group's ID (`group_id`).
    Create {
        name: String,
        members: Vec<Person>,
        nonce: [u8; 16],
    },
    Add(Person),
    Remove(Person),
    Leave,
    Rename(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("the event is damaged or of an unknown kind")]
    Malformed,
    #[error("the event is from a newer version of Mesh")]
    UnknownVersion,
    #[error("the {0} is too long")]
    TooLong(&'static str),
    #[error("too many {0}")]
    TooMany(&'static str),
}

impl Event {
    /// The event's bytes, once it's checked against the limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EventError> {
        self.check()?;
        let bytes = postcard::to_stdvec(self).map_err(|_| EventError::Malformed)?;
        if bytes.len() > MAX_EVENT_LEN {
            return Err(EventError::TooLong("message"));
        }
        Ok(bytes)
    }

    /// An event from a message body: refused if it doesn't parse, has bytes
    /// left over, is of another version, or breaks a limit.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventError> {
        if bytes.len() > MAX_EVENT_LEN {
            return Err(EventError::TooLong("message"));
        }
        // The version is the first byte (postcard writes a u8 as itself), and
        // a newer one may lay the rest out differently.
        match bytes.first() {
            None => return Err(EventError::Malformed),
            Some(&v) if v != VERSION => return Err(EventError::UnknownVersion),
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
        match &self.body {
            Body::Text {
                text: t,
                attachments,
                ..
            } => {
                text(t)?;
                if attachments.len() > MAX_ATTACHMENTS {
                    return Err(EventError::TooMany("attachments"));
                }
                for a in attachments {
                    long(&a.name, MAX_NAME, "file name")?;
                    long(&a.mime, MAX_NAME, "file type")?;
                    if a.preview.as_ref().is_some_and(|p| p.len() > MAX_PREVIEW) {
                        return Err(EventError::TooLong("preview"));
                    }
                }
            }
            Body::Edit { text: t, .. } => text(t)?,
            Body::React { emoji, .. } => {
                long(emoji, MAX_EMOJI, "emoji")?;
                if emoji.is_empty() {
                    return Err(EventError::Malformed);
                }
            }
            Body::Group(GroupChange { change, .. }) => match change {
                Change::Create { name, members, .. } => {
                    long(name, MAX_GROUP_NAME, "group name")?;
                    if members.len() > MAX_MEMBERS {
                        return Err(EventError::TooMany("members"));
                    }
                }
                Change::Rename(name) => long(name, MAX_GROUP_NAME, "group name")?,
                Change::Add(_) | Change::Remove(_) | Change::Leave => {}
            },
            Body::Delete { .. } | Body::Read { .. } => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(body: Body) -> Event {
        Event {
            version: VERSION,
            id: [7; 16],
            time: 1_800_000_000_000,
            seq: 42,
            n: 3,
            body,
        }
    }

    fn picture() -> Attachment {
        Attachment {
            key: [1; 32],
            hash: [2; 32],
            size: 5_000_000,
            name: "hike.jpg".into(),
            mime: "image/jpeg".into(),
            preview: Some(vec![9; 1000]),
        }
    }

    #[test]
    fn each_kind_round_trips() {
        let target = [3; 16];
        let bodies = [
            Body::Text {
                text: "hi 👋".into(),
                reply_to: Some(target),
                attachments: vec![picture()],
            },
            Body::Edit {
                target,
                text: "hi there".into(),
            },
            Body::Delete {
                target,
                everyone: true,
            },
            Body::React {
                target,
                emoji: "👍🏽".into(),
                on: true,
            },
            Body::Read { up_to: target },
            Body::Group(GroupChange {
                after: None,
                change: Change::Create {
                    name: "hike".into(),
                    members: vec![[4; 32], [5; 32]],
                    nonce: [6; 16],
                },
                signed: None,
            }),
            Body::Group(GroupChange {
                after: Some(target),
                change: Change::Remove([5; 32]),
                signed: None,
            }),
        ];
        for body in bodies {
            let e = event(body);
            assert_eq!(Event::from_bytes(&e.to_bytes().unwrap()), Ok(e));
        }
    }

    #[test]
    fn limits_are_refused_both_ways() {
        let long = event(Body::Text {
            text: "a".repeat(MAX_TEXT_CHARS + 1),
            reply_to: None,
            attachments: vec![],
        });
        assert_eq!(long.to_bytes(), Err(EventError::TooLong("text")));
        // A modified client could still send it: the reader refuses it too.
        let bytes = postcard::to_stdvec(&long).unwrap();
        assert_eq!(Event::from_bytes(&bytes), Err(EventError::TooLong("text")));
        // Characters, not bytes: 4,000 emoji are fine.
        let emoji = event(Body::Text {
            text: "😀".repeat(MAX_TEXT_CHARS),
            reply_to: None,
            attachments: vec![],
        });
        assert!(emoji.to_bytes().is_ok());
        let many = event(Body::Text {
            text: String::new(),
            reply_to: None,
            attachments: vec![picture(); MAX_ATTACHMENTS + 1],
        });
        assert_eq!(many.to_bytes(), Err(EventError::TooMany("attachments")));
        let mut big = picture();
        big.preview = Some(vec![0; MAX_PREVIEW + 1]);
        let preview = event(Body::Text {
            text: String::new(),
            reply_to: None,
            attachments: vec![big],
        });
        assert_eq!(preview.to_bytes(), Err(EventError::TooLong("preview")));
        let crowd = event(Body::Group(GroupChange {
            after: None,
            change: Change::Create {
                name: "all".into(),
                members: vec![[1; 32]; MAX_MEMBERS + 1],
                nonce: [0; 16],
            },
            signed: None,
        }));
        assert_eq!(crowd.to_bytes(), Err(EventError::TooMany("members")));
        let emoji = event(Body::React {
            target: [0; 16],
            emoji: "x".repeat(MAX_EMOJI + 1),
            on: true,
        });
        assert_eq!(emoji.to_bytes(), Err(EventError::TooLong("emoji")));
    }

    #[test]
    fn damaged_unknown_and_newer_events_are_refused() {
        let bytes = event(Body::Read { up_to: [1; 16] }).to_bytes().unwrap();
        assert_eq!(
            Event::from_bytes(&bytes[..bytes.len() - 1]),
            Err(EventError::Malformed),
            "truncated"
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Event::from_bytes(&extra), Err(EventError::Malformed));
        // The body's kind is the byte after the four counters; 9 is no kind.
        let mut unknown = postcard::to_stdvec(&event(Body::Read { up_to: [1; 16] })).unwrap();
        let kind = unknown.len() - 17;
        unknown[kind] = 9;
        assert_eq!(Event::from_bytes(&unknown), Err(EventError::Malformed));
        let mut newer = event(Body::Read { up_to: [1; 16] });
        newer.version = VERSION + 1;
        let newer = postcard::to_stdvec(&newer).unwrap();
        assert_eq!(Event::from_bytes(&newer), Err(EventError::UnknownVersion));
        assert_eq!(Event::from_bytes(&[]), Err(EventError::Malformed));
    }
}
