//! Spaces (SPEC-spaces): the signed event (S1, S3, S5, S12). A Space event
//! is signed by its author's device and carries that device's certificate,
//! which the author's ID signs, so any member can pass it on and a reader
//! can tell who wrote it without asking them (history, S10). Its own layout,
//! not dm's `Event`, so group DMs' formats don't change.

use mesh_identity::{DeviceCert, DeviceKey, verify_device_bytes};
use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::chat::Position;
use crate::event::{
    Attachment, EventError, EventId, MAX_ATTACHMENTS, MAX_EMOJI, MAX_NAME, MAX_PREVIEW,
    MAX_TEXT_CHARS,
};
use crate::group::{LastTie, Node, Settled, settle};
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

/// A member's role (S7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Member,
    Admin,
    Owner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub role: Role,
    /// The name they joined with (S6).
    pub display: String,
    /// The change they joined at: the creation, or their add.
    pub joined: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub name: String,
    pub category: Option<CategoryId>,
    pub position: u16,
    /// Only admins post (S3).
    pub admins_post: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub name: String,
    pub position: u16,
}

/// A Space as one version of its chain leaves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceState {
    pub owner: Person,
    pub name: String,
    pub members: BTreeMap<Person, Member>,
    pub bans: BTreeSet<Person>,
    pub members_may_add: bool,
    pub channels: BTreeMap<ChannelId, Channel>,
    pub categories: BTreeMap<CategoryId, Category>,
    /// The owner ended it: no change counts after.
    pub ended: bool,
}

impl SpaceState {
    pub fn role(&self, who: &Person) -> Option<Role> {
        self.members.get(who).map(|m| m.role)
    }

    /// Whether `who` may post in `channel` in this version (S3).
    pub fn may_post(&self, who: &Person, channel: &ChannelId) -> bool {
        match (self.role(who), self.channels.get(channel)) {
            (Some(role), Some(c)) => !c.admins_post || role >= Role::Admin,
            _ => false,
        }
    }
}

/// The Space as its winning line leaves it, with what history (S5) and
/// redo (S7) need from the rest of the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceVersion {
    pub state: SpaceState,
    /// The newest change on the winning line: what a new one follows.
    pub head: EventId,
    /// Who each change on the line goes to: the members before it or after
    /// it, so a removal reaches the person removed and an add the added.
    pub audience: BTreeMap<EventId, BTreeSet<Person>>,
    /// Everyone who was a member in some version on the line (S5 (2)).
    pub ever_members: BTreeSet<Person>,
    /// Who could post in each channel in some version on the line (S5 (3)).
    pub posters: BTreeMap<ChannelId, BTreeSet<Person>>,
    /// Changes that counted where they were made but are off the winning
    /// line: (ID, author, change, position).
    pub dropped: Vec<(EventId, Person, Change, Position)>,
}

/// A Space's changes (S7): dm D7's chain, with roles.
#[derive(Default)]
pub struct Chain {
    changes: HashMap<EventId, Node<Change>>,
}

impl Chain {
    /// A change by `by`, sitting at `at`.
    pub fn add(&mut self, id: EventId, by: Person, change: SpaceChange, at: Position) {
        self.changes.entry(id).or_insert(Node {
            by,
            after: change.after,
            change: change.change,
            at,
        });
    }

    /// Every change held, to save with the Space.
    pub fn changes(&self) -> Vec<(EventId, Person, SpaceChange, Position)> {
        let changes = self.changes.iter().map(|(id, n)| {
            let change = SpaceChange {
                after: n.after,
                change: n.change.clone(),
            };
            (*id, n.by, change, n.at)
        });
        changes.collect()
    }

    /// The Space `space` as its winning line leaves it; `None` before its
    /// creation has arrived. A creation counts only if its sender and nonce
    /// hash to `space`, so nobody else can replace the owner.
    pub fn version(&self, space: &SpaceId) -> Option<SpaceVersion> {
        let creates = self.changes.iter().filter(|(_, n)| {
            n.after.is_none()
                && matches!(&n.change, Change::Create { nonce, .. } if space_id(&n.by, nonce) == *space)
        });
        let (root, node) = creates.min_by_key(|(_, n)| n.at)?;
        let Change::Create { name, display, .. } = &node.change else {
            unreachable!("filtered above")
        };
        let start = SpaceState {
            owner: node.by,
            name: name.clone(),
            members: BTreeMap::from([(
                node.by,
                Member {
                    role: Role::Owner,
                    display: display.clone(),
                    joined: *root,
                },
            )]),
            bans: BTreeSet::new(),
            members_may_add: true,
            channels: BTreeMap::new(),
            categories: BTreeMap::new(),
            ended: false,
        };
        let root = *root;
        let apply = |v: &SpaceState, id: EventId, n: &Node<Change>| apply(space, v, id, n);
        // The owner's changes rank highest, then admins' (S7).
        let rank = |v: &SpaceState, n: &Node<Change>| match v.role(&n.by) {
            Some(Role::Owner) => 2,
            Some(Role::Admin) => 1,
            _ => 0,
        };
        let Settled { versions, line } = settle(
            &self.changes,
            root,
            start,
            apply,
            rank,
            2,
            LastTie::Position,
        );
        let mut audience = BTreeMap::new();
        let mut ever_members = BTreeSet::new();
        let mut posters: BTreeMap<ChannelId, BTreeSet<Person>> = BTreeMap::new();
        // ponytail: walks every version on the line at each call; keep the
        // sums with the chain if a long-lived Space makes this slow.
        for (i, id) in line.iter().enumerate() {
            let v = &versions[id];
            let before = i.checked_sub(1).map(|j| &versions[&line[j]]);
            let mut who: BTreeSet<Person> = v.members.keys().copied().collect();
            who.extend(before.into_iter().flat_map(|b| b.members.keys().copied()));
            audience.insert(*id, who);
            ever_members.extend(v.members.keys().copied());
            for channel in v.channels.keys() {
                let can = v.members.keys().filter(|m| v.may_post(m, channel));
                posters.entry(*channel).or_default().extend(can.copied());
            }
        }
        let on_line: BTreeSet<&EventId> = line.iter().collect();
        let mut dropped: Vec<_> = (versions.keys())
            .filter(|id| !on_line.contains(id))
            .map(|id| {
                let n = &self.changes[id];
                (*id, n.by, n.change.clone(), n.at)
            })
            .collect();
        dropped.sort_by_key(|d| d.3);
        let head = *line.last().expect("the root");
        Some(SpaceVersion {
            state: versions[&head].clone(),
            head,
            audience,
            ever_members,
            posters,
            dropped,
        })
    }
}

/// `me`'s changes that were dropped off the winning line and would still
/// count and change something now (S7), oldest first, less those in `done`
/// (already redone). The caller makes each again after `v.head`.
pub fn to_redo(
    space: &SpaceId,
    v: &SpaceVersion,
    me: &Person,
    done: &BTreeSet<EventId>,
) -> Vec<(EventId, Change)> {
    let mut state = v.state.clone();
    let mut out = Vec::new();
    for (id, by, change, at) in &v.dropped {
        if by != me || done.contains(id) {
            continue;
        }
        let node = Node {
            by: *by,
            after: Some(v.head),
            change: change.clone(),
            at: *at,
        };
        if let Some(next) = apply(space, &state, *id, &node)
            && next != state
        {
            state = next;
            out.push((*id, change.clone()));
        }
    }
    out
}

/// The state after `node`, if its sender may make that change in `v` (S7).
fn apply(space: &SpaceId, v: &SpaceState, id: EventId, node: &Node<Change>) -> Option<SpaceState> {
    let role = v.role(&node.by)?;
    if v.ended {
        return None;
    }
    let admin = role >= Role::Admin;
    let owner = role == Role::Owner;
    // Only the owner acts on an admin (S7); nobody acts on the owner.
    let over = |who: &Person| match v.role(who) {
        Some(Role::Owner) => false,
        Some(Role::Admin) => owner,
        _ => admin,
    };
    let mut next = v.clone();
    match &node.change {
        Change::Create { .. } => return None,
        Change::Add { who, display }
            if (admin || v.members_may_add)
                && !v.members.contains_key(who)
                && !v.bans.contains(who)
                && v.members.len() < MAX_SPACE_MEMBERS =>
        {
            let member = Member {
                role: Role::Member,
                display: display.clone(),
                joined: id,
            };
            next.members.insert(*who, member);
        }
        Change::Leave if !owner => {
            next.members.remove(&node.by);
        }
        Change::Kick(who) if v.members.contains_key(who) && over(who) => {
            next.members.remove(who);
        }
        Change::Ban(who) if !v.bans.contains(who) && over(who) => {
            next.members.remove(who);
            next.bans.insert(*who);
        }
        Change::Unban(who) if admin && v.bans.contains(who) => {
            next.bans.remove(who);
        }
        Change::MakeAdmin(who) if owner && v.role(who) == Some(Role::Member) => {
            next.members.get_mut(who).expect("a member").role = Role::Admin;
        }
        Change::Demote(who) if owner && v.role(who) == Some(Role::Admin) => {
            next.members.get_mut(who).expect("a member").role = Role::Member;
        }
        Change::Transfer(who) if owner && *who != node.by && v.members.contains_key(who) => {
            next.members.get_mut(who).expect("a member").role = Role::Owner;
            next.members.get_mut(&node.by).expect("the owner").role = Role::Admin;
            next.owner = *who;
        }
        Change::Rename(name) if admin => next.name = name.clone(),
        Change::MembersMayAdd(on) if admin => next.members_may_add = *on,
        Change::ChannelCreate {
            nonce,
            name,
            category,
            admins_post,
        } if admin
            && v.channels.len() < MAX_CHANNELS
            && category.is_none_or(|c| v.categories.contains_key(&c)) =>
        {
            let channel = part_id(space, nonce);
            if v.channels.contains_key(&channel) || v.categories.contains_key(&channel) {
                return None;
            }
            let position = u16::try_from(v.channels.len()).unwrap_or(u16::MAX);
            next.channels.insert(
                channel,
                Channel {
                    name: name.clone(),
                    category: *category,
                    position,
                    admins_post: *admins_post,
                },
            );
        }
        Change::ChannelRename { channel, name } if admin => {
            next.channels.get_mut(channel)?.name = name.clone();
        }
        Change::ChannelMove {
            channel,
            category,
            position,
        } if admin && category.is_none_or(|c| v.categories.contains_key(&c)) => {
            let c = next.channels.get_mut(channel)?;
            (c.category, c.position) = (*category, *position);
        }
        Change::ChannelDelete(channel) if admin => {
            next.channels.remove(channel)?;
        }
        Change::ChannelPost {
            channel,
            admins_only,
        } if admin => next.channels.get_mut(channel)?.admins_post = *admins_only,
        Change::CategoryCreate { nonce, name } if admin && v.categories.len() < MAX_CATEGORIES => {
            let category = part_id(space, nonce);
            if v.channels.contains_key(&category) || v.categories.contains_key(&category) {
                return None;
            }
            let position = u16::try_from(v.categories.len()).unwrap_or(u16::MAX);
            next.categories.insert(
                category,
                Category {
                    name: name.clone(),
                    position,
                },
            );
        }
        Change::CategoryRename { category, name } if admin => {
            next.categories.get_mut(category)?.name = name.clone();
        }
        Change::CategoryMove { category, position } if admin => {
            next.categories.get_mut(category)?.position = *position;
        }
        Change::CategoryDelete(category) if admin => {
            next.categories.remove(category)?;
            for c in next.channels.values_mut() {
                if c.category == Some(*category) {
                    c.category = None;
                }
            }
        }
        Change::End if owner => next.ended = true,
        _ => return None,
    }
    Some(next)
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

    mod chain {
        use super::super::*;

        const O: Person = [1; 32];
        const X: Person = [2; 32];
        const Y: Person = [3; 32];
        const B: Person = [4; 32];
        const C: Person = [5; 32];
        const D: Person = [6; 32];
        const NONCE: [u8; 16] = [7; 16];

        fn space() -> SpaceId {
            space_id(&O, &NONCE)
        }

        /// (id, by, after, change, seq)
        type Step = (u8, Person, Option<u8>, Change, u64);

        fn chain(steps: &[Step]) -> Chain {
            let mut c = Chain::default();
            for (id, by, after, change, seq) in steps.iter().cloned() {
                let change = SpaceChange {
                    after: after.map(|a| [a; 16]),
                    change,
                };
                c.add([id; 16], by, change, (seq, [id; 16]));
            }
            c
        }

        fn version(steps: &[Step]) -> SpaceVersion {
            chain(steps).version(&space()).expect("created")
        }

        /// Every order of `steps` gives the same Space.
        fn in_any_order(steps: &[Step]) -> SpaceVersion {
            let first = version(steps);
            let mut order: Vec<usize> = (0..steps.len()).collect();
            for _ in 0..24 {
                order.rotate_left(1);
                let middle = order.len() / 2;
                order.swap(0, middle);
                let shuffled: Vec<Step> = order.iter().map(|&i| steps[i].clone()).collect();
                assert_eq!(version(&shuffled), first, "order {order:?}");
            }
            first
        }

        fn add(who: Person) -> Change {
            Change::Add {
                who,
                display: "n".into(),
            }
        }

        /// O creates; adds X, Y, B, C; makes X and Y admins: ids 1 to 7.
        fn base() -> Vec<Step> {
            let create = Change::Create {
                name: "club".into(),
                nonce: NONCE,
                display: "o".into(),
            };
            vec![
                (1, O, None, create, 1),
                (2, O, Some(1), add(X), 2),
                (3, O, Some(2), add(Y), 3),
                (4, O, Some(3), add(B), 4),
                (5, O, Some(4), add(C), 5),
                (6, O, Some(5), Change::MakeAdmin(X), 6),
                (7, O, Some(6), Change::MakeAdmin(Y), 7),
            ]
        }

        fn with(mut steps: Vec<Step>, more: &[Step]) -> Vec<Step> {
            steps.extend_from_slice(more);
            steps
        }

        /// Whether `change` by `by` counts right after the base.
        fn counts(by: Person, change: Change) -> bool {
            let v = version(&with(base(), &[(50, by, Some(7), change, 50)]));
            v.head == [50; 16]
        }

        #[test]
        fn rights_by_role() {
            let channel = Change::ChannelCreate {
                nonce: [9; 16],
                name: "general".into(),
                category: None,
                admins_post: false,
            };
            // Members.
            assert!(counts(B, Change::Leave));
            assert!(counts(B, add(D)), "members may add by default");
            for change in [
                Change::Kick(C),
                Change::Ban(C),
                Change::Rename("x".into()),
                channel.clone(),
                Change::MakeAdmin(C),
                Change::MembersMayAdd(false),
                Change::End,
            ] {
                assert!(!counts(B, change.clone()), "a member's {change:?}");
            }
            // Admins: members, channels, the name; never another admin.
            for change in [
                Change::Kick(C),
                Change::Ban(C),
                Change::Rename("x".into()),
                channel.clone(),
                Change::MembersMayAdd(false),
            ] {
                assert!(counts(X, change.clone()), "an admin's {change:?}");
            }
            for change in [
                Change::Kick(Y),
                Change::Ban(Y),
                Change::Demote(Y),
                Change::MakeAdmin(C),
                Change::Kick(O),
                Change::Transfer(X),
                Change::End,
            ] {
                assert!(!counts(X, change.clone()), "an admin's {change:?}");
            }
            // The owner: admins too, but can't leave or be removed.
            for change in [
                Change::Kick(X),
                Change::Ban(X),
                Change::Demote(X),
                Change::MakeAdmin(B),
                Change::Transfer(B),
                Change::End,
            ] {
                assert!(counts(O, change.clone()), "the owner's {change:?}");
            }
            assert!(!counts(O, Change::Leave), "the owner hands it on first");
            assert!(!counts(X, Change::Kick(O)));
            // Strangers change nothing.
            assert!(!counts(D, Change::Leave));
            assert!(!counts(D, add([8; 32])));
        }

        #[test]
        fn bans_adds_and_the_cap() {
            let v = version(&with(base(), &[(8, X, Some(7), Change::Ban(C), 8)]));
            assert!(!v.state.members.contains_key(&C) && v.state.bans.contains(&C));
            let readd = (9, O, Some(8), add(C), 9);
            assert_eq!(
                version(&with(base(), &[(8, X, Some(7), Change::Ban(C), 8), readd])).head,
                [8; 16],
                "a banned person can't be added"
            );
            let off = (8, X, Some(7), Change::MembersMayAdd(false), 8);
            let v = version(&with(base(), &[off.clone(), (9, B, Some(8), add(D), 9)]));
            assert_eq!(v.head, [8; 16], "members may not add now");
            let v = version(&with(base(), &[off, (9, X, Some(8), add(D), 9)]));
            assert!(v.state.members.contains_key(&D), "admins still may");
            let mut steps = base();
            for i in 0..MAX_SPACE_MEMBERS as u8 {
                steps.push((
                    100 + i,
                    O,
                    Some(if i == 0 { 7 } else { 99 + i }),
                    add([200 - i; 32]),
                    100 + u64::from(i),
                ));
            }
            assert_eq!(version(&steps).state.members.len(), MAX_SPACE_MEMBERS);
        }

        #[test]
        fn channels_and_categories() {
            let s = space();
            let cat = Change::CategoryCreate {
                nonce: [10; 16],
                name: "text".into(),
            };
            let cat_id = part_id(&s, &[10; 16]);
            let ch = Change::ChannelCreate {
                nonce: [11; 16],
                name: "news".into(),
                category: Some(cat_id),
                admins_post: true,
            };
            let ch_id = part_id(&s, &[11; 16]);
            let v = version(&with(
                base(),
                &[(8, X, Some(7), cat, 8), (9, X, Some(8), ch, 9)],
            ));
            assert_eq!(v.state.channels[&ch_id].category, Some(cat_id));
            assert!(v.state.may_post(&X, &ch_id) && !v.state.may_post(&B, &ch_id));
            let gone = (10, Y, Some(9), Change::CategoryDelete(cat_id), 10);
            let open = (
                11,
                Y,
                Some(10),
                Change::ChannelPost {
                    channel: ch_id,
                    admins_only: false,
                },
                11,
            );
            let v = version(&with(
                base(),
                &[
                    (
                        8,
                        X,
                        Some(7),
                        Change::CategoryCreate {
                            nonce: [10; 16],
                            name: "text".into(),
                        },
                        8,
                    ),
                    (
                        9,
                        X,
                        Some(8),
                        Change::ChannelCreate {
                            nonce: [11; 16],
                            name: "news".into(),
                            category: Some(cat_id),
                            admins_post: true,
                        },
                        9,
                    ),
                    gone,
                    open,
                ],
            ));
            assert_eq!(
                v.state.channels[&ch_id].category, None,
                "out of a deleted category"
            );
            assert!(v.state.may_post(&B, &ch_id));
            assert!(v.posters[&ch_id].contains(&B) && v.posters[&ch_id].contains(&X));
        }

        /// Test 7.1: O removes admin X. X, apart, forks from before the
        /// removal with a ground-low ID and a back-dated seq, kicks B and
        /// renames. O's branch wins everywhere.
        #[test]
        fn an_ex_admin_cant_win_a_fork() {
            let v = in_any_order(&with(
                base(),
                &[
                    (20, O, Some(7), Change::Kick(X), 20),
                    (0, X, Some(7), Change::Kick(B), 0),
                    (8, X, Some(0), Change::Rename("mine".into()), 0),
                ],
            ));
            assert!(!v.state.members.contains_key(&X), "X is out");
            assert!(v.state.members.contains_key(&B), "B is in");
            assert_eq!(v.state.name, "club");
            // Even with another of O's changes on X's branch, the owner's own
            // earlier change decides, which only O controls.
            let v = in_any_order(&with(
                base(),
                &[
                    (20, O, Some(7), Change::Kick(X), 20),
                    (0, X, Some(7), Change::Kick(B), 0),
                    (9, O, Some(0), Change::Rename("later".into()), 30),
                ],
            ));
            assert!(!v.state.members.contains_key(&X));
        }

        /// Test 7.2: two admins apart; the losing branch's author redoes.
        #[test]
        fn two_admins_apart_both_end_up_applied() {
            let steps = with(
                base(),
                &[
                    (20, X, Some(7), Change::Kick(C), 20),
                    (21, Y, Some(7), Change::Rename("club!".into()), 21),
                ],
            );
            let v = in_any_order(&steps);
            assert_eq!(v.head, [20; 16], "the lower first admin change");
            let redo = to_redo(&space(), &v, &Y, &BTreeSet::new());
            assert_eq!(redo, vec![([21; 16], Change::Rename("club!".into()))]);
            assert!(to_redo(&space(), &v, &X, &BTreeSet::new()).is_empty());
            let v = version(&with(
                steps,
                &[(22, Y, Some(20), Change::Rename("club!".into()), 22)],
            ));
            assert!(!v.state.members.contains_key(&C));
            assert_eq!(v.state.name, "club!");
        }

        /// Test 7.3 and a second fork: a late fork drops X's ban; X redoes
        /// it; another late fork drops the redo; X redoes it again.
        #[test]
        fn a_redo_dropped_again_is_redone_again() {
            let mut steps = with(
                base(),
                &[
                    (30, X, Some(7), Change::Ban(C), 30),
                    (8, Y, Some(7), Change::Rename("forked".into()), 1),
                ],
            );
            let v = in_any_order(&steps);
            assert!(!v.state.bans.contains(&C), "Y's back-dated fork won");
            let mut done = BTreeSet::new();
            assert_eq!(
                to_redo(&space(), &v, &X, &done),
                vec![([30; 16], Change::Ban(C))]
            );
            done.insert([30; 16]);
            steps.push((31, X, Some(8), Change::Ban(C), 31));
            assert!(version(&steps).state.bans.contains(&C), "redone");
            // Y forks again, from before the redo.
            steps.push((9, Y, Some(8), Change::Rename("again".into()), 2));
            let v = in_any_order(&steps);
            assert!(!v.state.bans.contains(&C));
            assert_eq!(
                to_redo(&space(), &v, &X, &done),
                vec![([31; 16], Change::Ban(C))]
            );
            done.insert([31; 16]);
            steps.push((32, X, Some(9), Change::Ban(C), 32));
            assert!(version(&steps).state.bans.contains(&C), "redone again");
        }

        #[test]
        fn no_redo_when_it_would_change_nothing() {
            let v = version(&with(
                base(),
                &[
                    (20, X, Some(7), Change::Kick(C), 20),
                    (21, Y, Some(7), Change::Kick(C), 21),
                ],
            ));
            assert!(to_redo(&space(), &v, &Y, &BTreeSet::new()).is_empty());
            // And a change no longer allowed shows as undone, not redone.
            let v = version(&with(
                base(),
                &[
                    (20, O, Some(7), Change::Demote(Y), 20),
                    (21, Y, Some(7), Change::Rename("x".into()), 21),
                ],
            ));
            assert!(to_redo(&space(), &v, &Y, &BTreeSet::new()).is_empty());
        }

        /// A second creation, even one that sorts first, can't replace O.
        #[test]
        fn only_the_owners_creation_counts() {
            let theirs = Change::Create {
                name: "mine".into(),
                nonce: NONCE,
                display: "x".into(),
            };
            let v = version(&with(base(), &[(0, X, None, theirs, 0)]));
            assert_eq!((v.state.owner, v.state.name.as_str()), (O, "club"));
            assert!(chain(&[]).version(&space()).is_none());
        }

        #[test]
        fn saving_the_changes_round_trips() {
            let c = chain(&base());
            let mut back = Chain::default();
            for (id, by, change, at) in c.changes() {
                back.add(id, by, change, at);
            }
            assert_eq!(back.version(&space()), c.version(&space()));
        }
    }
}
