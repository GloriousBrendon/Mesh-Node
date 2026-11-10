//! Sender chains for groups and Spaces (D6, D7, D14). Each sending device
//! has one Megolm chain per conversation. Its key goes to every current
//! member device over the 1:1 sessions, in the same delivery as the first
//! message that needs it. A message is encrypted once.
//!
//! A group envelope's payload is `sender curve key [32] | chain ID [32] |
//! megolm message`, and Megolm encrypts `sender ID | sender device | inside`
//! as Olm does. Only a chain's creator holds its signing key, so a member
//! who passes a chain's key on can't pass its messages off as their own. A
//! key share's body (kind 2, over Olm) is:
//!
//! ```text
//! form u8 (1 = chain key, 2 = exported at an index) | key len u16 | key
//!   | members changed u64 | member count u16 | members [32 each]
//! ```
//!
//! Test groups carry their member list in each share; a device takes the
//! newest list from a member who is in it. `spaces` replaces this with the
//! Space's signed log. A key request's body (kind 3) is `chain ID [32] |
//! index u32`.

use std::collections::{BTreeSet, HashMap, HashSet};

use ed25519_dalek::VerifyingKey;
use mesh_identity::MeshId;
use serde::{Deserialize, Serialize};
use vodozemac::megolm::{
    ExportedSessionKey, GroupSession, GroupSessionPickle, InboundGroupSession,
    InboundGroupSessionPickle, MegolmMessage, SessionConfig, SessionKey,
};

use crate::E2eeError;
use crate::envelope::{Envelope, EnvelopeType, Inside, Kind};
use crate::session::{Conversation, E2ee, Opened, Received, claimed, key_of};

/// A chain is replaced after this many messages (D7).
pub const ROTATE_MESSAGES: u32 = 1000;
/// Or after this long.
pub const ROTATE_AFTER: u64 = 7 * 24 * 3600;
/// How long a message waits for its key share (D14).
pub const WAIT_FOR_KEY: u64 = 30 * 24 * 3600;
/// Messages waiting for a key, at most.
const MAX_WAITING: usize = 1000;
/// Members of a group, at most (`spaces` sizes Spaces at 500).
pub const MAX_MEMBERS: usize = 500;

const FORM_KEY: u8 = 1;
const FORM_EXPORTED: u8 = 2;

type Key = [u8; 32];

/// What each device should get for one group message: the key share it
/// still lacks (if any), then the message, encrypted once for everyone.
pub type Deliveries = Vec<(VerifyingKey, Vec<Vec<u8>>)>;

pub(crate) struct Group {
    members: Vec<MeshId>,
    changed: u64,
    outbound: Option<Outbound>,
}

impl Group {
    fn empty() -> Self {
        Self {
            members: Vec::new(),
            changed: 0,
            outbound: None,
        }
    }
}

struct Outbound {
    session: GroupSession,
    created: u64,
    /// The member devices that have this chain's key.
    shared: HashSet<(MeshId, Key)>,
}

struct Chain {
    /// We made it, so we answer key requests for it.
    ours: bool,
    session: InboundGroupSession,
    /// Indices already opened, past the first known one (replays, D13).
    seen: BTreeSet<u32>,
}

/// Group state: our groups and every chain we can read.
#[derive(Default)]
pub(crate) struct Groups {
    groups: HashMap<[u8; 16], Group>,
    /// By chain ID and conversation: a share naming the wrong conversation
    /// can't shut out the right one.
    chains: HashMap<(Key, [u8; 16]), Chain>,
    pub(crate) waiting: Vec<(u64, Vec<u8>)>,
    pub(crate) requested: HashSet<Key>,
}

/// Our chain as stored: the chain, when it started, who has its key.
type OutboundFile = (GroupSessionPickle, u64, Vec<(Key, Key)>);

/// A group as stored: its members, our chain and every chain we can read.
#[derive(Serialize, Deserialize)]
pub(crate) struct GroupFile {
    members: Vec<Key>,
    changed: u64,
    outbound: Option<OutboundFile>,
    chains: Vec<(Key, bool, InboundGroupSessionPickle, Vec<u32>)>,
}

impl Groups {
    pub(crate) fn conversations(&self) -> Vec<[u8; 16]> {
        self.groups.keys().copied().collect()
    }

    pub(crate) fn file(&self, conversation: &[u8; 16]) -> Option<GroupFile> {
        let group = self.groups.get(conversation)?;
        let outbound = group.outbound.as_ref().map(|out| {
            let shared = out
                .shared
                .iter()
                .map(|(id, d)| (id.to_bytes(), *d))
                .collect();
            (out.session.pickle(), out.created, shared)
        });
        let chains = (self.chains.iter())
            .filter(|((_, c), _)| c == conversation)
            .map(|((id, _), chain)| {
                let seen = chain.seen.iter().copied().collect();
                (*id, chain.ours, chain.session.pickle(), seen)
            })
            .collect();
        Some(GroupFile {
            members: group.members.iter().map(MeshId::to_bytes).collect(),
            changed: group.changed,
            outbound,
            chains,
        })
    }

    pub(crate) fn load(
        &mut self,
        conversation: [u8; 16],
        file: GroupFile,
    ) -> Result<(), E2eeError> {
        let id = |bytes: &Key| MeshId::from_bytes(bytes).map_err(|_| E2eeError::Store);
        let members = file.members.iter().map(id).collect::<Result<_, _>>()?;
        let outbound = match file.outbound {
            Some((pickle, created, shared)) => Some(Outbound {
                session: GroupSession::from_pickle(pickle),
                created,
                shared: (shared.iter())
                    .map(|(m, d)| Ok((id(m)?, *d)))
                    .collect::<Result<_, E2eeError>>()?,
            }),
            None => None,
        };
        let group = Group {
            members,
            changed: file.changed,
            outbound,
        };
        self.groups.insert(conversation, group);
        for (chain, ours, pickle, seen) in file.chains {
            let session = InboundGroupSession::from_pickle(pickle);
            let seen = seen.into_iter().collect();
            self.chains.insert(
                (chain, conversation),
                Chain {
                    ours,
                    session,
                    seen,
                },
            );
        }
        Ok(())
    }
}

impl E2ee {
    /// Starts a test group of `members` (we're added if missing). Returns its
    /// conversation ID, 16 random bytes (D10).
    pub fn new_group(&mut self, members: &[MeshId], now: u64) -> Result<[u8; 16], E2eeError> {
        let mut conversation = [0u8; 16];
        getrandom::fill(&mut conversation).map_err(|_| E2eeError::Random)?;
        self.set_members(conversation, members, now)?;
        Ok(conversation)
    }

    /// The group's member list changed (D7): the next send rotates if anyone
    /// left.
    pub fn set_members(
        &mut self,
        conversation: [u8; 16],
        members: &[MeshId],
        now: u64,
    ) -> Result<(), E2eeError> {
        let mut members: Vec<MeshId> = members.to_vec();
        members.push(self.me);
        members.sort_by_key(|m| m.to_bytes());
        members.dedup();
        if members.len() > MAX_MEMBERS {
            return Err(E2eeError::TooLong);
        }
        let group = self
            .groups
            .groups
            .entry(conversation)
            .or_insert_with(Group::empty);
        group.members = members;
        group.changed = now.max(group.changed + 1);
        self.dirty.account = true;
        self.dirty.groups.insert(conversation);
        self.save()
    }

    /// A group's members, if we're in it.
    pub fn members(&self, conversation: &[u8; 16]) -> Option<&[MeshId]> {
        self.groups.groups.get(conversation).map(|g| &g.members[..])
    }

    /// Encrypts `body` once for the group, with the key shares each current
    /// member device still lacks (D6, D14). Rotates first if due (D7).
    pub fn encrypt_group(
        &mut self,
        conversation: [u8; 16],
        kind: Kind,
        body: &[u8],
        now: u64,
    ) -> Result<Deliveries, E2eeError> {
        let members = self
            .members(&conversation)
            .ok_or(E2eeError::NotMember)?
            .to_vec();
        let me = self.device_bytes();
        let current = self.current_devices(&members);
        let mut targets: Vec<(MeshId, Key, VerifyingKey)> = Vec::new();
        for member in &members {
            let reachable = self
                .reachable_of(member)
                .into_iter()
                .filter(|(d, _)| *d != me);
            targets.extend(reachable.map(|(d, key)| (*member, d, key)));
        }
        let message = self.claim(&self.inside(conversation, kind, body)?);
        let group = self
            .groups
            .groups
            .get_mut(&conversation)
            .expect("found above");
        let due = group.outbound.as_ref().is_none_or(|out| {
            out.session.message_index() >= ROTATE_MESSAGES
                || now >= out.created + ROTATE_AFTER
                || !out.shared.is_subset(&current)
        });
        if due {
            let session = GroupSession::new(SessionConfig::version_1());
            let own = InboundGroupSession::new(&session.session_key(), SessionConfig::version_1());
            group.outbound = Some(Outbound {
                session,
                created: now,
                shared: HashSet::new(),
            });
            let chain = Chain {
                ours: true,
                session: own,
                seen: BTreeSet::new(),
            };
            let at = (chain_id_of(group)?, conversation);
            self.groups.chains.insert(at, chain);
        }
        let group = self
            .groups
            .groups
            .get_mut(&conversation)
            .expect("found above");
        let (changed, out) = (group.changed, group.outbound.as_mut().expect("made above"));
        let chain = chain_id(&out.session.session_id())?;
        let share = share_body(
            FORM_KEY,
            &out.session.session_key().to_bytes(),
            changed,
            &members,
        );
        let needs: Vec<bool> = targets
            .iter()
            .map(|(id, d, _)| !out.shared.contains(&(*id, *d)))
            .collect();
        let message = out.session.encrypt(&message);
        let mut payload = self.curve().to_vec();
        payload.extend_from_slice(&chain);
        payload.extend_from_slice(&message.to_bytes());
        let message = Envelope {
            kind: EnvelopeType::Group,
            payload,
        }
        .to_bytes();
        let share = self.inside(conversation, Kind::KeyShare, &share)?;

        let mut deliveries = Vec::with_capacity(targets.len());
        for ((id, device, key), needs) in targets.into_iter().zip(needs) {
            let mut envelopes = Vec::with_capacity(2);
            if needs {
                match self.encrypt_to(&id, &device, &share) {
                    Ok(share) => envelopes.push(share),
                    // No session and no keys for it: it can't be reached.
                    Err(_) => continue,
                }
                let group = self.groups.groups.get_mut(&conversation).expect("found");
                let out = group.outbound.as_mut().expect("made above");
                out.shared.insert((id, device));
            }
            envelopes.push(message.clone());
            deliveries.push((key, envelopes));
        }
        self.dirty.groups.insert(conversation);
        self.save()?;
        Ok(deliveries)
    }

    fn current_devices(&self, members: &[MeshId]) -> HashSet<(MeshId, Key)> {
        let mut out = HashSet::new();
        for member in members {
            if let Some(person) = self.people.get(member) {
                for cert in person.devices.devices() {
                    out.insert((*member, cert.device().to_bytes()));
                }
            }
        }
        out
    }

    /// Opens a group envelope, or keeps it if its key hasn't come yet (D14).
    pub(crate) fn open_group(
        &mut self,
        bytes: &[u8],
        envelope: &Envelope,
        now: u64,
        out: &mut Received,
    ) -> Result<(), E2eeError> {
        let payload = &envelope.payload;
        if payload.len() < 64 {
            return Err(E2eeError::Malformed);
        }
        let curve: Key = payload[..32].try_into().expect("32 bytes");
        let chain_key: Key = payload[32..64].try_into().expect("32 bytes");
        let message =
            MegolmMessage::from_bytes(&payload[64..]).map_err(|_| E2eeError::Malformed)?;
        let index = message.message_index();
        let mut opened = None;
        let mut replay = false;
        for ((id, conversation), chain) in self.groups.chains.iter_mut() {
            if *id != chain_key {
                continue;
            }
            if index < chain.session.first_known_index() || chain.seen.contains(&index) {
                replay = true;
                continue;
            }
            if let Ok(plain) = chain.session.decrypt(&message) {
                opened = Some((*conversation, plain.plaintext));
                break;
            }
        }
        let Some((conversation, plain)) = opened else {
            if replay {
                return Err(E2eeError::Replay);
            }
            return self.wait_for_key(bytes, curve, chain_key, index, now, out);
        };
        let (sender, device) = claimed(&plain)?;
        let inside = Inside::from_bytes(&plain[64..])?;
        if inside.conversation != conversation {
            return Err(E2eeError::NotMember);
        }
        let current = self
            .people
            .get(&sender)
            .is_some_and(|p| key_of(&device).is_ok_and(|d| p.devices.is_current(&d)));
        if !current {
            return Err(E2eeError::RevokedDevice);
        }
        let group = self.groups.groups.get(&conversation);
        if !group.is_some_and(|g| g.members.contains(&sender)) {
            return Err(E2eeError::NotMember);
        }
        let chain = self.groups.chains.get_mut(&(chain_key, conversation));
        let chain = chain.expect("opened with it");
        chain.seen.insert(index);
        // Forget the keys of every index up to the first gap (D13).
        let mut first = chain.session.first_known_index();
        while chain.seen.remove(&first) {
            first += 1;
        }
        chain.session.advance_to(first);
        self.dirty.groups.insert(conversation);
        out.opened.push(Opened {
            conversation: Conversation::Group(conversation),
            sender,
            device: key_of(&device)?,
            kind: inside.kind,
            body: inside.body,
        });
        Ok(())
    }

    /// Keeps a message whose chain we don't have, and asks the device that
    /// sent it, once per chain.
    fn wait_for_key(
        &mut self,
        bytes: &[u8],
        curve: Key,
        chain_key: Key,
        index: u32,
        now: u64,
        out: &mut Received,
    ) -> Result<(), E2eeError> {
        self.groups
            .waiting
            .retain(|(at, _)| now < at + WAIT_FOR_KEY);
        if self.groups.waiting.len() >= MAX_WAITING {
            return Err(E2eeError::TooLong);
        }
        self.groups.waiting.push((now, bytes.to_vec()));
        self.dirty.account = true;
        if self.groups.requested.insert(chain_key) {
            let mut request = chain_key.to_vec();
            request.extend_from_slice(&index.to_be_bytes());
            let inside = self.inside([0; 16], Kind::KeyRequest, &request)?;
            for (id, device) in self.candidates(&curve).unwrap_or_default() {
                if let Ok(env) = self.encrypt_to(&id, &device, &inside) {
                    out.replies.push((key_of(&device)?, env));
                }
            }
        }
        Ok(())
    }

    /// Takes a key share that came over a 1:1 session from `sender`.
    pub(crate) fn take_share(
        &mut self,
        sender: MeshId,
        inside: &Inside,
        now: u64,
        out: &mut Received,
    ) -> Result<(), E2eeError> {
        let share = parse_share(&inside.body)?;
        if !share.members.contains(&sender) || !share.members.contains(&self.me) {
            return Err(E2eeError::NotMember);
        }
        let conversation = inside.conversation;
        let group = self
            .groups
            .groups
            .entry(conversation)
            .or_insert_with(Group::empty);
        // Only a member may change the list, or share a chain.
        if !group.members.is_empty() && !group.members.contains(&sender) {
            return Err(E2eeError::NotMember);
        }
        if share.changed > group.changed {
            group.members = share.members;
            group.changed = share.changed;
            self.dirty.account = true;
            self.dirty.groups.insert(conversation);
        }
        if !group.members.contains(&sender) {
            return Err(E2eeError::NotMember);
        }
        let session = match share.form {
            FORM_KEY => SessionKey::from_bytes(&share.key)
                .map(|k| InboundGroupSession::new(&k, SessionConfig::version_1())),
            _ => ExportedSessionKey::from_bytes(&share.key)
                .map(|k| InboundGroupSession::import(&k, SessionConfig::version_1())),
        }
        .map_err(|_| E2eeError::Malformed)?;
        let chain_key = chain_id(&session.session_id())?;
        let at = (chain_key, conversation);
        if let Some(chain) = self.groups.chains.get(&at)
            && chain.session.first_known_index() <= session.first_known_index()
        {
            return Ok(());
        }
        let chain = Chain {
            ours: false,
            session,
            seen: BTreeSet::new(),
        };
        self.groups.chains.insert(at, chain);
        self.groups.requested.remove(&chain_key);
        self.dirty.account = true;
        self.dirty.groups.insert(conversation);
        // Messages that were waiting for this key.
        let waiting = std::mem::take(&mut self.groups.waiting);
        for (at, bytes) in waiting {
            let envelope = Envelope::from_bytes(&bytes)?;
            if envelope.payload.get(32..64) == Some(&chain_key[..]) {
                let _ = self.open_group(&bytes, &envelope, now, out);
            } else {
                self.groups.waiting.push((at, bytes));
            }
        }
        Ok(())
    }

    /// Answers a key request for one of our own chains, to a current member
    /// device (D14).
    pub(crate) fn answer_request(
        &mut self,
        sender: MeshId,
        device: Key,
        inside: &Inside,
        out: &mut Received,
    ) -> Result<(), E2eeError> {
        let body = &inside.body;
        if body.len() != 36 {
            return Err(E2eeError::Malformed);
        }
        let chain_key: Key = body[..32].try_into().expect("32 bytes");
        let index = u32::from_be_bytes(body[32..].try_into().expect("4 bytes"));
        let chains = &self.groups.chains;
        let ours = chains
            .iter()
            .find(|((id, _), c)| *id == chain_key && c.ours);
        let Some(((_, conversation), _)) = ours else {
            return Ok(());
        };
        let conversation = *conversation;
        let Some(group) = self.groups.groups.get(&conversation) else {
            return Ok(());
        };
        let current = self
            .people
            .get(&sender)
            .is_some_and(|p| key_of(&device).is_ok_and(|d| p.devices.is_current(&d)));
        if !group.members.contains(&sender) || !current {
            return Ok(());
        }
        let (changed, members) = (group.changed, group.members.clone());
        let chain = self.groups.chains.get_mut(&(chain_key, conversation));
        let Some(exported) = chain.and_then(|c| c.session.export_at(index)) else {
            return Ok(());
        };
        self.dirty.groups.insert(conversation);
        let share = share_body(FORM_EXPORTED, &exported.to_bytes(), changed, &members);
        let inside = self.inside(conversation, Kind::KeyShare, &share)?;
        let env = self.encrypt_to(&sender, &device, &inside)?;
        out.replies.push((key_of(&device)?, env));
        Ok(())
    }
}

/// The chain ID of a group's current outbound chain.
fn chain_id_of(group: &Group) -> Result<Key, E2eeError> {
    let out = group.outbound.as_ref().ok_or(E2eeError::Malformed)?;
    chain_id(&out.session.session_id())
}

struct Share {
    form: u8,
    key: Vec<u8>,
    changed: u64,
    members: Vec<MeshId>,
}

fn share_body(form: u8, key: &[u8], changed: u64, members: &[MeshId]) -> Vec<u8> {
    let mut out = vec![form];
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&changed.to_be_bytes());
    out.extend_from_slice(&(members.len() as u16).to_be_bytes());
    for member in members {
        out.extend_from_slice(&member.to_bytes());
    }
    out
}

fn parse_share(body: &[u8]) -> Result<Share, E2eeError> {
    let bad = E2eeError::Malformed;
    let form = *body.first().ok_or(bad)?;
    if form != FORM_KEY && form != FORM_EXPORTED {
        return Err(bad);
    }
    let len = u16::from_be_bytes(body.get(1..3).ok_or(bad)?.try_into().expect("2")) as usize;
    let key = body.get(3..3 + len).ok_or(bad)?.to_vec();
    let rest = &body[3 + len..];
    let changed = u64::from_be_bytes(rest.get(..8).ok_or(bad)?.try_into().expect("8"));
    let count = u16::from_be_bytes(rest.get(8..10).ok_or(bad)?.try_into().expect("2")) as usize;
    let list = &rest[10..];
    if count > MAX_MEMBERS || list.len() != count * 32 {
        return Err(bad);
    }
    let members = list
        .chunks(32)
        .map(|m| MeshId::from_bytes(m.try_into().expect("32")).map_err(|_| bad))
        .collect::<Result<_, _>>()?;
    Ok(Share {
        form,
        key,
        changed,
        members,
    })
}

/// A chain's ID: its signing key, raw.
fn chain_id(session_id: &str) -> Result<Key, E2eeError> {
    vodozemac::base64_decode(session_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(E2eeError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::tests::NOW;
    use crate::session::tests::{Device, device, friends};

    /// Alice, Bob and Carol, all friends with each other.
    fn three() -> (Device, Device, Device) {
        let (mut a, mut b, mut c) = (device(), device(), device());
        friends(&mut a, &mut b);
        friends(&mut a, &mut c);
        friends(&mut b, &mut c);
        (a, b, c)
    }

    fn id(d: &Device) -> MeshId {
        d.who.root.id()
    }

    fn key(d: &Device) -> VerifyingKey {
        d.who.device.public()
    }

    /// Hands each reader its delivery; returns what each opened.
    fn deliver(out: &Deliveries, readers: &mut [&mut Device]) -> Vec<Vec<Opened>> {
        readers
            .iter_mut()
            .map(|reader| {
                let mut opened = Vec::new();
                if let Some((_, envelopes)) = out.iter().find(|(d, _)| *d == key(reader)) {
                    for env in envelopes {
                        opened.extend(reader.e2ee.decrypt(env, NOW).unwrap().opened);
                    }
                }
                opened
            })
            .collect()
    }

    fn message_of(out: &Deliveries, reader: &Device) -> Vec<u8> {
        let (_, envelopes) = out.iter().find(|(d, _)| *d == key(reader)).unwrap();
        envelopes.last().unwrap().clone()
    }

    fn chain_of(envelope: &[u8]) -> Vec<u8> {
        envelope[2 + 32..2 + 64].to_vec()
    }

    #[test]
    fn one_ciphertext_reaches_every_member() {
        let (mut a, mut b, mut c) = three();
        let group = a.e2ee.new_group(&[id(&b), id(&c)], NOW).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"hi", NOW)
            .unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|(_, envs)| envs.len() == 2));
        assert_eq!(message_of(&out, &b), message_of(&out, &c));
        for opened in deliver(&out, &mut [&mut b, &mut c]) {
            assert_eq!(opened.len(), 1);
            assert_eq!(opened[0].conversation, Conversation::Group(group));
            assert_eq!(
                (opened[0].sender, &opened[0].body[..]),
                (id(&a), &b"hi"[..])
            );
        }
        // The share went once; the next message is the message alone.
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"2", NOW)
            .unwrap();
        assert!(out.iter().all(|(_, envs)| envs.len() == 1));
        deliver(&out, &mut [&mut b, &mut c]);
        // Bob learned the members from the share, and can send too.
        let mut members = [id(&a), id(&b), id(&c)];
        members.sort_by_key(|m| m.to_bytes());
        assert_eq!(b.e2ee.members(&group).unwrap(), &members[..]);
        let out = b
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"from bob", NOW)
            .unwrap();
        let opened = deliver(&out, &mut [&mut a, &mut c]);
        assert!(opened.iter().all(|o| o[0].sender == id(&b)));
    }

    #[test]
    fn a_later_member_cant_read_earlier_messages() {
        let (mut a, mut b, mut c) = three();
        let group = a.e2ee.new_group(&[id(&b)], NOW).unwrap();
        let first = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"before", NOW)
            .unwrap();
        deliver(&first, &mut [&mut b]);
        a.e2ee.set_members(group, &[id(&b), id(&c)], NOW).unwrap();
        let second = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"after", NOW)
            .unwrap();
        // Adding someone doesn't rotate: Bob gets no new share.
        let (_, to_bob) = second.iter().find(|(d, _)| *d == key(&b)).unwrap();
        assert_eq!(to_bob.len(), 1);
        let opened = deliver(&second, &mut [&mut c]);
        assert_eq!(opened[0][0].body, b"after");
        // The earlier message, handed to Carol, stays shut.
        let old = message_of(&first, &b);
        let got = c.e2ee.decrypt(&old, NOW);
        assert!(got.is_err() || got.unwrap().opened.is_empty());
    }

    #[test]
    fn a_removed_member_cant_read_the_next_message() {
        let (mut a, mut b, mut c) = three();
        let group = a.e2ee.new_group(&[id(&b), id(&c)], NOW).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"all", NOW)
            .unwrap();
        deliver(&out, &mut [&mut b, &mut c]);
        a.e2ee.set_members(group, &[id(&b)], NOW + 1).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"no carol", NOW)
            .unwrap();
        assert!(out.iter().all(|(d, _)| *d != key(&c)));
        let message = message_of(&out, &b);
        // A new chain, with a new share for Bob.
        assert_eq!(out[0].1.len(), 2);
        // Carol, with Bob's copy, has no key: she asks Alice, who says nothing.
        let got = c.e2ee.decrypt(&message, NOW).unwrap();
        assert!(got.opened.is_empty());
        let (to, request) = got.replies.into_iter().next().unwrap();
        assert_eq!(to, key(&a));
        let answer = a.e2ee.decrypt(&request, NOW).unwrap();
        assert!(answer.opened.is_empty() && answer.replies.is_empty());
        assert_eq!(deliver(&out, &mut [&mut b])[0][0].body, b"no carol");

        // Bob takes the new list from Alice's share: his next chain skips Carol.
        let out = b
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"bob", NOW)
            .unwrap();
        assert!(out.iter().all(|(d, _)| *d != key(&c)));
    }

    #[test]
    fn chains_rotate_after_a_thousand_messages_and_after_a_week() {
        let (mut a, b, _) = three();
        let group = a.e2ee.new_group(&[id(&b)], NOW).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"0", NOW)
            .unwrap();
        let first = chain_of(&message_of(&out, &b));
        for _ in 1..ROTATE_MESSAGES {
            a.e2ee
                .encrypt_group(group, Kind::TestNote, b"x", NOW)
                .unwrap();
        }
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"x", NOW)
            .unwrap();
        let second = chain_of(&message_of(&out, &b));
        assert_ne!(first, second);
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"x", NOW + ROTATE_AFTER - 1)
            .unwrap();
        assert_eq!(chain_of(&message_of(&out, &b)), second);
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"x", NOW + ROTATE_AFTER)
            .unwrap();
        assert_ne!(chain_of(&message_of(&out, &b)), second);
    }

    #[test]
    fn a_share_and_its_message_in_either_order() {
        let (mut a, mut b, _) = three();
        let group = a.e2ee.new_group(&[id(&b)], NOW).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"late key", NOW)
            .unwrap();
        let (_, envs) = &out[0];
        let got = b.e2ee.decrypt(&envs[1], NOW).unwrap();
        assert!(got.opened.is_empty());
        let got = b.e2ee.decrypt(&envs[0], NOW).unwrap();
        assert_eq!(got.opened[0].body, b"late key");
    }

    #[test]
    fn a_lost_share_is_asked_for_once() {
        let (mut a, mut b, _) = three();
        let group = a.e2ee.new_group(&[id(&b)], NOW).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"one", NOW)
            .unwrap();
        let first = out[0].1[1].clone();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"two", NOW)
            .unwrap();
        let second = out[0].1[0].clone();
        let asked = b.e2ee.decrypt(&first, NOW).unwrap();
        assert_eq!(asked.replies.len(), 1);
        // A second message on the same chain doesn't ask again.
        assert!(b.e2ee.decrypt(&second, NOW).unwrap().replies.is_empty());
        let answer = a.e2ee.decrypt(&asked.replies[0].1, NOW).unwrap();
        let (to, share) = answer.replies.into_iter().next().unwrap();
        assert_eq!(to, key(&b));
        let got = b.e2ee.decrypt(&share, NOW).unwrap();
        let bodies: Vec<_> = got.opened.iter().map(|o| o.body.clone()).collect();
        assert_eq!(bodies, [b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn replays_and_strangers_are_refused() {
        let (mut a, mut b, mut eve) = three();
        let group = a.e2ee.new_group(&[id(&b)], NOW).unwrap();
        let out = a
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"hi", NOW)
            .unwrap();
        deliver(&out, &mut [&mut b]);
        let message = message_of(&out, &b);
        assert_eq!(
            b.e2ee.decrypt(&message, NOW).unwrap_err(),
            E2eeError::Replay
        );

        // Eve, a friend of Bob's but not in the group, writes to it.
        eve.e2ee.set_members(group, &[id(&b)], NOW + 10).unwrap();
        let out = eve
            .e2ee
            .encrypt_group(group, Kind::TestNote, b"eve", NOW)
            .unwrap();
        let (_, envs) = out.iter().find(|(d, _)| *d == key(&b)).unwrap();
        assert_eq!(
            b.e2ee.decrypt(&envs[0], NOW).unwrap_err(),
            E2eeError::NotMember
        );
        let got = b.e2ee.decrypt(&envs[1], NOW).unwrap();
        assert!(got.opened.is_empty());
        let mut members = [id(&a), id(&b)];
        members.sort_by_key(|m| m.to_bytes());
        assert_eq!(b.e2ee.members(&group).unwrap(), &members[..]);
    }

    /// Success criterion 4: one message to 600 devices, and a full rotation.
    #[test]
    #[ignore = "timing; run with --release -- --ignored"]
    fn timing_for_a_space_of_three_hundred() {
        use mesh_identity::{DeviceCert, DeviceKey, DeviceList, RootKey};
        let mut alice = device();
        let mut members = Vec::new();
        for _ in 0..300 {
            let root = RootKey::generate().unwrap();
            let keys = [
                DeviceKey::generate().unwrap(),
                DeviceKey::generate().unwrap(),
            ];
            let first = DeviceCert::issue(&root, &keys[0].public(), "pc", NOW).unwrap();
            let second = DeviceCert::issue(&root, &keys[1].public(), "laptop", NOW).unwrap();
            let list = DeviceList::first(&root, first).unwrap();
            let list = list.with_device(&root, second).unwrap();
            for k in &keys {
                let mut theirs = E2ee::new(&root, k, &list, NOW).unwrap();
                let field = theirs.record_field(&id(&alice), NOW).unwrap();
                alice
                    .e2ee
                    .learn(&root.id(), &list, &k.public(), &field)
                    .unwrap();
            }
            members.push(root.id());
        }
        let group = alice.e2ee.new_group(&members, NOW).unwrap();
        let started = std::time::Instant::now();
        let out = alice
            .e2ee
            .encrypt_group(group, Kind::Message, b"rotation", NOW)
            .unwrap();
        let rotation = started.elapsed();
        assert_eq!(out.len(), 600);
        let started = std::time::Instant::now();
        alice
            .e2ee
            .encrypt_group(group, Kind::Message, b"one", NOW)
            .unwrap();
        let one = started.elapsed();
        eprintln!("600 devices: rotation {rotation:?}, one message {one:?}");
        assert!(one < std::time::Duration::from_millis(1));
        assert!(rotation < std::time::Duration::from_secs(1));
    }
}
