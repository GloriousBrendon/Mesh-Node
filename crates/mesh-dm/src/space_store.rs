//! Spaces on disk (SPEC-spaces S3, S11). Each Space has its own folder
//! under `<data>/dm/spaces/`, with its own log, so unlock reads only the
//! list of Spaces and a Space's log is read the first time it's used. Its
//! changes and each channel's events are kept as they came, signatures and
//! all, so they can be passed on as history (S10). A channel is folded for
//! showing by dm's `Chat`, which brings D2's order, edits, deletes and
//! reactions with it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::chat::{Chat, Taken};
use crate::event::{Body, Event, EventId, VERSION};
use crate::history::{HistoryError, Unread};
use crate::space::{Chain, ChannelId, Role, SpaceBody, SpaceEvent, SpaceId, SpaceVersion};
use crate::store::{ChatFiles, Conversation, Store, StoreError};
use crate::sync::{Counters, Entry, Log};
use crate::{Device, Person, Sender};
use mesh_identity::{DeviceCert, DeviceKey};

/// The format number in front of everything saved here.
pub const SPACE_FORMAT: u8 = 1;
/// Where a Space's changes are kept: no channel's key is this.
const CHANGES: Conversation = [0xff; 16];

fn framed(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.insert(0, SPACE_FORMAT);
    bytes
}

fn unframe<'a>(what: &'static str, bytes: &'a [u8]) -> Result<&'a [u8], HistoryError> {
    match bytes.split_first() {
        Some((&SPACE_FORMAT, rest)) => Ok(rest),
        Some((&v, _)) if v > SPACE_FORMAT => Err(HistoryError::Newer(what)),
        _ => Err(StoreError::Damaged.into()),
    }
}

fn read<T: for<'de> Deserialize<'de>>(what: &'static str, bytes: &[u8]) -> Result<T, HistoryError> {
    postcard::from_bytes(unframe(what, bytes)?).map_err(|_| StoreError::Damaged.into())
}

/// Where a channel's events are kept in its Space's folder.
fn channel_key(space: &SpaceId, channel: &ChannelId) -> Conversation {
    let key = blake3::derive_key("mesh/v1/space-chat", &[&space[..], channel].concat());
    key[..16].try_into().expect("16 bytes")
}

/// A Space's folder: a keyed hash of its ID, so the folder names say
/// nothing about which Spaces these are.
fn space_dir(root: &Path, data_key: &[u8; 32], space: &SpaceId) -> PathBuf {
    let names = blake3::derive_key("mesh/v1/space-dir", data_key);
    let name = blake3::keyed_hash(&names, space);
    let hex: String = name.as_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    root.join("spaces").join(hex)
}

/// One stored event, as it came.
#[derive(Serialize, Deserialize)]
struct Stored {
    received: u64,
    person: Person,
    device: Device,
    event: Vec<u8>,
}

/// The Spaces this device is in: all that unlock reads (S11).
pub struct SpaceList {
    files: ChatFiles,
    spaces: Vec<SpaceId>,
}

impl SpaceList {
    pub fn open(root: &Path, data_key: &[u8; 32]) -> Result<Self, HistoryError> {
        let files = Store::new(&root.join("spaces"), data_key).open(&[0; 16])?;
        let spaces = match files.index()? {
            Some(bytes) => read("the list of Spaces", &bytes)?,
            None => Vec::new(),
        };
        Ok(Self { files, spaces })
    }

    pub fn spaces(&self) -> &[SpaceId] {
        &self.spaces
    }

    pub fn add(&mut self, space: SpaceId) -> Result<(), HistoryError> {
        if !self.spaces.contains(&space) {
            self.spaces.push(space);
            self.save()?;
        }
        Ok(())
    }

    pub fn remove(&mut self, space: &SpaceId) -> Result<(), HistoryError> {
        self.spaces.retain(|s| s != space);
        self.save()
    }

    fn save(&self) -> Result<(), HistoryError> {
        let bytes = framed(postcard::to_stdvec(&self.spaces).expect("to memory"));
        Ok(self.files.write_index(&bytes)?)
    }
}

/// A Space's stored changes and channels, opened when first used.
pub struct SpaceHistory {
    pub space: SpaceId,
    me: Sender,
    store: Store,
    log_files: ChatFiles,
    log: Log,
    chain: Chain,
    change_files: ChatFiles,
    /// Channels read so far: their files and what they show.
    channels: HashMap<ChannelId, (ChatFiles, Chat)>,
    /// Deleted events, by channel, so a late copy stays out (dm D3).
    deleted: HashMap<Conversation, HashSet<EventId>>,
    /// Where each stored event sits, by number (from 1).
    places: Vec<(Conversation, u32, u32)>,
    /// What each device has acknowledged (dm D5).
    counters: Counters,
}

#[derive(Serialize, Deserialize)]
enum SpaceLog {
    /// A stored event, and where it sits in its chat's files.
    Stored {
        entry: Entry,
        segment: u32,
        position: u32,
    },
    Deleted {
        chat: Conversation,
        id: EventId,
    },
}

impl SpaceHistory {
    /// Reads the Space's log and changes; channels wait until asked for.
    pub fn open(
        root: &Path,
        data_key: &[u8; 32],
        me: Sender,
        space: SpaceId,
    ) -> Result<Self, HistoryError> {
        let store = Store::new(&space_dir(root, data_key, &space), data_key);
        let mut history = Self {
            space,
            me,
            log_files: store.open_log()?,
            change_files: store.open(&CHANGES)?,
            store,
            log: Log::default(),
            chain: Chain::default(),
            channels: HashMap::new(),
            deleted: HashMap::new(),
            places: Vec::new(),
            counters: Counters::new(me.person),
        };
        for n in 0..history.log_files.segments() {
            for record in history.log_files.read(n)? {
                match read("a Space log record", &record)? {
                    SpaceLog::Stored {
                        entry,
                        segment,
                        position,
                    } => {
                        let chat = entry.chat;
                        if history.log.take(entry).is_some() {
                            history.places.push((chat, segment, position));
                        }
                    }
                    SpaceLog::Deleted { chat, id } => {
                        history.deleted.entry(chat).or_default().insert(id);
                    }
                }
            }
        }
        read_changes(&mut history.change_files, &mut history.chain)?;
        if let Some(bytes) = history.log_files.index()? {
            history.counters = read("the delivery counters", &bytes)?;
        }
        Ok(history)
    }

    /// A Space's chain alone, without its log or any channel: what unlock
    /// reads to work out the peers (S2 as changed, plan Task 5).
    pub fn read_chain(
        root: &Path,
        data_key: &[u8; 32],
        space: &SpaceId,
    ) -> Result<Chain, HistoryError> {
        let store = Store::new(&space_dir(root, data_key, space), data_key);
        let mut files = store.open(&CHANGES)?;
        let mut chain = Chain::default();
        read_changes(&mut files, &mut chain)?;
        Ok(chain)
    }

    /// The Space as its winning line leaves it; `None` before its creation.
    pub fn version(&self) -> Option<SpaceVersion> {
        self.chain.version(&self.space)
    }

    /// The stored events in order, for the counters (dm D5).
    pub fn log(&self) -> &Log {
        &self.log
    }

    /// Stores an event that passed `check_live` or `check_history`, from
    /// `from`, first received at `received`. What `Chat` makes of it for a
    /// channel event; a change is kept whatever the chain makes of it, since
    /// a change off the winning line today can be on it tomorrow (S7).
    pub fn store(
        &mut self,
        event: &SpaceEvent,
        from: Sender,
        received: u64,
        now: u64,
    ) -> Result<Taken, HistoryError> {
        let taken = self.store_batch(vec![(event.clone(), from)], received, now)?;
        Ok(taken[0])
    }

    /// Stores many events at once, as `store` would one by one, with one
    /// sync per file touched: history's intake (S10).
    pub fn store_batch(
        &mut self,
        events: Vec<(SpaceEvent, Sender)>,
        received: u64,
        now: u64,
    ) -> Result<Vec<Taken>, HistoryError> {
        let mut taken = Vec::with_capacity(events.len());
        let mut seen: HashSet<EventId> = HashSet::new();
        // Each file's new records, in order, and the log's entries.
        let mut records: HashMap<Conversation, Vec<Vec<u8>>> = HashMap::new();
        let mut entries: Vec<Entry> = Vec::new();
        // A change may make or unmake an admin: the loaded channels learn
        // who moderates before the next message is judged (S8).
        let mut moderators_stale = false;
        for (event, from) in events {
            if self.log.number_of(&event.id).is_some() || !seen.insert(event.id) {
                taken.push(Taken::Duplicate);
                continue;
            }
            let bytes = event.to_bytes()?;
            let stored = framed(
                postcard::to_stdvec(&Stored {
                    received,
                    person: from.person,
                    device: from.device,
                    event: bytes,
                })
                .expect("to memory"),
            );
            let (chat, change, private) = match &event.body {
                SpaceBody::Change(change) => {
                    self.chain
                        .add(event.id, from.person, change.clone(), (event.seq, event.id));
                    moderators_stale = true;
                    (CHANGES, true, false)
                }
                body => {
                    let channel = channel_of(body).expect("not a change");
                    let dm = to_dm(&event).expect("not a change");
                    if std::mem::take(&mut moderators_stale) {
                        self.refresh_moderators();
                    }
                    self.load(&channel, now)?;
                    let (_, view) = self.channels.get_mut(&channel).expect("loaded");
                    let t = view.take_received(from, dm, now, received);
                    if !matches!(t, Taken::Shown | Taken::Waiting) {
                        taken.push(t);
                        continue;
                    }
                    let private = matches!(body, SpaceBody::Read { .. });
                    (channel_key(&self.space, &channel), false, private)
                }
            };
            records.entry(chat).or_default().push(stored);
            entries.push(Entry {
                id: event.id,
                chat,
                author: from.person,
                from: from.device,
                at: received,
                private,
                change,
            });
            taken.push(Taken::Shown);
        }
        // Where each new record lands, file by file, then one append each.
        let mut places: HashMap<Conversation, std::vec::IntoIter<(u32, u32)>> = HashMap::new();
        for (chat, recs) in &records {
            let files = self.files_mut(chat)?;
            places.insert(*chat, files.next_places(recs.len()).into_iter());
            files.append(recs)?;
        }
        let mut log_records = Vec::with_capacity(entries.len());
        for entry in entries {
            let (segment, position) = places
                .get_mut(&entry.chat)
                .and_then(Iterator::next)
                .expect("a place for each record");
            self.log.take(entry.clone());
            self.places.push((entry.chat, segment, position));
            let stored = SpaceLog::Stored {
                entry,
                segment,
                position,
            };
            log_records.push(framed(postcard::to_stdvec(&stored).expect("to memory")));
        }
        self.log_files.append(&log_records)?;
        if moderators_stale {
            self.refresh_moderators();
        }
        Ok(taken)
    }

    fn refresh_moderators(&mut self) {
        let who = self.moderators();
        for (_, view) in self.channels.values_mut() {
            view.set_moderators(who.clone());
        }
    }

    /// The files a chat's records go to: the changes', or a loaded channel's.
    fn files_mut(&mut self, chat: &Conversation) -> Result<&mut ChatFiles, HistoryError> {
        if *chat == CHANGES {
            return Ok(&mut self.change_files);
        }
        let space = self.space;
        let channel = (self.channels.iter_mut())
            .find(|(c, _)| channel_key(&space, c) == *chat)
            .map(|(_, (files, _))| files);
        channel.ok_or_else(|| StoreError::Damaged.into())
    }

    /// The owner and admins in force: who deletes anyone's message (S8).
    fn moderators(&self) -> HashSet<Person> {
        let Some(v) = self.version() else {
            return HashSet::new();
        };
        (v.state.members.iter())
            .filter(|(_, m)| m.role >= Role::Admin)
            .map(|(p, _)| *p)
            .collect()
    }

    /// A channel as it shows: its newest segment, read the first time.
    pub fn channel(&mut self, channel: &ChannelId, now: u64) -> Result<&Chat, HistoryError> {
        self.load(channel, now)?;
        Ok(&self.channels[channel].1)
    }

    /// Every stored event of a channel, or with `None` the changes, oldest
    /// first, as they came: what history is served from (S10).
    pub fn events(&mut self, channel: Option<&ChannelId>) -> Result<Vec<SpaceEvent>, HistoryError> {
        let key = channel.map_or(CHANGES, |c| channel_key(&self.space, c));
        let mut files = self.store.open(&key)?;
        let mut out = Vec::new();
        for n in 0..files.segments() {
            for record in files.read(n)? {
                let stored: Stored = read("a Space event", &record)?;
                out.push(SpaceEvent::from_bytes(&stored.event)?);
            }
        }
        Ok(out)
    }

    /// A device we'll send this Space's events to (dm D5's counters).
    pub fn add_device(&mut self, device: Device, person: Person) {
        self.counters.add_device(device, person);
    }

    /// What `device` hasn't acknowledged and is meant for it, oldest first
    /// in each part: (number, who it's from, first received, the event).
    pub fn outgoing(
        &mut self,
        device: &Device,
        now: u64,
    ) -> Result<Vec<(u64, Sender, u64, SpaceEvent)>, HistoryError> {
        let version = self.version();
        let shares = |e: &Entry, n: u64, p: &Person| shares(version.as_ref(), e, n, p);
        let out = self.counters.to_send(device, &self.log, shares, now);
        let mut segments: HashMap<(Conversation, u32), Vec<Vec<u8>>> = HashMap::new();
        let mut sent = Vec::with_capacity(out.send.len());
        for number in out.send {
            let Some(&(chat, segment, position)) = self.places.get(number as usize - 1) else {
                continue;
            };
            if let std::collections::hash_map::Entry::Vacant(slot) = segments.entry((chat, segment))
            {
                slot.insert(self.store.open(&chat)?.read(segment)?);
            }
            let Some(record) = segments[&(chat, segment)].get(position as usize) else {
                continue;
            };
            let stored: Stored = read("a Space event", record)?;
            let from = Sender {
                person: stored.person,
                device: stored.device,
            };
            sent.push((
                number,
                from,
                stored.received,
                SpaceEvent::from_bytes(&stored.event)?,
            ));
        }
        Ok(sent)
    }

    /// `device` answered for event `number`.
    pub fn acked(&mut self, device: &Device, number: u64, ok: bool) {
        let version = self.version();
        let shares = |e: &Entry, n: u64, p: &Person| shares(version.as_ref(), e, n, p);
        self.counters.acked(device, number, ok, &self.log, shares);
    }

    /// Writes the counters (after a batch of acks).
    pub fn save_counters(&self) -> Result<(), HistoryError> {
        let bytes = framed(postcard::to_stdvec(&self.counters).expect("to memory"));
        Ok(self.log_files.write_index(&bytes)?)
    }

    /// Signs, stores and returns a new event of ours (dm D2's `seq` and `n`).
    pub fn send(
        &mut self,
        body: SpaceBody,
        device: &DeviceKey,
        cert: &DeviceCert,
        now: u64,
    ) -> Result<SpaceEvent, HistoryError> {
        let me = Sender {
            person: cert.root().to_bytes(),
            device: device.public().to_bytes(),
        };
        let (seq, n) = match &body {
            SpaceBody::Change(_) => {
                // dm D2 over the chain: one past the highest held that isn't
                // ahead of the clock, and past our own last.
                let held = self.chain.changes();
                let highest = held.iter().map(|c| c.3.0).filter(|s| *s <= now).max();
                let ours = (1..=self.log.len())
                    .filter_map(|i| self.log.get(i))
                    .filter(|e| e.change && e.from == me.device)
                    .count() as u64;
                let own_last = (held.iter())
                    .filter(|c| c.1 == me.person)
                    .map(|c| c.3.0)
                    .max();
                let seq = highest.max(own_last).map_or(now, |s| s + 1);
                (seq, ours + 1)
            }
            body => {
                let channel = channel_of(body).expect("not a change");
                self.load(&channel, now)?;
                let view = &self.channels[&channel].1;
                (view.next_seq(&me.device, now), view.next_n(&me.device))
            }
        };
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        let event = SpaceEvent::signed(self.space, id, (now, seq, n), body, device, cert);
        self.store(&event, me, now, now)?;
        Ok(event)
    }

    /// Channels read into memory so far.
    pub fn loaded(&self) -> usize {
        self.channels.len()
    }

    fn load(&mut self, channel: &ChannelId, now: u64) -> Result<(), HistoryError> {
        if self.channels.contains_key(channel) {
            return Ok(());
        }
        let key = channel_key(&self.space, channel);
        let mut files = self.store.open(&key)?;
        let mut view = Chat::new(self.me.person);
        view.set_moderators(self.moderators());
        for id in self.deleted.get(&key).into_iter().flatten() {
            view.was_deleted(*id);
        }
        if let Some(newest) = files.segments().checked_sub(1) {
            for record in files.read(newest)? {
                let stored: Stored = read("a Space event", &record)?;
                let event = SpaceEvent::from_bytes(&stored.event)?;
                let from = Sender {
                    person: stored.person,
                    device: stored.device,
                };
                if let Some(dm) = to_dm(&event) {
                    view.restore(from, dm, stored.received, now);
                }
            }
        }
        self.channels.insert(*channel, (files, view));
        Ok(())
    }
}

/// Every stored change into `chain`.
fn read_changes(files: &mut ChatFiles, chain: &mut Chain) -> Result<(), HistoryError> {
    for n in 0..files.segments() {
        for record in files.read(n)? {
            let stored: Stored = read("a Space change", &record)?;
            let event = SpaceEvent::from_bytes(&stored.event)?;
            if let SpaceBody::Change(change) = event.body {
                chain.add(event.id, stored.person, change, (event.seq, event.id));
            }
        }
    }
    Ok(())
}

/// The first byte of a Space body on the wire: the friend layout's and the
/// forwarded layout's next version, so an engine without Spaces answers
/// `failed` and the sender keeps it (PLAN-spaces *Mixed versions*).
pub const SPACE_LAYOUT: u8 = 2;

#[derive(Serialize, Deserialize)]
struct ToMember {
    /// First: `SPACE_LAYOUT`.
    version: u8,
    space: SpaceId,
    event: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ToOwn {
    /// First: `SPACE_LAYOUT`.
    version: u8,
    space: SpaceId,
    person: Person,
    device: Device,
    received: u64,
    event: Vec<u8>,
}

/// Whether `bytes` starts with this layout, a newer one, or neither.
fn layout(bytes: &[u8]) -> Result<(), Unread> {
    match bytes.first() {
        Some(&v) if v == SPACE_LAYOUT => Ok(()),
        Some(&v) if crate::history::is_newer(v, SPACE_LAYOUT) => Err(Unread::Newer),
        _ => Err(Unread::Garbage),
    }
}

fn event_from(bytes: &[u8]) -> Result<SpaceEvent, Unread> {
    if bytes
        .first()
        .is_some_and(|&v| crate::history::is_newer(v, crate::space::SPACE_VERSION))
    {
        return Err(Unread::Newer);
    }
    SpaceEvent::from_bytes(bytes).map_err(|_| Unread::Garbage)
}

/// The first byte of a batch of Space events in one envelope (S9), mail's
/// layout. Also "newer" to an engine without Spaces.
pub const SPACE_BATCH: u8 = 3;
/// A batch's bytes at most: under e2ee's 64 KiB envelope with room to spare.
pub const SPACE_BATCH_MAX: usize = 56 * 1024;

#[derive(Serialize, Deserialize)]
struct Batch {
    /// First: `SPACE_BATCH`.
    version: u8,
    events: Vec<(SpaceId, Vec<u8>)>,
}

/// Events for one reader device, in one body, as many as fit under
/// `SPACE_BATCH_MAX`: the body and how many went in (the rest wait).
pub fn to_batch(events: &[(SpaceId, &SpaceEvent)]) -> (Vec<u8>, usize) {
    let mut batch = Batch {
        version: SPACE_BATCH,
        events: Vec::new(),
    };
    let mut size = 8;
    for (space, event) in events {
        let bytes = event.to_bytes().expect("checked when stored");
        if size + bytes.len() + 24 > SPACE_BATCH_MAX && !batch.events.is_empty() {
            break;
        }
        size += bytes.len() + 24;
        batch.events.push((*space, bytes));
    }
    let n = batch.events.len();
    (postcard::to_stdvec(&batch).expect("to memory"), n)
}

/// A batch's events.
pub fn from_batch(bytes: &[u8]) -> Result<Vec<(SpaceId, SpaceEvent)>, Unread> {
    match bytes.first() {
        Some(&SPACE_BATCH) => {}
        Some(&v) if crate::history::is_newer(v, SPACE_BATCH) => return Err(Unread::Newer),
        _ => return Err(Unread::Garbage),
    }
    let batch: Batch = postcard::from_bytes(bytes).map_err(|_| Unread::Garbage)?;
    (batch.events.iter())
        .map(|(space, e)| Ok((*space, event_from(e)?)))
        .collect()
}

/// A Space event as it goes to a member's device.
pub fn to_member(space: &SpaceId, event: &SpaceEvent) -> Vec<u8> {
    let body = ToMember {
        version: SPACE_LAYOUT,
        space: *space,
        event: event.to_bytes().expect("checked when stored"),
    };
    postcard::to_stdvec(&body).expect("to memory")
}

/// A member's body: the Space and its event.
pub fn from_member(bytes: &[u8]) -> Result<(SpaceId, SpaceEvent), Unread> {
    layout(bytes)?;
    let body: ToMember = postcard::from_bytes(bytes).map_err(|_| Unread::Garbage)?;
    Ok((body.space, event_from(&body.event)?))
}

/// A Space event as it goes to another of our devices (dm D8): who it's
/// from and when it first arrived, so that device stores it as it is here.
pub fn to_own(space: &SpaceId, from: Sender, received: u64, event: &SpaceEvent) -> Vec<u8> {
    let body = ToOwn {
        version: SPACE_LAYOUT,
        space: *space,
        person: from.person,
        device: from.device,
        received,
        event: event.to_bytes().expect("checked when stored"),
    };
    postcard::to_stdvec(&body).expect("to memory")
}

/// A forwarded body from another of our devices.
pub fn from_own(bytes: &[u8]) -> Result<(SpaceId, Sender, u64, SpaceEvent), Unread> {
    layout(bytes)?;
    let body: ToOwn = postcard::from_bytes(bytes).map_err(|_| Unread::Garbage)?;
    let from = Sender {
        person: body.person,
        device: body.device,
    };
    Ok((body.space, from, body.received, event_from(&body.event)?))
}

/// Whether event `e` (number `n`) is for `p`: a change, for every member
/// and for whoever it concerns (an add, a removal); anything else, for the
/// members now.
fn shares(version: Option<&SpaceVersion>, e: &Entry, n: u64, p: &Person) -> bool {
    let _ = n;
    let Some(v) = version else { return false };
    v.state.members.contains_key(p)
        || (e.change && v.audience.get(&e.id).is_some_and(|who| who.contains(p)))
}

fn channel_of(body: &SpaceBody) -> Option<ChannelId> {
    match body {
        SpaceBody::Post { channel, .. }
        | SpaceBody::Edit { channel, .. }
        | SpaceBody::Delete { channel, .. }
        | SpaceBody::React { channel, .. }
        | SpaceBody::Read { channel, .. } => Some(*channel),
        SpaceBody::Change(_) => None,
    }
}

/// A channel event as dm's `Chat` folds it; `None` for a change.
fn to_dm(e: &SpaceEvent) -> Option<Event> {
    let body = match &e.body {
        SpaceBody::Post {
            text,
            reply_to,
            attachments,
            ..
        } => Body::Text {
            text: text.clone(),
            reply_to: *reply_to,
            attachments: attachments.clone(),
        },
        SpaceBody::Edit { target, text, .. } => Body::Edit {
            target: *target,
            text: text.clone(),
        },
        SpaceBody::Delete { target, .. } => Body::Delete {
            target: *target,
            everyone: true,
        },
        SpaceBody::React {
            target, emoji, on, ..
        } => Body::React {
            target: *target,
            emoji: emoji.clone(),
            on: *on,
        },
        SpaceBody::Read { up_to, .. } => Body::Read { up_to: *up_to },
        SpaceBody::Change(_) => return None,
    };
    Some(Event {
        version: VERSION,
        id: e.id,
        time: e.time,
        seq: e.seq,
        n: e.n,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::tests::Someone;
    use crate::space::{Change, SpaceChange, part_id, space_id};

    const KEY: [u8; 32] = [7; 32];
    const NOW: u64 = 1_800_000_000_000;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mesh-space-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn sender(who: &Someone) -> Sender {
        Sender {
            person: who.id(),
            device: who.device.public().to_bytes(),
        }
    }

    struct Made {
        o: Someone,
        space: SpaceId,
        general: ChannelId,
        events: Vec<SpaceEvent>,
    }

    /// O creates a Space with #general and posts twice: changes 1 to 2,
    /// posts 3 and 4.
    fn made() -> Made {
        let o = Someone::new();
        let nonce = [9; 16];
        let space = space_id(&o.id(), &nonce);
        let general = part_id(&space, &[1; 16]);
        let change = |after: Option<u8>, change| {
            SpaceBody::Change(SpaceChange {
                after: after.map(|a| [a; 16]),
                change,
            })
        };
        let create = Change::Create {
            name: "club".into(),
            nonce,
            display: "o".into(),
        };
        let channel = Change::ChannelCreate {
            nonce: [1; 16],
            name: "general".into(),
            category: None,
            admins_post: false,
        };
        let post = |text: &str| SpaceBody::Post {
            channel: general,
            text: text.into(),
            reply_to: None,
            attachments: vec![],
            mentions: vec![],
            everyone: false,
        };
        let events = vec![
            o.event(space, 1, NOW - 4, change(None, create)),
            o.event(space, 2, NOW - 3, change(Some(1), channel)),
            o.event(space, 3, NOW - 2, post("one")),
            o.event(space, 4, NOW - 1, post("two")),
        ];
        Made {
            o,
            space,
            general,
            events,
        }
    }

    #[test]
    fn a_space_round_trips_across_reopen() {
        let root = dir("round");
        let m = made();
        let me = sender(&m.o);
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        for e in &m.events {
            assert_eq!(h.store(e, me, NOW, NOW).unwrap(), Taken::Shown);
        }
        assert_eq!(
            h.store(&m.events[2], me, NOW, NOW).unwrap(),
            Taken::Duplicate
        );
        let version = h.version().unwrap();
        assert!(version.state.channels.contains_key(&m.general));
        let texts = |h: &mut SpaceHistory| -> Vec<String> {
            let chat = h.channel(&m.general, NOW).unwrap();
            chat.messages().iter().map(|m| m.text.to_owned()).collect()
        };
        assert_eq!(texts(&mut h), ["one", "two"]);
        drop(h);
        let mut back = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        assert_eq!(back.version(), Some(version));
        assert_eq!(back.log().len(), 4);
        assert_eq!(back.loaded(), 0, "no channel read at open");
        assert_eq!(texts(&mut back), ["one", "two"]);
        // As they came, signatures and all, for history.
        let served = back.events(Some(&m.general)).unwrap();
        assert_eq!(served, m.events[2..]);
        assert!(served.iter().all(|e| e.author().is_some()));
        assert_eq!(back.events(None).unwrap(), m.events[..2]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// S8: an admin deletes anyone's message, as the role in force says; a
    /// member deletes only their own.
    #[test]
    fn an_admin_deletes_anyones_message_a_member_only_their_own() {
        let root = dir("delete");
        let m = made();
        let (a, b) = (Someone::new(), Someone::new());
        let mut h = SpaceHistory::open(&root, &KEY, sender(&m.o), m.space).unwrap();
        for e in &m.events {
            h.store(e, sender(&m.o), NOW, NOW).unwrap();
        }
        let change = |after: u8, change| {
            SpaceBody::Change(SpaceChange {
                after: Some([after; 16]),
                change,
            })
        };
        let add = |who: &Someone| Change::Add {
            who: who.id(),
            display: "x".into(),
        };
        for e in [
            m.o.event(m.space, 5, NOW, change(2, add(&a))),
            m.o.event(m.space, 6, NOW + 1, change(5, add(&b))),
            m.o.event(m.space, 7, NOW + 2, change(6, Change::MakeAdmin(a.id()))),
        ] {
            h.store(&e, sender(&m.o), NOW, NOW).unwrap();
        }
        let delete = |who: &Someone, id: u8, target: u8| {
            let body = SpaceBody::Delete {
                channel: m.general,
                target: [target; 16],
            };
            who.event(m.space, id, NOW + 10, body)
        };
        let later = NOW + 10;
        h.store(&delete(&b, 20, 3), sender(&b), later, later)
            .unwrap();
        h.store(&delete(&a, 21, 4), sender(&a), later, later)
            .unwrap();
        let chat = h.channel(&m.general, later).unwrap();
        let texts: Vec<String> = chat.messages().iter().map(|m| m.text.to_owned()).collect();
        assert_eq!(
            texts,
            ["one"],
            "the admin's delete stands; the member's doesn't"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_chain_reads_without_the_log_or_channels() {
        let root = dir("chain");
        let m = made();
        let me = sender(&m.o);
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        for e in &m.events {
            h.store(e, me, NOW, NOW).unwrap();
        }
        let version = h.version();
        drop(h);
        // Take away the log and the channel: the chain still reads.
        let store = Store::new(&space_dir(&root, &KEY, &m.space), &KEY);
        let gone = [
            store.open_log().unwrap(),
            store.open(&channel_key(&m.space, &m.general)).unwrap(),
        ];
        for files in gone {
            std::fs::remove_dir_all(files.dir()).unwrap();
        }
        let chain = SpaceHistory::read_chain(&root, &KEY, &m.space).unwrap();
        assert_eq!(chain.version(&m.space), version);
        // A Space never stored here has an empty chain.
        let none = SpaceHistory::read_chain(&root, &KEY, &[3; 16]).unwrap();
        assert_eq!(none.version(&[3; 16]), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// History (S10) comes in batches, stored with one sync per file: the
    /// same result as one at a time, duplicates and all.
    #[test]
    fn a_batch_stores_as_one_at_a_time_would() {
        let root = dir("batch");
        let m = made();
        let me = sender(&m.o);
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        let mut batch: Vec<(SpaceEvent, Sender)> =
            m.events.iter().map(|e| (e.clone(), me)).collect();
        for i in 0..1000u64 {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            id[8] = 9;
            let post = SpaceBody::Post {
                channel: m.general,
                text: format!("old {i}"),
                reply_to: None,
                attachments: vec![],
                mentions: vec![],
                everyone: false,
            };
            let seq = NOW - 10_000 + i;
            let e = SpaceEvent::signed(
                m.space,
                id,
                (seq, seq, 100 + i),
                post,
                &m.o.device,
                &m.o.cert,
            );
            batch.push((e, me));
        }
        batch.push(batch[5].clone());
        let taken = h.store_batch(batch, NOW, NOW).unwrap();
        assert_eq!(taken.len(), 1005);
        assert_eq!(taken.iter().filter(|t| **t == Taken::Shown).count(), 1004);
        assert_eq!(
            taken[1004],
            Taken::Duplicate,
            "the same event twice in one batch"
        );
        drop(h);
        let mut back = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        assert_eq!(back.log().len(), 1004);
        assert!(
            back.version()
                .unwrap()
                .state
                .channels
                .contains_key(&m.general)
        );
        assert_eq!(back.events(Some(&m.general)).unwrap().len(), 1002);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_deleted_channel_leaves_the_space() {
        let root = dir("deleted");
        let m = made();
        let me = sender(&m.o);
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        for e in &m.events {
            h.store(e, me, NOW, NOW).unwrap();
        }
        let delete = SpaceBody::Change(SpaceChange {
            after: Some([2; 16]),
            change: Change::ChannelDelete(m.general),
        });
        h.store(&m.o.event(m.space, 5, NOW, delete), me, NOW, NOW)
            .unwrap();
        drop(h);
        let back = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        assert!(back.version().unwrap().state.channels.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// dm D5's counters over a Space: our own events and every change go to
    /// each member's device until it acknowledges them; nothing goes to a
    /// non-member; our own other devices get everything; counters survive.
    #[test]
    fn delivery_follows_the_members() {
        let root = dir("deliver");
        let m = made();
        let me = sender(&m.o);
        let bob = Someone::new();
        let stranger = Someone::new();
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        for e in &m.events[..2] {
            h.store(e, me, NOW, NOW).unwrap();
        }
        let add = SpaceBody::Change(SpaceChange {
            after: Some([2; 16]),
            change: Change::Add {
                who: bob.id(),
                display: "bob".into(),
            },
        });
        h.send(add, &m.o.device, &m.o.cert, NOW).unwrap();
        let post = |text: &str| SpaceBody::Post {
            channel: m.general,
            text: text.into(),
            reply_to: None,
            attachments: vec![],
            mentions: vec![],
            everyone: false,
        };
        let sent = h
            .send(post("hi bob"), &m.o.device, &m.o.cert, NOW + 1)
            .unwrap();
        assert_eq!(sent.author().map(|a| a.person), Some(m.o.id()));
        let later = h
            .send(post("again"), &m.o.device, &m.o.cert, NOW + 1)
            .unwrap();
        assert!((later.seq, later.n) > (sent.seq, sent.n), "dm D2's order");
        // Bob's device: the three changes (he joined after two of them) and
        // both posts.
        let b_dev = bob.device.public().to_bytes();
        h.add_device(b_dev, bob.id());
        let out = h.outgoing(&b_dev, NOW + 2).unwrap();
        assert_eq!(
            out.len(),
            5,
            "{:?}",
            out.iter().map(|o| o.3.id).collect::<Vec<_>>()
        );
        // A stranger's device gets nothing.
        let s_dev = stranger.device.public().to_bytes();
        h.add_device(s_dev, stranger.id());
        assert!(h.outgoing(&s_dev, NOW + 2).unwrap().is_empty());
        // Acknowledged, they don't go again, even after a reopen.
        for (number, ..) in &out {
            h.acked(&b_dev, *number, true);
        }
        h.save_counters().unwrap();
        drop(h);
        let mut back = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        back.add_device(b_dev, bob.id());
        assert!(back.outgoing(&b_dev, NOW + 3).unwrap().is_empty());
        // Our own other device gets all five, our own included.
        let mine = Someone::with_root(mesh_identity::RootKey::from_secret_bytes(
            *m.o.root.secret_bytes(),
        ));
        let my_dev = mine.device.public().to_bytes();
        back.add_device(my_dev, m.o.id());
        assert_eq!(back.outgoing(&my_dev, NOW + 3).unwrap().len(), 5);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_wire_layouts_round_trip_and_read_as_newer_to_dm() {
        let m = made();
        let from = sender(&m.o);
        let e = &m.events[2];
        let body = to_member(&m.space, e);
        assert_eq!(body[0], SPACE_LAYOUT);
        assert_eq!(from_member(&body).unwrap(), (m.space, e.clone()));
        let own = to_own(&m.space, from, NOW, e);
        assert_eq!(from_own(&own).unwrap(), (m.space, from, NOW, e.clone()));
        // An engine without Spaces reads either as "newer": `failed`, kept.
        assert_eq!(
            crate::history::from_friend(&body).err(),
            Some(Unread::Newer)
        );
        assert_eq!(crate::history::unforward(&own).err(), Some(Unread::Newer));
        assert_eq!(from_member(b"junk").err(), Some(Unread::Garbage));
        // A batch for mail (S9), which an engine without Spaces also reads
        // as newer.
        let refs: Vec<(SpaceId, &SpaceEvent)> = m.events.iter().map(|e| (m.space, e)).collect();
        let (batch, n) = to_batch(&refs);
        assert_eq!(n, 4);
        let back: Vec<SpaceEvent> = from_batch(&batch)
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .collect();
        assert_eq!(back, m.events);
        assert_eq!(
            crate::history::from_friend(&batch).err(),
            Some(Unread::Newer)
        );
    }

    #[test]
    fn the_list_is_all_unlock_reads() {
        let root = dir("list");
        let mut list = SpaceList::open(&root, &KEY).unwrap();
        assert!(list.spaces().is_empty());
        list.add([1; 16]).unwrap();
        list.add([2; 16]).unwrap();
        list.add([1; 16]).unwrap();
        list.remove(&[2; 16]).unwrap();
        let back = SpaceList::open(&root, &KEY).unwrap();
        assert_eq!(back.spaces(), [[1; 16]]);
        // Another data key reads nothing of it.
        assert!(
            SpaceList::open(&root, &[8; 32])
                .unwrap()
                .spaces()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Test 10's pure half: unlock reads the list, not a Space's 100,000
    /// events; the Space's own first use pays for them. On real disk
    /// (target/), since /tmp is memory here.
    #[test]
    #[ignore = "a measurement: cargo test -p mesh-dm space_store -- --ignored --nocapture"]
    fn unlock_with_a_big_space() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/space-measure");
        let _ = std::fs::remove_dir_all(&root);
        let m = made();
        let me = sender(&m.o);
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        for e in &m.events[..2] {
            h.store(e, me, NOW, NOW).unwrap();
        }
        let started = std::time::Instant::now();
        for i in 0..100_000u64 {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            id[8] = 1;
            let post = SpaceBody::Post {
                channel: m.general,
                text: format!("line {i}"),
                reply_to: None,
                attachments: vec![],
                mentions: vec![],
                everyone: false,
            };
            let seq = NOW - 200_000 + i;
            let e =
                SpaceEvent::signed(m.space, id, (seq, seq, i + 1), post, &m.o.device, &m.o.cert);
            h.store(&e, me, NOW, NOW).unwrap();
        }
        eprintln!("stored 100,000 in {:?}", started.elapsed());
        drop(h);
        let mut list = SpaceList::open(&root, &KEY).unwrap();
        list.add(m.space).unwrap();
        let empty = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/space-measure-empty");
        let _ = std::fs::remove_dir_all(&empty);
        SpaceList::open(&empty, &KEY).unwrap().add([3; 16]).unwrap();
        for (what, at) in [
            ("with a 100,000-event Space", &root),
            ("with an empty one", &empty),
        ] {
            let t = std::time::Instant::now();
            let list = SpaceList::open(at, &KEY).unwrap();
            eprintln!(
                "unlock {what}: {:?} ({} Space)",
                t.elapsed(),
                list.spaces().len()
            );
        }
        let t = std::time::Instant::now();
        let mut h = SpaceHistory::open(&root, &KEY, me, m.space).unwrap();
        let opened = t.elapsed();
        let t = std::time::Instant::now();
        let shown = h.channel(&m.general, NOW).unwrap().messages().len();
        eprintln!(
            "first use: log and changes {opened:?}, then #general's newest segment {:?} ({shown} shown)",
            t.elapsed()
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
