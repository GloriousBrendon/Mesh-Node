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
use crate::history::HistoryError;
use crate::space::{Chain, ChannelId, SpaceBody, SpaceEvent, SpaceId, SpaceVersion};
use crate::store::{ChatFiles, Conversation, Store, StoreError};
use crate::sync::{Entry, Log};
use crate::{Device, Person, Sender};

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
}

#[derive(Serialize, Deserialize)]
enum SpaceLog {
    Stored(Entry),
    Deleted { chat: Conversation, id: EventId },
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
        };
        for n in 0..history.log_files.segments() {
            for record in history.log_files.read(n)? {
                match read("a Space log record", &record)? {
                    SpaceLog::Stored(entry) => {
                        history.log.take(entry);
                    }
                    SpaceLog::Deleted { chat, id } => {
                        history.deleted.entry(chat).or_default().insert(id);
                    }
                }
            }
        }
        for n in 0..history.change_files.segments() {
            for record in history.change_files.read(n)? {
                let stored: Stored = read("a Space change", &record)?;
                let event = SpaceEvent::from_bytes(&stored.event)?;
                if let SpaceBody::Change(change) = event.body {
                    let at = (event.seq, event.id);
                    history.chain.add(event.id, stored.person, change, at);
                }
            }
        }
        Ok(history)
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
        if self.log.number_of(&event.id).is_some() {
            return Ok(Taken::Duplicate);
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
                self.change_files.append(&[stored])?;
                (CHANGES, true, false)
            }
            body => {
                let channel = channel_of(body).expect("not a change");
                let dm = to_dm(event).expect("not a change");
                self.load(&channel, now)?;
                let (files, view) = self.channels.get_mut(&channel).expect("loaded");
                let taken = view.take_received(from, dm, now, received);
                if !matches!(taken, Taken::Shown | Taken::Waiting) {
                    return Ok(taken);
                }
                files.append(&[stored])?;
                let private = matches!(body, SpaceBody::Read { .. });
                (channel_key(&self.space, &channel), false, private)
            }
        };
        let entry = Entry {
            id: event.id,
            chat,
            author: from.person,
            from: from.device,
            at: received,
            private,
            change,
        };
        self.log.take(entry.clone());
        let record = framed(postcard::to_stdvec(&SpaceLog::Stored(entry)).expect("to memory"));
        self.log_files.append(&[record])?;
        Ok(Taken::Shown)
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
