//! One device's whole dm history on disk (PLAN-dm *Saving and loading*):
//! the chats' sealed segments, the log that numbers every stored event and
//! remembers deletions, and the per-device counters. Storing an event
//! appends; nothing that grows with history is rewritten for it.
//!
//! - A chat record is `received u64 | sender person [32] | sender device
//!   [32] | event`, so a reopened chat shows the same times and knows who
//!   sent what. A wiped record becomes empty, keeping every position.
//! - The log is a stream of its own, where no conversation ID reaches
//!   (`Store::open_log`): one record
//!   per stored event (its number's entry and where it's kept) or per
//!   deleted message. It's read whole at open: that's the set of every event
//!   held, which refuses late copies, and the deletions, which refuse late
//!   edits of messages deleted long ago.
//! - The counters live in the reserved stream's index, rewritten after each
//!   batch of acks; their size depends on devices, not history.
//! - A chat's index keeps its read marker and each sending device's highest
//!   `n` and `seq`, so a chat opened from its newest segment alone still
//!   checks "late and low" and "out of step" (D2).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::chat::{Chat, Position, Refusal, Taken};
use crate::event::{Body, Change, Event, EventError, EventId, GroupChange, VERSION};
use crate::group::Group;
use crate::store::{ChatFiles, Conversation, Store, StoreError};
use crate::sync::{Counters, Entry, Log, Outgoing};
use crate::{Device, Person, Sender, Where};

const RECORD_HEAD: usize = 8 + 32 + 32;

#[derive(Serialize, Deserialize)]
enum LogRecord {
    Stored {
        entry: Entry,
        segment: u32,
        position: u32,
    },
    Deleted {
        chat: Conversation,
        id: EventId,
    },
    /// A chat, logged before its first event is written, so an open can
    /// find events a crash left in it without a number.
    Chat {
        chat: Conversation,
        at: Where,
    },
}

#[derive(Serialize, Deserialize, Default)]
struct ChatIndex {
    read: Option<Position>,
    highs: Vec<(Device, u64, u64)>,
    /// A group's changes: its state, whichever segment holds them.
    group: Vec<(EventId, Person, GroupChange, Position)>,
}

/// Events from one sender that may wait for groups' creations, across all
/// groups (D7).
pub const MAX_BEFORE_CREATION: usize = 100;
/// Days an event may wait for its group's creation before it's wiped.
pub const WAIT_FOR_CREATION_DAYS: u64 = 7;
const DAY_MS: u64 = 24 * 3600 * 1000;

/// Signs group changes with this person's ID key (`RootKey::sign_bytes`
/// under `GROUP_SIGNATURE`): History holds no keys itself.
pub type Signer = Box<dyn Fn(&[u8]) -> [u8; 64] + Send>;

/// The number every saved format starts with: chat records, log records, a
/// chat's index, the counters. A higher one is from a newer Mesh.
pub const SAVED_FORMAT: u8 = 1;

/// `bytes` as saved: the format number first.
fn framed(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.insert(0, SAVED_FORMAT);
    bytes
}

/// What's after the format number of a saved `what`; a newer format is
/// refused as that, not as damage.
fn unframe<'a>(what: &'static str, bytes: &'a [u8]) -> Result<&'a [u8], HistoryError> {
    match bytes.split_first() {
        Some((&SAVED_FORMAT, rest)) => Ok(rest),
        Some((&v, _)) if v > SAVED_FORMAT => Err(HistoryError::Newer(what)),
        _ => Err(StoreError::Damaged.into()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("the {0} was written by a newer version of Mesh; update Mesh to read it")]
    Newer(&'static str),
    #[error("group changes can't be signed here")]
    NoSigner,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Event(#[from] EventError),
}

struct Open {
    files: ChatFiles,
    chat: Chat,
    /// Segments read into `chat`.
    loaded: HashSet<u32>,
}

pub struct History {
    store: Store,
    me: Sender,
    log: Log,
    log_files: ChatFiles,
    /// Where each stored event is kept, by number (from 1): segment and
    /// position. Its chat is in the log's entry.
    places: Vec<(u32, u32)>,
    deleted: HashMap<Conversation, HashSet<EventId>>,
    /// Every chat with events, and which chat each storage key is.
    known: HashMap<Conversation, Where>,
    /// Each group chat's members in its current version; none before its
    /// creation has arrived.
    members: HashMap<Conversation, BTreeMap<Person, EventId>>,
    /// Who each group change goes to (group.rs `audience`).
    audience: HashMap<Conversation, BTreeMap<EventId, BTreeSet<Person>>>,
    /// Events each sender has waiting for a group's creation.
    // ponytail: in memory, so a restart lets a sender start over at MAX_BEFORE_CREATION.
    before_creation: HashMap<(Conversation, Person), usize>,
    counters: Counters,
    chats: HashMap<Conversation, Open>,
    signer: Option<Signer>,
}

/// A message as a page shows it (dmOpen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub id: EventId,
    pub author: Person,
    pub text: String,
    pub edited: bool,
    pub reply_to: Option<EventId>,
    pub attachments: Vec<crate::event::Attachment>,
    /// Each emoji and who reacted with it.
    pub reactions: Vec<(String, Vec<Person>)>,
    /// Arrived at or below the read marker: unread (D2).
    pub late: bool,
    /// The time to show, in milliseconds (D2's clamp).
    pub time: u64,
}

/// An event to send a device, with its number for the ack.
pub struct ToSend {
    pub number: u64,
    /// Which chat, as e2ee names it.
    pub at: Where,
    /// Who wrote it, and when it first arrived here.
    pub from: Sender,
    pub received: u64,
    pub event: Event,
}

/// An event as it goes to another of our devices (D8): which chat, who wrote
/// it and when it first arrived, so that device stores it as it is here.
#[derive(Serialize, Deserialize)]
struct Forward {
    /// First, so a newer layout is told apart from garbage.
    version: u8,
    at: Where,
    person: Person,
    device: Device,
    received: u64,
    event: Vec<u8>,
}

/// The body that carries `t` to another of our devices.
pub fn forward(t: &ToSend) -> Vec<u8> {
    let forward = Forward {
        version: FORWARD_VERSION,
        at: t.at,
        person: t.from.person,
        device: t.from.device,
        received: t.received,
        event: t.event.to_bytes().expect("checked when stored"),
    };
    postcard::to_stdvec(&forward).expect("to memory")
}

/// What a friend's device gets: the event, and its group if it's in one.
/// Group DMs go over the 1:1 sessions (e2ee D6), so the group is named here.
#[derive(Serialize, Deserialize)]
struct Friend {
    /// First, so a newer layout is told apart from garbage.
    version: u8,
    group: Option<[u8; 16]>,
    event: Vec<u8>,
}

/// The friend layout's version.
pub const FRIEND_VERSION: u8 = 1;

/// The body that carries `event` in chat `at` to a friend's device.
pub fn to_friend(at: &Where, event: &Event) -> Vec<u8> {
    let group = match at {
        Where::Group(id) => Some(*id),
        Where::Direct(_) => None,
    };
    let friend = Friend {
        version: FRIEND_VERSION,
        group,
        event: event.to_bytes().expect("checked when stored"),
    };
    postcard::to_stdvec(&friend).expect("to memory")
}

/// A friend's body: the group, if it's a group's, and the event.
pub fn from_friend(bytes: &[u8]) -> Result<(Option<[u8; 16]>, Event), Unread> {
    match bytes.first() {
        Some(&v) if is_newer(v, FRIEND_VERSION) => return Err(Unread::Newer),
        Some(&v) if v == FRIEND_VERSION => {}
        _ => return Err(Unread::Garbage),
    }
    let f: Friend = postcard::from_bytes(bytes).map_err(|_| Unread::Garbage)?;
    if f.event.first().is_some_and(|&v| is_newer(v, VERSION)) {
        return Err(Unread::Newer);
    }
    let event = Event::from_bytes(&f.event).map_err(|_| Unread::Garbage)?;
    Ok((f.group, event))
}

/// The forwarded layout's version.
pub const FORWARD_VERSION: u8 = 1;
/// How far above ours a version byte may be and still mean "newer", not
/// garbage. A `failed` answer keeps the sender resending, so a damaged body
/// whose first byte is anything must not get one.
pub const NEWER_WITHIN: u8 = 8;

/// Whether a first byte reads as a newer version of `ours`.
pub fn is_newer(byte: u8, ours: u8) -> bool {
    byte > ours && byte <= ours.saturating_add(NEWER_WITHIN)
}

/// Why a body didn't read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    /// From a newer version of Mesh: the sender should keep it for us.
    Newer,
    /// Damaged or not ours: dropped.
    Garbage,
}

/// A forwarded body: the chat, the author, the first arrival, the event.
pub fn unforward(bytes: &[u8]) -> Result<(Where, Sender, u64, Event), Unread> {
    match bytes.first() {
        Some(&v) if is_newer(v, FORWARD_VERSION) => return Err(Unread::Newer),
        Some(&v) if v == FORWARD_VERSION => {}
        _ => return Err(Unread::Garbage),
    }
    let f: Forward = postcard::from_bytes(bytes).map_err(|_| Unread::Garbage)?;
    if f.event.first().is_some_and(|&v| is_newer(v, VERSION)) {
        return Err(Unread::Newer);
    }
    let event = Event::from_bytes(&f.event).map_err(|_| Unread::Garbage)?;
    let from = Sender {
        person: f.person,
        device: f.device,
    };
    Ok((f.at, from, f.received, event))
}

impl History {
    /// Opens the history under `root` for this device, reading the log.
    pub fn open(root: &Path, data_key: &[u8; 32], me: Sender) -> Result<Self, HistoryError> {
        let store = Store::new(root, data_key);
        let mut history = Self {
            me,
            log: Log::default(),
            places: Vec::new(),
            deleted: HashMap::new(),
            known: HashMap::new(),
            members: HashMap::new(),
            audience: HashMap::new(),
            before_creation: HashMap::new(),
            counters: Counters::new(me.person),
            signer: None,
            chats: HashMap::new(),
            log_files: store.open_log()?,
            store,
        };
        for n in 0..history.log_files.segments() {
            for record in history.log_files.read(n)? {
                let record = postcard::from_bytes::<LogRecord>(unframe("a log record", &record)?)
                    .map_err(|_| StoreError::Damaged)?;
                history.remember(record);
            }
        }
        if let Some(bytes) = history.log_files.index()? {
            let bytes = unframe("the delivery counters", &bytes)?;
            history.counters = postcard::from_bytes(bytes).map_err(|_| StoreError::Damaged)?;
        }
        history.number_the_missed()?;
        history.load_members()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        history.sweep_waiting(now)?;
        Ok(history)
    }

    /// Wipes events that have waited WAIT_FOR_CREATION_DAYS for their
    /// group's creation. Run at open, and by the caller now and then.
    pub fn sweep_waiting(&mut self, now: u64) -> Result<(), HistoryError> {
        let waiting: Vec<Conversation> = (self.known.iter())
            .filter(|(key, at)| matches!(at, Where::Group(_)) && !self.members.contains_key(*key))
            .map(|(key, _)| *key)
            .collect();
        let before = now.saturating_sub(WAIT_FOR_CREATION_DAYS * DAY_MS);
        for chat in waiting {
            self.load(&chat, now)?;
            let open = self.chats.get_mut(&chat).expect("loaded");
            open.chat.wipe_received_by(before);
            self.wipe(&chat)?;
        }
        Ok(())
    }

    /// Each group chat's members, from its index alone, so delivery and the
    /// list know them before any chat is opened.
    fn load_members(&mut self) -> Result<(), HistoryError> {
        let groups: Vec<(Conversation, [u8; 16])> = (self.known.iter())
            .filter_map(|(key, at)| match at {
                Where::Group(id) => Some((*key, *id)),
                Where::Direct(_) => None,
            })
            .collect();
        for (key, id) in groups {
            let Some(bytes) = self.store.open(&key)?.index()? else {
                continue;
            };
            let bytes = unframe("a chat index", &bytes)?;
            let index: ChatIndex = postcard::from_bytes(bytes).map_err(|_| StoreError::Damaged)?;
            let mut group = Group::default();
            for (event, by, change, at) in index.group {
                group.add(event, by, change, at);
            }
            if let Some(version) = group.version(&id) {
                self.members.insert(key, version.joined);
                self.audience.insert(key, version.audience);
            }
        }
        Ok(())
    }

    /// Events a crash left in a chat with no number (the chat file is
    /// written before the log) get one now, so they're still delivered.
    // ponytail: reads every chat's newest segment at unlock; fine for hundreds of chats, keep a "last written" mark if unlock grows slow.
    fn number_the_missed(&mut self) -> Result<(), HistoryError> {
        let chats: Vec<Conversation> = self.known.keys().copied().collect();
        let mut missed = Vec::new();
        for chat in chats {
            let mut files = self.store.open(&chat)?;
            // From the newest segment back, until one has nothing missing:
            // a batch can cross into a new segment (next_places).
            for segment in (0..files.segments()).rev() {
                let before = missed.len();
                self.missed_in(&mut files, chat, segment, &mut missed)?;
                if missed.len() == before {
                    break;
                }
            }
        }
        self.log(missed)
    }

    /// The events in one segment with no number, as log records.
    fn missed_in(
        &self,
        files: &mut ChatFiles,
        chat: Conversation,
        segment: u32,
        missed: &mut Vec<LogRecord>,
    ) -> Result<(), HistoryError> {
        for (position, record) in files.read(segment)?.iter().enumerate() {
            let Some((received, from, event)) = decode(record)? else {
                continue;
            };
            if self.log.number_of(&event.id).is_some() {
                continue;
            }
            let entry = Entry {
                id: event.id,
                chat,
                author: from.person,
                from: from.device,
                at: received,
                private: private(&event.body),
                change: matches!(event.body, Body::Group(_)),
            };
            let position = u32::try_from(position).map_err(|_| StoreError::Damaged)?;
            missed.push(LogRecord::Stored {
                entry,
                segment,
                position,
            });
        }
        Ok(())
    }

    /// Where event `number` is kept: its chat, segment and position.
    fn place(&self, number: u64) -> Option<(Conversation, u32, u32)> {
        let chat = self.log.get(number)?.chat;
        let (segment, position) = *self
            .places
            .get(usize::try_from(number.checked_sub(1)?).ok()?)?;
        Some((chat, segment, position))
    }

    /// Appends records to the log (one sync), then takes them in.
    fn log(&mut self, records: Vec<LogRecord>) -> Result<(), HistoryError> {
        if records.is_empty() {
            return Ok(());
        }
        let bytes: Vec<Vec<u8>> = records
            .iter()
            .map(|r| framed(postcard::to_stdvec(r).expect("to memory")))
            .collect();
        self.log_files.append(&bytes)?;
        for record in records {
            self.remember(record);
        }
        Ok(())
    }

    /// Takes in one log record, read back or just written.
    fn remember(&mut self, record: LogRecord) {
        match record {
            LogRecord::Stored {
                entry,
                segment,
                position,
            } => {
                if self.log.take(entry).is_some() {
                    self.places.push((segment, position));
                }
            }
            LogRecord::Deleted { chat, id } => {
                self.deleted.entry(chat).or_default().insert(id);
            }
            LogRecord::Chat { chat, at } => {
                self.known.insert(chat, at);
            }
        }
    }

    /// Loads a chat from its index and newest segment, once.
    fn load(&mut self, conversation: &Conversation, now: u64) -> Result<(), HistoryError> {
        if self.chats.contains_key(conversation) {
            return Ok(());
        }
        let files = self.store.open(conversation)?;
        let mut chat = Chat::new(self.me.person);
        if let Some(bytes) = files.index()? {
            let bytes = unframe("a chat index", &bytes)?;
            let index: ChatIndex = postcard::from_bytes(bytes).map_err(|_| StoreError::Damaged)?;
            if let Some(read) = index.read {
                chat.set_read_marker(read);
            }
            for (device, n, seq) in index.highs {
                chat.know_high(device, n, seq);
            }
            for (event, by, change, at) in index.group {
                chat.restore_group_change(event, by, change, at);
            }
        }
        for id in self.deleted.get(conversation).into_iter().flatten() {
            chat.was_deleted(*id);
        }
        let newest = files.segments().checked_sub(1);
        let open = Open {
            files,
            chat,
            loaded: HashSet::new(),
        };
        self.chats.insert(*conversation, open);
        if let Some(newest) = newest {
            self.load_segment(conversation, newest, now)?;
        }
        Ok(())
    }

    /// Reads one segment of a loaded chat into it.
    fn load_segment(
        &mut self,
        conversation: &Conversation,
        n: u32,
        now: u64,
    ) -> Result<(), HistoryError> {
        let open = self.chats.get_mut(conversation).expect("loaded");
        if !open.loaded.insert(n) {
            return Ok(());
        }
        for record in open.files.read(n)? {
            if let Some((received, from, event)) = decode(&record)? {
                open.chat.restore(from, event, received, now);
            }
        }
        // What restoring wipes or deletes was dealt with when it first came.
        open.chat.take_scrub();
        open.chat.take_deleted();
        Ok(())
    }

    /// A chat, loaded from its newest segment if it isn't yet.
    pub fn chat(&mut self, at: &Where, now: u64) -> Result<&Chat, HistoryError> {
        let chat = at.key();
        self.load(&chat, now)?;
        Ok(&self.chats[&chat].chat)
    }

    /// Makes, stores and returns this device's next event in `chat`.
    /// How group changes are signed (D7).
    pub fn set_signer(&mut self, signer: Signer) {
        self.signer = Some(signer);
    }

    pub fn send(&mut self, at: &Where, body: Body, now: u64) -> Result<Event, HistoryError> {
        let chat = &at.key();
        self.load(chat, now)?;
        let open = &self.chats[chat];
        let device = self.me.device;
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        let event = Event {
            version: VERSION,
            id,
            time: now,
            seq: open.chat.next_seq(&device, now),
            n: open.chat.next_n(&device),
            body,
        };
        let mut event = event;
        if let (Where::Group(group), Body::Group(_)) = (at, &event.body) {
            let signer = self.signer.as_ref().ok_or(HistoryError::NoSigner)?;
            let bytes = crate::event::group_signed_bytes(group, &event, &self.me.person, &device)
                .expect("a group change");
            let signature = signer(&bytes).to_vec();
            if let Body::Group(change) = &mut event.body {
                change.signed = Some(crate::event::Signed {
                    author: self.me.person,
                    device,
                    signature,
                });
            }
        }
        event.to_bytes()?;
        self.receive(at, self.me, vec![event.clone()], now)?;
        Ok(event)
    }

    /// Takes in events from `from` for `chat`, storing what's kept with one
    /// sync per batch. An error means nothing in the batch is acknowledged.
    pub fn receive(
        &mut self,
        at: &Where,
        from: Sender,
        events: Vec<Event>,
        now: u64,
    ) -> Result<Vec<Taken>, HistoryError> {
        let events = events.into_iter().map(|e| (now, e)).collect();
        self.receive_synced(at, from, from.device, events, now)
    }

    /// Events another of our devices passed on (`via`), each with the time
    /// it first arrived there; `from` wrote them.
    pub fn receive_synced(
        &mut self,
        at: &Where,
        from: Sender,
        via: Device,
        events: Vec<(u64, Event)>,
        now: u64,
    ) -> Result<Vec<Taken>, HistoryError> {
        // A 1:1 chat takes events only from that person and our own devices.
        if let Where::Direct(peer) = at
            && from.person != *peer
            && from.person != self.me.person
        {
            return Ok(vec![Taken::Refused(Refusal::NotInChat); events.len()]);
        }
        let chat = &at.key();
        self.load(chat, now)?;
        let group = match at {
            Where::Group(id) => Some(*id),
            Where::Direct(_) => None,
        };
        let created_before = group
            .and_then(|id| self.chats[chat].chat.group(&id))
            .is_some();
        let mut taken = Vec::with_capacity(events.len());
        let mut kept = Vec::new();
        for (received, event) in events {
            if self.log.number_of(&event.id).is_some() {
                taken.push(Taken::Duplicate);
                continue;
            }
            // A group change counts as its signed author's, whoever passed it
            // on (D7); one that isn't signed by its author is refused, and a
            // 1:1 chat has no changes.
            let author = match (group, &event.body) {
                (Some(id), Body::Group(_)) => match crate::event::group_author(&id, &event) {
                    Some(author) => author,
                    None => {
                        taken.push(Taken::Refused(Refusal::BadSignature));
                        continue;
                    }
                },
                (None, Body::Group(_)) => {
                    taken.push(Taken::Refused(Refusal::NotInChat));
                    continue;
                }
                _ => from,
            };
            if let Some(id) = group
                && let Some(refused) = self.group_refuses(chat, &id, &author, &event)
            {
                taken.push(Taken::Refused(refused));
                continue;
            }
            // An edit, delete or reaction of an old message: read its segment
            // first, so it folds in (or is refused) now.
            if let Some(target) = target(&event.body)
                && let Some((c, segment, _)) =
                    self.log.number_of(&target).and_then(|n| self.place(n))
                && c == *chat
            {
                self.load_segment(chat, segment, now)?;
            }
            let open = self.chats.get_mut(chat).expect("loaded");
            let t = open
                .chat
                .take_received(author, event.clone(), now, received);
            if matches!(t, Taken::Shown | Taken::Waiting) {
                kept.push((received, author, event));
            }
            taken.push(t);
        }
        if !kept.is_empty() && !self.known.contains_key(chat) {
            self.log(vec![LogRecord::Chat {
                chat: *chat,
                at: *at,
            }])?;
        }
        self.store_kept(chat, via, kept)?;
        if let Some(id) = group {
            let open = self.chats.get_mut(chat).expect("loaded");
            match open.chat.group(&id) {
                Some(version) => {
                    // Created just now: what waited is checked (D7), and no
                    // longer counts as waiting.
                    if !created_before {
                        open.chat.wipe_senders_not_in(&version.members);
                        self.before_creation.retain(|(c, _), _| c != chat);
                    }
                    self.members.insert(*chat, version.joined);
                    self.audience.insert(*chat, version.audience);
                }
                None => {
                    self.members.remove(chat);
                }
            }
        }
        self.wipe(chat)?;
        let open = &self.chats[chat];
        let index = ChatIndex {
            read: open.chat.read_marker(),
            highs: open.chat.highs(),
            group: open.chat.group_changes(),
        };
        open.files
            .write_index(&framed(postcard::to_stdvec(&index).expect("to memory")))?;
        Ok(taken)
    }

    /// Why a group event doesn't count (D7), if it doesn't: a creation that
    /// doesn't hash to the group's ID from its sender; once created, a
    /// sender who isn't a member of the current version; before, one with
    /// too many events already waiting.
    fn group_refuses(
        &mut self,
        chat: &Conversation,
        id: &[u8; 16],
        from: &Sender,
        event: &Event,
    ) -> Option<Refusal> {
        if let Body::Group(GroupChange {
            after: None,
            change: Change::Create { nonce, .. },
            ..
        }) = &event.body
        {
            return (crate::group_id(&from.person, nonce) != *id).then_some(Refusal::NotInChat);
        }
        match self.chats[chat].chat.group(id) {
            Some(version) if version.members.contains(&from.person) => None,
            // Was a member once, and left or was removed: for good. Never
            // one: their add may not have reached us yet.
            Some(version) if version.audience.values().any(|a| a.contains(&from.person)) => {
                Some(Refusal::NotInChat)
            }
            Some(_) => Some(Refusal::NotYetMember),
            None => {
                // Across all groups: one sender can't fill many of them.
                let waiting: usize = (self.before_creation.iter())
                    .filter(|((_, person), _)| *person == from.person)
                    .map(|(_, n)| n)
                    .sum();
                if waiting >= MAX_BEFORE_CREATION {
                    return Some(Refusal::TooManyWaiting);
                }
                *self
                    .before_creation
                    .entry((*chat, from.person))
                    .or_default() += 1;
                None
            }
        }
    }

    /// Appends kept events to the chat and the log: one sync each.
    fn store_kept(
        &mut self,
        chat: &Conversation,
        via: Device,
        kept: Vec<(u64, Sender, Event)>,
    ) -> Result<(), HistoryError> {
        if kept.is_empty() {
            return Ok(());
        }
        let open = self.chats.get_mut(chat).expect("loaded");
        let places = open.files.next_places(kept.len());
        let mut records = Vec::with_capacity(kept.len());
        for (received, from, event) in &kept {
            records.push(encode(*received, *from, event)?);
        }
        open.files.append(&records)?;
        let newest = open.files.segments() - 1;
        open.loaded.insert(newest);
        let mut records = Vec::with_capacity(kept.len());
        for ((received, from, event), (segment, position)) in kept.iter().zip(places) {
            let entry = Entry {
                id: event.id,
                chat: *chat,
                author: from.person,
                from: via,
                at: *received,
                private: private(&event.body),
                change: matches!(event.body, Body::Group(_)),
            };
            records.push(LogRecord::Stored {
                entry,
                segment,
                position,
            });
        }
        self.log(records)?;
        Ok(())
    }

    /// Wipes what the chat says to (D3), and logs its deletions.
    fn wipe(&mut self, chat: &Conversation) -> Result<(), HistoryError> {
        let scrub = self.chats.get_mut(chat).expect("loaded").chat.take_scrub();
        let mut by_segment: HashMap<u32, HashSet<u32>> = HashMap::new();
        for id in scrub {
            if let Some((_, segment, position)) =
                self.log.number_of(&id).and_then(|n| self.place(n))
            {
                by_segment.entry(segment).or_default().insert(position);
            }
        }
        let open = self.chats.get_mut(chat).expect("loaded");
        for (segment, positions) in by_segment {
            let mut at = 0u32;
            open.files.rewrite(segment, |record| {
                let keep = if positions.contains(&at) {
                    Vec::new()
                } else {
                    record
                };
                at += 1;
                Some(keep)
            })?;
        }
        let deleted = open.chat.take_deleted();
        if deleted.is_empty() {
            return Ok(());
        }
        let records = deleted
            .into_iter()
            .map(|id| LogRecord::Deleted { chat: *chat, id });
        self.log(records.collect())?;
        Ok(())
    }

    /// A device we send to (counters, D5).
    pub fn add_device(&mut self, device: Device, person: Person) {
        self.counters.add_device(device, person);
    }

    /// What `device` gets next, read back from disk.
    pub fn outgoing(&mut self, device: &Device, now: u64) -> Result<Vec<ToSend>, HistoryError> {
        let (known, members, log) = (&self.known, (&self.members, &self.audience), &self.log);
        let shares = |e: &Entry, n: u64, p: &Person| in_chat(known, members, log, e, n, p);
        let Outgoing { send, .. } = self.counters.to_send(device, &self.log, shares, now);
        let mut segments: HashMap<(Conversation, u32), Vec<Vec<u8>>> = HashMap::new();
        let mut out = Vec::with_capacity(send.len());
        for number in send {
            let Some((chat, segment, position)) = self.place(number) else {
                continue;
            };
            if let std::collections::hash_map::Entry::Vacant(slot) = segments.entry((chat, segment))
            {
                let records = match self.chats.get_mut(&chat) {
                    Some(open) => open.files.read(segment)?,
                    None => self.store.open(&chat)?.read(segment)?,
                };
                slot.insert(records);
            }
            let record = segments[&(chat, segment)].get(position as usize);
            match record.map(|r| decode(r)).transpose()?.flatten() {
                Some((received, from, event)) => {
                    let Some(at) = self.known.get(&chat).copied() else {
                        continue;
                    };
                    out.push(ToSend {
                        number,
                        at,
                        from,
                        received,
                        event,
                    });
                }
                // Wiped since: there's nothing to send, so it counts as taken.
                None => {
                    let (known, members, log) =
                        (&self.known, (&self.members, &self.audience), &self.log);
                    let shares =
                        |e: &Entry, n: u64, p: &Person| in_chat(known, members, log, e, n, p);
                    self.counters.acked(device, number, true, &self.log, shares)
                }
            }
        }
        Ok(out)
    }

    /// The device answered for event `number`.
    pub fn acked(&mut self, device: &Device, number: u64, ok: bool) {
        let (known, members, log) = (&self.known, (&self.members, &self.audience), &self.log);
        let shares = |e: &Entry, n: u64, p: &Person| in_chat(known, members, log, e, n, p);
        self.counters.acked(device, number, ok, &self.log, shares);
    }

    /// Writes the counters (after a batch of acks).
    pub fn save_counters(&self) -> Result<(), HistoryError> {
        let bytes = framed(postcard::to_stdvec(&self.counters).expect("to memory"));
        Ok(self.log_files.write_index(&bytes)?)
    }

    pub fn counter(&self, device: &Device) -> Option<u64> {
        self.counters.counter(device)
    }

    /// Every chat with events.
    pub fn chats(&self) -> Vec<Where> {
        let listed = self.known.iter().filter(|(key, at)| match at {
            Where::Direct(_) => true,
            // A group isn't listed before its creation has arrived (D7).
            Where::Group(_) => self.members.contains_key(*key),
        });
        listed.map(|(_, at)| *at).collect()
    }

    /// The chat an event is in.
    pub fn where_of(&self, id: &EventId) -> Option<Where> {
        let chat = self.log.get(self.log.number_of(id)?)?.chat;
        self.known.get(&chat).copied()
    }

    /// A group's members in its current version; `None` before its
    /// creation has arrived, or for a 1:1 chat.
    pub fn members(&self, at: &Where) -> Option<Vec<Person>> {
        let joined = self.members.get(&at.key())?;
        Some(joined.keys().copied().collect())
    }

    /// A group's current version (name, creator, head), from its chat.
    pub fn group(
        &mut self,
        at: &Where,
        now: u64,
    ) -> Result<Option<crate::group::Version>, HistoryError> {
        let Where::Group(id) = at else {
            return Ok(None);
        };
        Ok(self.chat(at, now)?.group(id))
    }

    /// A stored event, read back from its segment; `None` if it isn't here
    /// or was wiped.
    pub fn event(&mut self, id: &EventId) -> Result<Option<Event>, HistoryError> {
        let Some((chat, segment, position)) = self.log.number_of(id).and_then(|n| self.place(n))
        else {
            return Ok(None);
        };
        let records = match self.chats.get_mut(&chat) {
            Some(open) => open.files.read(segment)?,
            None => self.store.open(&chat)?.read(segment)?,
        };
        let Some(record) = records.get(position as usize) else {
            return Ok(None);
        };
        Ok(decode(record)?.map(|(_, _, event)| event))
    }

    /// Who wrote a stored event, from its log entry: no chat is loaded.
    pub fn author_of(&self, id: &EventId) -> Option<Person> {
        Some(self.log.get(self.log.number_of(id)?)?.author)
    }

    /// Whether one of the other person's devices has taken our event (D5).
    pub fn is_sent(&self, id: &EventId) -> bool {
        let (known, members, log) = (&self.known, (&self.members, &self.audience), &self.log);
        let shares = |e: &Entry, n: u64, p: &Person| in_chat(known, members, log, e, n, p);
        self.log
            .number_of(id)
            .is_some_and(|n| self.counters.taken_by_others(n, &self.log, shares))
    }

    /// Up to `count` messages before `before` (or the newest), oldest first,
    /// reading older segments as needed; and whether there are older ones.
    pub fn page(
        &mut self,
        at: &Where,
        before: Option<EventId>,
        count: usize,
        now: u64,
    ) -> Result<(Vec<Shown>, bool), HistoryError> {
        let chat = at.key();
        self.load(&chat, now)?;
        if let Where::Group(_) = at
            && !self.members.contains_key(&chat)
        {
            return Ok((Vec::new(), false));
        }
        loop {
            let open = &self.chats[&chat];
            let messages = open.chat.messages();
            let end = match before {
                Some(id) => messages.iter().position(|m| m.id == id).unwrap_or(0),
                None => messages.len(),
            };
            let oldest_loaded = open.loaded.iter().min().copied();
            let older = oldest_loaded.and_then(|n| n.checked_sub(1));
            if end >= count || older.is_none() {
                let start = end.saturating_sub(count);
                let page = messages[start..end]
                    .iter()
                    .map(|m| Shown {
                        id: m.id,
                        author: m.author,
                        text: m.text.to_owned(),
                        edited: m.edited,
                        reply_to: m.reply_to,
                        attachments: m.attachments.to_vec(),
                        reactions: (m.reactions.iter())
                            .map(|(e, who)| (e.to_string(), who.clone()))
                            .collect(),
                        late: m.late,
                        time: open.chat.display_time(&m.id).unwrap_or(0),
                    })
                    .collect();
                return Ok((page, start > 0 || older.is_some()));
            }
            self.load_segment(&chat, older.expect("checked"), now)?;
        }
    }
}

/// Whether event `n` (`e`) is for `person`: the person of a 1:1; in a
/// group, a member of its current version, for its changes always and for
/// the rest from the change they joined at on.
/// A group's members with their join points, and who each change goes to.
type Groups<'a> = (
    &'a HashMap<Conversation, BTreeMap<Person, EventId>>,
    &'a HashMap<Conversation, BTreeMap<EventId, BTreeSet<Person>>>,
);

fn in_chat(
    known: &HashMap<Conversation, Where>,
    (members, audience): Groups<'_>,
    log: &Log,
    e: &Entry,
    n: u64,
    person: &Person,
) -> bool {
    match known.get(&e.chat) {
        Some(Where::Direct(p)) => p == person,
        // A change goes to who it concerns, the person removed included.
        Some(Where::Group(_)) if e.change => {
            let concerns = audience.get(&e.chat).and_then(|a| a.get(&e.id));
            concerns.is_some_and(|a| a.contains(person))
                || members.get(&e.chat).is_some_and(|m| m.contains_key(person))
        }
        Some(Where::Group(_)) => {
            let Some(joined) = members.get(&e.chat).and_then(|m| m.get(person)) else {
                return false;
            };
            log.number_of(joined).is_none_or(|from| n >= from)
        }
        None => false,
    }
}

/// For our own devices only: "read up to here" and "delete for me" (D3, D9).
fn private(body: &Body) -> bool {
    matches!(
        body,
        Body::Read { .. }
            | Body::Delete {
                everyone: false,
                ..
            }
    )
}

/// What an edit, delete or reaction points at.
fn target(body: &Body) -> Option<EventId> {
    match body {
        Body::Edit { target, .. } | Body::Delete { target, .. } | Body::React { target, .. } => {
            Some(*target)
        }
        _ => None,
    }
}

/// A chat record: `received | sender person | sender device | event`.
fn encode(received: u64, from: Sender, event: &Event) -> Result<Vec<u8>, HistoryError> {
    let mut record = vec![SAVED_FORMAT];
    record.extend_from_slice(&received.to_be_bytes());
    record.extend_from_slice(&from.person);
    record.extend_from_slice(&from.device);
    record.extend(event.to_bytes()?);
    Ok(record)
}

/// A record read back; `None` for one wiped by a delete.
fn decode(record: &[u8]) -> Result<Option<(u64, Sender, Event)>, HistoryError> {
    if record.is_empty() {
        return Ok(None);
    }
    let record = unframe("a chat record", record)?;
    if record.len() < RECORD_HEAD {
        return Err(StoreError::Damaged.into());
    }
    let received = u64::from_be_bytes(record[..8].try_into().expect("8 bytes"));
    let from = Sender {
        person: record[8..40].try_into().expect("32 bytes"),
        device: record[40..72].try_into().expect("32 bytes"),
    };
    let event = Event::from_bytes(&record[RECORD_HEAD..]).map_err(|_| StoreError::Damaged)?;
    Ok(Some((received, from, event)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::Refusal;
    use crate::store::SEGMENT_EVENTS;
    use std::path::PathBuf;

    const NOW: u64 = 1_800_000_000_000;
    const KEY: [u8; 32] = [7; 32];
    const CHAT: Where = Where::Direct([2; 32]);
    const ME: Sender = Sender {
        person: [1; 32],
        device: [10; 32],
    };
    const BOB: Sender = Sender {
        person: [2; 32],
        device: [20; 32],
    };
    const CAROL: Sender = Sender {
        person: [4; 32],
        device: [40; 32],
    };

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-history-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn text(words: &str) -> Body {
        Body::Text {
            text: words.into(),
            reply_to: None,
            attachments: vec![],
        }
    }

    fn texts(h: &mut History) -> Vec<String> {
        let chat = h.chat(&CHAT, NOW).unwrap();
        chat.messages().iter().map(|m| m.text.to_owned()).collect()
    }

    /// Bob's event as his device would make it.
    fn bobs(id: u8, seq: u64, n: u64, body: Body) -> Event {
        Event {
            version: VERSION,
            id: [id; 16],
            time: NOW + 3_600_000,
            seq,
            n,
            body,
        }
    }

    #[test]
    fn a_reopened_chat_has_the_same_messages_and_times() {
        let root = dir("reopen");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        h.send(&CHAT, text("hi"), NOW).unwrap();
        // Bob's clock is an hour ahead: shown at its arrival time.
        let taken = h
            .receive(&CHAT, BOB, vec![bobs(1, NOW + 1, 1, text("yo"))], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Shown]);
        let time = h.chat(&CHAT, NOW).unwrap().display_time(&[1; 16]);
        assert_eq!(time, Some(NOW));
        drop(h);
        let mut again = History::open(&root, &KEY, ME).unwrap();
        assert_eq!(texts(&mut again), ["hi", "yo"]);
        let chat = again.chat(&CHAT, NOW + 10).unwrap();
        assert_eq!(
            chat.display_time(&[1; 16]),
            Some(NOW),
            "the same time after reopening"
        );
        // Our next event comes after both, and a repeat of Bob's is a duplicate.
        let next = again.send(&CHAT, text("again"), NOW + 10).unwrap();
        assert!(next.seq > NOW + 1 && next.n == 2);
        let taken = again
            .receive(&CHAT, BOB, vec![bobs(1, NOW + 1, 1, text("yo"))], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Duplicate]);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Deleted before the reopen: a late copy, and a late edit, are refused
    /// and never written, though the message's segment isn't loaded.
    #[test]
    fn a_message_deleted_long_ago_stays_deleted() {
        let root = dir("deleted");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        h.receive(&CHAT, BOB, vec![bobs(1, NOW - 100, 1, text("oops"))], NOW)
            .unwrap();
        // Fill a segment so the message's own isn't the newest.
        for i in 0..SEGMENT_EVENTS {
            h.send(&CHAT, text(&format!("filler {i}")), NOW).unwrap();
        }
        let delete = Body::Delete {
            target: [1; 16],
            everyone: true,
        };
        h.receive(&CHAT, BOB, vec![bobs(2, NOW + 1, 2, delete)], NOW)
            .unwrap();
        drop(h);
        let mut again = History::open(&root, &KEY, ME).unwrap();
        assert!(!texts(&mut again).contains(&"oops".to_owned()));
        let late_copy = bobs(1, NOW - 100, 1, text("oops"));
        let late_edit = bobs(
            3,
            NOW + 2,
            3,
            Body::Edit {
                target: [1; 16],
                text: "still oops".into(),
            },
        );
        let taken = again
            .receive(&CHAT, BOB, vec![late_copy, late_edit], NOW + 5)
            .unwrap();
        assert_eq!(taken, [Taken::Duplicate, Taken::Ignored]);
        // Nothing of it is on disk, even sealed and read back.
        let mut files = Store::new(&root, &KEY).open(&CHAT.key()).unwrap();
        for n in 0..files.segments() {
            for record in files.read(n).unwrap() {
                assert!(!record.windows(4).any(|w| w == b"oops"), "{n}");
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// A 1:1 chat takes events only from that person and our own devices.
    #[test]
    fn a_one_to_one_chat_takes_only_that_person_and_us() {
        let root = dir("one-to-one");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let taken = h
            .receive(&CHAT, CAROL, vec![bobs(1, NOW, 1, text("not Bob"))], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::NotInChat)]);
        let laptop = Sender {
            device: [11; 32],
            ..ME
        };
        let taken = h
            .receive(&CHAT, laptop, vec![bobs(2, NOW, 1, text("mine"))], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Shown]);
        drop(h);
        assert_eq!(
            texts(&mut History::open(&root, &KEY, ME).unwrap()),
            ["mine"]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// No group ID reaches the log, or a 1:1 chat: not the log's old
    /// reserved ID, and not the storage key of my chat with Bob.
    #[test]
    fn a_group_id_reaches_neither_the_log_nor_a_one_to_one_chat() {
        let root = dir("group-ids");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        h.receive(&CHAT, BOB, vec![bobs(1, NOW, 1, text("from Bob"))], NOW)
            .unwrap();
        for id in [[0xFF; 16], CHAT.key()] {
            let intruder = bobs(id[0], NOW, 1, text("intruder"));
            let taken = h
                .receive(&Where::Group(id), CAROL, vec![intruder], NOW)
                .unwrap();
            assert_eq!(taken, [Taken::Shown], "its own group chat");
        }
        drop(h);
        // The log still opens, and Bob's chat has only Bob's message.
        let mut again = History::open(&root, &KEY, ME).unwrap();
        assert_eq!(texts(&mut again), ["from Bob"]);
        let mut files = Store::new(&root, &KEY).open(&CHAT.key()).unwrap();
        assert_eq!(files.read(0).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A crash after the chat file was written but before the log: the
    /// event is in the chat with no number. At the next open it gets one,
    /// so it's still delivered, not just shown.
    #[test]
    fn an_event_the_log_missed_gets_a_number_at_open() {
        let root = dir("missed");
        let laptop: Device = [11; 32];
        let mut h = History::open(&root, &KEY, ME).unwrap();
        h.add_device(laptop, ME.person);
        h.send(&CHAT, text("logged"), NOW).unwrap();
        h.save_counters().unwrap();
        drop(h);
        // What the crash left: the record in the chat, none in the log.
        let missed = Event {
            version: VERSION,
            id: [9; 16],
            time: NOW,
            seq: NOW,
            n: 2,
            body: text("unlogged"),
        };
        let mut files = Store::new(&root, &KEY).open(&CHAT.key()).unwrap();
        files.append(&[encode(NOW, ME, &missed).unwrap()]).unwrap();
        let mut again = History::open(&root, &KEY, ME).unwrap();
        let out = again.outgoing(&laptop, NOW).unwrap();
        let sent: Vec<Body> = out.into_iter().map(|t| t.event.body).collect();
        assert_eq!(sent, [text("logged"), text("unlogged")]);
        // Numbered once: a third open finds nothing missing.
        drop(again);
        let mut third = History::open(&root, &KEY, ME).unwrap();
        assert_eq!(third.outgoing(&laptop, NOW).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Own-device sync (D8): the desk's history reaches the laptop as it is,
    /// authors and times kept, and nothing goes back where it came from.
    #[test]
    fn history_syncs_to_our_own_device() {
        let (desk_dir, laptop_dir) = (dir("sync-desk"), dir("sync-laptop"));
        let laptop_me = Sender {
            device: [11; 32],
            ..ME
        };
        let mut desk = History::open(&desk_dir, &KEY, ME).unwrap();
        let mut laptop = History::open(&laptop_dir, &KEY, laptop_me).unwrap();
        desk.send(&CHAT, text("from the desk"), NOW).unwrap();
        desk.receive(&CHAT, BOB, vec![bobs(1, NOW + 1, 1, text("from Bob"))], NOW)
            .unwrap();
        desk.add_device(laptop_me.device, ME.person);
        let out = desk.outgoing(&laptop_me.device, NOW + 60_000).unwrap();
        assert_eq!(out.len(), 2);
        for t in &out {
            let (at, author, received, event) = unforward(&forward(t)).unwrap();
            let taken = laptop
                .receive_synced(
                    &at,
                    author,
                    ME.device,
                    vec![(received, event)],
                    NOW + 60_000,
                )
                .unwrap();
            assert_eq!(taken, [Taken::Shown]);
        }
        assert_eq!(texts(&mut laptop), ["from the desk", "from Bob"]);
        let chat = laptop.chat(&CHAT, NOW + 60_000).unwrap();
        assert_eq!(
            chat.display_time(&[1; 16]),
            Some(NOW),
            "the desk's arrival time"
        );
        // The laptop sends none of it back to the desk.
        laptop.add_device(ME.device, ME.person);
        assert!(laptop.outgoing(&ME.device, NOW).unwrap().is_empty());
        for d in [desk_dir, laptop_dir] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// "Read up to here" and "delete for me" go only to our own devices.
    #[test]
    fn private_events_go_to_our_devices_only() {
        let root = dir("private");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let said = h.send(&CHAT, text("hi"), NOW).unwrap();
        let gone = h.send(&CHAT, text("gone"), NOW).unwrap();
        h.send(&CHAT, Body::Read { up_to: said.id }, NOW).unwrap();
        // Deleted for me: wiped here, so there's nothing of it to send.
        let only_me = Body::Delete {
            target: gone.id,
            everyone: false,
        };
        h.send(&CHAT, only_me, NOW).unwrap();
        h.add_device(BOB.device, BOB.person);
        h.add_device([11; 32], ME.person);
        assert_eq!(
            h.outgoing(&BOB.device, NOW).unwrap().len(),
            1,
            "the message only"
        );
        assert_eq!(h.outgoing(&[11; 32], NOW).unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Pages of a long chat (dmOpen): the newest first, older ones read
    /// from disk as they're asked for.
    #[test]
    fn pages_go_back_through_the_segments() {
        let root = dir("pages");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        for i in 0..SEGMENT_EVENTS + 10 {
            h.send(&CHAT, text(&format!("m{i}")), NOW).unwrap();
        }
        drop(h);
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let (page, more) = h.page(&CHAT, None, 50, NOW).unwrap();
        let last = format!("m{}", SEGMENT_EVENTS + 9);
        assert_eq!(
            (page.len(), page.last().unwrap().text.as_str(), more),
            (50, last.as_str(), true)
        );
        // Before the newest segment's first: read from the one before it.
        let mut before = page[0].id;
        let mut seen = 50;
        loop {
            let (older, more) = h.page(&CHAT, Some(before), 50, NOW).unwrap();
            seen += older.len();
            if !more {
                assert_eq!(older[0].text, "m0");
                break;
            }
            before = older[0].id;
        }
        assert_eq!(seen, SEGMENT_EVENTS + 10);
        assert_eq!(h.chats(), [CHAT]);
        assert_eq!(h.where_of(&page[0].id), Some(CHAT));
        let _ = std::fs::remove_dir_all(root);
    }

    /// "Sent" once one of the other person's devices took it (D5).
    #[test]
    fn sent_once_their_device_took_it() {
        let root = dir("sent");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let said = h.send(&CHAT, text("hi"), NOW).unwrap();
        h.add_device(BOB.device, BOB.person);
        h.add_device([11; 32], ME.person);
        assert!(!h.is_sent(&said.id));
        let number = h.outgoing(&[11; 32], NOW).unwrap()[0].number;
        h.acked(&[11; 32], number, true);
        assert!(!h.is_sent(&said.id), "our own laptop doesn't count");
        h.acked(&BOB.device, number, true);
        assert!(h.is_sent(&said.id));
        let _ = std::fs::remove_dir_all(root);
    }

    /// "Sent" with two friends: Bob taking his message says nothing about
    /// Carol's, though Bob's counter moves past it (it wasn't for him).
    #[test]
    fn sent_counts_only_people_in_that_chat() {
        let root = dir("sent-two");
        let carol_chat = Where::Direct(CAROL.person);
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let to_carol = h.send(&carol_chat, text("Carol?"), NOW).unwrap();
        let to_bob = h.send(&CHAT, text("Bob?"), NOW).unwrap();
        h.add_device(BOB.device, BOB.person);
        h.add_device(CAROL.device, CAROL.person);
        let out = h.outgoing(&BOB.device, NOW).unwrap();
        assert_eq!(out.len(), 1, "Bob gets only his");
        h.acked(&BOB.device, out[0].number, true);
        assert!(h.is_sent(&to_bob.id));
        assert!(!h.is_sent(&to_carol.id), "Carol is offline");
        let _ = std::fs::remove_dir_all(root);
    }

    /// The batch a crash cut short crossed into a new segment: the events
    /// at the end of the one before it get numbers too.
    #[test]
    fn missed_events_across_a_segment_boundary_get_numbers() {
        let root = dir("missed-across");
        let laptop: Device = [11; 32];
        let mut h = History::open(&root, &KEY, ME).unwrap();
        for i in 0..SEGMENT_EVENTS - 2 {
            h.send(&CHAT, text(&format!("logged {i}")), NOW).unwrap();
        }
        drop(h);
        // Four unlogged: two finish segment 0, two start segment 1.
        let missed: Vec<Vec<u8>> = (0..4u8)
            .map(|i| {
                let event = Event {
                    version: VERSION,
                    id: [200 + i; 16],
                    time: NOW,
                    seq: NOW + u64::from(i),
                    n: SEGMENT_EVENTS as u64 + u64::from(i),
                    body: text(&format!("unlogged {i}")),
                };
                encode(NOW, ME, &event).unwrap()
            })
            .collect();
        let mut files = Store::new(&root, &KEY).open(&CHAT.key()).unwrap();
        files.append(&missed).unwrap();
        assert_eq!(files.segments(), 2);
        let mut again = History::open(&root, &KEY, ME).unwrap();
        again.add_device(laptop, ME.person);
        let out = again.outgoing(&laptop, NOW).unwrap();
        assert_eq!(out.len(), SEGMENT_EVENTS + 2, "all of them");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A forwarded record or event from a newer version is told apart from
    /// garbage, so the reader can keep it waiting on the sender.
    #[test]
    fn newer_forwards_are_not_garbage() {
        let event = bobs(1, NOW, 1, text("hi"));
        let t = ToSend {
            number: 1,
            at: CHAT,
            from: BOB,
            received: NOW,
            event: event.clone(),
        };
        let bytes = forward(&t);
        assert!(matches!(unforward(&bytes), Ok((_, _, _, e)) if e == event));
        let mut newer = bytes.clone();
        newer[0] = FORWARD_VERSION + 1;
        assert_eq!(unforward(&newer).err(), Some(Unread::Newer));
        let mut newer_event = event.clone();
        newer_event.version = VERSION + 1;
        let inner = Forward {
            version: FORWARD_VERSION,
            at: CHAT,
            person: BOB.person,
            device: BOB.device,
            received: NOW,
            event: postcard::to_stdvec(&newer_event).unwrap(),
        };
        let inner = postcard::to_stdvec(&inner).unwrap();
        assert_eq!(unforward(&inner).err(), Some(Unread::Newer));
        assert_eq!(unforward(b"junk").err(), Some(Unread::Garbage));
    }

    /// Group DMs go over 1:1 sessions, so dm checks membership: an event
    /// counts only if its sender is a member of the current version (D7).
    #[test]
    fn group_events_count_only_from_members() {
        let (mut me, mut bob, carol) = (
            Member::new("gm-me"),
            Member::new("gm-bob"),
            Member::new("gm-carol"),
        );
        let group = make_group(&mut me, &[&bob]);
        me.pass_to(&mut bob);
        bob.history.send(&group, text("in"), NOW).unwrap();
        assert_eq!(bob.pass_to(&mut me), [Taken::Shown]);
        // Carol isn't in it.
        let out = bobs(2, NOW + 2, 1, text("out"));
        let taken = me
            .history
            .receive(&group, carol.me, vec![out], NOW)
            .unwrap();
        assert_eq!(
            taken,
            [Taken::Refused(Refusal::NotYetMember)],
            "never a member: maybe not yet"
        );
        // A creation, properly signed by Carol, that doesn't hash to the
        // group's ID from her: she can't make herself its creator.
        let Where::Group(id) = group else {
            unreachable!()
        };
        let mut fake = Event {
            version: VERSION,
            id: [55; 16],
            time: NOW,
            seq: NOW + 3,
            n: 1,
            body: Body::Group(crate::event::GroupChange {
                after: None,
                change: crate::event::Change::Create {
                    name: "mine".into(),
                    members: vec![],
                    nonce: [1; 16],
                },
                signed: None,
            }),
        };
        let bytes =
            crate::event::group_signed_bytes(&id, &fake, &carol.me.person, &carol.me.device)
                .unwrap();
        let signature = carol
            .root
            .sign_bytes(crate::event::GROUP_SIGNATURE, &bytes)
            .to_vec();
        if let Body::Group(change) = &mut fake.body {
            change.signed = Some(crate::event::Signed {
                author: carol.me.person,
                device: carol.me.device,
                signature,
            });
        }
        let taken = me
            .history
            .receive(&group, carol.me, vec![fake], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::NotInChat)]);
        assert_eq!(me.history.chats(), [group]);
    }

    /// Before its creation arrives a group's events wait: not shown, no chat
    /// listed, at most MAX_BEFORE_CREATION per sender. When it comes, the
    /// members' events show and anyone else's are wiped.
    #[test]
    fn before_its_creation_a_group_waits() {
        let (mut me, mut bob, mut carol) = (
            Member::new("w-me"),
            Member::new("w-bob"),
            Member::new("w-carol"),
        );
        let group = make_group(&mut carol, &[&me, &bob]);
        carol.pass_to(&mut bob);
        let early = bob.history.send(&group, text("early"), NOW).unwrap();
        // Bob's message reaches me before the creation does.
        assert_eq!(
            me.history
                .receive(&group, bob.me, vec![early], NOW)
                .unwrap(),
            [Taken::Shown]
        );
        let stranger = Sender {
            person: [9; 32],
            device: [90; 32],
        };
        for i in 0..MAX_BEFORE_CREATION as u64 {
            let mut e = bobs(0, NOW + 10 + i, i + 1, text("spam"));
            e.id[..8].copy_from_slice(&i.to_be_bytes());
            e.id[8] = 0xEE;
            me.history.receive(&group, stranger, vec![e], NOW).unwrap();
        }
        let over = bobs(250, NOW + 5000, 5000, text("one more"));
        let taken = me
            .history
            .receive(&group, stranger, vec![over], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::TooManyWaiting)]);
        assert!(
            me.history.chats().is_empty(),
            "not listed before its creation"
        );
        assert!(me.history.page(&group, None, 50, NOW).unwrap().0.is_empty());
        carol.pass_to(&mut me);
        let (page, _) = me.history.page(&group, None, 50, NOW).unwrap();
        let texts: Vec<&str> = page.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, ["early"], "Bob's waited; the stranger's are gone");
        assert_eq!(me.history.chats(), [group]);
    }

    /// Someone added to a group gets its messages from their add on, not the
    /// ones before; its changes they get all of, to know who's in it.
    #[test]
    fn a_new_member_gets_events_from_their_add() {
        let (mut me, mut bob, mut carol) = (
            Member::new("j-me"),
            Member::new("j-bob"),
            Member::new("j-carol"),
        );
        let group = make_group(&mut me, &[&bob]);
        me.history.send(&group, text("before Carol"), NOW).unwrap();
        me.change(&group, crate::event::Change::Add(carol.me.person));
        me.history.send(&group, text("with Carol"), NOW).unwrap();
        me.history.add_device(carol.me.device, carol.me.person);
        me.history.add_device(bob.me.device, bob.me.person);
        let to_carol = me.history.outgoing(&carol.me.device, NOW).unwrap();
        let carol_got: Vec<Body> = to_carol.into_iter().map(|t| t.event.body).collect();
        assert_eq!(
            carol_got.len(),
            3,
            "the creation, her add, then the message"
        );
        assert!(!carol_got.contains(&text("before Carol")));
        assert_eq!(carol_got[2], text("with Carol"));
        assert_eq!(me.history.outgoing(&bob.me.device, NOW).unwrap().len(), 4);
        let _ = (&mut bob, &mut carol);
    }

    /// The removal reaches the person removed, though they're no longer a
    /// member; later messages don't.
    #[test]
    fn a_removal_reaches_the_removed() {
        let (mut me, bob, mut carol) = (
            Member::new("r-me"),
            Member::new("r-bob"),
            Member::new("r-carol"),
        );
        let group = make_group(&mut me, &[&bob, &carol]);
        me.pass_to(&mut carol);
        me.change(&group, crate::event::Change::Remove(carol.me.person));
        me.history.send(&group, text("just us"), NOW).unwrap();
        me.pass_to(&mut carol);
        let seen = carol.version(&group).unwrap();
        assert!(!seen.members.contains(&carol.me.person), "she learned");
        let (page, _) = carol.history.page(&group, None, 50, NOW).unwrap();
        assert!(page.iter().all(|m| m.text != "just us"));
    }

    /// The group's state comes back with the chat, though its creation is
    /// in a segment the reopened chat doesn't read.
    #[test]
    fn a_group_survives_a_reopen() {
        let (mut me, bob) = (Member::new("s-me"), Member::new("s-bob"));
        let group = make_group(&mut me, &[&bob]);
        for i in 0..SEGMENT_EVENTS {
            me.history
                .send(&group, text(&format!("m{i}")), NOW)
                .unwrap();
        }
        me.history = History::open(&me.dir, &KEY, me.me).unwrap();
        assert_eq!(
            me.history.chats(),
            [group],
            "listed before any chat is opened"
        );
        let from_bob = Event {
            version: VERSION,
            id: [1; 16],
            time: NOW,
            seq: NOW + 999,
            n: 1,
            body: text("still in"),
        };
        assert_eq!(
            me.history
                .receive(&group, bob.me, vec![from_bob], NOW)
                .unwrap(),
            [Taken::Shown]
        );
    }

    /// A person with an ID key and one device, and their history.
    struct Member {
        root: mesh_identity::RootKey,
        me: Sender,
        history: History,
        dir: PathBuf,
    }

    impl Member {
        fn new(name: &str) -> Self {
            let root = mesh_identity::RootKey::generate().unwrap();
            let me = Sender {
                person: root.id().to_bytes(),
                device: mesh_identity::DeviceKey::generate()
                    .unwrap()
                    .public()
                    .to_bytes(),
            };
            let dir = dir(&format!("relay-{name}"));
            let mut history = History::open(&dir, &KEY, me).unwrap();
            let signer = mesh_identity::RootKey::from_secret_bytes(*root.secret_bytes());
            history.set_signer(Box::new(move |bytes| {
                signer.sign_bytes(crate::event::GROUP_SIGNATURE, bytes)
            }));
            Self {
                root,
                me,
                history,
                dir,
            }
        }

        fn head(&mut self, group: &Where) -> EventId {
            self.history.group(group, NOW).unwrap().unwrap().head
        }

        fn change(&mut self, group: &Where, change: crate::event::Change) {
            let after = Some(self.head(group));
            let body = Body::Group(crate::event::GroupChange {
                after,
                change,
                signed: None,
            });
            self.history.send(group, body, NOW).unwrap();
        }

        /// Everything of ours that's meant for `to`, passed to them.
        fn pass_to(&mut self, to: &mut Member) -> Vec<Taken> {
            self.history.add_device(to.me.device, to.me.person);
            let out = self.history.outgoing(&to.me.device, NOW).unwrap();
            let mut taken = Vec::new();
            for t in out {
                let got = to
                    .history
                    .receive(&t.at, self.me, vec![t.event], NOW)
                    .unwrap();
                self.history.acked(&to.me.device, t.number, true);
                taken.extend(got);
            }
            taken
        }

        fn version(&mut self, group: &Where) -> Option<crate::group::Version> {
            self.history.group(group, NOW).unwrap()
        }
    }

    impl Drop for Member {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn make_group(creator: &mut Member, members: &[&Member]) -> Where {
        let ids: Vec<Person> = members.iter().map(|m| m.me.person).collect();
        let (nonce, id) = crate::new_group(&creator.me.person).unwrap();
        let change = crate::event::Change::Create {
            name: "hike".into(),
            members: ids,
            nonce,
        };
        let body = Body::Group(crate::event::GroupChange {
            after: None,
            change,
            signed: None,
        });
        let group = Where::Group(id);
        creator.history.send(&group, body, NOW).unwrap();
        group
    }

    /// The creator makes a group with A and B and goes away for good; B
    /// adds D. D, hearing only from A and B, sees the group with the right
    /// members, and can chat (D7, changes passed on by members).
    #[test]
    fn a_new_member_joins_while_the_creator_is_away() {
        let (mut c, mut a, mut b, mut d) = (
            Member::new("c"),
            Member::new("a"),
            Member::new("b"),
            Member::new("d"),
        );
        let group = make_group(&mut c, &[&a, &b]);
        c.pass_to(&mut a);
        c.pass_to(&mut b);
        drop(c);
        b.change(&group, crate::event::Change::Add(d.me.person));
        b.pass_to(&mut d);
        b.pass_to(&mut a);
        let seen = d.version(&group).expect("D sees the group");
        assert_eq!(seen, a.version(&group).unwrap());
        assert!(seen.members.contains(&d.me.person) && seen.members.len() == 4);
        d.history.send(&group, text("hi, I'm new"), NOW).unwrap();
        // D passes on the group's changes too; A has them already.
        let taken = d.pass_to(&mut a);
        assert_eq!(taken.last(), Some(&Taken::Shown), "{taken:?}");
        let (page, _) = a.history.page(&group, None, 50, NOW).unwrap();
        assert_eq!(page.last().unwrap().text, "hi, I'm new");
    }

    /// A member renames the group, leaves and never comes back; someone who
    /// missed both still ends with the same group as everyone else.
    #[test]
    fn a_departed_members_changes_still_reach_everyone() {
        let (mut c, mut a, mut m, mut n) = (
            Member::new("c2"),
            Member::new("a2"),
            Member::new("m2"),
            Member::new("n2"),
        );
        let group = make_group(&mut c, &[&a, &m, &n]);
        for to in [&mut a, &mut m, &mut n] {
            c.pass_to(to);
        }
        m.change(&group, crate::event::Change::Rename("trip".into()));
        m.change(&group, crate::event::Change::Leave);
        m.pass_to(&mut a);
        drop(m);
        a.pass_to(&mut n);
        let (theirs, ours) = (n.version(&group).unwrap(), a.version(&group).unwrap());
        assert_eq!(theirs, ours);
        assert_eq!((theirs.name.as_str(), theirs.members.len()), ("trip", 3));
    }

    /// D's message arrives before the add of D: refused for now, so the
    /// sender keeps it (answered `failed`), and it shows when it comes again
    /// after the add. Someone who was a member and left is refused for good.
    #[test]
    fn a_message_before_its_senders_add_waits_on_the_sender() {
        let (mut c, mut a, mut d) = (
            Member::new("na-c"),
            Member::new("na-a"),
            Member::new("na-d"),
        );
        let group = make_group(&mut c, &[&a]);
        c.pass_to(&mut a);
        c.pass_to(&mut d);
        c.change(&group, crate::event::Change::Add(d.me.person));
        c.pass_to(&mut d);
        let early = d.history.send(&group, text("hi from D"), NOW).unwrap();
        let taken = a
            .history
            .receive(&group, d.me, vec![early.clone()], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::NotYetMember)]);
        assert!(
            a.history.page(&group, None, 50, NOW).unwrap().0.is_empty(),
            "not stored"
        );
        c.pass_to(&mut a);
        assert_eq!(
            a.history.receive(&group, d.me, vec![early], NOW).unwrap(),
            [Taken::Shown]
        );
        // Someone who was a member and left is refused for good.
        d.change(&group, crate::event::Change::Leave);
        d.pass_to(&mut a);
        let late = d.history.send(&group, text("I left"), NOW).unwrap();
        let taken = a.history.receive(&group, d.me, vec![late], NOW).unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::NotInChat)]);
    }

    /// Events waiting for a group's creation count per sender across all
    /// groups, not per group.
    #[test]
    fn waiting_is_capped_per_sender_across_groups() {
        let mut me = Member::new("cap-me");
        let stranger = Sender {
            person: [9; 32],
            device: [90; 32],
        };
        let mut sent = 0u64;
        for (group, count) in [([1; 16], 60), ([2; 16], MAX_BEFORE_CREATION as u64 - 60)] {
            for _ in 0..count {
                let mut e = bobs(0, NOW + sent, sent + 1, text("spam"));
                e.id[..8].copy_from_slice(&sent.to_be_bytes());
                me.history
                    .receive(&Where::Group(group), stranger, vec![e], NOW)
                    .unwrap();
                sent += 1;
            }
        }
        let over = bobs(250, NOW + 5000, 5000, text("one more"));
        let taken = me
            .history
            .receive(&Where::Group([3; 16]), stranger, vec![over], NOW)
            .unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::TooManyWaiting)]);
    }

    /// Events still waiting for a creation after WAIT_FOR_CREATION_DAYS are
    /// wiped.
    #[test]
    fn waiting_events_are_wiped_after_some_days() {
        let mut me = Member::new("old-me");
        let group = Where::Group([4; 16]);
        let stranger = Sender {
            person: [9; 32],
            device: [90; 32],
        };
        me.history
            .receive(
                &group,
                stranger,
                vec![bobs(1, NOW, 1, text("forever?"))],
                NOW,
            )
            .unwrap();
        let day = 24 * 3600 * 1000;
        me.history
            .sweep_waiting(NOW + WAIT_FOR_CREATION_DAYS * day - 1)
            .unwrap();
        let mut files = Store::new(&me.dir, &KEY).open(&group.key()).unwrap();
        assert!(!files.read(0).unwrap()[0].is_empty(), "still waiting");
        me.history
            .sweep_waiting(NOW + WAIT_FOR_CREATION_DAYS * day)
            .unwrap();
        let mut files = Store::new(&me.dir, &KEY).open(&group.key()).unwrap();
        assert!(files.read(0).unwrap()[0].is_empty(), "wiped");
    }

    /// Every saved format carries a number; one from a newer version of
    /// Mesh is refused as that, not as damage.
    #[test]
    fn a_newer_saved_format_is_refused_clearly() {
        let newer = |bytes: &mut Vec<u8>| bytes[0] = SAVED_FORMAT + 1;
        // A chat record.
        let root = dir("newer-record");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        h.send(&CHAT, text("hi"), NOW).unwrap();
        drop(h);
        let mut files = Store::new(&root, &KEY).open(&CHAT.key()).unwrap();
        let mut record = files.read(0).unwrap().remove(0);
        newer(&mut record);
        files.rewrite(0, |_| Some(record.clone())).unwrap();
        // Refused at unlock (the crash repair reads the newest segment) or
        // when the chat opens: either way, as newer.
        let err = History::open(&root, &KEY, ME)
            .and_then(|mut h| h.chat(&CHAT, NOW).map(|_| ()))
            .err()
            .unwrap();
        assert!(matches!(err, HistoryError::Newer("a chat record")), "{err}");
        assert!(err.to_string().contains("newer version of Mesh"));
        let _ = std::fs::remove_dir_all(&root);
        // The chat's index.
        let root = dir("newer-index");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        h.send(&CHAT, text("hi"), NOW).unwrap();
        drop(h);
        let files = Store::new(&root, &KEY).open(&CHAT.key()).unwrap();
        let mut index = files.index().unwrap().unwrap();
        newer(&mut index);
        files.write_index(&index).unwrap();
        let err = History::open(&root, &KEY, ME)
            .and_then(|mut h| h.chat(&CHAT, NOW).map(|_| ()))
            .err()
            .unwrap();
        assert!(matches!(err, HistoryError::Newer("a chat index")), "{err}");
        let _ = std::fs::remove_dir_all(&root);
        // A log record, and the counters.
        for what in ["a log record", "the delivery counters"] {
            let root = dir("newer-log");
            let mut h = History::open(&root, &KEY, ME).unwrap();
            h.send(&CHAT, text("hi"), NOW).unwrap();
            h.save_counters().unwrap();
            drop(h);
            let mut log = Store::new(&root, &KEY).open_log().unwrap();
            if what == "a log record" {
                let mut first = log.read(0).unwrap().remove(0);
                newer(&mut first);
                log.rewrite(0, |_| Some(first.clone())).unwrap();
            } else {
                let mut counters = log.index().unwrap().unwrap();
                newer(&mut counters);
                log.write_index(&counters).unwrap();
            }
            let err = History::open(&root, &KEY, ME).err().unwrap();
            assert!(matches!(err, HistoryError::Newer(w) if w == what), "{err}");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// A member passes on a change claiming the creator made it: refused.
    #[test]
    fn a_change_passed_on_in_someone_elses_name_is_refused() {
        let (mut c, mut b, mut d) = (Member::new("c3"), Member::new("b3"), Member::new("d3"));
        let group = make_group(&mut c, &[&b, &d]);
        c.pass_to(&mut b);
        c.pass_to(&mut d);
        let head = b.head(&group);
        let forged = Event {
            version: VERSION,
            id: [77; 16],
            time: NOW,
            seq: NOW,
            n: 1,
            body: Body::Group(crate::event::GroupChange {
                after: Some(head),
                change: crate::event::Change::Remove(d.me.person),
                // Claims the creator, signed by B.
                signed: Some(crate::event::Signed {
                    author: c.me.person,
                    device: c.me.device,
                    signature: b
                        .root
                        .sign_bytes(crate::event::GROUP_SIGNATURE, b"anything")
                        .to_vec(),
                }),
            }),
        };
        let taken = d.history.receive(&group, b.me, vec![forged], NOW).unwrap();
        assert_eq!(taken, [Taken::Refused(Refusal::BadSignature)]);
        assert!(d.version(&group).unwrap().members.contains(&d.me.person));
    }

    /// One stored event read back by its ID, with no chat loaded.
    #[test]
    fn an_event_is_read_back_by_id() {
        let root = dir("event-back");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let said = h.send(&CHAT, text("find me"), NOW).unwrap();
        drop(h);
        let mut again = History::open(&root, &KEY, ME).unwrap();
        assert_eq!(again.event(&said.id).unwrap(), Some(said));
        assert_eq!(again.event(&[9; 16]).unwrap(), None);
        let _ = std::fs::remove_dir_all(root);
    }

    /// An event's author comes from the log, with no chat loaded.
    #[test]
    fn the_author_is_in_the_log() {
        let root = dir("author");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let mine = h.send(&CHAT, text("mine"), NOW).unwrap();
        h.receive(&CHAT, BOB, vec![bobs(1, NOW + 1, 1, text("his"))], NOW)
            .unwrap();
        drop(h);
        let again = History::open(&root, &KEY, ME).unwrap();
        assert_eq!(again.author_of(&mine.id), Some(ME.person));
        assert_eq!(again.author_of(&[1; 16]), Some(BOB.person));
        assert_eq!(again.author_of(&[9; 16]), None);
        assert!(again.chats.is_empty(), "no chat was loaded");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Given up for a device after 30 days isn't "sent" either.
    #[test]
    fn given_up_isnt_sent() {
        let root = dir("given-up");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let old = h.send(&CHAT, text("long ago"), NOW).unwrap();
        h.add_device(BOB.device, BOB.person);
        let later = NOW + crate::sync::FRIEND_WAIT + 1;
        assert!(h.outgoing(&BOB.device, later).unwrap().is_empty());
        assert!(!h.is_sent(&old.id));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outgoing_reads_events_back_and_counters_survive() {
        let root = dir("outgoing");
        let mut h = History::open(&root, &KEY, ME).unwrap();
        let laptop: Device = [11; 32];
        h.add_device(laptop, ME.person);
        for i in 0..3 {
            h.send(&CHAT, text(&format!("m{i}")), NOW).unwrap();
        }
        let out = h.outgoing(&laptop, NOW).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[2].event.body, text("m2"));
        h.acked(&laptop, out[0].number, true);
        h.save_counters().unwrap();
        drop(h);
        let mut again = History::open(&root, &KEY, ME).unwrap();
        assert_eq!(again.counter(&laptop), Some(1));
        assert_eq!(again.outgoing(&laptop, NOW).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }
}
