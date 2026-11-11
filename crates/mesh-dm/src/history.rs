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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::chat::{Chat, Position, Refusal, Taken};
use crate::event::{Body, Event, EventError, EventId, VERSION};
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
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
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
    /// Each group chat's members in its current version.
    members: HashMap<Conversation, BTreeSet<Person>>,
    counters: Counters,
    chats: HashMap<Conversation, Open>,
}

/// A message as a page shows it (dmOpen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub id: EventId,
    pub author: Person,
    pub text: String,
    pub edited: bool,
    pub reply_to: Option<EventId>,
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
    at: Where,
    person: Person,
    device: Device,
    received: u64,
    event: Vec<u8>,
}

/// The body that carries `t` to another of our devices.
pub fn forward(t: &ToSend) -> Vec<u8> {
    let forward = Forward {
        at: t.at,
        person: t.from.person,
        device: t.from.device,
        received: t.received,
        event: t.event.to_bytes().expect("checked when stored"),
    };
    postcard::to_stdvec(&forward).expect("to memory")
}

/// A forwarded body: the chat, the author, the first arrival, the event.
pub fn unforward(bytes: &[u8]) -> Option<(Where, Sender, u64, Event)> {
    let f: Forward = postcard::from_bytes(bytes).ok()?;
    let event = Event::from_bytes(&f.event).ok()?;
    let from = Sender {
        person: f.person,
        device: f.device,
    };
    Some((f.at, from, f.received, event))
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
            counters: Counters::new(me.person),
            chats: HashMap::new(),
            log_files: store.open_log()?,
            store,
        };
        for n in 0..history.log_files.segments() {
            for record in history.log_files.read(n)? {
                let record =
                    postcard::from_bytes::<LogRecord>(&record).map_err(|_| StoreError::Damaged)?;
                history.remember(record);
            }
        }
        if let Some(bytes) = history.log_files.index()? {
            history.counters = postcard::from_bytes(&bytes).map_err(|_| StoreError::Damaged)?;
        }
        history.number_the_missed()?;
        Ok(history)
    }

    /// Events a crash left in a chat's newest segment with no number (the
    /// chat file is written before the log) get one now, so they're still
    /// delivered.
    // ponytail: reads every chat's newest segment at unlock; fine for hundreds of chats, keep a "last written" mark if unlock grows slow.
    fn number_the_missed(&mut self) -> Result<(), HistoryError> {
        let chats: Vec<Conversation> = self.known.keys().copied().collect();
        let mut missed = Vec::new();
        for chat in chats {
            let mut files = self.store.open(&chat)?;
            let Some(newest) = files.segments().checked_sub(1) else {
                continue;
            };
            for (position, record) in files.read(newest)?.iter().enumerate() {
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
                };
                let position = u32::try_from(position).map_err(|_| StoreError::Damaged)?;
                missed.push(LogRecord::Stored {
                    entry,
                    segment: newest,
                    position,
                });
            }
        }
        self.log(missed)
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
            .map(|r| postcard::to_stdvec(r).expect("to memory"))
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
            let index: ChatIndex = postcard::from_bytes(&bytes).map_err(|_| StoreError::Damaged)?;
            if let Some(read) = index.read {
                chat.set_read_marker(read);
            }
            for (device, n, seq) in index.highs {
                chat.know_high(device, n, seq);
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
        let mut taken = Vec::with_capacity(events.len());
        let mut kept = Vec::new();
        for (received, event) in events {
            if self.log.number_of(&event.id).is_some() {
                taken.push(Taken::Duplicate);
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
            let t = open.chat.take_received(from, event.clone(), now, received);
            if matches!(t, Taken::Shown | Taken::Waiting) {
                kept.push((received, event));
            }
            taken.push(t);
        }
        if !kept.is_empty() && !self.known.contains_key(chat) {
            self.log(vec![LogRecord::Chat {
                chat: *chat,
                at: *at,
            }])?;
        }
        self.store_kept(chat, from, via, kept)?;
        self.wipe(chat)?;
        let open = &self.chats[chat];
        let index = ChatIndex {
            read: open.chat.read_marker(),
            highs: open.chat.highs(),
        };
        open.files
            .write_index(&postcard::to_stdvec(&index).expect("to memory"))?;
        Ok(taken)
    }

    /// Appends kept events to the chat and the log: one sync each.
    fn store_kept(
        &mut self,
        chat: &Conversation,
        from: Sender,
        via: Device,
        kept: Vec<(u64, Event)>,
    ) -> Result<(), HistoryError> {
        if kept.is_empty() {
            return Ok(());
        }
        let open = self.chats.get_mut(chat).expect("loaded");
        let places = open.files.next_places(kept.len());
        let mut records = Vec::with_capacity(kept.len());
        for (received, event) in &kept {
            records.push(encode(*received, from, event)?);
        }
        open.files.append(&records)?;
        let newest = open.files.segments() - 1;
        open.loaded.insert(newest);
        let mut records = Vec::with_capacity(kept.len());
        for ((received, event), (segment, position)) in kept.iter().zip(places) {
            let entry = Entry {
                id: event.id,
                chat: *chat,
                author: from.person,
                from: via,
                at: *received,
                private: private(&event.body),
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
        let (known, members) = (&self.known, &self.members);
        let shares = |c: &Conversation, p: &Person| in_chat(known, members, c, p);
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
                    let (known, members) = (&self.known, &self.members);
                    let shares = |c: &Conversation, p: &Person| in_chat(known, members, c, p);
                    self.counters.acked(device, number, true, &self.log, shares)
                }
            }
        }
        Ok(out)
    }

    /// The device answered for event `number`.
    pub fn acked(&mut self, device: &Device, number: u64, ok: bool) {
        let (known, members) = (&self.known, &self.members);
        let shares = |c: &Conversation, p: &Person| in_chat(known, members, c, p);
        self.counters.acked(device, number, ok, &self.log, shares);
    }

    /// Writes the counters (after a batch of acks).
    pub fn save_counters(&self) -> Result<(), HistoryError> {
        let bytes = postcard::to_stdvec(&self.counters).expect("to memory");
        Ok(self.log_files.write_index(&bytes)?)
    }

    pub fn counter(&self, device: &Device) -> Option<u64> {
        self.counters.counter(device)
    }

    /// Every chat with events.
    pub fn chats(&self) -> Vec<Where> {
        self.known.values().copied().collect()
    }

    /// The chat an event is in.
    pub fn where_of(&self, id: &EventId) -> Option<Where> {
        let chat = self.log.get(self.log.number_of(id)?)?.chat;
        self.known.get(&chat).copied()
    }

    /// Who wrote a stored event, from its log entry: no chat is loaded.
    pub fn author_of(&self, id: &EventId) -> Option<Person> {
        Some(self.log.get(self.log.number_of(id)?)?.author)
    }

    /// Whether one of the other person's devices has taken our event (D5).
    pub fn is_sent(&self, id: &EventId) -> bool {
        let (known, members) = (&self.known, &self.members);
        let shares = |c: &Conversation, p: &Person| in_chat(known, members, c, p);
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

/// Whether `person` is in chat `chat`: the person of a 1:1, a member of a
/// group's current version.
fn in_chat(
    known: &HashMap<Conversation, Where>,
    members: &HashMap<Conversation, BTreeSet<Person>>,
    chat: &Conversation,
    person: &Person,
) -> bool {
    match known.get(chat) {
        Some(Where::Direct(p)) => p == person,
        Some(Where::Group(_)) => members.get(chat).is_some_and(|m| m.contains(person)),
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
    let mut record = received.to_be_bytes().to_vec();
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
