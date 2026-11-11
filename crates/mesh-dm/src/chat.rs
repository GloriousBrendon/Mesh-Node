//! Folding events into a chat (SPEC-dm D2–D4, D7). Pure: the caller passes
//! who sent each event (as e2ee checked it) and its own clock, and stores
//! what this says to keep.
//!
//! Order (D2): `seq` never runs ahead of the clock. A reader checks each
//! event against its own clock and the sending device's earlier events,
//! never against the highest `seq` it holds, so nothing anyone sends or
//! withholds can push a reader out of range.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::event::{Attachment, Body, Event, EventId, GroupChange};
use crate::group::{Group, Version};
use crate::{Device, Person, Sender};

/// How far ahead of the reader's clock an event may be and still show (D2).
pub const AHEAD_SHOWN: u64 = 5 * 60 * 1000;
/// Further ahead than this, an event is dropped (D2).
pub const AHEAD_DROPPED: u64 = 24 * 3600 * 1000;
/// Events from one device that may wait for the clock at once (D2).
pub const MAX_WAITING: usize = 1000;
/// Different emoji on one message (D4).
pub const MAX_REACTIONS: usize = 20;
/// A sender time this far past its arrival shows as the arrival (D2).
pub const DISPLAY_CLAMP: u64 = 5 * 60 * 1000;

/// Where an event sits in the chat: by `seq`, then event ID.
pub type Position = (u64, EventId);

/// A message as the chat shows it.
#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub id: EventId,
    pub author: Person,
    pub text: &'a str,
    pub edited: bool,
    pub reply_to: Option<EventId>,
    pub attachments: &'a [Attachment],
    /// Each emoji and who reacted with it, both sorted.
    pub reactions: Vec<(&'a str, Vec<Person>)>,
    pub late: bool,
}

/// What became of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Taken {
    /// In the chat now: store it.
    Shown,
    /// Ahead of the clock: store it, show it later (`tick`).
    Waiting,
    /// Already here.
    Duplicate,
    /// Has nothing left to do (its target is gone): don't store it.
    Ignored,
    /// Dropped: acknowledge it, don't store it, count it (D14).
    Refused(Refusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// More than a day ahead of the clock.
    TooFarAhead,
    /// Its device already has `MAX_WAITING` events waiting.
    TooManyWaiting,
    /// A higher `n` with a lower `seq` than an event from the same device,
    /// or the same `n` twice.
    OutOfStep,
    /// From someone who isn't in this chat: a 1:1 chat takes events only
    /// from that person and our own devices.
    NotInChat,
    /// A group change whose author's signature doesn't check out (D7).
    BadSignature,
    /// From someone this device doesn't know as a member yet (their add
    /// hasn't arrived): answered `failed`, so the sender keeps it.
    NotYetMember,
}

struct Held {
    sender: Sender,
    event: Event,
    /// The reader's clock when it came, in milliseconds.
    received: u64,
    waiting: bool,
}

pub struct Chat {
    me: Person,
    held: HashMap<EventId, Held>,
    /// Events in the chat, in order.
    shown: BTreeSet<Position>,
    /// Each device's events by `n`, with their `seq` (waiting ones too).
    steps: HashMap<Device, BTreeMap<u64, u64>>,
    waiting: HashMap<Device, usize>,
    /// "Read up to here" (D9).
    read: Option<Position>,
    /// Arrived at or below the read marker: still unread (D2, rule 3).
    late: HashSet<EventId>,
    /// Each message's edits and reactions (D3, D4).
    folded: HashMap<EventId, Folded>,
    /// Edits, deletes and reactions waiting for their target.
    pending: HashMap<EventId, Vec<EventId>>,
    /// Deleted messages: a late copy, edit or reaction can't bring them back.
    deleted: HashSet<EventId>,
    /// Deleted since `take_deleted` last asked, for the log.
    newly_deleted: Vec<EventId>,
    /// Stored events to wipe (`take_scrub`).
    scrub: Vec<EventId>,
    /// A group's changes (D7).
    group: Group,
}

#[derive(Default)]
struct Folded {
    /// The newest edit by the author, and where it sits.
    edit: Option<(Position, String)>,
    /// Every edit and reaction, to wipe with the message.
    linked: Vec<EventId>,
    /// (person, emoji) → the newest reaction's position and whether it's on.
    reactions: HashMap<(Person, String), (Position, bool)>,
}

impl Chat {
    /// A chat as seen by `me`.
    pub fn new(me: Person) -> Self {
        Self {
            me,
            held: HashMap::new(),
            shown: BTreeSet::new(),
            steps: HashMap::new(),
            waiting: HashMap::new(),
            read: None,
            late: HashSet::new(),
            folded: HashMap::new(),
            pending: HashMap::new(),
            deleted: HashSet::new(),
            newly_deleted: Vec::new(),
            scrub: Vec::new(),
            group: Group::default(),
        }
    }

    /// The `seq` for `device`'s next event: one more than the highest held
    /// that isn't ahead of `now`, or than the device's own last, whichever is
    /// higher (D2).
    pub fn next_seq(&self, device: &Device, now: u64) -> u64 {
        let held = self.held.values().map(|h| h.event.seq);
        let caught_up = held.filter(|&seq| seq <= now).max().unwrap_or(0);
        // Never at or below our own last: readers would drop it as out of step.
        let ours = self
            .steps
            .get(device)
            .and_then(|s| s.values().max().copied());
        caught_up.max(ours.unwrap_or(0)) + 1
    }

    /// Takes in an event from `from`, at the reader's clock `now`.
    pub fn take(&mut self, from: Sender, event: Event, now: u64) -> Taken {
        self.take_received(from, event, now, now)
    }

    /// As `take`, for an event that first arrived at `received` on another
    /// of our devices (history sync): the time it shows is that arrival.
    pub fn take_received(&mut self, from: Sender, event: Event, now: u64, received: u64) -> Taken {
        if self.held.contains_key(&event.id) || self.deleted.contains(&event.id) {
            return Taken::Duplicate;
        }
        if self.pointless(&from, &event) {
            return Taken::Ignored;
        }
        if event.seq > now.saturating_add(AHEAD_DROPPED) {
            return Taken::Refused(Refusal::TooFarAhead);
        }
        if !self.in_step(&from.device, event.n, event.seq) {
            return Taken::Refused(Refusal::OutOfStep);
        }
        let waiting = event.seq > now.saturating_add(AHEAD_SHOWN);
        if waiting {
            let count = self.waiting.entry(from.device).or_default();
            if *count >= MAX_WAITING {
                return Taken::Refused(Refusal::TooManyWaiting);
            }
            *count += 1;
        }
        let steps = self.steps.entry(from.device).or_default();
        steps.insert(event.n, event.seq);
        let id = event.id;
        self.held.insert(
            id,
            Held {
                sender: from,
                event,
                received,
                waiting,
            },
        );
        if waiting {
            return Taken::Waiting;
        }
        self.show(id);
        Taken::Shown
    }

    /// An event with nothing to do, known before it's kept: an edit, delete
    /// or reaction for a deleted message, an edit or delete by someone who
    /// may not, or a message already deleted by an early delete.
    fn pointless(&mut self, from: &Sender, event: &Event) -> bool {
        let author = |target: &EventId| self.held.get(target).map(|h| h.sender.person);
        match &event.body {
            Body::Edit { target, .. }
            | Body::Delete { target, .. }
            | Body::React { target, .. }
                if self.deleted.contains(target) =>
            {
                true
            }
            Body::Edit { target, .. } => author(target).is_some_and(|a| a != from.person),
            Body::Delete { target, everyone } => {
                author(target).is_some_and(|a| !self.may_delete(from, a, *everyone))
            }
            Body::Text { .. } => {
                let early = self.pending.get(&event.id).into_iter().flatten();
                let deletes = early.filter_map(|id| match &self.held[id].event.body {
                    Body::Delete { everyone, .. } => Some((self.held[id].sender, *everyone)),
                    _ => None,
                });
                let mut deletes = deletes.collect::<Vec<_>>().into_iter();
                if !deletes.any(|(by, everyone)| self.may_delete(&by, from.person, everyone)) {
                    return false;
                }
                // Deleted before it came: never kept; what waited for it goes.
                let waited = self.pending.remove(&event.id).unwrap_or_default();
                for id in waited {
                    if !matches!(self.held[&id].event.body, Body::Delete { .. }) {
                        self.wipe(id);
                    }
                }
                self.deleted.insert(event.id);
                self.newly_deleted.push(event.id);
                true
            }
            _ => false,
        }
    }

    /// Only the author deletes for everyone; "delete for me" comes only from
    /// our own devices (D3).
    fn may_delete(&self, by: &Sender, author: Person, everyone: bool) -> bool {
        if everyone {
            by.person == author
        } else {
            by.person == self.me
        }
    }

    /// Forgets a kept event and asks for its stored copy to be wiped.
    fn wipe(&mut self, id: EventId) {
        if let Some(held) = self.held.remove(&id) {
            self.shown.remove(&(held.event.seq, id));
            if held.waiting
                && let Some(count) = self.waiting.get_mut(&held.sender.device)
            {
                *count = count.saturating_sub(1);
            }
        }
        self.late.remove(&id);
        self.scrub.push(id);
    }

    /// For one device, a higher `n` must have a higher `seq` (D2, rule 2).
    fn in_step(&self, device: &Device, n: u64, seq: u64) -> bool {
        let Some(steps) = self.steps.get(device) else {
            return true;
        };
        if steps.contains_key(&n) {
            return false;
        }
        let below = steps.range(..n).next_back().is_none_or(|(_, &s)| s < seq);
        let above = steps.range(n + 1..).next().is_none_or(|(_, &s)| s > seq);
        below && above
    }

    /// Puts a held event in the chat, and folds it in.
    fn show(&mut self, id: EventId) {
        let held = &self.held[&id];
        let at = (held.event.seq, id);
        let (from, body) = (held.sender, held.event.body.clone());
        self.shown.insert(at);
        match body {
            Body::Text { .. } => {
                if from.person != self.me && self.read.is_some_and(|read| at <= read) {
                    self.late.insert(id);
                }
                self.folded.insert(id, Folded::default());
                let mut waited = self.pending.remove(&id).unwrap_or_default();
                waited.sort_by_key(|w| (self.held[w].event.seq, *w));
                for w in waited {
                    if self.folded.contains_key(&id) {
                        self.fold(id, w);
                    } else {
                        self.wipe(w);
                    }
                }
            }
            Body::Edit { target, .. }
            | Body::Delete { target, .. }
            | Body::React { target, .. } => {
                if self.folded.contains_key(&target) {
                    self.fold(target, id);
                } else if self.deleted.contains(&target) {
                    self.wipe(id);
                } else {
                    self.pending.entry(target).or_default().push(id);
                }
            }
            Body::Read { up_to } if from.person == self.me => self.mark_read(&up_to),
            Body::Group(change) => self.group.add(id, from.person, change, at),
            Body::Read { .. } => {}
        }
    }

    /// Folds edit, delete or reaction `id` into message `target`.
    fn fold(&mut self, target: EventId, id: EventId) {
        let author = self.held[&target].sender.person;
        let held = &self.held[&id];
        let (by, at) = (held.sender, (held.event.seq, id));
        match held.event.body.clone() {
            Body::Edit { text, .. } if by.person == author => {
                let folded = self.folded.get_mut(&target).expect("folded");
                folded.linked.push(id);
                if folded.edit.as_ref().is_none_or(|(old, _)| at > *old) {
                    folded.edit = Some((at, text));
                }
            }
            Body::React { emoji, on, .. } => {
                let folded = self.folded.get_mut(&target).expect("folded");
                folded.linked.push(id);
                let showing: HashSet<&String> = (folded.reactions.iter())
                    .filter(|(_, (_, on))| *on)
                    .map(|((_, e), _)| e)
                    .collect();
                let full = showing.len() >= MAX_REACTIONS && !showing.contains(&emoji);
                let key = (by.person, emoji);
                let newer = folded.reactions.get(&key).is_none_or(|(old, _)| at > *old);
                if newer && !(on && full) {
                    folded.reactions.insert(key, (at, on));
                }
            }
            Body::Delete { everyone, .. } if self.may_delete(&by, author, everyone) => {
                let folded = self.folded.remove(&target).unwrap_or_default();
                for linked in folded.linked {
                    self.wipe(linked);
                }
                // Edits and reactions still waiting for it go too.
                for waited in self.pending.remove(&target).unwrap_or_default() {
                    self.wipe(waited);
                }
                self.wipe(target);
                self.deleted.insert(target);
                self.newly_deleted.push(target);
            }
            _ => self.wipe(id),
        }
    }

    /// Shows the waiting events the clock has caught up with; their IDs.
    pub fn tick(&mut self, now: u64) -> Vec<EventId> {
        let due: Vec<EventId> = self
            .held
            .iter()
            .filter(|(_, h)| h.waiting && h.event.seq <= now.saturating_add(AHEAD_SHOWN))
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            let held = self.held.get_mut(id).expect("just found");
            held.waiting = false;
            if let Some(count) = self.waiting.get_mut(&held.sender.device) {
                *count = count.saturating_sub(1);
            }
            self.show(*id);
        }
        due
    }

    /// The events in the chat, in order.
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.shown.iter().map(|(_, id)| &self.held[id].event)
    }

    /// The time to show for an event: the sender's, unless that's more than
    /// `DISPLAY_CLAMP` past its arrival.
    pub fn display_time(&self, id: &EventId) -> Option<u64> {
        let held = self.held.get(id)?;
        let latest = held.received.saturating_add(DISPLAY_CLAMP);
        Some(if held.event.time > latest {
            held.received
        } else {
            held.event.time
        })
    }

    /// Whether an event arrived at or below the read marker and is unread.
    pub fn is_late(&self, id: &EventId) -> bool {
        self.late.contains(id)
    }

    /// Others' messages after the read marker, and late ones.
    pub fn unread(&self) -> usize {
        let after = |at: &&Position| self.read.is_none_or(|read| **at > read);
        let theirs = |(_, id): &&Position| {
            let held = &self.held[id];
            held.sender.person != self.me && matches!(held.event.body, Body::Text { .. })
        };
        let new = self.shown.iter().filter(after).filter(theirs).count();
        new + self.late.len()
    }

    /// The messages to show, in order: deleted ones are gone, edits and
    /// reactions folded in.
    pub fn messages(&self) -> Vec<Message<'_>> {
        let message = |id: &EventId| {
            let held = &self.held[id];
            let Body::Text {
                text,
                reply_to,
                attachments,
            } = &held.event.body
            else {
                return None;
            };
            let folded = self.folded.get(id)?;
            let mut reactions: BTreeMap<&str, Vec<Person>> = BTreeMap::new();
            for ((person, emoji), (_, on)) in &folded.reactions {
                if *on {
                    reactions.entry(emoji).or_default().push(*person);
                }
            }
            reactions.values_mut().for_each(|who| who.sort());
            Some(Message {
                id: *id,
                author: held.sender.person,
                text: folded.edit.as_ref().map_or(text, |(_, t)| t),
                edited: folded.edit.is_some(),
                reply_to: *reply_to,
                attachments,
                reactions: reactions.into_iter().collect(),
                late: self.late.contains(id),
            })
        };
        self.shown
            .iter()
            .filter_map(|(_, id)| message(id))
            .collect()
    }

    /// Group `id`'s members and name; `None` for a 1:1 chat, or before its
    /// creation has arrived.
    pub fn group(&self, id: &[u8; 16]) -> Option<Version> {
        self.group.version(id)
    }

    /// Puts back an event read from disk. No checks: it passed them when it
    /// came. Shown, or waiting if it's still ahead of the clock.
    pub fn restore(&mut self, from: Sender, event: Event, received: u64, now: u64) {
        if self.held.contains_key(&event.id) || self.deleted.contains(&event.id) {
            return;
        }
        let waiting = event.seq > now.saturating_add(AHEAD_SHOWN);
        if waiting {
            *self.waiting.entry(from.device).or_default() += 1;
        }
        let steps = self.steps.entry(from.device).or_default();
        steps.insert(event.n, event.seq);
        let id = event.id;
        let held = Held {
            sender: from,
            event,
            received,
            waiting,
        };
        self.held.insert(id, held);
        if !waiting {
            self.show(id);
        }
    }

    /// A message deleted before this chat was loaded: late copies, edits
    /// and reactions of it stay refused.
    pub fn was_deleted(&mut self, id: EventId) {
        self.deleted.insert(id);
    }

    /// Messages deleted since this was last asked, for the log.
    pub fn take_deleted(&mut self) -> Vec<EventId> {
        std::mem::take(&mut self.newly_deleted)
    }

    pub fn read_marker(&self) -> Option<Position> {
        self.read
    }

    /// The read marker as the index saved it.
    pub fn set_read_marker(&mut self, at: Position) {
        self.read = Some(self.read.map_or(at, |read| read.max(at)));
    }

    /// Each sending device's highest `n` and its `seq`, for the index.
    pub fn highs(&self) -> Vec<(Device, u64, u64)> {
        let highs = self.steps.iter();
        let highs = highs.filter_map(|(d, s)| s.last_key_value().map(|(n, seq)| (*d, *n, *seq)));
        highs.collect()
    }

    /// A device's highest `n` and `seq` from history not loaded: "out of
    /// step" and `next_seq` check against it too.
    pub fn know_high(&mut self, device: Device, n: u64, seq: u64) {
        self.steps.entry(device).or_default().insert(n, seq);
    }

    /// The next `n` for `device`.
    pub fn next_n(&self, device: &Device) -> u64 {
        let last = self.steps.get(device).and_then(|s| s.last_key_value());
        last.map_or(0, |(n, _)| *n) + 1
    }

    /// The group's changes, to save with the chat's index.
    pub fn group_changes(&self) -> Vec<(EventId, Person, GroupChange, Position)> {
        self.group.changes()
    }

    /// A group change from the index: the group's state, though the segment
    /// that holds it isn't loaded.
    pub fn restore_group_change(
        &mut self,
        id: EventId,
        by: Person,
        change: GroupChange,
        at: Position,
    ) {
        self.group.add(id, by, change, at);
    }

    /// Events whose stored copies must now be wiped: a deleted message, its
    /// edits and its reactions (D3, D11). Taken once.
    pub fn take_scrub(&mut self) -> Vec<EventId> {
        std::mem::take(&mut self.scrub)
    }

    /// You read up to `up_to` (here, or a `Read` from your other device).
    pub fn mark_read(&mut self, up_to: &EventId) {
        let Some(held) = self.held.get(up_to).filter(|h| !h.waiting) else {
            return;
        };
        let at = (held.event.seq, *up_to);
        self.read = Some(self.read.map_or(at, |read| read.max(at)));
        // ponytail: a Read clears every late mark; it can't say which ones its device had seen.
        self.late.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Body, VERSION};

    const NOW: u64 = 1_800_000_000_000;
    const ME: Person = [1; 32];
    const ALICE: Sender = Sender {
        person: [2; 32],
        device: [20; 32],
    };
    const BOB: Sender = Sender {
        person: [3; 32],
        device: [30; 32],
    };

    const MINE: Sender = Sender {
        person: ME,
        device: [10; 32],
    };

    /// A device never numbers at or below its own last event: not when its
    /// clock steps back, nor for two sends in one millisecond once `seq` has
    /// reached the clock. Readers would drop the repeat as out of step.
    #[test]
    fn a_device_never_repeats_its_own_seq() {
        let mut chat = Chat::new(ME);
        // Sent at NOW, then the clock stepped back a minute.
        chat.take(MINE, text(1, NOW, 1), NOW);
        let back = NOW - 60_000;
        assert_eq!(chat.next_seq(&MINE.device, back), NOW + 1);
        // Two sends in one millisecond, seq already at the clock.
        let seq = chat.next_seq(&MINE.device, NOW);
        assert_eq!(chat.take(MINE, text(2, seq, 2), NOW), Taken::Shown);
        let again = chat.next_seq(&MINE.device, NOW);
        assert!(again > seq, "{again} after {seq}");
        assert_eq!(chat.take(MINE, text(3, again, 3), NOW), Taken::Shown);
        // Another device's events ahead of our clock still don't count.
        let laptop = Sender {
            device: [11; 32],
            ..MINE
        };
        chat.take(laptop, text(4, NOW + 120_000, 1), NOW);
        assert_eq!(chat.next_seq(&MINE.device, NOW), again + 1);
    }

    pub(super) fn text(id: u8, seq: u64, n: u64) -> Event {
        Event {
            version: VERSION,
            id: [id; 16],
            time: NOW,
            seq,
            n,
            body: Body::Text {
                text: format!("message {id}"),
                reply_to: None,
                attachments: vec![],
            },
        }
    }

    fn ids(chat: &Chat) -> Vec<u8> {
        chat.events().map(|e| e.id[0]).collect()
    }

    #[test]
    fn order_is_by_seq_whatever_the_clocks_say() {
        let mut chat = Chat::new(ME);
        let mut late_clock = text(1, 10, 1);
        late_clock.time = NOW + 3_600_000;
        assert_eq!(chat.take(ALICE, late_clock, NOW), Taken::Shown);
        let mut old_time = text(2, 11, 1);
        old_time.time = 5;
        assert_eq!(chat.take(BOB, old_time, NOW), Taken::Shown);
        // An old sender time can't move a message up: seq says where it goes.
        assert_eq!(ids(&chat), [1, 2]);
        // A time far past its arrival shows as the arrival.
        assert_eq!(chat.display_time(&[1; 16]), Some(NOW));
        assert_eq!(chat.display_time(&[2; 16]), Some(5));
        assert_eq!(chat.take(BOB, text(2, 11, 1), NOW), Taken::Duplicate);
    }

    #[test]
    fn a_sender_ignores_a_held_seq_ahead_of_its_clock() {
        let mut chat = Chat::new(ME);
        assert_eq!(chat.next_seq(&MINE.device, NOW), 1, "a new chat");
        chat.take(ALICE, text(1, NOW - 10, 1), NOW);
        assert_eq!(chat.next_seq(&MINE.device, NOW), NOW - 9);
        // A forger's jump, still within the 5 minutes: shown, not taken up.
        chat.take(BOB, text(2, NOW + 60_000, 1), NOW);
        assert_eq!(chat.next_seq(&MINE.device, NOW), NOW - 9);
        // Once the clock passes it, it is.
        assert_eq!(chat.next_seq(&MINE.device, NOW + 60_000), NOW + 60_001);
    }

    #[test]
    fn ahead_of_the_clock_waits_or_is_dropped() {
        let mut chat = Chat::new(ME);
        assert_eq!(
            chat.take(ALICE, text(1, NOW + AHEAD_SHOWN, 1), NOW),
            Taken::Shown
        );
        let ahead = NOW + AHEAD_SHOWN + 1;
        assert_eq!(chat.take(ALICE, text(2, ahead, 2), NOW), Taken::Waiting);
        assert_eq!(ids(&chat), [1]);
        assert!(chat.tick(NOW).is_empty());
        assert_eq!(chat.tick(NOW + 1), vec![[2; 16]]);
        assert_eq!(ids(&chat), [1, 2]);
        let far = text(3, NOW + AHEAD_DROPPED + 1, 3);
        assert_eq!(
            chat.take(ALICE, far, NOW),
            Taken::Refused(Refusal::TooFarAhead)
        );
        assert_eq!(
            chat.take(BOB, text(4, NOW + AHEAD_DROPPED, 1), NOW),
            Taken::Waiting
        );
    }

    #[test]
    fn at_most_a_thousand_wait_per_device() {
        let mut chat = Chat::new(ME);
        let ahead = NOW + AHEAD_SHOWN + 1000;
        for n in 0..MAX_WAITING as u64 {
            let mut e = text(0, ahead + n, n + 1);
            e.id[..8].copy_from_slice(&n.to_be_bytes());
            assert_eq!(chat.take(ALICE, e, NOW), Taken::Waiting);
        }
        let mut one_more = text(0, ahead + 5000, MAX_WAITING as u64 + 1);
        one_more.id = [0xEE; 16];
        assert_eq!(
            chat.take(ALICE, one_more, NOW),
            Taken::Refused(Refusal::TooManyWaiting)
        );
        // Another device's waiting room is its own.
        assert_eq!(chat.take(BOB, text(9, ahead, 1), NOW), Taken::Waiting);
    }

    /// The attack your review found: big jumps sent to everyone but one
    /// member. Here the reader is that member: it never sees the jumps, and
    /// still takes the next honest event, which its clock alone judges.
    #[test]
    fn jumps_withheld_from_one_member_dont_cut_them_out() {
        let mut left_out = Chat::new(ME);
        left_out.take(ALICE, text(1, NOW - 1000, 1), NOW);
        // Bob saw a forger's jump to just under the bound, and carried on
        // honestly: he ignores it until his clock passes it.
        let mut bob_view = Chat::new(BOB.person);
        bob_view.take(ALICE, text(1, NOW - 1000, 1), NOW);
        let forger = Sender {
            person: [4; 32],
            device: [40; 32],
        };
        bob_view.take(forger, text(8, NOW + AHEAD_SHOWN, 1), NOW);
        let seq = bob_view.next_seq(&BOB.device, NOW);
        assert_eq!(seq, NOW - 999, "the jump didn't carry");
        assert_eq!(left_out.take(BOB, text(2, seq, 1), NOW), Taken::Shown);
        // Even after the clocks pass the jump, Bob's next is within range.
        let later = NOW + AHEAD_SHOWN + 1;
        let seq = bob_view.next_seq(&BOB.device, later);
        assert_eq!(left_out.take(BOB, text(3, seq, 2), later), Taken::Shown);
        assert_eq!(ids(&left_out), [1, 2, 3]);
    }

    #[test]
    fn a_new_device_takes_its_first_event() {
        let mut chat = Chat::new(ME);
        assert_eq!(
            chat.take(ALICE, text(1, NOW - 86_400_000 * 300, 7), NOW),
            Taken::Shown
        );
    }

    #[test]
    fn out_of_step_is_refused_whichever_arrives_first() {
        let step = Taken::Refused(Refusal::OutOfStep);
        // n 2 with a seq below n 1's.
        let mut a = Chat::new(ME);
        assert_eq!(a.take(ALICE, text(1, 100, 1), NOW), Taken::Shown);
        assert_eq!(a.take(ALICE, text(2, 50, 2), NOW), step);
        let mut b = Chat::new(ME);
        assert_eq!(b.take(ALICE, text(2, 50, 2), NOW), Taken::Shown);
        assert_eq!(b.take(ALICE, text(1, 100, 1), NOW), step);
        // The same n twice.
        assert_eq!(b.take(ALICE, text(3, 60, 2), NOW), step);
        // Another device of the same person has its own count.
        let laptop = Sender {
            device: [21; 32],
            ..ALICE
        };
        assert_eq!(b.take(laptop, text(4, 10, 1), NOW), Taken::Shown);
        // Honest events arriving out of order are all taken.
        let mut c = Chat::new(ME);
        for (id, seq, n) in [(3, 30, 3), (1, 10, 1), (4, 40, 4), (2, 20, 2)] {
            assert_eq!(c.take(BOB, text(id, seq, n), NOW), Taken::Shown);
        }
        assert_eq!(ids(&c), [1, 2, 3, 4]);
    }

    fn body(id: u8, seq: u64, body: Body) -> Event {
        Event {
            body,
            ..text(id, seq, seq)
        }
    }

    fn edit(id: u8, seq: u64, target: u8, words: &str) -> Event {
        body(
            id,
            seq,
            Body::Edit {
                target: [target; 16],
                text: words.into(),
            },
        )
    }

    fn react(id: u8, seq: u64, target: u8, emoji: &str, on: bool) -> Event {
        body(
            id,
            seq,
            Body::React {
                target: [target; 16],
                emoji: emoji.into(),
                on,
            },
        )
    }

    fn delete(id: u8, seq: u64, target: u8, everyone: bool) -> Event {
        body(
            id,
            seq,
            Body::Delete {
                target: [target; 16],
                everyone,
            },
        )
    }

    fn only(chat: &Chat) -> (String, bool, Vec<(String, usize)>) {
        let messages = chat.messages();
        assert_eq!(messages.len(), 1, "{messages:?}");
        let m = &messages[0];
        let reactions = m
            .reactions
            .iter()
            .map(|(e, who)| (e.to_string(), who.len()));
        (m.text.to_owned(), m.edited, reactions.collect())
    }

    #[test]
    fn edits_and_reactions_before_their_target_wait_for_it() {
        let mut chat = Chat::new(ME);
        assert_eq!(chat.take(ALICE, edit(2, 20, 1, "fixed"), NOW), Taken::Shown);
        assert_eq!(
            chat.take(BOB, react(3, 30, 1, "👍", true), NOW),
            Taken::Shown
        );
        assert!(chat.messages().is_empty());
        chat.take(ALICE, text(1, 10, 1), NOW);
        assert_eq!(only(&chat), ("fixed".into(), true, vec![("👍".into(), 1)]));
    }

    #[test]
    fn the_newest_edit_by_the_author_wins() {
        let mut a = Chat::new(ME);
        let mut b = Chat::new(ME);
        let events = [
            text(1, 10, 1),
            edit(2, 20, 1, "second"),
            edit(3, 30, 1, "third"),
        ];
        for e in events.clone() {
            a.take(ALICE, e, NOW);
        }
        for e in events.into_iter().rev() {
            b.take(ALICE, e, NOW);
        }
        assert_eq!(only(&a), ("third".into(), true, vec![]));
        assert_eq!(only(&b), only(&a), "whatever the order");
        // Someone else's edit is ignored, and not even kept.
        assert_eq!(a.take(BOB, edit(4, 40, 1, "hijacked"), NOW), Taken::Ignored);
        assert_eq!(only(&a).0, "third");
    }

    #[test]
    fn a_delete_takes_its_edits_and_beats_late_copies() {
        let mut chat = Chat::new(ME);
        chat.take(ALICE, text(1, 10, 1), NOW);
        chat.take(ALICE, edit(2, 20, 1, "edited"), NOW);
        chat.take(BOB, react(3, 30, 1, "🎉", true), NOW);
        // Only the author deletes for everyone.
        assert_eq!(chat.take(BOB, delete(4, 40, 1, true), NOW), Taken::Ignored);
        assert_eq!(chat.take(ALICE, delete(5, 50, 1, true), NOW), Taken::Shown);
        assert!(chat.messages().is_empty());
        let mut wiped = chat.take_scrub();
        wiped.sort();
        assert_eq!(
            wiped,
            [[1; 16], [2; 16], [3; 16]],
            "the message, its edit and its reaction"
        );
        // A late copy, edit or reaction changes nothing and isn't kept.
        assert_eq!(chat.take(ALICE, text(1, 10, 1), NOW), Taken::Duplicate);
        assert_eq!(
            chat.take(ALICE, edit(6, 60, 1, "back"), NOW),
            Taken::Ignored
        );
        assert_eq!(
            chat.take(BOB, react(7, 70, 1, "👀", true), NOW),
            Taken::Ignored
        );
        assert!(chat.messages().is_empty());

        // A delete that comes first: the message never shows, nor is stored.
        let mut early = Chat::new(ME);
        early.take(ALICE, delete(5, 50, 1, true), NOW);
        assert_eq!(early.take(ALICE, text(1, 10, 1), NOW), Taken::Ignored);
        assert!(early.messages().is_empty());
        // But a forged early delete from someone else doesn't hide it.
        let mut forged = Chat::new(ME);
        forged.take(BOB, delete(5, 50, 1, true), NOW);
        assert_eq!(forged.take(ALICE, text(1, 10, 1), NOW), Taken::Shown);
        assert_eq!(only(&forged).0, "message 1");
        assert_eq!(forged.take_scrub(), [[5; 16]], "the forged delete goes");
    }

    #[test]
    fn delete_for_me_comes_only_from_my_devices() {
        let mine = Sender {
            person: ME,
            device: [10; 32],
        };
        let mut chat = Chat::new(ME);
        chat.take(ALICE, text(1, 10, 1), NOW);
        assert_eq!(chat.take(BOB, delete(2, 20, 1, false), NOW), Taken::Ignored);
        assert_eq!(chat.take(mine, delete(3, 30, 1, false), NOW), Taken::Shown);
        assert!(chat.messages().is_empty());
    }

    #[test]
    fn reactions_are_per_person_and_emoji() {
        let mut chat = Chat::new(ME);
        chat.take(ALICE, text(1, 10, 1), NOW);
        chat.take(BOB, react(2, 20, 1, "👍", true), NOW);
        chat.take(ALICE, react(3, 30, 1, "👍", true), NOW);
        assert_eq!(only(&chat).2, [("👍".into(), 2)]);
        // An older "off" loses to a newer "on".
        chat.take(BOB, react(4, 15, 1, "👍", false), NOW);
        assert_eq!(only(&chat).2, [("👍".into(), 2)]);
        chat.take(BOB, react(5, 40, 1, "👍", false), NOW);
        assert_eq!(only(&chat).2, [("👍".into(), 1)]);
        for i in 0..MAX_REACTIONS as u8 + 1 {
            chat.take(
                BOB,
                react(100 + i, 50 + u64::from(i), 1, &format!("e{i}"), true),
                NOW,
            );
        }
        assert_eq!(only(&chat).2.len(), MAX_REACTIONS, "at most 20 different");
    }

    #[test]
    fn group_changes_in_the_chat() {
        use crate::event::{Change, GroupChange};
        let mut chat = Chat::new(ME);
        let id = crate::group_id(&ALICE.person, &[3; 16]);
        assert_eq!(chat.group(&id), None);
        let create = Body::Group(GroupChange {
            after: None,
            change: Change::Create {
                name: "hike".into(),
                members: vec![ME, BOB.person],
                nonce: [3; 16],
            },
            signed: None,
        });
        let rename = Body::Group(GroupChange {
            after: Some([1; 16]),
            change: Change::Rename("trip".into()),
            signed: None,
        });
        // The rename comes first and waits for the creation.
        chat.take(BOB, body(2, 20, rename), NOW);
        chat.take(ALICE, body(1, 10, create), NOW);
        let group = chat.group(&id).unwrap();
        assert_eq!(
            (group.creator, group.name.as_str(), group.members.len()),
            (ALICE.person, "trip", 3)
        );
        assert!(chat.messages().is_empty(), "changes aren't messages");
    }

    #[test]
    fn late_and_low_counts_as_unread() {
        let mut chat = Chat::new(ME);
        chat.take(ALICE, text(1, 10, 1), NOW);
        chat.take(ALICE, text(3, 30, 2), NOW);
        assert_eq!(chat.unread(), 2);
        chat.mark_read(&[3; 16]);
        assert_eq!(chat.unread(), 0);
        // Bob's message sorts above the marker, by an old seq: still unread.
        assert_eq!(chat.take(BOB, text(2, 20, 1), NOW), Taken::Shown);
        assert!(chat.is_late(&[2; 16]));
        assert_eq!(chat.unread(), 1);
        chat.mark_read(&[3; 16]);
        assert_eq!(chat.unread(), 0);
        // Our own messages are never unread.
        let mine = Sender {
            person: ME,
            device: [10; 32],
        };
        chat.take(mine, text(4, 40, 1), NOW);
        assert_eq!(chat.unread(), 0);
    }
}
