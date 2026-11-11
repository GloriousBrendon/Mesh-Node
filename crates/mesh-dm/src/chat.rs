//! Folding events into a chat (SPEC-dm D2–D4, D7). Pure: the caller passes
//! who sent each event (as e2ee checked it) and its own clock, and stores
//! what this says to keep.
//!
//! Order (D2): `seq` never runs ahead of the clock. A reader checks each
//! event against its own clock and the sending device's earlier events,
//! never against the highest `seq` it holds, so nothing anyone sends or
//! withholds can push a reader out of range.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::event::{Event, EventId};
use crate::{Device, Person, Sender};

/// How far ahead of the reader's clock an event may be and still show (D2).
pub const AHEAD_SHOWN: u64 = 5 * 60 * 1000;
/// Further ahead than this, an event is dropped (D2).
pub const AHEAD_DROPPED: u64 = 24 * 3600 * 1000;
/// Events from one device that may wait for the clock at once (D2).
pub const MAX_WAITING: usize = 1000;
/// A sender time this far past its arrival shows as the arrival (D2).
pub const DISPLAY_CLAMP: u64 = 5 * 60 * 1000;

/// Where an event sits in the chat: by `seq`, then event ID.
pub type Position = (u64, EventId);

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
        }
    }

    /// The `seq` for this device's next event: one more than the highest
    /// held that isn't ahead of `now` (D2).
    pub fn next_seq(&self, now: u64) -> u64 {
        let held = self.held.values().map(|h| h.event.seq);
        held.filter(|&seq| seq <= now).max().unwrap_or(0) + 1
    }

    /// Takes in an event from `from`, at the reader's clock `now`.
    pub fn take(&mut self, from: Sender, event: Event, now: u64) -> Taken {
        if self.held.contains_key(&event.id) {
            return Taken::Duplicate;
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
                received: now,
                waiting,
            },
        );
        if waiting {
            return Taken::Waiting;
        }
        self.show(id);
        Taken::Shown
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

    /// Puts a held event in the chat.
    fn show(&mut self, id: EventId) {
        let held = &self.held[&id];
        let at = (held.event.seq, id);
        let others = held.sender.person != self.me;
        if others && self.read.is_some_and(|read| at <= read) {
            self.late.insert(id);
        }
        self.shown.insert(at);
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
        let theirs = |(_, id): &&Position| self.held[id].sender.person != self.me;
        let new = self.shown.iter().filter(after).filter(theirs).count();
        new + self.late.len()
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
        assert_eq!(chat.next_seq(NOW), 1, "a new chat");
        chat.take(ALICE, text(1, NOW - 10, 1), NOW);
        assert_eq!(chat.next_seq(NOW), NOW - 9);
        // A forger's jump, still within the 5 minutes: shown, not taken up.
        chat.take(BOB, text(2, NOW + 60_000, 1), NOW);
        assert_eq!(chat.next_seq(NOW), NOW - 9);
        // Once the clock passes it, it is.
        assert_eq!(chat.next_seq(NOW + 60_000), NOW + 60_001);
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
        let seq = bob_view.next_seq(NOW);
        assert_eq!(seq, NOW - 999, "the jump didn't carry");
        assert_eq!(left_out.take(BOB, text(2, seq, 1), NOW), Taken::Shown);
        // Even after the clocks pass the jump, Bob's next is within range.
        let later = NOW + AHEAD_SHOWN + 1;
        let seq = bob_view.next_seq(later);
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
