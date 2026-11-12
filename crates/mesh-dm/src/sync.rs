//! What each device gets next (SPEC-dm D5, D8). Every event this device
//! stores gets a number, 1, 2, 3, in stored order (`Log`). For each device
//! it sends to, it keeps a counter: the number up to which that device has
//! acknowledged everything meant for it. One mechanism covers delivery to
//! friends, retries, and catching up our own devices.
//!
//! A friend's device gets only our own events in chats we share with them,
//! for up to 30 days and 2,000 events; past that they're given up for that
//! device. Our own devices get everything, except what came from them.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::event::EventId;
use crate::store::Conversation;
use crate::{Device, Person};

/// How long a friend's device is waited for, in milliseconds (D5).
pub const FRIEND_WAIT: u64 = 30 * 24 * 3600 * 1000;
/// How far behind a friend's device may fall, in events (D5).
pub const FRIEND_BEHIND: usize = 2000;

/// One stored event, as the counters need it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: EventId,
    pub chat: Conversation,
    pub author: Person,
    /// The device it came from (ours, for our own events).
    pub from: Device,
    /// When it was stored, in milliseconds.
    pub at: u64,
    /// For our own devices only: "read up to here", "delete for me".
    pub private: bool,
    /// A group change: every member gets these, whenever they joined.
    pub change: bool,
}

/// The stored events in order.
// ponytail: all in memory, about 150 bytes an event with History's places (15 MB at 100,000, 150 MB at a million); past about a million, keep the IDs and places on disk and page the entries.
#[derive(Default, Serialize, Deserialize)]
pub struct Log {
    entries: Vec<Entry>,
    /// Each event's number, by ID: what refuses a late copy.
    #[serde(skip)]
    ids: HashMap<EventId, u64>,
    /// The numbers of group changes, which a device may come to need after
    /// its counter has passed them (someone added to a group, D7).
    #[serde(skip)]
    changes: Vec<u64>,
}

impl Log {
    /// Numbers a newly stored event; `None` if it's already here.
    pub fn take(&mut self, entry: Entry) -> Option<u64> {
        if self.ids.contains_key(&entry.id) {
            return None;
        }
        self.ids.insert(entry.id, self.len() + 1);
        if entry.change {
            self.changes.push(self.len() + 1);
        }
        self.entries.push(entry);
        Some(self.len())
    }

    pub fn get(&self, number: u64) -> Option<&Entry> {
        let index = usize::try_from(number.checked_sub(1)?).ok()?;
        self.entries.get(index)
    }

    /// The number an event was stored under, if it's here.
    pub fn number_of(&self, id: &EventId) -> Option<u64> {
        self.ids.get(id).copied()
    }

    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// After loading: rebuilds what isn't saved.
    pub fn loaded(mut self) -> Self {
        self.ids = (self.entries.iter().enumerate())
            .map(|(i, e)| (e.id, i as u64 + 1))
            .collect();
        self.changes = (self.entries.iter().enumerate())
            .filter(|(_, e)| e.change)
            .map(|(i, _)| i as u64 + 1)
            .collect();
        self
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Counter {
    person: Person,
    /// Everything up to here is acknowledged (or not meant for it).
    upto: u64,
    /// Acknowledged past `upto`.
    above: BTreeSet<u64>,
    /// Given up for this device (past the friend limits): never "sent".
    // ponytail: kept for good; only a friend's device away 30 days or 2,000 events behind adds to it.
    given_up: BTreeSet<u64>,
    /// Group changes this device took. A change can come to be meant for a
    /// device after its counter passed it (its person added to a group), so
    /// these are tracked one by one; they're few.
    changes_taken: BTreeSet<u64>,
}

/// What to send a device now, and what's given up for it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outgoing {
    /// Numbers to send, chats with the newest events first, each chat in
    /// stored order (D2).
    pub send: Vec<u64>,
    /// Past the friend limits: marked as not delivered to this device.
    pub given_up: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct Counters {
    me: Person,
    devices: HashMap<Device, Counter>,
}

impl Counters {
    pub fn new(me: Person) -> Self {
        Self {
            me,
            devices: HashMap::new(),
        }
    }

    /// A device we'll send to. One of ours starts from nothing; a friend's
    /// starts at the lowest counter of their other devices, so a reinstall
    /// or a new device misses nothing still waiting for them.
    pub fn add_device(&mut self, device: Device, person: Person) {
        if self.devices.contains_key(&device) {
            return;
        }
        let upto = if person == self.me {
            0
        } else {
            let others = self.devices.values().filter(|c| c.person == person);
            others.map(|c| c.upto).min().unwrap_or(0)
        };
        let counter = Counter {
            person,
            upto,
            above: BTreeSet::new(),
            given_up: BTreeSet::new(),
            changes_taken: BTreeSet::new(),
        };
        self.devices.insert(device, counter);
    }

    /// Whether a device of someone in that event's chat, other than us, has
    /// acknowledged it: what "sent" means (D5). A counter also moves past
    /// events that weren't for it, and past ones given up for it; neither
    /// counts.
    pub fn taken_by_others(
        &self,
        number: u64,
        log: &Log,
        shares: impl Fn(&Entry, u64, &Person) -> bool,
    ) -> bool {
        let Some(e) = log.get(number) else {
            return false;
        };
        let theirs = self.devices.values().filter(|c| {
            c.person != self.me && e.author == self.me && !e.private && shares(e, number, &c.person)
        });
        let mut theirs = theirs;
        theirs.any(|c| {
            !c.given_up.contains(&number) && (c.upto >= number || c.above.contains(&number))
        })
    }

    pub fn counter(&self, device: &Device) -> Option<u64> {
        self.devices.get(device).map(|c| c.upto)
    }

    /// Whether `device` has acknowledged event `number` (or it wasn't for
    /// it): its counter is past it, or it's acknowledged above.
    pub fn has_ok(&self, device: &Device, number: u64) -> bool {
        self.devices
            .get(device)
            .is_some_and(|c| number <= c.upto || c.above.contains(&number))
    }

    /// What `device` gets next. `shares` says whether a chat includes a
    /// person; `now` is in milliseconds.
    pub fn to_send(
        &mut self,
        device: &Device,
        log: &Log,
        shares: impl Fn(&Entry, u64, &Person) -> bool,
        now: u64,
    ) -> Outgoing {
        let me = self.me;
        let Some(counter) = self.devices.get_mut(device) else {
            return Outgoing::default();
        };
        let meant = |n: u64| meant_for(log, n, device, counter.person, me, &shares);
        let mut waiting: Vec<u64> = (counter.upto + 1..=log.len())
            .filter(|n| !counter.above.contains(n) && meant(*n))
            .collect();
        // Group changes behind the counter that are meant for it now.
        let behind = log
            .changes
            .iter()
            .copied()
            .take_while(|n| *n <= counter.upto);
        let behind: Vec<u64> = behind
            .filter(|n| !counter.changes_taken.contains(n) && meant(*n))
            .collect();
        waiting.splice(0..0, behind);
        let mut given_up = Vec::new();
        if counter.person != me {
            let (old, kept): (Vec<u64>, Vec<u64>) = waiting.into_iter().partition(|&n| {
                log.get(n)
                    .is_some_and(|e| e.at.saturating_add(FRIEND_WAIT) < now)
            });
            given_up = old;
            let over = kept.len().saturating_sub(FRIEND_BEHIND);
            given_up.extend(&kept[..over]);
            given_up.sort_unstable();
            waiting = kept[over..].to_vec();
        }
        counter.above.extend(&given_up);
        counter.given_up.extend(&given_up);
        let person = counter.person;
        advance(counter, log, |n| {
            meant_for(log, n, device, person, me, &shares)
        });
        Outgoing {
            send: newest_chat_first(log, waiting),
            given_up,
        }
    }

    /// The device answered for event `number`: `ok` once it stored it.
    pub fn acked(
        &mut self,
        device: &Device,
        number: u64,
        ok: bool,
        log: &Log,
        shares: impl Fn(&Entry, u64, &Person) -> bool,
    ) {
        let me = self.me;
        let Some(counter) = self.devices.get_mut(device) else {
            return;
        };
        if ok && log.get(number).is_some_and(|e| e.change) {
            counter.changes_taken.insert(number);
        }
        if ok && number > counter.upto {
            counter.above.insert(number);
        }
        let person = counter.person;
        advance(counter, log, |n| {
            meant_for(log, n, device, person, me, &shares)
        });
    }
}

/// Whether event `n` is meant for `device`, of `person`.
fn meant_for(
    log: &Log,
    n: u64,
    device: &Device,
    person: Person,
    me: Person,
    shares: &impl Fn(&Entry, u64, &Person) -> bool,
) -> bool {
    let Some(e) = log.get(n) else { return false };
    if person == me {
        e.from != *device
    } else {
        // Our own events; and a group's changes, whoever made them, so a
        // member can pass them on to one who lacks them (D7).
        (e.author == me || e.change) && e.author != person && !e.private && shares(e, n, &person)
    }
}

/// Moves the counter past everything acknowledged or not meant for it.
fn advance(counter: &mut Counter, log: &Log, meant: impl Fn(u64) -> bool) {
    while counter.upto < log.len() {
        let next = counter.upto + 1;
        if !counter.above.remove(&next) && meant(next) {
            break;
        }
        counter.upto = next;
    }
}

/// `numbers` grouped by chat, the chat with the newest event first, each
/// chat in stored order.
fn newest_chat_first(log: &Log, numbers: Vec<u64>) -> Vec<u64> {
    let mut chats: BTreeMap<Conversation, Vec<u64>> = BTreeMap::new();
    for n in numbers {
        if let Some(e) = log.get(n) {
            chats.entry(e.chat).or_default().push(n);
        }
    }
    let mut chats: Vec<Vec<u64>> = chats.into_values().collect();
    chats.sort_by_key(|c| std::cmp::Reverse(c.last().copied()));
    chats.concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const ME: Person = [1; 32];
    const BOB: Person = [2; 32];
    const DESK: Device = [10; 32];
    const LAPTOP: Device = [11; 32];
    const NEW: Device = [12; 32];
    const BOB_1: Device = [20; 32];
    const BOB_2: Device = [21; 32];
    const BOB_3: Device = [22; 32];
    const WITH_BOB: Conversation = [5; 16];
    const ALONE: Conversation = [6; 16];

    fn entry(id: u16, chat: Conversation, author: Person, from: Device, at: u64) -> Entry {
        let mut bytes = [0; 16];
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        Entry {
            id: bytes,
            chat,
            author,
            from,
            at,
            private: false,
            change: false,
        }
    }

    fn shares(e: &Entry, _: u64, person: &Person) -> bool {
        e.chat == WITH_BOB && *person == BOB
    }

    fn all(_: &Entry, _: u64, _: &Person) -> bool {
        true
    }

    /// Sends `from`'s log to `to` until nothing is left, acking each one.
    fn catch_up(from: &Log, counters: &mut Counters, to_device: Device, to: &mut Log, by: Device) {
        loop {
            let out = counters.to_send(&to_device, from, all, NOW);
            if out.send.is_empty() {
                return;
            }
            for n in out.send {
                let mut e = from.get(n).unwrap().clone();
                e.from = by;
                to.take(e);
                counters.acked(&to_device, n, true, from, all);
            }
        }
    }

    /// postcard isn't self-describing: reading what an older version wrote,
    /// a field added since can't be filled by `#[serde(default)]`. That's
    /// why the saved formats carry a number instead (history.rs).
    #[test]
    fn serde_default_does_nothing_with_postcard() {
        #[derive(Serialize)]
        struct Old {
            a: u8,
        }
        #[derive(Deserialize, Debug)]
        struct New {
            #[allow(dead_code)]
            a: u8,
            #[serde(default)]
            #[allow(dead_code)]
            b: u8,
        }
        let bytes = postcard::to_stdvec(&Old { a: 1 }).unwrap();
        assert!(postcard::from_bytes::<New>(&bytes).is_err());
    }

    #[test]
    fn duplicates_get_no_number() {
        let mut log = Log::default();
        assert_eq!(log.take(entry(1, ALONE, ME, DESK, NOW)), Some(1));
        assert_eq!(log.take(entry(1, ALONE, ME, DESK, NOW)), None);
        assert_eq!(log.take(entry(2, ALONE, ME, DESK, NOW)), Some(2));
        let saved = postcard::to_stdvec(&log).unwrap();
        let mut back = postcard::from_bytes::<Log>(&saved).unwrap().loaded();
        assert_eq!(back.take(entry(2, ALONE, ME, DESK, NOW)), None);
    }

    #[test]
    fn two_own_devices_with_gaps_converge() {
        let (mut desk, mut laptop) = (Log::default(), Log::default());
        for i in 0..5 {
            desk.take(entry(i, ALONE, ME, DESK, NOW));
        }
        for i in 3..9 {
            laptop.take(entry(i, WITH_BOB, ME, LAPTOP, NOW));
        }
        let (mut on_desk, mut on_laptop) = (Counters::new(ME), Counters::new(ME));
        on_desk.add_device(LAPTOP, ME);
        on_laptop.add_device(DESK, ME);
        catch_up(&desk, &mut on_desk, LAPTOP, &mut laptop, DESK);
        catch_up(&laptop, &mut on_laptop, DESK, &mut desk, LAPTOP);
        assert_eq!((desk.len(), laptop.len()), (9, 9), "ids 3 and 4 came twice");
        // Nothing goes back where it came from.
        let out = on_desk.to_send(&LAPTOP, &desk, all, NOW);
        assert_eq!(out, Outgoing::default());
    }

    #[test]
    fn a_new_device_gets_everything_newest_chat_first() {
        let mut log = Log::default();
        log.take(entry(1, ALONE, ME, DESK, NOW));
        log.take(entry(2, WITH_BOB, BOB, BOB_1, NOW));
        log.take(entry(3, ALONE, ME, DESK, NOW));
        log.take(entry(4, WITH_BOB, ME, DESK, NOW));
        let mut counters = Counters::new(ME);
        counters.add_device(NEW, ME);
        assert_eq!(counters.counter(&NEW), Some(0));
        let out = counters.to_send(&NEW, &log, all, NOW);
        // The chat with Bob has the newest event: its events first, in order.
        assert_eq!(out.send, [2, 4, 1, 3]);
    }

    #[test]
    fn the_counter_stops_at_a_failure() {
        let mut log = Log::default();
        for i in 1..=3 {
            log.take(entry(i, ALONE, ME, DESK, NOW));
        }
        let mut counters = Counters::new(ME);
        counters.add_device(LAPTOP, ME);
        assert_eq!(counters.to_send(&LAPTOP, &log, all, NOW).send, [1, 2, 3]);
        counters.acked(&LAPTOP, 1, true, &log, all);
        counters.acked(&LAPTOP, 2, false, &log, all);
        counters.acked(&LAPTOP, 3, true, &log, all);
        assert_eq!(counters.counter(&LAPTOP), Some(1));
        let oks: Vec<bool> = (1..=3).map(|n| counters.has_ok(&LAPTOP, n)).collect();
        assert_eq!(oks, [true, false, true], "1 by the counter, 3 above it");
        assert!(!counters.has_ok(&DESK, 1), "a device we don't send to");
        assert_eq!(
            counters.to_send(&LAPTOP, &log, all, NOW).send,
            [2],
            "only the failed one"
        );
        counters.acked(&LAPTOP, 2, true, &log, all);
        assert_eq!(counters.counter(&LAPTOP), Some(3));
    }

    #[test]
    fn a_friend_gets_only_our_events_in_chats_with_them() {
        let mut log = Log::default();
        log.take(entry(1, ALONE, ME, DESK, NOW));
        log.take(entry(2, WITH_BOB, BOB, BOB_1, NOW));
        log.take(entry(3, WITH_BOB, ME, DESK, NOW));
        let mut counters = Counters::new(ME);
        counters.add_device(BOB_1, BOB);
        assert_eq!(counters.to_send(&BOB_1, &log, shares, NOW).send, [3]);
        counters.acked(&BOB_1, 3, true, &log, shares);
        assert_eq!(counters.counter(&BOB_1), Some(3), "the rest wasn't for Bob");
    }

    #[test]
    fn a_friends_new_device_starts_at_their_lowest_counter() {
        let mut log = Log::default();
        for i in 1..=6 {
            log.take(entry(i, WITH_BOB, ME, DESK, NOW));
        }
        let mut counters = Counters::new(ME);
        counters.add_device(BOB_1, BOB);
        counters.add_device(BOB_2, BOB);
        for n in 1..=5 {
            counters.acked(&BOB_1, n, true, &log, shares);
        }
        for n in 1..=3 {
            counters.acked(&BOB_2, n, true, &log, shares);
        }
        counters.add_device(BOB_3, BOB);
        assert_eq!(counters.counter(&BOB_3), Some(3));
        assert_eq!(counters.to_send(&BOB_3, &log, shares, NOW).send, [4, 5, 6]);
    }

    #[test]
    fn past_the_friend_limits_events_are_given_up() {
        let mut log = Log::default();
        log.take(entry(0, WITH_BOB, ME, DESK, NOW - FRIEND_WAIT - 1));
        for i in 1..=FRIEND_BEHIND as u16 + 100 {
            log.take(entry(i, WITH_BOB, ME, DESK, NOW));
        }
        let mut counters = Counters::new(ME);
        counters.add_device(BOB_1, BOB);
        let out = counters.to_send(&BOB_1, &log, shares, NOW);
        assert_eq!(out.send.len(), FRIEND_BEHIND);
        assert_eq!(
            out.given_up.len(),
            101,
            "the old one and the 100 oldest past 2,000"
        );
        assert_eq!(out.send[0], 102);
        assert_eq!(counters.counter(&BOB_1), Some(101));
        // Our own devices have no such limit.
        counters.add_device(LAPTOP, ME);
        let own = counters.to_send(&LAPTOP, &log, all, NOW);
        assert_eq!(
            (own.send.len(), own.given_up.len()),
            (FRIEND_BEHIND + 101, 0)
        );
    }
}
