//! The account state (SPEC-social D8, D11, D13, D14): everyone you've
//! friended, asked, been asked by, blocked or removed, and your chosen status.
//! It's the same on every device of yours: a last-writer-wins map keyed by ID,
//! each entry stamped `(changed, by)` (time, then device key to break ties).
//! Removals stay as tombstones for 90 days so an old copy can't bring them
//! back.

use serde::{Deserialize, Serialize};

use crate::id::MeshId;

/// How long a `removed` tombstone is kept.
pub const TOMBSTONE_LIFE: u64 = 90 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// You asked them, or added their ID; they haven't connected yet.
    Outgoing,
    Friend,
    /// They asked you; not let in until you accept.
    Incoming,
    Blocked,
    /// A tombstone, so the removal syncs.
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Online,
    Idle,
    Dnd,
    Invisible,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Online => "online",
            Status::Idle => "idle",
            Status::Dnd => "dnd",
            Status::Invisible => "invisible",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Status::Online, Status::Idle, Status::Dnd, Status::Invisible]
            .into_iter()
            .find(|s| s.as_str() == text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    id: [u8; 32],
    pub kind: Kind,
    /// Your name for them; empty if you haven't set one.
    pub nick: String,
    /// The name they gave themselves (from their request): a hint only.
    pub name: String,
    /// Their request's note.
    pub note: String,
    pub verified: bool,
    /// When they entered this kind (the request's time, the add).
    pub at: u64,
    changed: u64,
    by: [u8; 32],
}

impl Entry {
    pub fn id(&self) -> MeshId {
        MeshId::from_bytes(&self.id).expect("checked when added or merged")
    }

    fn stamp(&self) -> (u64, [u8; 32]) {
        (self.changed, self.by)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    entries: Vec<Entry>,
    status: Status,
    status_stamp: (u64, [u8; 32]),
}

impl Default for Account {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            status: Status::Online,
            status_stamp: (0, [0; 32]),
        }
    }
}

impl Account {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: &MeshId) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id.to_bytes())
    }

    pub fn kind(&self, id: &MeshId) -> Option<Kind> {
        self.get(id).map(|e| e.kind)
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// Whether every ID is a valid key (checked on load and merge).
    pub(crate) fn valid(&self) -> bool {
        self.entries
            .iter()
            .all(|e| MeshId::from_bytes(&e.id).is_ok())
    }

    /// A change made on this device (`by`) at `now`: the entry for `id`
    /// (a new `removed` one if there's none) goes through `f`, then gets a
    /// stamp later than its last, even if this clock is behind.
    pub fn change(&mut self, id: &MeshId, by: [u8; 32], now: u64, f: impl FnOnce(&mut Entry)) {
        let index = match self.entries.iter().position(|e| e.id == id.to_bytes()) {
            Some(i) => i,
            None => {
                self.entries.push(Entry {
                    id: id.to_bytes(),
                    kind: Kind::Removed,
                    nick: String::new(),
                    name: String::new(),
                    note: String::new(),
                    verified: false,
                    at: now,
                    changed: 0,
                    by,
                });
                self.entries.len() - 1
            }
        };
        let entry = &mut self.entries[index];
        f(entry);
        entry.changed = now.max(entry.changed + 1);
        entry.by = by;
    }

    pub fn set_status(&mut self, status: Status, by: [u8; 32], now: u64) {
        self.status = status;
        self.status_stamp = (now.max(self.status_stamp.0 + 1), by);
    }

    /// Takes whatever is newer in `other`, entry by entry. True if anything
    /// changed here. An entry we don't have that would let someone in, last
    /// changed a tombstone's life ago, isn't taken: we may have removed them
    /// and since dropped the tombstone (audit finding 14).
    pub fn merge(&mut self, other: &Account, now: u64) -> bool {
        let mut changed = false;
        for theirs in &other.entries {
            match self.entries.iter_mut().find(|e| e.id == theirs.id) {
                Some(ours) if ours.stamp() >= theirs.stamp() => {}
                Some(ours) => {
                    *ours = theirs.clone();
                    changed = true;
                }
                None if theirs.kind != Kind::Blocked
                    && theirs.changed.saturating_add(TOMBSTONE_LIFE) <= now => {}
                None => {
                    self.entries.push(theirs.clone());
                    changed = true;
                }
            }
        }
        if other.status_stamp > self.status_stamp {
            self.status = other.status;
            self.status_stamp = other.status_stamp;
            changed = true;
        }
        changed
    }

    /// Drops tombstones older than [`TOMBSTONE_LIFE`].
    pub fn prune(&mut self, now: u64) {
        self.entries
            .retain(|e| e.kind != Kind::Removed || e.changed + TOMBSTONE_LIFE > now);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.status_stamp.0 == 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("serialising to memory")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes::<Self>(bytes).ok().filter(Self::valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RootKey;

    const DESK: [u8; 32] = [1; 32];
    const LAPTOP: [u8; 32] = [2; 32];

    fn id() -> MeshId {
        RootKey::generate().unwrap().id()
    }

    fn kind(kind: Kind) -> impl FnOnce(&mut Entry) {
        move |e| e.kind = kind
    }

    #[test]
    fn newer_wins_and_merging_is_order_free() {
        let (alice, bob) = (id(), id());
        let mut desk = Account::default();
        desk.change(&alice, DESK, 100, kind(Kind::Friend));
        desk.change(&bob, DESK, 100, kind(Kind::Outgoing));
        let mut laptop = Account::default();
        laptop.change(&alice, LAPTOP, 200, kind(Kind::Removed));
        laptop.change(&bob, LAPTOP, 50, kind(Kind::Blocked));
        laptop.set_status(Status::Dnd, LAPTOP, 10);

        let mut a = desk.clone();
        assert!(a.merge(&laptop, 0));
        let mut b = laptop.clone();
        b.merge(&desk, 0);
        // Same entries whichever way round (order in the list aside).
        for who in [&alice, &bob] {
            assert_eq!(a.get(who), b.get(who));
        }
        assert_eq!(a.kind(&alice), Some(Kind::Removed));
        assert_eq!(a.kind(&bob), Some(Kind::Outgoing));
        assert_eq!((a.status(), b.status()), (Status::Dnd, Status::Dnd));

        // Idempotent.
        let before = a.clone();
        assert!(!a.merge(&laptop, 0));
        assert!(!a.merge(&before, 0));
        assert_eq!(a, before);
    }

    #[test]
    fn ties_go_to_the_higher_device_and_local_changes_move_forward() {
        let alice = id();
        let mut desk = Account::default();
        desk.change(&alice, DESK, 100, kind(Kind::Friend));
        let mut laptop = Account::default();
        laptop.change(&alice, LAPTOP, 100, kind(Kind::Blocked));
        let mut a = desk.clone();
        a.merge(&laptop, 0);
        assert_eq!(a.kind(&alice), Some(Kind::Blocked));
        laptop.merge(&desk, 0);
        assert_eq!(laptop.kind(&alice), Some(Kind::Blocked));

        // A device whose clock is behind still makes a newer change.
        a.change(&alice, DESK, 5, kind(Kind::Friend));
        let mut b = laptop.clone();
        assert!(b.merge(&a, 0));
        assert_eq!(b.kind(&alice), Some(Kind::Friend));
    }

    #[test]
    fn tombstones_beat_older_adds_and_expire() {
        let alice = id();
        let mut old = Account::default();
        old.change(&alice, DESK, 100, kind(Kind::Friend));
        let mut new = Account::default();
        new.change(&alice, LAPTOP, 200, kind(Kind::Removed));
        let mut merged = new.clone();
        assert!(!merged.merge(&old, 0));
        assert_eq!(merged.kind(&alice), Some(Kind::Removed));

        merged.prune(200 + TOMBSTONE_LIFE - 1);
        assert_eq!(merged.kind(&alice), Some(Kind::Removed));
        merged.prune(200 + TOMBSTONE_LIFE);
        assert_eq!(merged.kind(&alice), None);
        // Other kinds are never pruned.
        old.prune(u64::MAX / 2);
        assert_eq!(old.kind(&alice), Some(Kind::Friend));
    }

    /// A laptop unused past a tombstone's life still says "friend" about
    /// someone the desk removed and has since forgotten removing. That
    /// mustn't bring them back (audit finding 14).
    #[test]
    fn a_stale_device_cant_bring_back_an_expired_removal() {
        let (alice, eve) = (id(), id());
        let mut laptop = Account::default();
        laptop.change(&alice, LAPTOP, 100, kind(Kind::Friend));
        laptop.change(&eve, LAPTOP, 100, kind(Kind::Blocked));
        let mut desk = Account::default();
        let now = 100 + TOMBSTONE_LIFE;
        // Its tombstone for Alice is gone: it has no entry at all.
        assert!(desk.merge(&laptop, now));
        assert_eq!(desk.kind(&alice), None, "an old friend came back");
        // A block only ever keeps someone out: it still comes across.
        assert_eq!(desk.kind(&eve), Some(Kind::Blocked));
        // A recent add still does, as does one we already hold.
        laptop.change(&alice, LAPTOP, now, kind(Kind::Friend));
        assert!(desk.merge(&laptop, now));
        assert_eq!(desk.kind(&alice), Some(Kind::Friend));
    }

    #[test]
    fn bytes_round_trip_and_bad_ids_are_refused() {
        let mut a = Account::default();
        a.change(&id(), DESK, 1, kind(Kind::Incoming));
        assert_eq!(Account::from_bytes(&a.to_bytes()), Some(a.clone()));
        a.entries[0].id = (0..=255u8)
            .map(|b| [b; 32])
            .find(|b| MeshId::from_bytes(b).is_err())
            .unwrap();
        assert!(!a.valid());
        assert_eq!(Account::from_bytes(&a.to_bytes()), None);
    }
}
