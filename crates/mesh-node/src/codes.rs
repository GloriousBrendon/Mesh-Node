//! The friend codes a seed holds (SPEC-seed D7–D10). Records are identity's
//! `HeldCode`s: a lookup ID and ciphertext, so the store never knows whose
//! code it holds. It keeps no record of who held or fetched what; the rate
//! counters live in memory for a minute or an hour.
//!
//! Pure: callers pass the time and who's asking, and save when `dirty`.

use crate::saved::{self, StoreError};
use mesh_identity::{CodeRevoke, HeldCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Lookups one device may make a minute.
pub const LOOKUPS_PER_DEVICE: u32 = 10;
/// Lookups one network (/24 or /48) may make a minute.
pub const LOOKUPS_PER_NETWORK: u32 = 30;
/// Lookups everyone reaching the seed through a relay may make a minute,
/// together: half the total, so direct callers keep the rest.
pub const LOOKUPS_RELAYED: u32 = LOOKUPS_TOTAL / 2;
/// Lookups everyone together may make a minute.
pub const LOOKUPS_TOTAL: u32 = 600;
/// New codes one device may hold an hour.
pub const HOLDS_PER_DEVICE: u32 = 20;
/// Holds, new or again, one network may make an hour.
pub const HOLDS_PER_NETWORK: u32 = 60;
/// Holds everyone reaching the seed through a relay may make an hour, together.
pub const HOLDS_RELAYED: u32 = 1000;
/// How long a held code stays after its last hold, whatever its own expiry:
/// junk drains by itself, and owners hold their codes again well before
/// (audit finding 3, part 2).
pub const HOLD_LIFE: u64 = 30 * 24 * 3600;
/// Records and markers the seed keeps at most.
pub const MAX_ENTRIES: usize = 100_000;

/// The file format: 2 added each code's `until`.
const FORMAT: u8 = 2;
const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
/// The store's name in errors.
const WHAT: &str = "code";

/// Who's asking: their (throwaway) device key, and their network when the
/// connection is direct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Caller {
    pub device: [u8; 32],
    pub network: Option<[u8; 6]>,
}

impl Caller {
    /// The network limit's key and size for this caller. Through a relay the
    /// seed sees no network, and fresh keys are free, so relayed callers
    /// share one bucket of their own (audit finding 3, part 1).
    pub fn network_limit(&self, per_network: u32, relayed: u32) -> (Vec<u8>, u32) {
        match self.network {
            Some(net) => ([b"net:".as_slice(), &net].concat(), per_network),
            // 7 bytes after the prefix: never a /24 or /48's 6.
            None => (b"net:relayed".to_vec(), relayed),
        }
    }
}

/// The /24 (IPv4) or /48 (IPv6) an address is in.
pub fn network(ip: IpAddr) -> [u8; 6] {
    let mut net = [0u8; 6];
    match ip.to_canonical() {
        IpAddr::V4(v4) => net[..3].copy_from_slice(&v4.octets()[..3]),
        IpAddr::V6(v6) => net.copy_from_slice(&v6.octets()[..6]),
    }
    net
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    /// Stored, or already held for the same owner (unchanged).
    Ok = 0,
    /// The owner's code was used up or revoked.
    Gone = 1,
    /// Another owner's code has this lookup ID.
    Taken = 2,
    SlowDown = 3,
    Full = 4,
    Bad = 5,
}

impl Hold {
    /// The answer byte on the wire.
    pub fn byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        [
            Hold::Ok,
            Hold::Gone,
            Hold::Taken,
            Hold::SlowDown,
            Hold::Full,
            Hold::Bad,
        ]
        .into_iter()
        .find(|h| h.byte() == byte)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Get {
    Found(Vec<u8>),
    /// Never held, expired, used up or revoked: all look the same.
    None,
    SlowDown,
}

impl Get {
    /// On the wire: `0` and the record, `1`, or `3` (as `Hold::SlowDown`).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Get::Found(record) => [&[0][..], record].concat(),
            Get::None => vec![1],
            Get::SlowDown => vec![Hold::SlowDown.byte()],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (0, record) => Some(Get::Found(record.to_vec())),
            (1, []) => Some(Get::None),
            (3, []) => Some(Get::SlowDown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Entry {
    Live {
        held: Vec<u8>,
        /// `None` is unlimited.
        uses_left: Option<u32>,
        /// Gone at this time: the code's expiry, or [`HOLD_LIFE`] after its
        /// last hold if sooner.
        until: u64,
    },
    /// Used up or revoked: kept as long as the record would have been, so
    /// the owner holding it again can't bring it back.
    Gone { tag: [u8; 32], until: u64 },
}

impl Entry {
    fn expired(&self, now: u64) -> bool {
        match self {
            Entry::Live { until, .. } | Entry::Gone { until, .. } => *until <= now,
        }
    }

    fn tag(&self) -> [u8; 32] {
        match self {
            Entry::Live { held, .. } => held_code(held).revoke_tag(),
            Entry::Gone { tag, .. } => *tag,
        }
    }

    fn gone(&self) -> Entry {
        let (Entry::Live { until, .. } | Entry::Gone { until, .. }) = self;
        Entry::Gone {
            tag: self.tag(),
            until: *until,
        }
    }
}

/// When a code held at `now` goes.
fn until(held: &HeldCode, now: u64) -> u64 {
    let life = now.saturating_add(HOLD_LIFE);
    held.expires_at().map_or(life, |at| at.min(life))
}

/// The entries as the first file format kept them, before [`HOLD_LIFE`].
#[derive(Deserialize)]
enum EntryV1 {
    Live {
        held: Vec<u8>,
        uses_left: Option<u32>,
    },
    Gone {
        tag: [u8; 32],
        expires_at: Option<u64>,
    },
}

impl EntryV1 {
    /// As if every code was held again at `now`.
    fn upgrade(self, now: u64) -> Entry {
        match self {
            EntryV1::Live { held, uses_left } => Entry::Live {
                until: until(&held_code(&held), now),
                held,
                uses_left,
            },
            EntryV1::Gone { tag, expires_at } => {
                let life = now.saturating_add(HOLD_LIFE);
                Entry::Gone {
                    tag,
                    until: expires_at.map_or(life, |at| at.min(life)),
                }
            }
        }
    }
}

/// Live entries were checked by `HeldCode::from_bytes` when held or loaded.
fn held_code(bytes: &[u8]) -> HeldCode {
    HeldCode::from_bytes(bytes).expect("checked when stored")
}

/// Counts per key within a fixed window, reset when the window passes.
#[derive(Default)]
pub(crate) struct Window {
    started: u64,
    counts: HashMap<Vec<u8>, u32>,
}

impl Window {
    /// Counts one for every key if each is still under its limit; otherwise
    /// counts nothing.
    pub(crate) fn allow(&mut self, now: u64, length: u64, keys: &[(Vec<u8>, u32)]) -> bool {
        if now >= self.started + length {
            self.started = now;
            self.counts.clear();
        }
        if keys
            .iter()
            .any(|(key, limit)| self.counts.get(key).copied().unwrap_or(0) >= *limit)
        {
            return false;
        }
        for (key, _) in keys {
            *self.counts.entry(key.clone()).or_default() += 1;
        }
        true
    }
}

pub struct Store {
    path: PathBuf,
    entries: HashMap<[u8; 16], Entry>,
    lookups: Window,
    holds: Window,
    /// Changed since the last save.
    pub dirty: bool,
}

impl Store {
    /// Loads the store at `path`, or starts empty if there's none. A damaged
    /// file is an error, never silently replaced.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let live = |held: &Vec<u8>| HeldCode::from_bytes(held).is_ok();
        let entries = match saved::load(
            path,
            WHAT,
            FORMAT,
            |(_, e): &([u8; 16], Entry)| !matches!(e, Entry::Live { held, .. } if !live(held)),
        ) {
            Ok(entries) => entries.into_iter().collect(),
            Err(StoreError::Corrupt(..)) if saved::format(path)? == Some(1) => {
                let old = saved::load(
                    path,
                    WHAT,
                    1,
                    |(_, e): &([u8; 16], EntryV1)| !matches!(e, EntryV1::Live { held, .. } if !live(held)),
                )?;
                let now = mesh_identity::unix_now();
                let entries = old.into_iter().map(|(k, e)| (k, e.upgrade(now)));
                entries.collect()
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            path: path.to_owned(),
            entries,
            lookups: Window::default(),
            holds: Window::default(),
            dirty: false,
        })
    }

    /// Writes the store so that a crash leaves the old file or the new one.
    /// The seed writes snapshots instead, outside the lock.
    #[cfg(test)]
    pub fn save(&mut self) -> Result<(), StoreError> {
        self.snapshot().write().inspect_err(|_| self.dirty = true)
    }

    /// The file's bytes now, for writing outside the store's lock. The
    /// store counts as saved; mark it dirty again if the write fails.
    pub fn snapshot(&mut self) -> saved::Snapshot {
        self.dirty = false;
        saved::Snapshot {
            path: self.path.clone(),
            what: WHAT,
            bytes: saved::encode(FORMAT, self.entries.iter().collect()),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn hold(&mut self, caller: &Caller, bytes: &[u8], now: u64) -> Hold {
        let Ok(held) = HeldCode::from_bytes(bytes) else {
            return Hold::Bad;
        };
        if held.expires_at().is_some_and(|at| at <= now) {
            return Hold::Bad;
        }
        let lookup_id = held.lookup_id();
        let network = caller.network_limit(HOLDS_PER_NETWORK, HOLDS_RELAYED);
        if let Some(entry) = self.entries.get_mut(&lookup_id).filter(|e| !e.expired(now)) {
            return match (entry, held.revoke_tag()) {
                (entry, tag) if entry.tag() != tag => Hold::Taken,
                (Entry::Gone { .. }, _) => Hold::Gone,
                // Held again: it stays another HOLD_LIFE. Only the network
                // limits apply, so junk can't be kept alive for free.
                (Entry::Live { until: at, .. }, _) => {
                    if !self.holds.allow(now, HOUR, &[network]) {
                        return Hold::SlowDown;
                    }
                    let later = until(&held, now).max(*at);
                    self.dirty |= later != *at;
                    *at = later;
                    Hold::Ok
                }
            };
        }
        let device = (caller.device.to_vec(), HOLDS_PER_DEVICE);
        if !self.holds.allow(now, HOUR, &[device, network]) {
            return Hold::SlowDown;
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.sweep(now);
            if self.entries.len() >= MAX_ENTRIES {
                return Hold::Full;
            }
        }
        let entry = Entry::Live {
            held: bytes.to_vec(),
            uses_left: held.max_uses(),
            until: until(&held, now),
        };
        self.entries.insert(lookup_id, entry);
        self.dirty = true;
        Hold::Ok
    }

    /// Every lookup counts against the limits, found or not.
    pub fn get(&mut self, caller: &Caller, lookup_id: &[u8; 16], now: u64) -> Get {
        let mut keys = vec![
            (caller.device.to_vec(), LOOKUPS_PER_DEVICE),
            (b"total".to_vec(), LOOKUPS_TOTAL),
        ];
        keys.push(caller.network_limit(LOOKUPS_PER_NETWORK, LOOKUPS_RELAYED));
        if !self.lookups.allow(now, MINUTE, &keys) {
            return Get::SlowDown;
        }
        let Some(entry) = self.entries.get_mut(lookup_id) else {
            return Get::None;
        };
        if entry.expired(now) {
            self.entries.remove(lookup_id);
            self.dirty = true;
            return Get::None;
        }
        match entry {
            Entry::Live { held, .. } => Get::Found(held.clone()),
            Entry::Gone { .. } => Get::None,
        }
    }

    /// Uses up one of a live code's uses for a friend request (SPEC-social
    /// D1), and gives its revoke tag. `None` if no live code has that ID.
    pub fn spend(&mut self, lookup_id: &[u8; 16], now: u64) -> Option<[u8; 32]> {
        let entry = self.entries.get_mut(lookup_id)?;
        if entry.expired(now) {
            return None;
        }
        let Entry::Live { uses_left, .. } = entry else {
            return None;
        };
        match *uses_left {
            None => {}
            Some(1) => *entry = entry.gone(),
            Some(n) => *uses_left = Some(n - 1),
        }
        self.dirty = true;
        Some(entry.tag())
    }

    /// For the code's owner (who has the revoke): whether the code is still
    /// live. `None` if the seed knows no code with that ID and revoke.
    pub fn owner_status(&self, revoke: &CodeRevoke, now: u64) -> Option<bool> {
        let entry = self.entries.get(&revoke.lookup_id())?;
        (revoke.tag() == entry.tag())
            .then(|| matches!(entry, Entry::Live { .. }) && !entry.expired(now))
    }

    /// Deletes the record if the revoke is its owner's. Says nothing back
    /// either way.
    pub fn revoke(&mut self, bytes: &[u8]) {
        let Ok(revoke) = CodeRevoke::from_bytes(bytes) else {
            return;
        };
        if let Some(entry) = self.entries.get_mut(&revoke.lookup_id())
            && let Entry::Live { held, .. } = entry
            && held_code(held).is_revoked_by(&revoke)
        {
            *entry = entry.gone();
            self.dirty = true;
        }
    }

    /// Drops expired records and markers.
    pub fn sweep(&mut self, now: u64) {
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.expired(now));
        self.dirty |= self.entries.len() != before;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_identity::{FriendCode, RootKey};

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    fn caller(n: u8) -> Caller {
        Caller {
            device: [n; 32],
            network: None,
        }
    }

    fn code(root: &RootKey, expiry: Option<u64>, uses: Option<u32>) -> (FriendCode, HeldCode) {
        let code = FriendCode::generate().unwrap();
        let held = HeldCode::new(root, &code, NOW, expiry, uses).unwrap();
        (code, held)
    }

    fn store(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("mesh-codes-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store::load(&dir.join("codes.bin")).unwrap()
    }

    /// Through a relay the seed sees no network, so fresh keys alone would
    /// get round every limit but the total. Relayed callers share one
    /// bucket, and direct callers keep theirs (audit finding 3, part 1).
    fn relayed(i: u32) -> Caller {
        let mut device = [0xAA; 32];
        device[..4].copy_from_slice(&i.to_be_bytes());
        Caller {
            device,
            network: None,
        }
    }

    #[test]
    fn relayed_callers_share_one_bucket() {
        let mut s = store("relayed");
        let root = RootKey::generate().unwrap();
        let (_, held) = code(&root, None, None);
        let id = held.lookup_id();
        assert_eq!(s.hold(&caller(1), held.as_bytes(), NOW), Hold::Ok);
        for i in 0..LOOKUPS_RELAYED {
            assert!(matches!(s.get(&relayed(i), &id, NOW), Get::Found(_)));
        }
        assert_eq!(s.get(&relayed(u32::MAX), &id, NOW), Get::SlowDown);
        let direct = Caller {
            device: [9; 32],
            network: Some(network("203.0.113.9".parse().unwrap())),
        };
        assert!(matches!(s.get(&direct, &id, NOW), Get::Found(_)));
    }

    #[test]
    fn hold_get_and_open() {
        let mut s = store("basic");
        let root = RootKey::generate().unwrap();
        let (code, held) = code(&root, Some(7 * DAY), Some(5));
        assert_eq!(s.hold(&caller(1), held.as_bytes(), NOW), Hold::Ok);
        let Get::Found(bytes) = s.get(&caller(2), &held.lookup_id(), NOW) else {
            panic!("not found")
        };
        let record = HeldCode::from_bytes(&bytes)
            .unwrap()
            .open(&code, NOW)
            .unwrap();
        assert_eq!(record.root(), root.id());
        assert_eq!(s.get(&caller(2), &[9; 16], NOW), Get::None);
    }

    #[test]
    fn uses_count_down_then_gone() {
        let mut s = store("uses");
        let root = RootKey::generate().unwrap();
        let (_, once) = code(&root, Some(7 * DAY), Some(1));
        let (_, five) = code(&root, Some(7 * DAY), Some(5));
        let (_, unlimited) = code(&root, None, None);
        for held in [&once, &five, &unlimited] {
            assert_eq!(s.hold(&caller(1), held.as_bytes(), NOW), Hold::Ok);
        }
        // Looking a code up doesn't use it (SPEC-social D1); a request does.
        for i in 0..3 {
            assert!(matches!(
                s.get(&caller(2 + i), &once.lookup_id(), NOW),
                Get::Found(_)
            ));
        }
        assert_eq!(s.spend(&once.lookup_id(), NOW), Some(once.revoke_tag()));
        assert_eq!(s.spend(&once.lookup_id(), NOW), None, "single use");
        assert_eq!(s.get(&caller(3), &once.lookup_id(), NOW), Get::None);
        for _ in 0..5 {
            assert!(s.spend(&five.lookup_id(), NOW).is_some());
        }
        assert_eq!(s.spend(&five.lookup_id(), NOW), None, "five used");
        for _ in 0..8 {
            assert!(s.spend(&unlimited.lookup_id(), NOW).is_some());
        }
        assert_eq!(s.spend(&[9; 16], NOW), None, "never held");

        // The owner holding a used-up code again doesn't bring it back.
        assert_eq!(s.hold(&caller(1), once.as_bytes(), NOW), Hold::Gone);
        let (_, again) = code(&root, None, None);
        assert_eq!(s.hold(&caller(1), again.as_bytes(), NOW), Hold::Ok);
        assert_eq!(
            s.hold(&caller(1), again.as_bytes(), NOW),
            Hold::Ok,
            "repeat is fine"
        );
    }

    #[test]
    fn a_repeat_hold_keeps_the_count() {
        let mut s = store("repeat");
        let root = RootKey::generate().unwrap();
        let (code_, held) = code(&root, Some(7 * DAY), Some(5));
        s.hold(&caller(1), held.as_bytes(), NOW);
        for _ in 0..4 {
            s.spend(&held.lookup_id(), NOW);
        }
        // Rebuilt with a fresh nonce, as the helper does.
        let rebuilt = HeldCode::new(&root, &code_, NOW, Some(7 * DAY), Some(5)).unwrap();
        assert_ne!(rebuilt.as_bytes(), held.as_bytes());
        assert_eq!(s.hold(&caller(1), rebuilt.as_bytes(), NOW), Hold::Ok);
        assert!(s.spend(&held.lookup_id(), NOW).is_some());
        assert_eq!(s.spend(&held.lookup_id(), NOW), None, "still five in all");
    }

    #[test]
    fn someone_elses_code_under_the_same_lookup_is_taken() {
        let mut s = store("taken");
        let code = FriendCode::generate().unwrap();
        let (a, b) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let mine = HeldCode::new(&a, &code, NOW, None, None).unwrap();
        let theirs = HeldCode::new(&b, &code, NOW, None, None).unwrap();
        assert_eq!(s.hold(&caller(1), mine.as_bytes(), NOW), Hold::Ok);
        assert_eq!(s.hold(&caller(2), theirs.as_bytes(), NOW), Hold::Taken);
    }

    #[test]
    fn expiry() {
        let mut s = store("expiry");
        let root = RootKey::generate().unwrap();
        let (_, held) = code(&root, Some(1800), Some(1));
        assert_eq!(
            s.hold(&caller(1), held.as_bytes(), NOW + 1800),
            Hold::Bad,
            "already expired"
        );
        assert_eq!(s.hold(&caller(1), held.as_bytes(), NOW), Hold::Ok);
        assert_eq!(s.get(&caller(2), &held.lookup_id(), NOW + 1800), Get::None);
        assert_eq!(s.len(), 0, "dropped on sight");

        let (_, used) = code(&root, Some(3600), Some(1));
        s.hold(&caller(1), used.as_bytes(), NOW);
        s.spend(&used.lookup_id(), NOW);
        assert_eq!(s.len(), 1, "a marker");
        assert_eq!(s.spend(&used.lookup_id(), NOW + 3600), None);
        s.sweep(NOW + 3600);
        assert_eq!(s.len(), 0, "the marker expires with the record");
        assert_eq!(s.hold(&caller(1), b"short", NOW), Hold::Bad);
    }

    #[test]
    fn revoke_needs_the_owners_secret() {
        let mut s = store("revoke");
        let (root, other) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let (code, held) = code(&root, None, None);
        s.hold(&caller(1), held.as_bytes(), NOW);
        s.revoke(&CodeRevoke::new(&other, &code).to_bytes());
        s.revoke(b"garbage");
        assert!(matches!(
            s.get(&caller(2), &held.lookup_id(), NOW),
            Get::Found(_)
        ));
        let (theirs, mine) = (
            CodeRevoke::new(&other, &code),
            CodeRevoke::new(&root, &code),
        );
        assert_eq!(s.owner_status(&theirs, NOW), None);
        assert_eq!(s.owner_status(&mine, NOW), Some(true));
        s.revoke(&mine.to_bytes());
        assert_eq!(s.owner_status(&mine, NOW), Some(false));
        assert_eq!(s.get(&caller(2), &held.lookup_id(), NOW), Get::None);
        assert_eq!(
            s.hold(&caller(1), held.as_bytes(), NOW),
            Hold::Gone,
            "stays revoked"
        );
    }

    #[test]
    fn lookup_limits() {
        let mut s = store("lookups");
        let root = RootKey::generate().unwrap();
        let (_, held) = code(&root, None, None);
        s.hold(&caller(1), held.as_bytes(), NOW);
        let id = held.lookup_id();

        // Per device: misses count too.
        for _ in 0..LOOKUPS_PER_DEVICE {
            assert_eq!(s.get(&caller(2), &[0; 16], NOW), Get::None);
        }
        assert_eq!(s.get(&caller(2), &id, NOW), Get::SlowDown);
        assert!(
            matches!(s.get(&caller(3), &id, NOW), Get::Found(_)),
            "others unaffected"
        );
        assert!(
            matches!(s.get(&caller(2), &id, NOW + 60), Get::Found(_)),
            "a minute later"
        );

        // Per network: fresh keys don't get round it.
        let net = Some(network("203.0.113.9".parse().unwrap()));
        for i in 0..LOOKUPS_PER_NETWORK {
            let c = Caller {
                device: [100 + i as u8; 32],
                network: net,
            };
            assert!(matches!(s.get(&c, &id, NOW + 60), Get::Found(_)));
        }
        let fresh = Caller {
            device: [250; 32],
            network: net,
        };
        assert_eq!(s.get(&fresh, &id, NOW + 60), Get::SlowDown);
        let elsewhere = Caller {
            network: Some(network("198.51.100.1".parse().unwrap())),
            ..fresh
        };
        assert!(matches!(s.get(&elsewhere, &id, NOW + 60), Get::Found(_)));

        // Everyone together, each from a network of their own.
        let mut found = 0;
        for i in 0..LOOKUPS_TOTAL + 5 {
            let mut net = [7u8; 6];
            net[..4].copy_from_slice(&i.to_be_bytes());
            let c = Caller {
                device: (i + 1000).to_be_bytes().repeat(8).try_into().unwrap(),
                network: Some(net),
            };
            if matches!(s.get(&c, &id, NOW + 120), Get::Found(_)) {
                found += 1;
            }
        }
        assert_eq!(found, LOOKUPS_TOTAL);
    }

    #[test]
    fn hold_limits() {
        let mut s = store("holds");
        let root = RootKey::generate().unwrap();
        for _ in 0..HOLDS_PER_DEVICE {
            assert_eq!(
                s.hold(&caller(1), code(&root, None, None).1.as_bytes(), NOW),
                Hold::Ok
            );
        }
        let (_, extra) = code(&root, None, None);
        assert_eq!(s.hold(&caller(1), extra.as_bytes(), NOW), Hold::SlowDown);
        assert_eq!(
            s.hold(&caller(1), extra.as_bytes(), NOW + HOUR),
            Hold::Ok,
            "an hour later"
        );
    }

    /// Even a "never" code goes 30 days after its last hold; holding it
    /// again keeps it (audit finding 3, part 2).
    #[test]
    fn a_held_code_lasts_thirty_days_from_its_last_hold() {
        let mut s = store("life");
        let root = RootKey::generate().unwrap();
        let (_, never) = code(&root, None, None);
        let (_, kept) = code(&root, None, None);
        s.hold(&caller(1), never.as_bytes(), NOW);
        s.hold(&caller(1), kept.as_bytes(), NOW);
        assert_eq!(
            s.hold(&caller(2), kept.as_bytes(), NOW + HOLD_LIFE - 1),
            Hold::Ok
        );
        let later = NOW + HOLD_LIFE;
        assert_eq!(s.get(&caller(3), &never.lookup_id(), later), Get::None);
        assert!(matches!(
            s.get(&caller(3), &kept.lookup_id(), later),
            Get::Found(_)
        ));
        // Held again at HOLD_LIFE - 1, so it goes a HOLD_LIFE after that.
        s.sweep(NOW + 2 * HOLD_LIFE - 2);
        assert_eq!(s.len(), 1);
        s.sweep(NOW + 2 * HOLD_LIFE - 1);
        assert_eq!(s.len(), 0);

        // A used-up marker drains the same way.
        let (_, used) = code(&root, None, Some(1));
        s.hold(&caller(1), used.as_bytes(), later);
        s.spend(&used.lookup_id(), later);
        s.sweep(later + HOLD_LIFE);
        assert_eq!(s.len(), 0);
    }

    /// Fresh keys don't get round the hold limits: a network, and everyone
    /// relayed together, have one each. Holding a code again counts too.
    #[test]
    fn hold_limits_per_network_and_relayed() {
        let mut s = store("hold-nets");
        let root = RootKey::generate().unwrap();
        let net = Some(network("203.0.113.9".parse().unwrap()));
        let (_, again) = code(&root, None, None);
        let first = Caller {
            device: [9; 32],
            network: net,
        };
        assert_eq!(s.hold(&first, again.as_bytes(), NOW), Hold::Ok);
        for i in 1..HOLDS_PER_NETWORK {
            let c = Caller {
                device: (i + 1).to_be_bytes().repeat(8).try_into().unwrap(),
                network: net,
            };
            assert_eq!(s.hold(&c, again.as_bytes(), NOW), Hold::Ok);
        }
        let (_, extra) = code(&root, None, None);
        let fresh = Caller {
            device: [250; 32],
            network: net,
        };
        assert_eq!(s.hold(&fresh, extra.as_bytes(), NOW), Hold::SlowDown);
        let direct = Caller {
            network: Some(network("198.51.100.1".parse().unwrap())),
            ..fresh
        };
        assert_eq!(s.hold(&direct, extra.as_bytes(), NOW), Hold::Ok);

        let (_, shared) = code(&root, None, None);
        for i in 0..HOLDS_RELAYED {
            assert_eq!(s.hold(&relayed(i), shared.as_bytes(), NOW), Hold::Ok);
        }
        let (_, late) = code(&root, None, None);
        assert_eq!(
            s.hold(&relayed(HOLDS_RELAYED), late.as_bytes(), NOW),
            Hold::SlowDown
        );
    }

    #[test]
    fn answers_on_the_wire() {
        for h in [
            Hold::Ok,
            Hold::Gone,
            Hold::Taken,
            Hold::SlowDown,
            Hold::Full,
            Hold::Bad,
        ] {
            assert_eq!(Hold::from_byte(h.byte()), Some(h));
        }
        assert_eq!(Hold::from_byte(9), None);
        for g in [Get::Found(vec![7; 3]), Get::None, Get::SlowDown] {
            assert_eq!(Get::from_bytes(&g.to_bytes()), Some(g));
        }
        assert_eq!(Get::from_bytes(&[]), None);
        assert_eq!(Get::from_bytes(&[1, 2]), None);
    }

    #[test]
    fn networks() {
        assert_eq!(
            network("203.0.113.9".parse().unwrap()),
            network("203.0.113.200".parse().unwrap())
        );
        assert_ne!(
            network("203.0.113.9".parse().unwrap()),
            network("203.0.114.9".parse().unwrap())
        );
        assert_eq!(
            network("::ffff:203.0.113.9".parse().unwrap()),
            network("203.0.113.1".parse().unwrap())
        );
        assert_eq!(
            network("2001:db8:1::1".parse().unwrap()),
            network("2001:db8:1:ffff::2".parse().unwrap())
        );
        assert_ne!(
            network("2001:db8:1::1".parse().unwrap()),
            network("2001:db8:2::1".parse().unwrap())
        );
    }

    #[test]
    fn survives_a_restart_and_refuses_a_damaged_file() {
        let mut s = store("restart");
        let root = RootKey::generate().unwrap();
        let (_, live) = code(&root, None, Some(5));
        let (_, used) = code(&root, None, Some(1));
        s.hold(&caller(1), live.as_bytes(), NOW);
        s.hold(&caller(1), used.as_bytes(), NOW);
        s.spend(&live.lookup_id(), NOW);
        s.spend(&used.lookup_id(), NOW);
        assert!(s.dirty);
        s.save().unwrap();
        assert!(!s.dirty);

        let mut back = Store::load(&s.path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.hold(&caller(1), used.as_bytes(), NOW), Hold::Gone);
        for _ in 0..4 {
            assert!(back.spend(&live.lookup_id(), NOW).is_some());
        }
        assert_eq!(
            back.spend(&live.lookup_id(), NOW),
            None,
            "the count survived"
        );

        std::fs::write(&s.path, b"not a store").unwrap();
        assert!(matches!(Store::load(&s.path), Err(StoreError::Corrupt(..))));
        std::fs::write(&s.path, [1u8, 1, 2]).unwrap();
        assert!(matches!(Store::load(&s.path), Err(StoreError::Corrupt(..))));
        let _ = std::fs::remove_dir_all(s.path.parent().unwrap());
    }

    /// A file from before HOLD_LIFE still loads: each code counts as held
    /// again at load.
    #[test]
    fn a_first_format_file_loads() {
        #[derive(Serialize)]
        enum Old<'a> {
            Live {
                held: &'a [u8],
                uses_left: Option<u32>,
            },
            Gone {
                tag: [u8; 32],
                expires_at: Option<u64>,
            },
        }
        let s = store("v1");
        let root = RootKey::generate().unwrap();
        let (_, live) = code(&root, None, Some(5));
        let entries = vec![
            (
                live.lookup_id(),
                Old::Live {
                    held: live.as_bytes(),
                    uses_left: Some(2),
                },
            ),
            (
                [7; 16],
                Old::Gone {
                    tag: [1; 32],
                    expires_at: None,
                },
            ),
        ];
        std::fs::write(&s.path, saved::encode(1, entries)).unwrap();
        let mut back = Store::load(&s.path).unwrap();
        let now = mesh_identity::unix_now();
        assert_eq!(back.len(), 2);
        assert!(back.spend(&live.lookup_id(), now).is_some());
        assert!(back.spend(&live.lookup_id(), now).is_some());
        assert_eq!(
            back.spend(&live.lookup_id(), now),
            None,
            "the count came across"
        );
        back.sweep(now + HOLD_LIFE + 1);
        assert_eq!(back.len(), 0, "and the markers drain");
        let _ = std::fs::remove_dir_all(s.path.parent().unwrap());
    }
}
