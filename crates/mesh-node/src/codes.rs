//! The friend codes a seed holds (SPEC-seed D7–D10). Records are identity's
//! `HeldCode`s: a lookup ID and ciphertext, so the store never knows whose
//! code it holds. It keeps no record of who held or fetched what; the rate
//! counters live in memory for a minute or an hour.
//!
//! Pure: callers pass the time and who's asking, and save when `dirty`.

use mesh_identity::{CodeRevoke, HeldCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Lookups one device may make a minute.
pub const LOOKUPS_PER_DEVICE: u32 = 10;
/// Lookups one network (/24 or /48) may make a minute.
pub const LOOKUPS_PER_NETWORK: u32 = 30;
/// Lookups everyone together may make a minute.
pub const LOOKUPS_TOTAL: u32 = 600;
/// New codes one device may hold an hour.
pub const HOLDS_PER_DEVICE: u32 = 20;
/// Records and markers the seed keeps at most.
pub const MAX_ENTRIES: usize = 100_000;

const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const FORMAT_V1: u8 = 1;

/// Who's asking: their (throwaway) device key, and their network when the
/// connection is direct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Caller {
    pub device: [u8; 32],
    pub network: Option<[u8; 6]>,
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
    },
    /// Used up or revoked: kept until the record would have expired, so the
    /// owner holding it again can't bring it back.
    Gone {
        tag: [u8; 32],
        expires_at: Option<u64>,
    },
}

impl Entry {
    fn expired(&self, now: u64) -> bool {
        let at = match self {
            Entry::Live { held, .. } => held_code(held).expires_at(),
            Entry::Gone { expires_at, .. } => *expires_at,
        };
        at.is_some_and(|at| at <= now)
    }

    fn tag(&self) -> [u8; 32] {
        match self {
            Entry::Live { held, .. } => held_code(held).revoke_tag(),
            Entry::Gone { tag, .. } => *tag,
        }
    }

    fn gone(&self) -> Entry {
        let expires_at = match self {
            Entry::Live { held, .. } => held_code(held).expires_at(),
            Entry::Gone { expires_at, .. } => *expires_at,
        };
        Entry::Gone {
            tag: self.tag(),
            expires_at,
        }
    }
}

/// Live entries were checked by `HeldCode::from_bytes` when held or loaded.
fn held_code(bytes: &[u8]) -> HeldCode {
    HeldCode::from_bytes(bytes).expect("checked when stored")
}

#[derive(Serialize, Deserialize)]
struct Saved {
    format: u8,
    entries: Vec<([u8; 16], Entry)>,
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

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the code store {0} is damaged; move it aside to start empty")]
    Corrupt(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
        let entries = match std::fs::read(path) {
            Ok(bytes) => {
                let saved: Saved = postcard::from_bytes(&bytes)
                    .map_err(|_| StoreError::Corrupt(path.to_owned()))?;
                let valid = saved.format == FORMAT_V1
                    && saved.entries.iter().all(|(_, e)| match e {
                        Entry::Live { held, .. } => HeldCode::from_bytes(held).is_ok(),
                        Entry::Gone { .. } => true,
                    });
                if !valid {
                    return Err(StoreError::Corrupt(path.to_owned()));
                }
                saved.entries.into_iter().collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: path.to_owned(),
            entries,
            lookups: Window::default(),
            holds: Window::default(),
            dirty: false,
        })
    }

    /// Writes the store to a temporary file, then renames it over the old one.
    pub fn save(&mut self) -> Result<(), StoreError> {
        let saved = Saved {
            format: FORMAT_V1,
            entries: self.entries.iter().map(|(k, e)| (*k, e.clone())).collect(),
        };
        let bytes = postcard::to_stdvec(&saved).expect("serialising to memory");
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
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
        if let Some(entry) = self.entries.get(&lookup_id).filter(|e| !e.expired(now)) {
            return match (entry, entry.tag() == held.revoke_tag()) {
                (_, false) => Hold::Taken,
                (Entry::Live { .. }, true) => Hold::Ok,
                (Entry::Gone { .. }, true) => Hold::Gone,
            };
        }
        if !self
            .holds
            .allow(now, HOUR, &[(caller.device.to_vec(), HOLDS_PER_DEVICE)])
        {
            return Hold::SlowDown;
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.sweep(now);
            if self.entries.len() >= MAX_ENTRIES {
                return Hold::Full;
            }
        }
        let uses_left = held.max_uses();
        self.entries.insert(
            lookup_id,
            Entry::Live {
                held: bytes.to_vec(),
                uses_left,
            },
        );
        self.dirty = true;
        Hold::Ok
    }

    /// Every lookup counts against the limits, found or not.
    pub fn get(&mut self, caller: &Caller, lookup_id: &[u8; 16], now: u64) -> Get {
        let mut keys = vec![
            (caller.device.to_vec(), LOOKUPS_PER_DEVICE),
            (b"total".to_vec(), LOOKUPS_TOTAL),
        ];
        if let Some(net) = caller.network {
            keys.push(([b"net:".as_slice(), &net].concat(), LOOKUPS_PER_NETWORK));
        }
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
        let Entry::Live { held, uses_left } = entry else {
            return Get::None;
        };
        let found = held.clone();
        match *uses_left {
            None => return Get::Found(found),
            Some(1) => *entry = entry.gone(),
            Some(n) => *uses_left = Some(n - 1),
        }
        self.dirty = true;
        Get::Found(found)
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
        assert!(matches!(
            s.get(&caller(2), &once.lookup_id(), NOW),
            Get::Found(_)
        ));
        assert_eq!(
            s.get(&caller(3), &once.lookup_id(), NOW),
            Get::None,
            "single use"
        );
        for i in 0..5 {
            assert!(matches!(
                s.get(&caller(10 + i), &five.lookup_id(), NOW),
                Get::Found(_)
            ));
        }
        assert_eq!(
            s.get(&caller(20), &five.lookup_id(), NOW),
            Get::None,
            "five used"
        );
        for i in 0..8 {
            assert!(matches!(
                s.get(&caller(30 + i), &unlimited.lookup_id(), NOW),
                Get::Found(_)
            ));
        }

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
        for i in 0..4 {
            s.get(&caller(10 + i), &held.lookup_id(), NOW);
        }
        // Rebuilt with a fresh nonce, as the helper does.
        let rebuilt = HeldCode::new(&root, &code_, NOW, Some(7 * DAY), Some(5)).unwrap();
        assert_ne!(rebuilt.as_bytes(), held.as_bytes());
        assert_eq!(s.hold(&caller(1), rebuilt.as_bytes(), NOW), Hold::Ok);
        assert!(matches!(
            s.get(&caller(20), &held.lookup_id(), NOW),
            Get::Found(_)
        ));
        assert_eq!(
            s.get(&caller(21), &held.lookup_id(), NOW),
            Get::None,
            "still five in all"
        );
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
        s.get(&caller(2), &used.lookup_id(), NOW);
        assert_eq!(s.len(), 1, "a marker");
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
        s.revoke(&CodeRevoke::new(&root, &code).to_bytes());
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

        // Everyone together.
        let mut found = 0;
        for i in 0..LOOKUPS_TOTAL + 5 {
            let c = Caller {
                device: (i + 1000).to_be_bytes().repeat(8).try_into().unwrap(),
                network: None,
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
        s.get(&caller(2), &live.lookup_id(), NOW);
        s.get(&caller(2), &used.lookup_id(), NOW);
        assert!(s.dirty);
        s.save().unwrap();
        assert!(!s.dirty);

        let mut back = Store::load(&s.path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.hold(&caller(1), used.as_bytes(), NOW), Hold::Gone);
        for i in 0..4 {
            assert!(matches!(
                back.get(&caller(10 + i), &live.lookup_id(), NOW),
                Get::Found(_)
            ));
        }
        assert_eq!(
            back.get(&caller(20), &live.lookup_id(), NOW),
            Get::None,
            "the count survived"
        );

        std::fs::write(&s.path, b"not a store").unwrap();
        assert!(matches!(Store::load(&s.path), Err(StoreError::Corrupt(_))));
        let _ = std::fs::remove_dir_all(s.path.parent().unwrap());
    }
}
