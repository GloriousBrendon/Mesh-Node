//! The address records a seed holds (SPEC-routing D5, D6): identity's sealed
//! records, stored under their lookup ID and slot. The seed reads only those
//! and the expiry; it can't tell whose records they are or link two of them.
//!
//! Pure, like `codes.rs`: callers pass the time and who's asking, and save
//! when `dirty`.

use crate::codes::{Caller, Window};
use mesh_identity::{MAX_RECORD_LEN, addr_outer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Records one device may put an hour.
pub const PUTS_PER_DEVICE: u32 = 2000;
/// Records one network (/24 or /48) may put an hour.
pub const PUTS_PER_NETWORK: u32 = 4000;
/// Lookups one device may make a minute.
pub const GETS_PER_DEVICE: u32 = 120;
/// Records under one lookup ID: one per device of the sender.
pub const SLOTS_PER_LOOKUP: usize = 8;
/// Records the seed keeps at most.
pub const MAX_RECORDS: usize = 200_000;
/// How far ahead a record may expire.
pub const MAX_AHEAD: u64 = 3 * HOUR;

const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const FORMAT_V1: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    Ok = 0,
    SlowDown = 3,
    Full = 4,
    Bad = 5,
}

impl Put {
    pub fn byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Option<Self> {
        [Put::Ok, Put::SlowDown, Put::Full, Put::Bad]
            .into_iter()
            .find(|p| p.byte() == byte)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Get {
    /// 0 to 8 records; none looks the same whether it never existed or expired.
    Found(Vec<Vec<u8>>),
    SlowDown,
}

impl Get {
    /// On the wire: `0` then (u16 length, record) each, or `3`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Get::SlowDown => vec![Put::SlowDown.byte()],
            Get::Found(records) => {
                let mut out = vec![0];
                for record in records {
                    out.extend_from_slice(&(record.len() as u16).to_be_bytes());
                    out.extend_from_slice(record);
                }
                out
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (3, []) => Some(Get::SlowDown),
            (0, mut rest) => {
                let mut records = Vec::new();
                while !rest.is_empty() {
                    let (len, tail) = rest.split_first_chunk::<2>()?;
                    let len = u16::from_be_bytes(*len) as usize;
                    if tail.len() < len || records.len() == SLOTS_PER_LOOKUP {
                        return None;
                    }
                    records.push(tail[..len].to_vec());
                    rest = &tail[len..];
                }
                Some(Get::Found(records))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Slot {
    slot: [u8; 8],
    expires_at: u64,
    record: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Saved {
    format: u8,
    entries: Vec<([u8; 16], Vec<Slot>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the address store {0} is damaged; move it aside to start empty")]
    Corrupt(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Store {
    path: PathBuf,
    entries: HashMap<[u8; 16], Vec<Slot>>,
    records: usize,
    puts: Window,
    gets: Window,
    pub dirty: bool,
}

impl Store {
    /// Loads the store at `path`, or starts empty. A damaged file is an
    /// error, never silently replaced.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let entries: HashMap<_, Vec<Slot>> = match std::fs::read(path) {
            Ok(bytes) => {
                let corrupt = || StoreError::Corrupt(path.to_owned());
                let saved: Saved = postcard::from_bytes(&bytes).map_err(|_| corrupt())?;
                let valid = saved.format == FORMAT_V1
                    && saved.entries.iter().all(|(lookup, slots)| {
                        slots.len() <= SLOTS_PER_LOOKUP
                            && slots.iter().all(|s| {
                                addr_outer(&s.record) == Some((*lookup, s.slot, s.expires_at))
                            })
                    });
                if !valid {
                    return Err(corrupt());
                }
                saved.entries.into_iter().collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: path.to_owned(),
            records: entries.values().map(Vec::len).sum(),
            entries,
            puts: Window::default(),
            gets: Window::default(),
            dirty: false,
        })
    }

    /// Writes the store so that a crash leaves the old file or the new one.
    pub fn save(&mut self) -> Result<(), StoreError> {
        let saved = Saved {
            format: FORMAT_V1,
            entries: self.entries.iter().map(|(k, v)| (*k, v.clone())).collect(),
        };
        let bytes = postcard::to_stdvec(&saved).expect("serialising to memory");
        mesh_identity::write_atomically(&self.path, &bytes)?;
        self.dirty = false;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records
    }

    /// Stores a record in its slot, replacing an older one there (a later
    /// expiry is a newer record: every client uses the same lifetime).
    pub fn put(&mut self, caller: &Caller, record: &[u8], now: u64) -> Put {
        let Some((lookup, slot, expires_at)) = addr_outer(record) else {
            return Put::Bad;
        };
        if record.len() > MAX_RECORD_LEN || expires_at <= now || expires_at > now + MAX_AHEAD {
            return Put::Bad;
        }
        let mut keys = vec![(caller.device.to_vec(), PUTS_PER_DEVICE)];
        if let Some(net) = caller.network {
            keys.push(([b"net:".as_slice(), &net].concat(), PUTS_PER_NETWORK));
        }
        if !self.puts.allow(now, HOUR, &keys) {
            return Put::SlowDown;
        }
        let new = Slot {
            slot,
            expires_at,
            record: record.to_vec(),
        };
        let slots = self.entries.get(&lookup);
        let existing = slots.and_then(|s| s.iter().position(|s| s.slot == slot));
        match existing {
            Some(i) => {
                let slots = self.entries.get_mut(&lookup).expect("found above");
                if slots[i].expires_at <= expires_at {
                    slots[i] = new;
                    self.dirty = true;
                }
                // An older record changes nothing, and that's fine to say.
                Put::Ok
            }
            None => {
                if self.records >= MAX_RECORDS {
                    self.sweep(now);
                    if self.records >= MAX_RECORDS {
                        return Put::Full;
                    }
                }
                let slots = self.entries.entry(lookup).or_default();
                slots.retain(|s| s.expires_at > now);
                if slots.len() >= SLOTS_PER_LOOKUP {
                    return Put::Full;
                }
                slots.push(new);
                self.records = self.entries.values().map(Vec::len).sum();
                self.dirty = true;
                Put::Ok
            }
        }
    }

    /// The live records under `lookup`. Every lookup counts, found or not.
    pub fn get(&mut self, caller: &Caller, lookup: &[u8; 16], now: u64) -> Get {
        if !self
            .gets
            .allow(now, MINUTE, &[(caller.device.to_vec(), GETS_PER_DEVICE)])
        {
            return Get::SlowDown;
        }
        let records = self
            .entries
            .get(lookup)
            .map(|slots| {
                slots
                    .iter()
                    .filter(|s| s.expires_at > now)
                    .map(|s| s.record.clone())
                    .collect()
            })
            .unwrap_or_default();
        Get::Found(records)
    }

    /// Drops expired records.
    pub fn sweep(&mut self, now: u64) {
        let before = self.records;
        for slots in self.entries.values_mut() {
            slots.retain(|s| s.expires_at > now);
        }
        self.entries.retain(|_, slots| !slots.is_empty());
        self.records = self.entries.values().map(Vec::len).sum();
        self.dirty |= self.records != before;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn caller(n: u8) -> Caller {
        Caller {
            device: [n; 32],
            network: None,
        }
    }

    /// A record as the seed sees one: only the outer part matters to it.
    fn record(lookup: u8, slot: u8, expires_at: u64, body: u8) -> Vec<u8> {
        let mut r = vec![lookup; 16];
        r.extend_from_slice(&[slot; 8]);
        r.extend_from_slice(&expires_at.to_be_bytes());
        r.extend_from_slice(&[body; 24 + 40]);
        r
    }

    fn store(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("mesh-addrs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store::load(&dir.join("addrs.bin")).unwrap()
    }

    fn found(get: Get) -> Vec<Vec<u8>> {
        match get {
            Get::Found(records) => records,
            Get::SlowDown => panic!("slowed"),
        }
    }

    #[test]
    fn put_get_and_newer_replaces_older() {
        let mut s = store("basic");
        let a = record(1, 1, NOW + 100, 1);
        let b = record(1, 2, NOW + 100, 2);
        assert_eq!(s.put(&caller(1), &a, NOW), Put::Ok);
        assert_eq!(s.put(&caller(2), &b, NOW), Put::Ok);
        assert_eq!(found(s.get(&caller(3), &[1; 16], NOW)).len(), 2);
        assert!(found(s.get(&caller(3), &[9; 16], NOW)).is_empty());

        let newer = record(1, 1, NOW + 200, 7);
        let older = record(1, 1, NOW + 50, 8);
        assert_eq!(s.put(&caller(1), &newer, NOW), Put::Ok);
        assert_eq!(s.put(&caller(1), &older, NOW), Put::Ok);
        let got = found(s.get(&caller(3), &[1; 16], NOW));
        assert!(got.contains(&newer) && got.contains(&b) && got.len() == 2);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn bad_records() {
        let mut s = store("bad");
        assert_eq!(s.put(&caller(1), b"short", NOW), Put::Bad);
        assert_eq!(s.put(&caller(1), &record(1, 1, NOW, 0), NOW), Put::Bad);
        let far = record(1, 1, NOW + MAX_AHEAD + 1, 0);
        assert_eq!(s.put(&caller(1), &far, NOW), Put::Bad);
        let mut huge = record(1, 1, NOW + 60, 0);
        huge.resize(MAX_RECORD_LEN + 1, 0);
        assert_eq!(s.put(&caller(1), &huge, NOW), Put::Bad);
    }

    #[test]
    fn expiry_and_sweep() {
        let mut s = store("expiry");
        s.put(&caller(1), &record(1, 1, NOW + 10, 0), NOW);
        s.put(&caller(1), &record(2, 1, NOW + 100, 0), NOW);
        assert!(found(s.get(&caller(2), &[1; 16], NOW + 10)).is_empty());
        s.sweep(NOW + 10);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn limits() {
        let mut s = store("limits");
        for i in 0..SLOTS_PER_LOOKUP as u8 {
            assert_eq!(s.put(&caller(1), &record(1, i, NOW + 60, 0), NOW), Put::Ok);
        }
        assert_eq!(
            s.put(&caller(1), &record(1, 99, NOW + 60, 0), NOW),
            Put::Full
        );

        for _ in 0..GETS_PER_DEVICE {
            assert!(matches!(s.get(&caller(2), &[1; 16], NOW), Get::Found(_)));
        }
        assert_eq!(s.get(&caller(2), &[1; 16], NOW), Get::SlowDown);
        assert!(matches!(s.get(&caller(3), &[1; 16], NOW), Get::Found(_)));
        assert!(matches!(
            s.get(&caller(2), &[1; 16], NOW + MINUTE),
            Get::Found(_)
        ));

        let mut s = store("put-limit");
        let net = Caller {
            device: [5; 32],
            network: Some([1; 6]),
        };
        for i in 0..PUTS_PER_DEVICE {
            let r = record((i % 250) as u8, (i / 250) as u8, NOW + 60, 0);
            assert_eq!(s.put(&net, &r, NOW), Put::Ok, "put {i}");
        }
        let r = record(250, 0, NOW + 60, 0);
        assert_eq!(s.put(&net, &r, NOW), Put::SlowDown);
        let later = record(250, 0, NOW + HOUR + 60, 0);
        assert_eq!(s.put(&net, &later, NOW + HOUR), Put::Ok);
    }

    #[test]
    fn answers_on_the_wire() {
        for get in [
            Get::SlowDown,
            Get::Found(vec![]),
            Get::Found(vec![vec![1, 2], vec![3; 300]]),
        ] {
            assert_eq!(Get::from_bytes(&get.to_bytes()), Some(get));
        }
        assert_eq!(Get::from_bytes(&[0, 0, 5, 1]), None);
        for p in [Put::Ok, Put::SlowDown, Put::Full, Put::Bad] {
            assert_eq!(Put::from_byte(p.byte()), Some(p));
        }
    }

    #[test]
    fn survives_a_restart_and_refuses_a_damaged_file() {
        let mut s = store("restart");
        let a = record(1, 1, NOW + 100, 3);
        s.put(&caller(1), &a, NOW);
        s.save().unwrap();
        let mut back = Store::load(&s.path).unwrap();
        assert_eq!(found(back.get(&caller(2), &[1; 16], NOW)), vec![a]);
        std::fs::write(&s.path, b"not a store").unwrap();
        assert!(matches!(Store::load(&s.path), Err(StoreError::Corrupt(_))));
        let _ = std::fs::remove_dir_all(s.path.parent().unwrap());
    }
}
