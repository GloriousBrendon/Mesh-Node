//! The friend requests a seed holds (SPEC-social D1, D3, D6): identity's
//! sealed requests, under the lookup ID of the code they came through. A put
//! needs a live code there and uses one of its uses; only the code's owner,
//! with its revoke, reads them back. The seed sees lookup IDs, slots and
//! ciphertext, never who asked whom.
//!
//! Pure, like `codes.rs`: callers pass the time, who's asking and the code
//! store, and save when `dirty`.

use crate::codes::{self, Caller, Window};
use crate::saved::{self, StoreError};
use mesh_identity::{CodeRevoke, knock_outer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Requests one device may put an hour.
pub const PUTS_PER_DEVICE: u32 = 20;
/// Requests one network (/24 or /48) may put an hour.
pub const PUTS_PER_NETWORK: u32 = 60;
/// Requests everyone reaching the seed through a relay may put an hour,
/// together.
pub const PUTS_RELAYED: u32 = 1000;
/// Reads one device may make a minute.
pub const GETS_PER_DEVICE: u32 = 60;
/// Requests kept per code; past this, the oldest goes.
pub const PER_CODE: usize = 32;
/// Requests the seed keeps at most.
pub const MAX_KNOCKS: usize = 100_000;
/// How long a request is kept, even after its code is gone.
pub const KEEP: u64 = 7 * 24 * HOUR;

const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
/// The store's name in errors.
const WHAT: &str = "request";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    Ok = 0,
    /// No live code under that lookup ID (or never one).
    Gone = 1,
    SlowDown = 3,
    Full = 4,
    Bad = 5,
}

impl Put {
    pub fn byte(self) -> u8 {
        self as u8
    }

    // The seed still serves 0.5.x clients' requests (social R3-4); only they read this.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn from_byte(byte: u8) -> Option<Self> {
        [Put::Ok, Put::Gone, Put::SlowDown, Put::Full, Put::Bad]
            .into_iter()
            .find(|p| p.byte() == byte)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Get {
    /// Whether the code is still live, and its requests.
    Found {
        live: bool,
        knocks: Vec<Vec<u8>>,
    },
    /// No code or requests for that revoke.
    None,
    SlowDown,
}

impl Get {
    /// On the wire: `0`, live (1) or gone (0), then (u16 length, request)
    /// each; `1`; or `3`.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Get::None => vec![1],
            Get::SlowDown => vec![Put::SlowDown.byte()],
            Get::Found { live, knocks } => {
                let mut out = vec![0, u8::from(*live)];
                for knock in knocks {
                    out.extend_from_slice(&(knock.len() as u16).to_be_bytes());
                    out.extend_from_slice(knock);
                }
                out
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [1] => Some(Get::None),
            [3] => Some(Get::SlowDown),
            [0, live @ (0 | 1), rest @ ..] => {
                let (mut rest, mut knocks) = (rest, Vec::new());
                while !rest.is_empty() {
                    let (len, tail) = rest.split_first_chunk::<2>()?;
                    let len = u16::from_be_bytes(*len) as usize;
                    if tail.len() < len || knocks.len() == PER_CODE {
                        return None;
                    }
                    knocks.push(tail[..len].to_vec());
                    rest = &tail[len..];
                }
                Some(Get::Found {
                    live: *live == 1,
                    knocks,
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Held {
    slot: [u8; 8],
    put_at: u64,
    knock: Vec<u8>,
}

/// A code's requests, and its revoke tag, so the owner can read them after
/// the code itself is gone.
#[derive(Clone, Serialize, Deserialize)]
struct CodeBox {
    tag: [u8; 32],
    knocks: Vec<Held>,
}

pub struct Store {
    path: PathBuf,
    boxes: HashMap<[u8; 16], CodeBox>,
    /// Requests in all boxes, kept as they come and go.
    count: usize,
    puts: Window,
    gets: Window,
    pub dirty: bool,
}

impl Store {
    /// Loads the store at `path`, or starts empty. A damaged file is an
    /// error, never silently replaced.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let boxes = saved::load(
            path,
            WHAT,
            saved::FORMAT_V1,
            |(lookup, b): &([u8; 16], CodeBox)| {
                b.knocks.len() <= PER_CODE
                    && (b.knocks.iter()).all(|k| knock_outer(&k.knock) == Some((*lookup, k.slot)))
            },
        )?;
        let boxes: HashMap<_, CodeBox> = boxes.into_iter().collect();
        Ok(Self {
            path: path.to_owned(),
            count: boxes.values().map(|b| b.knocks.len()).sum(),
            boxes,
            puts: Window::default(),
            gets: Window::default(),
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
            bytes: saved::encode(saved::FORMAT_V1, self.boxes.iter().collect()),
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// Takes a request if its code is live, using one of the code's uses. A
    /// resend from the same sender replaces their last one.
    pub fn put(
        &mut self,
        caller: &Caller,
        knock: &[u8],
        codes: &mut codes::Store,
        now: u64,
    ) -> Put {
        let Some((lookup, slot)) = knock_outer(knock) else {
            return Put::Bad;
        };
        let mut keys = vec![(caller.device.to_vec(), PUTS_PER_DEVICE)];
        keys.push(caller.network_limit(PUTS_PER_NETWORK, PUTS_RELAYED));
        if !self.puts.allow(now, HOUR, &keys) {
            return Put::SlowDown;
        }
        if self.len() >= MAX_KNOCKS {
            self.sweep(now);
            if self.len() >= MAX_KNOCKS {
                return Put::Full;
            }
        }
        let Some(tag) = codes.spend(&lookup, now) else {
            return Put::Gone;
        };
        let held = Held {
            slot,
            put_at: now,
            knock: knock.to_vec(),
        };
        let b = self.boxes.entry(lookup).or_insert_with(|| CodeBox {
            tag,
            knocks: Vec::new(),
        });
        b.tag = tag;
        let before = b.knocks.len();
        b.knocks.retain(|k| k.slot != slot);
        if b.knocks.len() >= PER_CODE {
            b.knocks.remove(0);
        }
        b.knocks.push(held);
        self.count = self.count + b.knocks.len() - before;
        self.dirty = true;
        Put::Ok
    }

    /// The owner reading a code's requests with its revoke. Every read
    /// counts, found or not.
    pub fn get(&mut self, caller: &Caller, revoke: &[u8], codes: &codes::Store, now: u64) -> Get {
        if !self
            .gets
            .allow(now, MINUTE, &[(caller.device.to_vec(), GETS_PER_DEVICE)])
        {
            return Get::SlowDown;
        }
        let Ok(revoke) = CodeRevoke::from_bytes(revoke) else {
            return Get::None;
        };
        let live = codes.owner_status(&revoke, now);
        let held = self
            .boxes
            .get(&revoke.lookup_id())
            .filter(|b| revoke.tag() == b.tag);
        if live.is_none() && held.is_none() {
            return Get::None;
        }
        let knocks = held.into_iter().flat_map(|b| &b.knocks);
        Get::Found {
            live: live.unwrap_or(false),
            knocks: knocks
                .filter(|k| k.put_at + KEEP > now)
                .map(|k| k.knock.clone())
                .collect(),
        }
    }

    /// Drops requests older than [`KEEP`], and boxes left empty.
    pub fn sweep(&mut self, now: u64) {
        let before = self.len();
        for b in self.boxes.values_mut() {
            b.knocks.retain(|k| k.put_at + KEEP > now);
        }
        self.boxes.retain(|_, b| !b.knocks.is_empty());
        self.count = self.boxes.values().map(|b| b.knocks.len()).sum();
        self.dirty |= self.len() != before;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_identity::{
        DeviceCert, DeviceKey, DeviceList, FriendCode, HeldCode, KnockFrom, MAX_KNOCK_LEN, RootKey,
        seal_knock,
    };

    const NOW: u64 = 1_800_000_000;

    fn caller(n: u8) -> Caller {
        Caller {
            device: [n; 32],
            network: None,
        }
    }

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mesh-knocks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct Seed {
        codes: codes::Store,
        knocks: Store,
    }

    fn seed(name: &str) -> Seed {
        let dir = dir(name);
        Seed {
            codes: codes::Store::load(&dir.join("codes.bin")).unwrap(),
            knocks: Store::load(&dir.join("knocks.bin")).unwrap(),
        }
    }

    /// The owner's code, held by the seed.
    fn code(s: &mut Seed, owner: &RootKey, uses: Option<u32>) -> FriendCode {
        let code = FriendCode::generate().unwrap();
        let held = HeldCode::new(owner, &code, NOW, Some(86_400), uses).unwrap();
        assert_eq!(
            s.codes.hold(&caller(0), held.as_bytes(), NOW),
            codes::Hold::Ok
        );
        code
    }

    fn knock(from: &RootKey, owner: &RootKey, code: &FriendCode) -> Vec<u8> {
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(from, &device.public(), "pc", NOW).unwrap();
        let devices = DeviceList::first(from, cert).unwrap();
        let from = KnockFrom {
            root: from,
            device: &device,
            devices: &devices,
            name: "Sam",
        };
        seal_knock(&from, &owner.id(), &code.lookup_id(), "", NOW).unwrap()
    }

    fn put(s: &mut Seed, who: u8, knock: &[u8], now: u64) -> Put {
        s.knocks.put(&caller(who), knock, &mut s.codes, now)
    }

    fn get(s: &mut Seed, revoke: &CodeRevoke, now: u64) -> Get {
        s.knocks.get(&caller(9), &revoke.to_bytes(), &s.codes, now)
    }

    #[test]
    fn a_request_needs_a_live_code_and_uses_it() {
        let mut s = seed("live");
        let (owner, sam, kim) = (
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
            RootKey::generate().unwrap(),
        );
        let once = code(&mut s, &owner, Some(1));
        let first = knock(&sam, &owner, &once);
        assert_eq!(put(&mut s, 1, &first, NOW), Put::Ok);
        assert_eq!(
            put(&mut s, 2, &knock(&kim, &owner, &once), NOW),
            Put::Gone,
            "used up"
        );
        let never = FriendCode::generate().unwrap();
        assert_eq!(put(&mut s, 2, &knock(&kim, &owner, &never), NOW), Put::Gone);
        assert_eq!(put(&mut s, 2, b"junk", NOW), Put::Bad);

        // Only the owner reads it, and it outlives the code.
        let revoke = CodeRevoke::new(&owner, &once);
        assert_eq!(
            get(&mut s, &revoke, NOW),
            Get::Found {
                live: false,
                knocks: vec![first]
            }
        );
        assert_eq!(get(&mut s, &CodeRevoke::new(&sam, &once), NOW), Get::None);
        assert_eq!(
            get(&mut s, &CodeRevoke::new(&owner, &never), NOW),
            Get::None
        );
        s.knocks.sweep(NOW + KEEP - 1);
        assert_eq!(s.knocks.len(), 1);
        s.knocks.sweep(NOW + KEEP);
        assert_eq!(s.knocks.len(), 0);
        assert_eq!(
            get(&mut s, &revoke, NOW + KEEP),
            Get::Found {
                live: false,
                knocks: vec![]
            },
            "the code's marker is still there; its requests aren't"
        );
    }

    #[test]
    fn resends_replace_and_a_full_box_drops_the_oldest() {
        let mut s = seed("box");
        let (owner, sam) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let open = code(&mut s, &owner, None);
        let revoke = CodeRevoke::new(&owner, &open);
        assert_eq!(
            get(&mut s, &revoke, NOW),
            Get::Found {
                live: true,
                knocks: vec![]
            }
        );

        put(&mut s, 1, &knock(&sam, &owner, &open), NOW);
        let again = knock(&sam, &owner, &open);
        put(&mut s, 1, &again, NOW);
        assert_eq!(s.knocks.len(), 1, "a resend replaces");
        assert_eq!(
            get(&mut s, &revoke, NOW),
            Get::Found {
                live: true,
                knocks: vec![again]
            }
        );

        let first = knock(&RootKey::generate().unwrap(), &owner, &open);
        put(&mut s, 2, &first, NOW);
        for i in 0..PER_CODE {
            let k = knock(&RootKey::generate().unwrap(), &owner, &open);
            assert_eq!(put(&mut s, 10 + i as u8, &k, NOW), Put::Ok);
        }
        let Get::Found { knocks, .. } = get(&mut s, &revoke, NOW) else {
            panic!()
        };
        assert_eq!(knocks.len(), PER_CODE);
        assert!(!knocks.contains(&first), "the oldest went");
        assert_eq!(s.knocks.len(), PER_CODE, "the count follows");
        s.knocks.sweep(NOW + KEEP);
        assert_eq!(s.knocks.len(), 0);
    }

    #[test]
    fn limits() {
        let mut s = seed("limits");
        let owner = RootKey::generate().unwrap();
        let open = code(&mut s, &owner, None);
        for _ in 0..PUTS_PER_DEVICE {
            let k = knock(&RootKey::generate().unwrap(), &owner, &open);
            assert_eq!(put(&mut s, 1, &k, NOW), Put::Ok);
        }
        let k = knock(&RootKey::generate().unwrap(), &owner, &open);
        assert_eq!(put(&mut s, 1, &k, NOW), Put::SlowDown);
        assert_eq!(put(&mut s, 1, &k, NOW + HOUR), Put::Ok, "an hour later");

        let net = Some(codes::network("203.0.113.9".parse().unwrap()));
        for i in 0..PUTS_PER_NETWORK {
            let c = Caller {
                device: [100 + i as u8; 32],
                network: net,
            };
            let k = knock(&RootKey::generate().unwrap(), &owner, &open);
            assert_eq!(s.knocks.put(&c, &k, &mut s.codes, NOW), Put::Ok);
        }
        let c = Caller {
            device: [250; 32],
            network: net,
        };
        assert_eq!(s.knocks.put(&c, &k, &mut s.codes, NOW), Put::SlowDown);

        // Relayed callers share one bucket (audit finding 3, part 1), in a
        // later hour than the relayed puts above. One sender's resends: each
        // still counts.
        let later = NOW + 2 * HOUR;
        for i in 0..PUTS_RELAYED {
            let mut device = [0xAA; 32];
            device[..4].copy_from_slice(&i.to_be_bytes());
            let c = Caller {
                device,
                network: None,
            };
            assert_eq!(s.knocks.put(&c, &k, &mut s.codes, later), Put::Ok);
        }
        let c = Caller {
            device: [251; 32],
            network: None,
        };
        assert_eq!(s.knocks.put(&c, &k, &mut s.codes, later), Put::SlowDown);

        let revoke = CodeRevoke::new(&owner, &open);
        for _ in 0..GETS_PER_DEVICE {
            assert!(matches!(get(&mut s, &revoke, NOW), Get::Found { .. }));
        }
        assert_eq!(get(&mut s, &revoke, NOW), Get::SlowDown);
    }

    #[test]
    fn answers_on_the_wire() {
        for p in [Put::Ok, Put::Gone, Put::SlowDown, Put::Full, Put::Bad] {
            assert_eq!(Put::from_byte(p.byte()), Some(p));
        }
        for g in [
            Get::Found {
                live: true,
                knocks: vec![vec![1, 2], vec![]],
            },
            Get::Found {
                live: false,
                knocks: vec![],
            },
            Get::None,
            Get::SlowDown,
        ] {
            assert_eq!(Get::from_bytes(&g.to_bytes()), Some(g));
        }
        assert_eq!(Get::from_bytes(&[0, 2]), None);
        assert_eq!(Get::from_bytes(&[0, 1, 0, 5, 1]), None);
    }

    #[test]
    fn survives_a_restart_and_refuses_a_damaged_file() {
        let mut s = seed("restart");
        let (owner, sam) = (RootKey::generate().unwrap(), RootKey::generate().unwrap());
        let once = code(&mut s, &owner, Some(1));
        let k = knock(&sam, &owner, &once);
        put(&mut s, 1, &k, NOW);
        assert!(s.knocks.dirty);
        s.knocks.save().unwrap();
        assert!(!s.knocks.dirty);
        let path = s.knocks.path.clone();
        s.knocks = Store::load(&path).unwrap();
        let revoke = CodeRevoke::new(&owner, &once);
        assert_eq!(
            get(&mut s, &revoke, NOW),
            Get::Found {
                live: false,
                knocks: vec![k]
            }
        );
        std::fs::write(&path, b"not a store").unwrap();
        assert!(matches!(Store::load(&path), Err(StoreError::Corrupt(..))));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_big_request_is_refused() {
        let mut s = seed("big");
        assert_eq!(put(&mut s, 1, &vec![0; MAX_KNOCK_LEN + 1], NOW), Put::Bad);
    }
}
