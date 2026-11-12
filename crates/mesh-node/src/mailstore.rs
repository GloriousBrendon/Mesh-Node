//! The seed's mail (SPEC-mailbox): sealed envelopes held in boxes, by slot,
//! only for slots their reader claimed (M6), until the reader collects them
//! with its collect secret. Requests on the batched services:
//!
//! ```text
//! mail-claim = token | box [16] | slot [8] | collect tag [32] | expiry u64  -> answer u8
//! mail-put   = token | sealed (its first 24 bytes are box [16] | slot [8])  -> answer u8
//! token      = len u8 | the seed's `--mail-token` [len] (len 0 for an open seed)
//! mail-get   = box [16] | slot [8] | collect secret [32]
//!              -> count u16 | (len u32 | sealed)*, or answer u8 (no-box)
//! mail-take  = box [16] | slot [8] | collect secret [32] | count u32 -> answer u8
//! ```
//!
//! A claim names the hash of a secret only the reader's device can make; a
//! renewal is the same claim with a later expiry. The seal's associated data
//! starts with the box and slot (e2ee D8), so an envelope moved to another
//! box doesn't open. A get hands back the slot's oldest envelopes, as many as
//! fit one frame; a take of `count` then deletes those, once the reader has
//! stored them. Envelopes put meanwhile go after them, so they stay.

//! On disk (seed D9 as changed): `<data>/mail/claims` and
//! `<data>/mail/envelopes`, append-only logs (`maillog`). Claims are held in
//! memory; envelopes stay on disk, with only where each sits in memory. A
//! put is synced before it's answered; a claim or take isn't: a lost claim
//! comes back at the next renewal, and a lost take hands the reader a
//! duplicate it drops by event ID. A damaged log is moved aside and starts
//! empty; when that's the envelopes, the claims are dropped with it, so
//! readers see `no-box` and their senders mail again.

//! Mail records (routing D3, D5, D6 as changed) are the third log,
//! `<data>/mail/records`: sealed as address records are, and read by the
//! seed the same way (`addr_outer`), but kept up to 7 days ahead, under
//! their own rates, and counted in the store's total. `mrec-put` is
//! `token | record`, answered as `addr-put` is (and `closed`, 6); `mrec-get` is a lookup ID [16],
//! answered as `addr-get` is.
//!
//! Limits (mailbox *Limits*, M14, M18): rates per throwaway key, per
//! network and for everyone through a relay; a quota per box; the store's
//! total (`--mail-max`), past which new claims and puts answer `full`; and,
//! with `--mail-token`, nothing claimed, put or recorded without it: records
//! count in the total, so a stranger mustn't fill a closed seed with them.

use crate::addrs::{Get as RecordGet, Put as RecordPut, SLOTS_PER_LOOKUP};
use crate::codes::{Caller, Window};
use crate::maillog::{At, Keep, Log, LogError, move_aside};
use mesh_identity::{MAX_CONTACTS, addr_outer, mail_collect_tag};
use std::collections::{HashMap, VecDeque};
use std::path::Path;

pub const BOX: usize = 16;
pub const SLOT: usize = 8;
const HEAD: usize = BOX + SLOT;
const SECRET: usize = 32;
/// The largest sealed envelope a put takes: the largest e2ee frame and the
/// mail wrapper's head and seal.
pub const MAX_SEALED: usize = crate::e2ee::MAX_FRAME + 1024;
/// What one get hands back at most, under the transport's frame limit.
const MAX_GET_BYTES: usize = mesh_transport::frame::MAX_FRAME - 1024;
/// A claim lasts this long after its last renewal (mailbox *Limits*): 30
/// days away plus a partial first week.
pub const CLAIM_LIFE: u64 = 35 * 86_400;
/// An envelope is held this long after its put (mailbox *Limits*): the
/// 30-day promise.
pub const MAIL_LIFE: u64 = 30 * 86_400;
/// Per throwaway key, an hour: claims or renewals; collect queries; puts,
/// and their KiB.
pub const CLAIMS_PER_KEY: u32 = 8_192;
pub const COLLECTS_PER_KEY: u32 = 16_384;
pub const PUTS_PER_KEY: u32 = 600;
pub const PUT_KIB_PER_KEY: u32 = 64 * 1024;
/// A network's limits are this many keys'; everyone through a relay
/// shares this many.
const PER_NETWORK: u32 = 2;
const RELAYED: u32 = 100;
/// The boxes a device claims at most each week: every contact and the self
/// pair, padded to 64 (M13).
const MOST_BOXES: u32 = (MAX_CONTACTS as u32 + 1).div_ceil(64) * 64;
// A first unlock claims this week and five ahead; a refresh at unlock
// collects six weeks and then two, twice in its hour.
const _: () = assert!(CLAIMS_PER_KEY >= MOST_BOXES * 6);
const _: () = assert!(COLLECTS_PER_KEY >= MOST_BOXES * (6 + 2 * 2));
/// Per throwaway key, an hour: mail records put, and lookups (routing D6
/// as changed): every contact's at unlock, and last week's for misses.
pub const RECORD_PUTS_PER_KEY: u32 = 2_048;
pub const RECORD_GETS_PER_KEY: u32 = 4_096;
const _: () = assert!(RECORD_PUTS_PER_KEY as usize >= 2 * (MAX_CONTACTS + 1));
const _: () = assert!(RECORD_GETS_PER_KEY as usize >= 4 * (MAX_CONTACTS + 1));
/// How far ahead a mail record may expire: the fallback key's week
/// (`MAIL_RECORD_LIFE`).
pub const RECORD_AHEAD: u64 = 7 * 86_400;
/// Per box (one sender, one reader, one week).
pub const BOX_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const BOX_MAX_ENVELOPES: u32 = 1_000;
/// The store's total, for claims and mail together, unless `--mail-max`
/// says otherwise: the built-in seeds' beta size (decided Q12).
pub const MAIL_STORE_MAX: u64 = 2 * 1024 * 1024 * 1024;
/// The longest `--mail-token`.
pub const MAX_TOKEN: usize = 64;
const HOUR: u64 = 3600;
/// How far a caller's clock may be ahead of ours: a claim or mail record
/// may expire this much later than it asks for, as address records have
/// an hour over their 2 (routing D4).
pub const CLOCK_ROOM: u64 = HOUR;
/// A claim's record in its log: box, slot, tag, expiry.
const CLAIM_RECORD: usize = HEAD + 32 + 8;
/// An envelope log's records: a put, or a take.
const PUT: u8 = 1;
const TAKE: u8 = 2;
/// A put's record before its sealed bytes: the op and the put time.
const PUT_HEAD: usize = 1 + 8;

/// An answer to a claim, put or take (and to a get that may not collect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Ok = 0,
    Bad = 1,
    /// Nobody claimed that slot, or that isn't its collect secret.
    NoBox = 2,
    /// Someone else's claim stands on that slot.
    Taken = 3,
    /// The box's quota or the store's total is reached.
    Full = 4,
    /// Over this hour's limits.
    SlowDown = 5,
    /// A closed seed, and that isn't its token.
    Closed = 6,
}

/// How the operator set the store up.
pub struct Settings {
    /// `--mail-token`: claims, puts and mail records need it.
    pub token: Option<Vec<u8>>,
    /// `--mail-max`, in bytes.
    pub max: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            token: None,
            max: MAIL_STORE_MAX,
        }
    }
}

/// The token a claim or put starts with, and the rest.
fn token(request: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = request.split_first()?;
    let len = usize::from(*len);
    (len <= MAX_TOKEN).then(|| rest.split_at_checked(len))?
}

type Key = ([u8; BOX], [u8; SLOT]);

struct Claim {
    tag: [u8; 32],
    expiry: u64,
}

/// A mail record's slot under its lookup ID, its expiry, and where it sits.
struct Record {
    slot: [u8; SLOT],
    expiry: u64,
    at: At,
}

/// Where an envelope sits in its log, and when it was put.
struct Held {
    at: At,
    put: u64,
}

pub struct Store {
    claims: HashMap<Key, Claim>,
    slots: HashMap<Key, VecDeque<Held>>,
    /// Each box's bytes and envelopes, across its slots.
    boxes: HashMap<[u8; BOX], (u64, u32)>,
    records: HashMap<[u8; 16], Vec<Record>>,
    claims_log: Log,
    envelopes_log: Log,
    records_log: Log,
    settings: Settings,
    record_puts: Window,
    record_gets: Window,
    claim_rate: Window,
    collect_rate: Window,
    put_rate: Window,
    put_kib: Window,
}

/// A caller's keys for one limit of `per_key` an hour.
fn limits(caller: &Caller, per_key: u32) -> [(Vec<u8>, u32); 2] {
    [
        (caller.device.to_vec(), per_key),
        caller.network_limit(per_key * PER_NETWORK, per_key * RELAYED),
    ]
}

/// A log's size for a record of `len` payload bytes.
fn record(len: u32) -> u64 {
    4 + u64::from(len)
}

/// Opens one of the logs; a damaged one is moved aside and started anew,
/// and says so.
fn open_log(path: &Path, mut each: impl FnMut(At, &[u8]) -> bool) -> Result<(Log, bool), LogError> {
    match Log::open(path, &mut each) {
        Err(LogError::Damaged(_)) => {
            eprintln!("mesh-node seed: a mail log was damaged; it starts empty");
            move_aside(path).map_err(|e| LogError::Io(path.to_owned(), e))?;
            Ok((Log::open(path, each)?, true))
        }
        opened => Ok((opened?, false)),
    }
}

fn key(request: &[u8]) -> Option<(Key, &[u8])> {
    let (head, rest) = request.split_at_checked(HEAD)?;
    let (b, s) = head.split_at(BOX);
    Some(((b.try_into().ok()?, s.try_into().ok()?), rest))
}

impl Store {
    /// The store in `dir`: its logs read, what has expired by `now`
    /// dropped, and both compacted.
    pub fn open(dir: &Path, now: u64, settings: Settings) -> Result<Store, LogError> {
        let mut claims = HashMap::new();
        let (claims_log, _) = open_log(&dir.join("claims"), |_, p| {
            let Some(((key, rest), true)) = key(p).map(|k| (k, p.len() == CLAIM_RECORD)) else {
                return false;
            };
            let (tag, expiry) = rest.split_at(32);
            let claim = Claim {
                tag: tag.try_into().expect("32 bytes"),
                expiry: u64::from_be_bytes(expiry.try_into().expect("8 bytes")),
            };
            claims.insert(key, claim);
            true
        })?;
        let mut slots: HashMap<Key, VecDeque<Held>> = HashMap::new();
        let (envelopes_log, lost) = open_log(&dir.join("envelopes"), |at, p| match p.first() {
            Some(&PUT) if p.len() > PUT_HEAD + HEAD => {
                let put = u64::from_be_bytes(p[1..PUT_HEAD].try_into().expect("8 bytes"));
                let (key, _) = key(&p[PUT_HEAD..]).expect("long enough");
                slots.entry(key).or_default().push_back(Held { at, put });
                true
            }
            Some(&TAKE) if p.len() == 1 + HEAD + 4 => {
                let (key, count) = key(&p[1..]).expect("long enough");
                let count = u32::from_be_bytes(count.try_into().expect("4 bytes")) as usize;
                if let Some(held) = slots.get_mut(&key) {
                    held.drain(..count.min(held.len()));
                }
                true
            }
            _ => false,
        })?;
        if lost {
            // Readers must see no-box, so their `since` moves and senders
            // mail again (seed D9, mailbox M12).
            eprintln!(
                "mesh-node seed: {} mail claims dropped with it",
                claims.len()
            );
            claims.clear();
        }
        let mut records: HashMap<[u8; 16], Vec<Record>> = HashMap::new();
        let (records_log, _) = open_log(&dir.join("records"), |at, p| {
            let Some((lookup, slot, expiry)) = addr_outer(p) else {
                return false;
            };
            let slots = records.entry(lookup).or_default();
            match slots.iter_mut().find(|r| r.slot == slot) {
                Some(r) if r.expiry <= expiry => *r = Record { slot, expiry, at },
                Some(_) => {}
                None => slots.push(Record { slot, expiry, at }),
            }
            true
        })?;
        let mut store = Store {
            claims,
            slots,
            boxes: HashMap::new(),
            records,
            claims_log,
            envelopes_log,
            records_log,
            settings,
            record_puts: Window::default(),
            record_gets: Window::default(),
            claim_rate: Window::default(),
            collect_rate: Window::default(),
            put_rate: Window::default(),
            put_kib: Window::default(),
        };
        store.sweep(now);
        store
            .compact()
            .map_err(|e| LogError::Io(dir.to_owned(), e))?;
        Ok(store)
    }

    /// Drops claims past their expiry and envelopes past `MAIL_LIFE`, and
    /// compacts a log that's more dead than live.
    pub fn sweep(&mut self, now: u64) {
        self.claims.retain(|_, c| c.expiry > now);
        for held in self.slots.values_mut() {
            held.retain(|h| h.put + MAIL_LIFE > now);
        }
        self.slots.retain(|_, held| !held.is_empty());
        for slots in self.records.values_mut() {
            slots.retain(|r| r.expiry > now);
        }
        self.records.retain(|_, slots| !slots.is_empty());
        self.count_live();
        if (self.claims_log.wants_compacting()
            || self.envelopes_log.wants_compacting()
            || self.records_log.wants_compacting())
            && let Err(e) = self.compact()
        {
            eprintln!("mesh-node seed: couldn't compact the mail logs: {e}");
        }
    }

    fn count_live(&mut self) {
        self.claims_log.live = self.claims.len() as u64 * record(CLAIM_RECORD as u32);
        self.envelopes_log.live = (self.slots.values().flatten())
            .map(|h| record(h.at.len))
            .sum();
        self.records_log.live = (self.records.values().flatten())
            .map(|r| record(r.at.len))
            .sum();
        self.boxes.clear();
        for ((b, _), held) in &self.slots {
            let counted = self.boxes.entry(*b).or_default();
            counted.0 += held.iter().map(|h| u64::from(h.at.len)).sum::<u64>();
            counted.1 += held.len() as u32;
        }
    }

    /// Bytes held, claims, records and mail together, against `--mail-max`.
    pub fn total(&self) -> u64 {
        self.claims_log.live + self.envelopes_log.live + self.records_log.live
    }

    /// Whether `request` carries this seed's token, if it has one.
    fn admits<'a>(&self, request: &'a [u8]) -> Option<Result<&'a [u8], Answer>> {
        let (token, rest) = token(request)?;
        Some(match &self.settings.token {
            Some(ours) if ours != token => Err(Answer::Closed),
            _ => Ok(rest),
        })
    }

    /// Writes both logs anew with only what's live.
    fn compact(&mut self) -> std::io::Result<()> {
        let claims: Vec<Keep> = (self.claims.iter())
            .map(|((b, s), c)| Keep::Bytes([&b[..], s, &c.tag, &c.expiry.to_be_bytes()].concat()))
            .collect();
        self.claims_log.compact(&claims)?;
        let keep: Vec<Keep> = (self.slots.values().flatten())
            .map(|h| Keep::At(h.at))
            .collect();
        let places = self.envelopes_log.compact(&keep)?;
        for (held, at) in self.slots.values_mut().flatten().zip(places) {
            held.at = at;
        }
        let keep: Vec<Keep> = (self.records.values().flatten())
            .map(|r| Keep::At(r.at))
            .collect();
        let places = self.records_log.compact(&keep)?;
        for (r, at) in self.records.values_mut().flatten().zip(places) {
            r.at = at;
        }
        self.count_live();
        Ok(())
    }

    fn log_claim(&mut self, key: &Key, claim: &Claim) {
        let bytes = [&key.0[..], &key.1, &claim.tag, &claim.expiry.to_be_bytes()].concat();
        if let Err(e) = self.claims_log.append(&bytes, false) {
            eprintln!("mesh-node seed: couldn't write a mail claim: {e}");
        }
    }

    pub fn claim(&mut self, caller: &Caller, request: &[u8], now: u64) -> Answer {
        let request = match self.admits(request) {
            None => return Answer::Bad,
            Some(Err(answer)) => return answer,
            Some(Ok(rest)) => rest,
        };
        let Some((key, rest)) = key(request) else {
            return Answer::Bad;
        };
        let Some((tag, expiry)) = rest.split_first_chunk::<32>() else {
            return Answer::Bad;
        };
        let Ok(expiry) = <[u8; 8]>::try_from(expiry).map(u64::from_be_bytes) else {
            return Answer::Bad;
        };
        if expiry <= now || expiry > now + CLAIM_LIFE + CLOCK_ROOM {
            return Answer::Bad;
        }
        if !self
            .claim_rate
            .allow(now, HOUR, &limits(caller, CLAIMS_PER_KEY))
        {
            return Answer::SlowDown;
        }
        let standing = self.claims.get(&key).filter(|c| c.expiry > now);
        if standing.is_some_and(|c| c.tag != *tag) {
            return Answer::Taken;
        }
        // A renewal takes no more room; a new claim must fit.
        if standing.is_none() && self.total() + record(CLAIM_RECORD as u32) > self.settings.max {
            return Answer::Full;
        }
        let claim = Claim { tag: *tag, expiry };
        self.log_claim(&key, &claim);
        if self.claims.insert(key, claim).is_none() {
            self.claims_log.live += record(CLAIM_RECORD as u32);
        }
        Answer::Ok
    }

    fn claimed(&self, key: &Key, now: u64) -> bool {
        self.claims.get(key).is_some_and(|c| c.expiry > now)
    }

    /// The slot, if `secret` is its claimer's collect secret.
    fn collecting<'a>(&self, request: &'a [u8], now: u64) -> Option<(Key, &'a [u8])> {
        let (key, rest) = key(request)?;
        let (secret, rest) = rest.split_first_chunk::<SECRET>()?;
        let claim = self.claims.get(&key).filter(|c| c.expiry > now)?;
        (claim.tag == mail_collect_tag(secret)).then_some((key, rest))
    }

    pub fn put(&mut self, caller: &Caller, request: &[u8], now: u64) -> Answer {
        let request = match self.admits(request) {
            None => return Answer::Bad,
            Some(Err(answer)) => return answer,
            Some(Ok(rest)) => rest,
        };
        let key = match key(request) {
            Some((_, sealed)) if sealed.is_empty() || sealed.len() > MAX_SEALED => {
                return Answer::Bad;
            }
            Some((key, _)) => key,
            None => return Answer::Bad,
        };
        let kib = request.len().div_ceil(1024) as u32;
        let rates = self
            .put_rate
            .allow(now, HOUR, &limits(caller, PUTS_PER_KEY))
            && self
                .put_kib
                .allow_by(now, HOUR, &limits(caller, PUT_KIB_PER_KEY), kib);
        if !rates {
            return Answer::SlowDown;
        }
        if !self.claimed(&key, now) {
            return Answer::NoBox;
        }
        let payload = [&[PUT][..], &now.to_be_bytes(), request].concat();
        let (bytes, count) = self.boxes.get(&key.0).copied().unwrap_or_default();
        let len = payload.len() as u64;
        if bytes + len > BOX_MAX_BYTES
            || count >= BOX_MAX_ENVELOPES
            || self.total() + 4 + len > self.settings.max
        {
            return Answer::Full;
        }
        match self.envelopes_log.append(&payload, true) {
            Ok(at) => {
                self.envelopes_log.live += record(at.len);
                let counted = self.boxes.entry(key.0).or_default();
                counted.0 += u64::from(at.len);
                counted.1 += 1;
                let held = Held { at, put: now };
                self.slots.entry(key).or_default().push_back(held);
                Answer::Ok
            }
            Err(e) => {
                eprintln!("mesh-node seed: couldn't write mail: {e}");
                Answer::Bad
            }
        }
    }

    pub fn get(&mut self, caller: &Caller, request: &[u8], now: u64) -> Vec<u8> {
        if !self
            .collect_rate
            .allow(now, HOUR, &limits(caller, COLLECTS_PER_KEY))
        {
            return vec![Answer::SlowDown as u8];
        }
        let Some((key, [])) = self.collecting(request, now) else {
            return vec![Answer::NoBox as u8];
        };
        let mut out = vec![0, 0];
        let mut count = 0u16;
        let places: Vec<At> = (self.slots.get(&key).into_iter().flatten())
            .filter(|h| h.put + MAIL_LIFE > now)
            .map(|h| h.at)
            .collect();
        for at in places {
            let sealed_len = at.len as usize - PUT_HEAD;
            if out.len() + 4 + sealed_len > MAX_GET_BYTES || count == u16::MAX {
                break;
            }
            let Ok(payload) = self.envelopes_log.read(at) else {
                eprintln!("mesh-node seed: couldn't read mail");
                break;
            };
            out.extend_from_slice(&(sealed_len as u32).to_be_bytes());
            out.extend_from_slice(&payload[PUT_HEAD..]);
            count += 1;
        }
        out[..2].copy_from_slice(&count.to_be_bytes());
        out
    }

    pub fn take(&mut self, request: &[u8], now: u64) -> Answer {
        let Some((key, count)) = self.collecting(request, now) else {
            return Answer::NoBox;
        };
        let Ok(count) = <[u8; 4]>::try_from(count) else {
            return Answer::Bad;
        };
        let Some(held) = self.slots.get_mut(&key) else {
            return Answer::Ok;
        };
        let count = (u32::from_be_bytes(count) as usize).min(held.len());
        let gone: Vec<u32> = held.drain(..count).map(|h| h.at.len).collect();
        if held.is_empty() {
            self.slots.remove(&key);
        }
        if let Some(counted) = self.boxes.get_mut(&key.0) {
            counted.0 -= gone.iter().map(|l| u64::from(*l)).sum::<u64>();
            counted.1 -= gone.len() as u32;
        }
        let gone: u64 = gone.into_iter().map(record).sum();
        let payload = [&[TAKE][..], &key.0, &key.1, &(count as u32).to_be_bytes()].concat();
        if let Err(e) = self.envelopes_log.append(&payload, false) {
            eprintln!("mesh-node seed: couldn't write a mail take: {e}");
        }
        self.envelopes_log.live -= gone;
        if self.envelopes_log.wants_compacting()
            && let Err(e) = self.compact()
        {
            eprintln!("mesh-node seed: couldn't compact the mail logs: {e}");
        }
        Answer::Ok
    }

    /// Stores a mail record in its slot, replacing an older one there (a
    /// later expiry is newer), as `addr-put` does.
    pub fn put_record(&mut self, caller: &Caller, request: &[u8], now: u64) -> RecordPut {
        let bytes = match self.admits(request) {
            None => return RecordPut::Bad,
            Some(Err(_)) => return RecordPut::Closed,
            Some(Ok(rest)) => rest,
        };
        let Some((lookup, slot, expiry)) = addr_outer(bytes) else {
            return RecordPut::Bad;
        };
        if expiry <= now || expiry > now + RECORD_AHEAD + CLOCK_ROOM {
            return RecordPut::Bad;
        }
        if !self
            .record_puts
            .allow(now, HOUR, &limits(caller, RECORD_PUTS_PER_KEY))
        {
            return RecordPut::SlowDown;
        }
        let slots = self.records.entry(lookup).or_default();
        slots.retain(|r| r.expiry > now);
        let existing = slots.iter().position(|r| r.slot == slot);
        if existing.is_some_and(|i| slots[i].expiry > expiry) {
            // An older record changes nothing, and that's fine to say.
            return RecordPut::Ok;
        }
        if existing.is_none() && slots.len() >= SLOTS_PER_LOOKUP {
            return RecordPut::Full;
        }
        let old = existing.map_or(0, |i| u64::from(slots[i].at.len));
        if self.total() + 4 + bytes.len() as u64 > self.settings.max + old {
            return RecordPut::Full;
        }
        let at = match self.records_log.append(bytes, false) {
            Ok(at) => at,
            Err(e) => {
                eprintln!("mesh-node seed: couldn't write a mail record: {e}");
                return RecordPut::Bad;
            }
        };
        let slots = self.records.entry(lookup).or_default();
        let new = Record { slot, expiry, at };
        match existing {
            Some(i) => {
                self.records_log.live -= record(slots[i].at.len);
                slots[i] = new;
            }
            None => slots.push(new),
        }
        self.records_log.live += record(at.len);
        if self.records_log.wants_compacting()
            && let Err(e) = self.compact()
        {
            eprintln!("mesh-node seed: couldn't compact the mail logs: {e}");
        }
        RecordPut::Ok
    }

    /// The live mail records under `lookup`, as `addr-get` answers.
    pub fn get_records(&mut self, caller: &Caller, request: &[u8], now: u64) -> RecordGet {
        if !self
            .record_gets
            .allow(now, HOUR, &limits(caller, RECORD_GETS_PER_KEY))
        {
            return RecordGet::SlowDown;
        }
        let Ok(lookup) = <[u8; 16]>::try_from(request) else {
            return RecordGet::Found(Vec::new());
        };
        let places: Vec<At> = (self.records.get(&lookup).into_iter().flatten())
            .filter(|r| r.expiry > now)
            .map(|r| r.at)
            .collect();
        let found = places
            .into_iter()
            .filter_map(|at| self.records_log.read(at).ok())
            .collect();
        RecordGet::Found(found)
    }

    /// Envelopes held.
    pub fn len(&self) -> usize {
        self.slots.values().map(VecDeque::len).sum()
    }
}

/// A get's answer: the envelopes, oldest first. `None` if it doesn't read,
/// or is a no-box.
pub fn read_got(answer: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (count, mut rest) = answer.split_first_chunk::<2>()?;
    let mut out = Vec::new();
    for _ in 0..u16::from_be_bytes(*count) {
        let (len, after) = rest.split_first_chunk::<4>()?;
        let (sealed, after) = after.split_at_checked(u32::from_be_bytes(*len) as usize)?;
        out.push(sealed.to_vec());
        rest = after;
    }
    rest.is_empty().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const C: Caller = Caller {
        device: [1; 32],
        network: Some([10, 0, 0, 0, 0, 0]),
    };

    /// A claim or put for an open seed: no token.
    fn admit(request: &[u8]) -> Vec<u8> {
        [&[0u8][..], request].concat()
    }
    const SECRET: [u8; 32] = [7; 32];

    fn head(b: u8, s: u8) -> Vec<u8> {
        [[b; BOX].as_slice(), &[s; SLOT]].concat()
    }

    fn claim(at: &[u8], secret: &[u8; 32], expiry: u64) -> Vec<u8> {
        let tag = mail_collect_tag(secret);
        [at, &tag, &expiry.to_be_bytes()].concat()
    }

    fn with(at: &[u8], secret: &[u8; 32], more: &[u8]) -> Vec<u8> {
        [at, secret, more].concat()
    }

    fn empty(name: &str) -> Store {
        Store::open(&crate::maillog::temp(name), NOW, Settings::default()).unwrap()
    }

    fn claimed(at: &[u8]) -> Store {
        let mut store = empty(&format!("claimed-{}", at[0]));
        assert_eq!(
            store.claim(&C, &admit(&claim(at, &SECRET, NOW + 86_400)), NOW),
            Answer::Ok
        );
        store
    }

    #[test]
    fn put_get_take() {
        let at = head(1, 2);
        let mut store = claimed(&at);
        let whole = |s: &[u8]| [at.clone(), s.to_vec()].concat();
        assert_eq!(store.put(&C, &admit(&whole(b"one")), NOW), Answer::Ok);
        assert_eq!(store.put(&C, &admit(&whole(b"two")), NOW), Answer::Ok);
        let got = store.get(&C, &with(&at, &SECRET, &[]), NOW);
        assert_eq!(read_got(&got), Some(vec![whole(b"one"), whole(b"two")]));
        // One more comes after the get: a take of two leaves it.
        store.put(&C, &admit(&whole(b"three")), NOW);
        let take = |n: u32| with(&at, &SECRET, &n.to_be_bytes());
        assert_eq!(store.take(&take(2), NOW), Answer::Ok);
        let got = store.get(&C, &with(&at, &SECRET, &[]), NOW);
        assert_eq!(read_got(&got), Some(vec![whole(b"three")]));
        store.take(&take(9), NOW);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn only_claimed_slots_hold_and_only_their_secret_collects() {
        let at = head(3, 2);
        let mut store = empty("only-claimed");
        let put = [at.clone(), b"x".to_vec()].concat();
        assert_eq!(store.put(&C, &admit(&put), NOW), Answer::NoBox);
        store = claimed(&at);
        // Another slot of the same box is its own.
        let other = [head(3, 3), b"x".to_vec()].concat();
        assert_eq!(store.put(&C, &admit(&other), NOW), Answer::NoBox);
        assert_eq!(store.put(&C, &admit(&put), NOW), Answer::Ok);
        let wrong = [8; 32];
        assert_eq!(
            store.get(&C, &with(&at, &wrong, &[]), NOW),
            [Answer::NoBox as u8]
        );
        let take = with(&at, &wrong, &1u32.to_be_bytes());
        assert_eq!(store.take(&take, NOW), Answer::NoBox);
        assert_eq!(store.len(), 1, "nothing deleted");
        // A claim on a held slot under another tag is refused; a renewal
        // by the same tag moves it on.
        let theirs = claim(&at, &wrong, NOW + 86_400);
        assert_eq!(store.claim(&C, &admit(&theirs), NOW), Answer::Taken);
        let renewed = claim(&at, &SECRET, NOW + CLAIM_LIFE);
        assert_eq!(store.claim(&C, &admit(&renewed), NOW), Answer::Ok);
        // Past its expiry a claim holds nothing new, and someone may claim.
        let later = NOW + CLAIM_LIFE + 1;
        assert_eq!(store.put(&C, &admit(&put), later), Answer::NoBox);
        assert_eq!(
            store.get(&C, &with(&at, &SECRET, &[]), later),
            [Answer::NoBox as u8]
        );
        assert_eq!(
            store.claim(&C, &admit(&claim(&at, &wrong, later + 1)), later),
            Answer::Ok
        );
    }

    #[test]
    fn bad_requests() {
        let at = head(4, 2);
        let mut store = claimed(&at);
        assert_eq!(
            store.put(&C, &admit(&at), NOW),
            Answer::Bad,
            "nothing to hold"
        );
        assert_eq!(store.put(&C, &admit(&[0; 10]), NOW), Answer::Bad);
        let big = [at.clone(), vec![0; MAX_SEALED + 1]].concat();
        assert_eq!(store.put(&C, &admit(&big), NOW), Answer::Bad);
        assert_eq!(
            store.take(&with(&at, &SECRET, &[]), NOW),
            Answer::Bad,
            "no count"
        );
        assert_eq!(store.claim(&C, &admit(&at), NOW), Answer::Bad, "no tag");
        assert_eq!(
            store.claim(&C, &admit(&claim(&at, &SECRET, NOW)), NOW),
            Answer::Bad,
            "expired"
        );
        let ahead = claim(&head(9, 9), &SECRET, NOW + 30 + CLAIM_LIFE);
        assert_eq!(
            store.claim(&C, &admit(&ahead), NOW),
            Answer::Ok,
            "a clock 30 s ahead"
        );
        let far = claim(&at, &SECRET, NOW + CLAIM_LIFE + CLOCK_ROOM + 1);
        assert_eq!(
            store.claim(&C, &admit(&far), NOW),
            Answer::Bad,
            "too far ahead"
        );
        assert_eq!(read_got(&[Answer::NoBox as u8]), None);
        assert_eq!(read_got(&[0, 1, 0, 0, 0, 9]), None, "cut short");
    }

    #[test]
    fn a_get_fits_one_frame() {
        let at = head(5, 2);
        let mut store = claimed(&at);
        for _ in 0..40 {
            store.put(&C, &admit(&[at.clone(), vec![7; 60 * 1024]].concat()), NOW);
        }
        let got = store.get(&C, &with(&at, &SECRET, &[]), NOW);
        assert!(got.len() <= mesh_transport::frame::MAX_FRAME);
        assert!(read_got(&got).unwrap().len() < 40);
    }

    #[test]
    fn a_restart_keeps_claims_and_mail_and_drops_the_expired() {
        let dir = crate::maillog::temp("restart");
        let (a, b) = (head(6, 1), head(6, 2));
        let mut store = Store::open(&dir, NOW, Settings::default()).unwrap();
        store.claim(&C, &admit(&claim(&a, &SECRET, NOW + 86_400)), NOW);
        store.claim(&C, &admit(&claim(&b, &SECRET, NOW + CLAIM_LIFE)), NOW);
        let whole = |at: &[u8], s: &[u8]| [at.to_vec(), s.to_vec()].concat();
        store.put(&C, &admit(&whole(&a, b"one")), NOW);
        store.put(&C, &admit(&whole(&a, b"two")), NOW);
        store.put(&C, &admit(&whole(&b, b"old")), NOW);
        store.take(&with(&a, &SECRET, &1u32.to_be_bytes()), NOW);
        drop(store);
        let mut store = Store::open(&dir, NOW + 10, Settings::default()).unwrap();
        let got = store.get(&C, &with(&a, &SECRET, &[]), NOW + 10);
        assert_eq!(
            read_got(&got),
            Some(vec![whole(&a, b"two")]),
            "the take held too"
        );
        // A day later the first claim has lapsed; a month on, the mail too.
        let later = NOW + MAIL_LIFE;
        drop(store);
        let mut store = Store::open(&dir, later, Settings::default()).unwrap();
        assert_eq!(
            store.put(&C, &admit(&whole(&a, b"x")), later),
            Answer::NoBox
        );
        assert_eq!(store.len(), 0);
        let got = store.get(&C, &with(&b, &SECRET, &[]), later);
        assert_eq!(
            read_got(&got),
            Some(vec![]),
            "the claim stands, the mail is gone"
        );
        drop(store);
        let files = [dir.join("claims"), dir.join("envelopes")].map(|f| std::fs::read(f).unwrap());
        assert!(
            !crate::maillog::tests_contain(&files[1], b"old"),
            "gone from the file"
        );
        assert!(
            !crate::maillog::tests_contain(&files[0], &a[..HEAD]),
            "the lapsed claim too"
        );
    }

    #[test]
    fn a_damaged_log_starts_empty_and_a_newer_one_stops() {
        let dir = crate::maillog::temp("damaged");
        let at = head(7, 1);
        let mut store = Store::open(&dir, NOW, Settings::default()).unwrap();
        store.claim(&C, &admit(&claim(&at, &SECRET, NOW + 86_400)), NOW);
        drop(store);
        std::fs::write(dir.join("envelopes"), b"MLOG\x01\x00\x00\x00\x02??").unwrap();
        let mut store = Store::open(&dir, NOW, Settings::default()).unwrap();
        assert!(dir.join("envelopes.damaged").exists());
        // Mail was lost, so the claims go too: the reader's next renewal or
        // collect answers no-box, its `since` moves, and senders mail again
        // (seed D9, mailbox M12).
        let get = with(&at, &SECRET, &[]);
        assert_eq!(
            store.get(&C, &get, NOW),
            [Answer::NoBox as u8],
            "claims gone"
        );
        assert_eq!(
            store.put(&C, &admit(&[at.clone(), b"x".to_vec()].concat()), NOW),
            Answer::NoBox
        );
        drop(store);
        let store = Store::open(&dir, NOW, Settings::default()).unwrap();
        assert_eq!(store.claims.len(), 0, "and stay gone after a restart");
        // A damaged claims log alone takes nothing else with it.
        let mut store = store;
        store.claim(&C, &admit(&claim(&at, &SECRET, NOW + 86_400)), NOW);
        let put = admit(&[at.clone(), b"y".to_vec()].concat());
        assert_eq!(store.put(&C, &put, NOW), Answer::Ok);
        drop(store);
        std::fs::write(dir.join("records"), b"junk").unwrap();
        let store = Store::open(&dir, NOW, Settings::default()).unwrap();
        assert_eq!(
            (store.claims.len(), store.len()),
            (1, 1),
            "a damaged records log only"
        );
        drop(store);
        std::fs::write(dir.join("claims"), b"MLOG\x02").unwrap();
        assert!(matches!(
            Store::open(&dir, NOW, Settings::default()),
            Err(LogError::Newer(_))
        ));
    }

    fn caller(i: u32, network: u8) -> Caller {
        let mut device = [0; 32];
        device[..4].copy_from_slice(&i.to_be_bytes());
        Caller {
            device,
            network: Some([network, 0, 0, 0, 0, 0]),
        }
    }

    #[test]
    fn rates_per_key_and_network() {
        let at = head(8, 1);
        let mut store = claimed(&at);
        let put = admit(&[at.clone(), b"x".to_vec()].concat());
        for _ in 0..PUTS_PER_KEY {
            assert_eq!(store.put(&C, &put, NOW), Answer::Ok);
        }
        assert_eq!(store.put(&C, &put, NOW), Answer::SlowDown);
        assert_eq!(store.put(&C, &put, NOW + HOUR), Answer::Ok, "a new hour");
        // Claims: per key, then per network (two keys' worth).
        let mut store = empty("claim-rates");
        let claim_of = |i: u32| admit(&claim(&head(9, (i % 200) as u8), &SECRET, NOW + 86_400));
        for i in 0..CLAIMS_PER_KEY {
            assert_eq!(store.claim(&caller(1, 9), &claim_of(i), NOW), Answer::Ok);
        }
        assert_eq!(
            store.claim(&caller(1, 9), &claim_of(0), NOW),
            Answer::SlowDown
        );
        for i in 0..CLAIMS_PER_KEY {
            assert_eq!(store.claim(&caller(2, 9), &claim_of(i), NOW), Answer::Ok);
        }
        assert_eq!(
            store.claim(&caller(3, 9), &claim_of(0), NOW),
            Answer::SlowDown,
            "the network's"
        );
        assert_eq!(
            store.claim(&caller(3, 8), &claim_of(0), NOW),
            Answer::Ok,
            "another network"
        );
        // Collects.
        let get = with(&head(9, 0), &SECRET, &[]);
        for _ in 0..COLLECTS_PER_KEY {
            assert_ne!(
                store.get(&caller(4, 7), &get, NOW),
                [Answer::SlowDown as u8]
            );
        }
        assert_eq!(
            store.get(&caller(4, 7), &get, NOW),
            [Answer::SlowDown as u8]
        );
    }

    #[test]
    fn a_relayed_caller_shares_the_relayed_bucket() {
        let mut store = empty("relayed");
        let claim_of = |i: u32| admit(&claim(&head(10, (i % 200) as u8), &SECRET, NOW + 86_400));
        let relayed = |i| Caller {
            device: caller(i, 0).device,
            network: None,
        };
        for i in 0..RELAYED {
            for _ in 0..CLAIMS_PER_KEY {
                assert_eq!(store.claim(&relayed(i), &claim_of(i), NOW), Answer::Ok);
            }
        }
        assert_eq!(
            store.claim(&relayed(RELAYED), &claim_of(0), NOW),
            Answer::SlowDown
        );
    }

    #[test]
    fn a_box_has_a_quota() {
        let at = head(11, 1);
        let mut store = claimed(&at);
        let big = admit(&[at.clone(), vec![7; 60 * 1024]].concat());
        let fit = (BOX_MAX_BYTES / (60 * 1024 + 1024)) as u32;
        for i in 0..fit {
            assert_eq!(store.put(&caller(i, i as u8), &big, NOW), Answer::Ok);
        }
        let mut full = 0;
        for i in fit..fit + 3 {
            full += u32::from(store.put(&caller(i, i as u8), &big, NOW) == Answer::Full);
        }
        assert!(full >= 2, "past 4 MiB a box is full");
        // Another box of the same seed still takes mail.
        let other = head(12, 1);
        store.claim(&C, &admit(&claim(&other, &SECRET, NOW + 86_400)), NOW);
        let small = admit(&[other.clone(), b"x".to_vec()].concat());
        assert_eq!(store.put(&C, &small, NOW), Answer::Ok);
        // And at 1,000 envelopes, however small.
        let at = head(13, 1);
        store.claim(&C, &admit(&claim(&at, &SECRET, NOW + 86_400)), NOW);
        let tiny = admit(&[at.clone(), b"x".to_vec()].concat());
        for i in 0..BOX_MAX_ENVELOPES {
            assert_eq!(
                store.put(&caller(i + 100, (i % 250) as u8), &tiny, NOW),
                Answer::Ok
            );
        }
        assert_eq!(store.put(&caller(5_000, 251), &tiny, NOW), Answer::Full);
        // A take makes room again.
        let take = with(&at, &SECRET, &1u32.to_be_bytes());
        assert_eq!(store.take(&take, NOW), Answer::Ok);
        assert_eq!(store.put(&caller(5_001, 252), &tiny, NOW), Answer::Ok);
    }

    #[test]
    fn the_store_has_a_total_and_a_token() {
        let settings = Settings {
            token: Some(b"a-token-for-friends".to_vec()),
            max: 4096,
        };
        let mut store = Store::open(&crate::maillog::temp("total"), NOW, settings).unwrap();
        let at = head(14, 1);
        let with_token = |r: &[u8]| [&[19u8][..], b"a-token-for-friends", r].concat();
        let c = claim(&at, &SECRET, NOW + 86_400);
        assert_eq!(store.claim(&C, &admit(&c), NOW), Answer::Closed, "no token");
        let wrong = [&[19u8][..], b"not-the-token-at-al", &c].concat();
        assert_eq!(store.claim(&C, &wrong, NOW), Answer::Closed);
        assert_eq!(store.claim(&C, &with_token(&c), NOW), Answer::Ok);
        let put = |n: usize| with_token(&[at.clone(), vec![1; n]].concat());
        assert_eq!(
            store.put(&C, &admit(&[at.clone(), vec![1]].concat()), NOW),
            Answer::Closed
        );
        assert_eq!(store.put(&C, &put(3950), NOW), Answer::Ok);
        assert_eq!(
            store.put(&C, &put(1000), NOW),
            Answer::Full,
            "past --mail-max"
        );
        // A renewal still goes; a new claim doesn't fit.
        assert_eq!(store.claim(&C, &with_token(&c), NOW), Answer::Ok);
        let other = claim(&head(14, 2), &SECRET, NOW + 86_400);
        assert_eq!(store.claim(&C, &with_token(&other), NOW), Answer::Full);
        // Records too need the token: a stranger can't fill a closed seed
        // with them, and that's checked before it's full.
        let r = mail_record(3, 3, NOW + 60, 0);
        assert_eq!(store.put_record(&C, &admit(&r), NOW), RecordPut::Closed);
        assert_eq!(store.put_record(&C, &with_token(&r), NOW), RecordPut::Full);
        assert!(store.total() <= 4096);
    }

    /// A sealed record as the seed sees it: lookup, slot, expiry, then
    /// what only the pair can read.
    fn mail_record(lookup: u8, slot: u8, expiry: u64, fill: u8) -> Vec<u8> {
        [
            &[lookup; 16][..],
            &[slot; 8],
            &expiry.to_be_bytes(),
            &[fill; 80],
        ]
        .concat()
    }

    fn found(get: RecordGet) -> Vec<Vec<u8>> {
        match get {
            RecordGet::Found(records) => records,
            RecordGet::SlowDown => panic!("slowed"),
        }
    }

    #[test]
    fn mail_records_keep_a_week_and_replace_by_slot() {
        let dir = crate::maillog::temp("records");
        let mut store = Store::open(&dir, NOW, Settings::default()).unwrap();
        let week = mail_record(1, 1, NOW + RECORD_AHEAD, 1);
        assert_eq!(
            store.put_record(&C, &admit(&week), NOW),
            RecordPut::Ok,
            "7 days ahead"
        );
        let past = mail_record(1, 2, NOW + RECORD_AHEAD + CLOCK_ROOM + 1, 1);
        assert_eq!(
            store.put_record(&C, &admit(&past), NOW),
            RecordPut::Bad,
            "past the clock's room"
        );
        // A caller whose clock is 30 s ahead still asks for a week.
        let ahead = mail_record(9, 3, NOW + 30 + RECORD_AHEAD, 1);
        assert_eq!(store.put_record(&C, &admit(&ahead), NOW), RecordPut::Ok);
        assert_eq!(
            store.put_record(&C, &admit(&b"short"[..]), NOW),
            RecordPut::Bad
        );
        // A newer record replaces its slot; an older one changes nothing.
        let newer = mail_record(1, 1, NOW + RECORD_AHEAD, 2);
        let older = mail_record(1, 1, NOW + 60, 3);
        assert_eq!(store.put_record(&C, &admit(&newer), NOW), RecordPut::Ok);
        assert_eq!(store.put_record(&C, &admit(&older), NOW), RecordPut::Ok);
        assert_eq!(
            found(store.get_records(&C, &[1; 16], NOW)),
            [newer.as_slice()]
        );
        let total = store.total();
        assert!(total > 0, "records count in the total");
        // Eight slots a lookup, as address records.
        for slot in 2..=8 {
            store.put_record(&C, &admit(&mail_record(1, slot, NOW + 60, 0)), NOW);
        }
        let ninth = mail_record(1, 9, NOW + 60, 0);
        assert_eq!(store.put_record(&C, &admit(&ninth), NOW), RecordPut::Full);
        // A restart keeps them; a week later they've swept.
        drop(store);
        let mut store = Store::open(&dir, NOW + 10, Settings::default()).unwrap();
        assert_eq!(found(store.get_records(&C, &[1; 16], NOW + 10))[0], newer);
        let later = NOW + 30 + RECORD_AHEAD;
        store.sweep(later);
        assert!(found(store.get_records(&C, &[1; 16], later)).is_empty());
        assert_eq!(store.total(), 0);
    }

    #[test]
    fn mail_records_have_their_rates() {
        let mut store = empty("record-rates");
        for i in 0..RECORD_PUTS_PER_KEY {
            let r = mail_record((i % 200) as u8, (i / 200) as u8, NOW + 60, 0);
            assert_ne!(store.put_record(&C, &admit(&r), NOW), RecordPut::SlowDown);
        }
        let r = mail_record(0, 0, NOW + 60, 0);
        assert_eq!(store.put_record(&C, &admit(&r), NOW), RecordPut::SlowDown);
        for _ in 0..RECORD_GETS_PER_KEY {
            assert_ne!(store.get_records(&C, &[0; 16], NOW), RecordGet::SlowDown);
        }
        assert_eq!(store.get_records(&C, &[0; 16], NOW), RecordGet::SlowDown);
    }
}
