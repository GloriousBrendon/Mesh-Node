//! The seed's mail (SPEC-mailbox): sealed envelopes held in boxes, by slot,
//! only for slots their reader claimed (M6), until the reader collects them
//! with its collect secret. Requests on the batched services:
//!
//! ```text
//! mail-claim = box [16] | slot [8] | collect tag [32] | expiry u64  -> answer u8
//! mail-put   = sealed (its first 24 bytes are box [16] | slot [8])  -> answer u8
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
//! duplicate it drops by event ID.

// ponytail: no limits yet (PLAN-mailbox Task 4).

use crate::maillog::{At, Keep, Log, LogError, move_aside};
use mesh_identity::mail_collect_tag;
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
}

type Key = ([u8; BOX], [u8; SLOT]);

struct Claim {
    tag: [u8; 32],
    expiry: u64,
}

/// Where an envelope sits in its log, and when it was put.
struct Held {
    at: At,
    put: u64,
}

pub struct Store {
    claims: HashMap<Key, Claim>,
    slots: HashMap<Key, VecDeque<Held>>,
    claims_log: Log,
    envelopes_log: Log,
}

/// A log's size for a record of `len` payload bytes.
fn record(len: u32) -> u64 {
    4 + u64::from(len)
}

/// Opens one of the logs; a damaged one is moved aside and started anew.
fn open_log(path: &Path, mut each: impl FnMut(At, &[u8]) -> bool) -> Result<Log, LogError> {
    match Log::open(path, &mut each) {
        Err(LogError::Damaged(_)) => {
            eprintln!("mesh-node seed: a mail log was damaged; it starts empty");
            move_aside(path).map_err(|e| LogError::Io(path.to_owned(), e))?;
            Log::open(path, each)
        }
        opened => opened,
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
    pub fn open(dir: &Path, now: u64) -> Result<Store, LogError> {
        let mut claims = HashMap::new();
        let claims_log = open_log(&dir.join("claims"), |_, p| {
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
        let envelopes_log = open_log(&dir.join("envelopes"), |at, p| match p.first() {
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
        let mut store = Store {
            claims,
            slots,
            claims_log,
            envelopes_log,
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
        self.count_live();
        if (self.claims_log.wants_compacting() || self.envelopes_log.wants_compacting())
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
        self.count_live();
        Ok(())
    }

    fn log_claim(&mut self, key: &Key, claim: &Claim) {
        let bytes = [&key.0[..], &key.1, &claim.tag, &claim.expiry.to_be_bytes()].concat();
        if let Err(e) = self.claims_log.append(&bytes, false) {
            eprintln!("mesh-node seed: couldn't write a mail claim: {e}");
        }
    }

    pub fn claim(&mut self, request: &[u8], now: u64) -> Answer {
        let Some((key, rest)) = key(request) else {
            return Answer::Bad;
        };
        let Some((tag, expiry)) = rest.split_first_chunk::<32>() else {
            return Answer::Bad;
        };
        let Ok(expiry) = <[u8; 8]>::try_from(expiry).map(u64::from_be_bytes) else {
            return Answer::Bad;
        };
        if expiry <= now || expiry > now + CLAIM_LIFE {
            return Answer::Bad;
        }
        if self
            .claims
            .get(&key)
            .is_some_and(|c| c.expiry > now && c.tag != *tag)
        {
            return Answer::Taken;
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

    pub fn put(&mut self, request: &[u8], now: u64) -> Answer {
        match key(request) {
            Some((_, sealed)) if sealed.is_empty() || sealed.len() > MAX_SEALED => Answer::Bad,
            Some((key, _)) if self.claimed(&key, now) => {
                let payload = [&[PUT][..], &now.to_be_bytes(), request].concat();
                match self.envelopes_log.append(&payload, true) {
                    Ok(at) => {
                        self.envelopes_log.live += record(at.len);
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
            Some(_) => Answer::NoBox,
            None => Answer::Bad,
        }
    }

    pub fn get(&mut self, request: &[u8], now: u64) -> Vec<u8> {
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
        let gone: u64 = held.drain(..count).map(|h| record(h.at.len)).sum();
        if held.is_empty() {
            self.slots.remove(&key);
        }
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
        Store::open(&crate::maillog::temp(name), NOW).unwrap()
    }

    fn claimed(at: &[u8]) -> Store {
        let mut store = empty(&format!("claimed-{}", at[0]));
        assert_eq!(
            store.claim(&claim(at, &SECRET, NOW + 86_400), NOW),
            Answer::Ok
        );
        store
    }

    #[test]
    fn put_get_take() {
        let at = head(1, 2);
        let mut store = claimed(&at);
        let whole = |s: &[u8]| [at.clone(), s.to_vec()].concat();
        assert_eq!(store.put(&whole(b"one"), NOW), Answer::Ok);
        assert_eq!(store.put(&whole(b"two"), NOW), Answer::Ok);
        let got = store.get(&with(&at, &SECRET, &[]), NOW);
        assert_eq!(read_got(&got), Some(vec![whole(b"one"), whole(b"two")]));
        // One more comes after the get: a take of two leaves it.
        store.put(&whole(b"three"), NOW);
        let take = |n: u32| with(&at, &SECRET, &n.to_be_bytes());
        assert_eq!(store.take(&take(2), NOW), Answer::Ok);
        let got = store.get(&with(&at, &SECRET, &[]), NOW);
        assert_eq!(read_got(&got), Some(vec![whole(b"three")]));
        store.take(&take(9), NOW);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn only_claimed_slots_hold_and_only_their_secret_collects() {
        let at = head(3, 2);
        let mut store = empty("only-claimed");
        let put = [at.clone(), b"x".to_vec()].concat();
        assert_eq!(store.put(&put, NOW), Answer::NoBox);
        store = claimed(&at);
        // Another slot of the same box is its own.
        let other = [head(3, 3), b"x".to_vec()].concat();
        assert_eq!(store.put(&other, NOW), Answer::NoBox);
        assert_eq!(store.put(&put, NOW), Answer::Ok);
        let wrong = [8; 32];
        assert_eq!(
            store.get(&with(&at, &wrong, &[]), NOW),
            [Answer::NoBox as u8]
        );
        let take = with(&at, &wrong, &1u32.to_be_bytes());
        assert_eq!(store.take(&take, NOW), Answer::NoBox);
        assert_eq!(store.len(), 1, "nothing deleted");
        // A claim on a held slot under another tag is refused; a renewal
        // by the same tag moves it on.
        let theirs = claim(&at, &wrong, NOW + 86_400);
        assert_eq!(store.claim(&theirs, NOW), Answer::Taken);
        let renewed = claim(&at, &SECRET, NOW + CLAIM_LIFE);
        assert_eq!(store.claim(&renewed, NOW), Answer::Ok);
        // Past its expiry a claim holds nothing new, and someone may claim.
        let later = NOW + CLAIM_LIFE + 1;
        assert_eq!(store.put(&put, later), Answer::NoBox);
        assert_eq!(
            store.get(&with(&at, &SECRET, &[]), later),
            [Answer::NoBox as u8]
        );
        assert_eq!(
            store.claim(&claim(&at, &wrong, later + 1), later),
            Answer::Ok
        );
    }

    #[test]
    fn bad_requests() {
        let at = head(4, 2);
        let mut store = claimed(&at);
        assert_eq!(store.put(&at, NOW), Answer::Bad, "nothing to hold");
        assert_eq!(store.put(&[0; 10], NOW), Answer::Bad);
        let big = [at.clone(), vec![0; MAX_SEALED + 1]].concat();
        assert_eq!(store.put(&big, NOW), Answer::Bad);
        assert_eq!(
            store.take(&with(&at, &SECRET, &[]), NOW),
            Answer::Bad,
            "no count"
        );
        assert_eq!(store.claim(&at, NOW), Answer::Bad, "no tag");
        assert_eq!(
            store.claim(&claim(&at, &SECRET, NOW), NOW),
            Answer::Bad,
            "expired"
        );
        let far = claim(&at, &SECRET, NOW + CLAIM_LIFE + 1);
        assert_eq!(store.claim(&far, NOW), Answer::Bad, "too far ahead");
        assert_eq!(read_got(&[Answer::NoBox as u8]), None);
        assert_eq!(read_got(&[0, 1, 0, 0, 0, 9]), None, "cut short");
    }

    #[test]
    fn a_get_fits_one_frame() {
        let at = head(5, 2);
        let mut store = claimed(&at);
        for _ in 0..40 {
            store.put(&[at.clone(), vec![7; 60 * 1024]].concat(), NOW);
        }
        let got = store.get(&with(&at, &SECRET, &[]), NOW);
        assert!(got.len() <= mesh_transport::frame::MAX_FRAME);
        assert!(read_got(&got).unwrap().len() < 40);
    }

    #[test]
    fn a_restart_keeps_claims_and_mail_and_drops_the_expired() {
        let dir = crate::maillog::temp("restart");
        let (a, b) = (head(6, 1), head(6, 2));
        let mut store = Store::open(&dir, NOW).unwrap();
        store.claim(&claim(&a, &SECRET, NOW + 86_400), NOW);
        store.claim(&claim(&b, &SECRET, NOW + CLAIM_LIFE), NOW);
        let whole = |at: &[u8], s: &[u8]| [at.to_vec(), s.to_vec()].concat();
        store.put(&whole(&a, b"one"), NOW);
        store.put(&whole(&a, b"two"), NOW);
        store.put(&whole(&b, b"old"), NOW);
        store.take(&with(&a, &SECRET, &1u32.to_be_bytes()), NOW);
        drop(store);
        let mut store = Store::open(&dir, NOW + 10).unwrap();
        let got = store.get(&with(&a, &SECRET, &[]), NOW + 10);
        assert_eq!(
            read_got(&got),
            Some(vec![whole(&a, b"two")]),
            "the take held too"
        );
        // A day later the first claim has lapsed; a month on, the mail too.
        let later = NOW + MAIL_LIFE;
        drop(store);
        let mut store = Store::open(&dir, later).unwrap();
        assert_eq!(store.put(&whole(&a, b"x"), later), Answer::NoBox);
        assert_eq!(store.len(), 0);
        let got = store.get(&with(&b, &SECRET, &[]), later);
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
        let mut store = Store::open(&dir, NOW).unwrap();
        store.claim(&claim(&at, &SECRET, NOW + 86_400), NOW);
        drop(store);
        std::fs::write(dir.join("envelopes"), b"MLOG\x01\x00\x00\x00\x02??").unwrap();
        let mut store = Store::open(&dir, NOW).unwrap();
        assert!(dir.join("envelopes.damaged").exists());
        assert_eq!(
            store.put(&[at.clone(), b"x".to_vec()].concat(), NOW),
            Answer::Ok,
            "claims kept"
        );
        drop(store);
        std::fs::write(dir.join("claims"), b"MLOG\x02").unwrap();
        assert!(matches!(Store::open(&dir, NOW), Err(LogError::Newer(_))));
    }
}
