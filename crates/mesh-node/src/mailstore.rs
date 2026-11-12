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

// ponytail: in memory, no limits (PLAN-mailbox Tasks 3 and 4).

use mesh_identity::mail_collect_tag;
use std::collections::HashMap;

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

#[derive(Default)]
pub struct Store {
    claims: HashMap<Key, Claim>,
    slots: HashMap<Key, Vec<Vec<u8>>>,
}

fn key(request: &[u8]) -> Option<(Key, &[u8])> {
    let (head, rest) = request.split_at_checked(HEAD)?;
    let (b, s) = head.split_at(BOX);
    Some(((b.try_into().ok()?, s.try_into().ok()?), rest))
}

impl Store {
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
        match self.claims.get_mut(&key) {
            Some(c) if c.expiry > now && c.tag != *tag => Answer::Taken,
            Some(c) => {
                *c = Claim { tag: *tag, expiry };
                Answer::Ok
            }
            None => {
                self.claims.insert(key, Claim { tag: *tag, expiry });
                Answer::Ok
            }
        }
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
                self.slots.entry(key).or_default().push(request.to_vec());
                Answer::Ok
            }
            Some(_) => Answer::NoBox,
            None => Answer::Bad,
        }
    }

    pub fn get(&self, request: &[u8], now: u64) -> Vec<u8> {
        let Some((key, [])) = self.collecting(request, now) else {
            return vec![Answer::NoBox as u8];
        };
        let mut out = vec![0, 0];
        let mut count = 0u16;
        for sealed in self.slots.get(&key).into_iter().flatten() {
            if out.len() + 4 + sealed.len() > MAX_GET_BYTES || count == u16::MAX {
                break;
            }
            out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
            out.extend_from_slice(sealed);
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
        if let Some(held) = self.slots.get_mut(&key) {
            let count = (u32::from_be_bytes(count) as usize).min(held.len());
            held.drain(..count);
            if held.is_empty() {
                self.slots.remove(&key);
            }
        }
        Answer::Ok
    }

    /// Envelopes held.
    pub fn len(&self) -> usize {
        self.slots.values().map(Vec::len).sum()
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

    fn claimed(at: &[u8]) -> Store {
        let mut store = Store::default();
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
        let at = head(1, 2);
        let mut store = Store::default();
        let put = [at.clone(), b"x".to_vec()].concat();
        assert_eq!(store.put(&put, NOW), Answer::NoBox);
        store = claimed(&at);
        // Another slot of the same box is its own.
        let other = [head(1, 3), b"x".to_vec()].concat();
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
        let at = head(1, 2);
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
        let at = head(1, 2);
        let mut store = claimed(&at);
        for _ in 0..40 {
            store.put(&[at.clone(), vec![7; 60 * 1024]].concat(), NOW);
        }
        let got = store.get(&with(&at, &SECRET, &[]), NOW);
        assert!(got.len() <= mesh_transport::frame::MAX_FRAME);
        assert!(read_got(&got).unwrap().len() < 40);
    }
}
