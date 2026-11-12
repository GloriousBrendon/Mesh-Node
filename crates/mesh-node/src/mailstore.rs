//! The seed's mail (SPEC-mailbox): sealed envelopes held in boxes, by slot,
//! until the reader collects them. Requests on the batched services:
//!
//! ```text
//! mail-put  = sealed (its first 24 bytes are box [16] | slot [8])  -> answer u8
//! mail-get  = box [16] | slot [8]                 -> count u16 | (len u32 | sealed)*
//! mail-take = box [16] | slot [8] | count u32     -> answer u8
//! ```
//!
//! The seal's associated data starts with the box and slot (e2ee D8), so an
//! envelope moved to another box doesn't open. A get hands back the slot's oldest envelopes, as many as fit one frame;
//! a take of `count` then deletes those, once the reader has stored them.
//! Envelopes put meanwhile go after them, so they stay.

// ponytail: in memory, any box, no claims or limits (PLAN-mailbox Task 1); Tasks 2 to 4.

use std::collections::HashMap;

pub const BOX: usize = 16;
pub const SLOT: usize = 8;
const HEAD: usize = BOX + SLOT;
/// The largest sealed envelope a put takes: the largest e2ee frame and the
/// mail wrapper's head and seal.
pub const MAX_SEALED: usize = crate::e2ee::MAX_FRAME + 1024;
/// What one get hands back at most, under the transport's frame limit.
const MAX_GET_BYTES: usize = mesh_transport::frame::MAX_FRAME - 1024;

/// A put's or take's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Ok = 0,
    Bad = 1,
}

type Key = ([u8; BOX], [u8; SLOT]);

#[derive(Default)]
pub struct Store {
    slots: HashMap<Key, Vec<Vec<u8>>>,
}

fn key(request: &[u8]) -> Option<(Key, &[u8])> {
    let (head, rest) = request.split_at_checked(HEAD)?;
    let (b, s) = head.split_at(BOX);
    Some(((b.try_into().ok()?, s.try_into().ok()?), rest))
}

impl Store {
    pub fn put(&mut self, request: &[u8]) -> Answer {
        match key(request) {
            Some((key, sealed)) if !sealed.is_empty() && sealed.len() <= MAX_SEALED => {
                self.slots.entry(key).or_default().push(request.to_vec());
                Answer::Ok
            }
            _ => Answer::Bad,
        }
    }

    pub fn get(&self, request: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0];
        let Some((key, [])) = key(request) else {
            return out;
        };
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

    pub fn take(&mut self, request: &[u8]) -> Answer {
        let Some((key, count)) = key(request) else {
            return Answer::Bad;
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

/// A get's answer: the envelopes, oldest first. `None` if it doesn't read.
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

    fn head(b: u8, s: u8) -> Vec<u8> {
        [[b; BOX].as_slice(), &[s; SLOT]].concat()
    }

    #[test]
    fn put_get_take() {
        let mut store = Store::default();
        let at = head(1, 2);
        assert_eq!(
            store.put(&[at.clone(), b"one".to_vec()].concat()),
            Answer::Ok
        );
        assert_eq!(
            store.put(&[at.clone(), b"two".to_vec()].concat()),
            Answer::Ok
        );
        let whole = |s: &[u8]| [at.clone(), s.to_vec()].concat();
        assert_eq!(
            read_got(&store.get(&at)),
            Some(vec![whole(b"one"), whole(b"two")])
        );
        // Another slot of the same box is its own.
        assert_eq!(read_got(&store.get(&head(1, 3))), Some(vec![]));
        // One more comes after the get: a take of two leaves it.
        store.put(&[at.clone(), b"three".to_vec()].concat());
        assert_eq!(
            store.take(&[at.clone(), 2u32.to_be_bytes().to_vec()].concat()),
            Answer::Ok
        );
        assert_eq!(read_got(&store.get(&at)), Some(vec![whole(b"three")]));
        store.take(&[at.clone(), 9u32.to_be_bytes().to_vec()].concat());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn bad_requests() {
        let mut store = Store::default();
        assert_eq!(store.put(&head(1, 2)), Answer::Bad, "nothing to hold");
        assert_eq!(store.put(&[0; 10]), Answer::Bad);
        let big = [head(1, 2), vec![0; MAX_SEALED + 1]].concat();
        assert_eq!(store.put(&big), Answer::Bad);
        assert_eq!(store.take(&head(1, 2)), Answer::Bad, "no count");
        assert_eq!(read_got(&store.get(&[0; 3])), Some(vec![]));
        assert_eq!(read_got(&[0, 1, 0, 0, 0, 9]), None, "cut short");
    }

    #[test]
    fn a_get_fits_one_frame() {
        let mut store = Store::default();
        let at = head(1, 2);
        for _ in 0..40 {
            store.put(&[at.clone(), vec![7; 60 * 1024]].concat());
        }
        let got = store.get(&at);
        assert!(got.len() <= mesh_transport::frame::MAX_FRAME);
        assert!(read_got(&got).unwrap().len() < 40);
    }
}
