//! The helper's side of `mailbox` (SPEC-mailbox). Events waiting for a
//! friend's device with no open connection are encrypted for it as live,
//! sealed in the mail wrapper and put into this week's box for that device
//! on a seed (M1, M2, M5, M7). At unlock the helper collects its own boxes
//! before any live delivery, opens what it finds as if it had come live,
//! stores it, deletes it from the seed, and puts a receipt into the sender's
//! box; a sender that collects the receipt moves its counters (M9).
//!
//! A child of `helper`, as `dm` is.

// ponytail: PLAN-mailbox Task 1, the thin path. The first `--seed` is the
// only holder, this week's box the only one, no claims; marks and `mseq`s
// live in memory (Task 11 saves them); receipts carry `ok` only (Task 8);
// friends' devices only (Task 13 adds our own).

use super::*;
use crate::mailstore;
use mesh_e2ee::{MAIL, MailHead, RECEIPT, open_mail, seal_mail};
use mesh_identity::{PairKeys, VerifyingKey, week_of};
use tokio::task::JoinHandle;

/// Lock and quit wait this long for puts under way (mailbox *Limits*).
pub(super) const MAIL_FLUSH: Duration = Duration::from_secs(3);
/// A holder silent this long is skipped (mailbox M10).
pub(super) const HOLDER_WAIT: Duration = Duration::from_secs(10);
/// A box and slot, as the seed names a slot.
const ADDRESS: usize = mailstore::BOX + mailstore::SLOT;

/// What mail knows between locks, in this process.
#[derive(Default)]
pub(super) struct Mail {
    /// The last `mseq` used for each reader device.
    seq: HashMap<[u8; 32], u64>,
    /// Each put, by reader device and `mseq`: the event's number.
    sent: HashMap<([u8; 32], u64), u64>,
    /// Events already mailed to a device, so they aren't put again (M15).
    marked: HashSet<([u8; 32], u64)>,
    /// Puts under way, which lock and quit wait for.
    pending: Vec<JoinHandle<()>>,
    /// The unlock's collect hasn't come back: live sending waits for it.
    pub(super) collecting: bool,
}

/// What a collect found in one contact's box for us.
pub(super) struct Found {
    pub id: MeshId,
    pub address: [u8; ADDRESS],
    pub sealed: Vec<Vec<u8>>,
}

impl Mail {
    /// The next `mseq` for a reader device: always higher than the last,
    /// and than any before a restart, since it starts from the clock.
    fn next_seq(&mut self, reader: [u8; 32]) -> u64 {
        let now = unix_now_ms();
        let seq = self.seq.entry(reader).or_insert(0);
        *seq = (*seq + 1).max(now);
        *seq
    }
}

fn unix_now_ms() -> u64 {
    unix_now() * 1000
}

/// The box and slot of `reader`'s `device` for the pair `keys`, this week.
fn mail_address(keys: &PairKeys, reader: &MeshId, device: &VerifyingKey) -> [u8; ADDRESS] {
    let mut out = [0u8; ADDRESS];
    out[..mailstore::BOX].copy_from_slice(&keys.mail_box(reader, week_of(unix_now())));
    out[mailstore::BOX..].copy_from_slice(&keys.mail_slot(device));
    out
}

/// A receipt's body: the `mseq`s answered `ok`.
fn receipt_body(oks: &[u64]) -> Vec<u8> {
    oks.iter().flat_map(|m| m.to_be_bytes()).collect()
}

fn read_receipt(body: &[u8]) -> Option<Vec<u64>> {
    let (chunks, rest) = body.as_chunks::<8>();
    rest.is_empty()
        .then(|| chunks.iter().map(|c| u64::from_be_bytes(*c)).collect())
}

impl Helper {
    /// Mails what waits for each of `id`'s devices that has no open
    /// connection (M2), to the first seed.
    pub(super) fn mail_out(&mut self, id: &MeshId) {
        let (Some(store), Some(net), Some(e2ee)) = (&self.store, &self.net, &self.e2ee) else {
            return;
        };
        if store.id() == *id {
            return;
        }
        let Some(seed) = self.seeds.first().cloned() else {
            return;
        };
        let (Some(keys), anon) = (store.pair_keys(id), net.anon.clone()) else {
            return;
        };
        let me = store.device_key().public().to_bytes();
        let connected: HashSet<[u8; 32]> = (net.node.connected(id).iter())
            .map(|a| *a.device.as_bytes())
            .collect();
        let away: Vec<[u8; 32]> = (e2ee.device_keys(id).into_iter())
            .filter(|d| !connected.contains(d))
            .collect();
        let mut puts = Vec::new();
        let mut numbers_put = Vec::new();
        for device in away {
            let marked: HashSet<u64> = (self.mail.marked.iter())
                .filter(|(d, _)| *d == device)
                .map(|(_, n)| *n)
                .collect();
            let Some((numbers, envelopes)) = self.dm_batch(id, device, |n| marked.contains(&n))
            else {
                continue;
            };
            let Ok(reader) = VerifyingKey::from_bytes(&device) else {
                continue;
            };
            let at = mail_address(&keys, id, &reader);
            for (number, envelope) in numbers.into_iter().zip(envelopes) {
                let mseq = self.mail.next_seq(device);
                let head = MailHead {
                    sender: me,
                    kind: MAIL,
                    mseq,
                };
                let Ok(sealed) = seal_mail(&reader, &at, &head, &envelope) else {
                    continue;
                };
                self.mail.sent.insert((device, mseq), number);
                self.mail.marked.insert((device, number));
                numbers_put.push((device, mseq, number));
                puts.push(sealed);
            }
        }
        if puts.is_empty() {
            return;
        }
        eprintln!("mesh-node: mailed {} events", puts.len());
        let back = self.back.clone();
        self.mail.pending.retain(|h| !h.is_finished());
        self.mail.pending.push(tokio::spawn(async move {
            let answers = seed::ask_many(&anon, &seed, seed::MAIL_PUT, &puts).await;
            let taken =
                answers.is_ok_and(|a| a.iter().all(|a| a == &[mailstore::Answer::Ok as u8]));
            if !taken {
                let _ = back.send(Back::MailUnput(numbers_put));
            }
        }));
    }

    /// Mails what waits for every contact.
    pub(super) fn mail_out_all(&mut self) {
        let ids: Vec<MeshId> = (self.store.iter())
            .flat_map(|s| s.contacts().iter().map(|c| c.id()))
            .collect();
        for id in ids {
            self.mail_out(&id);
        }
    }

    /// A put didn't go through: those events may be mailed again.
    pub(super) fn mail_unput(&mut self, puts: Vec<([u8; 32], u64, u64)>) {
        eprintln!("mesh-node: {} mailed events weren't taken", puts.len());
        for (device, mseq, number) in puts {
            self.mail.sent.remove(&(device, mseq));
            self.mail.marked.remove(&(device, number));
        }
    }

    /// At lock and quit: mail what waits, then let the puts finish, up to
    /// `MAIL_FLUSH`.
    pub(super) async fn mail_flush(&mut self) {
        self.mail_out_all();
        let deadline = tokio::time::Instant::now() + MAIL_FLUSH;
        for put in std::mem::take(&mut self.mail.pending) {
            let _ = tokio::time::timeout_at(deadline, put).await;
        }
    }

    /// At unlock: collect this week's mail for this device, from every
    /// contact's box, before any live sending.
    pub(super) fn mail_collect(&mut self) {
        let (Some(store), Some(net), Some(seed)) = (&self.store, &self.net, self.seeds.first())
        else {
            return;
        };
        let (me, device) = (store.id(), store.device_key().public());
        let mut asked = Vec::new();
        for contact in store.contacts() {
            if let Some(keys) = store.pair_keys(&contact.id()) {
                asked.push((contact.id(), mail_address(&keys, &me, &device)));
            }
        }
        if asked.is_empty() {
            return;
        }
        self.mail.collecting = true;
        let (anon, seed, back) = (net.anon.clone(), seed.clone(), self.back.clone());
        tokio::spawn(async move {
            let requests: Vec<Vec<u8>> = asked.iter().map(|(_, a)| a.to_vec()).collect();
            let asking = seed::ask_many(&anon, &seed, seed::MAIL_GET, &requests);
            let answers = tokio::time::timeout(HOLDER_WAIT, asking).await;
            let found = match answers {
                Ok(Ok(answers)) => (asked.into_iter().zip(answers))
                    .filter_map(|((id, address), answer)| {
                        let sealed = mailstore::read_got(&answer)?;
                        (!sealed.is_empty()).then_some(Found {
                            id,
                            address,
                            sealed,
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let _ = back.send(Back::MailFound(found));
        });
    }

    /// Collected mail: opened in each sender's order, stored, deleted from
    /// the seed, and answered by receipt; receipts move our counters. Then
    /// live sending starts.
    pub(super) fn mail_found(&mut self, found: Vec<Found>) {
        self.mail.collecting = false;
        let mut receipts = Vec::new();
        let mut takes = Vec::new();
        let mut opened_count = 0;
        let mut acked = false;
        for Found {
            id,
            address,
            sealed,
        } in found
        {
            let Some(store) = &self.store else { return };
            let device_key = store.device_key();
            let mut mail: Vec<(MailHead, Vec<u8>)> = Vec::new();
            let mut got_receipts = Vec::new();
            for bytes in &sealed {
                match open_mail(device_key, ADDRESS, bytes) {
                    Ok((head, body)) if head.kind == MAIL => mail.push((head, body)),
                    Ok(receipt) => got_receipts.push(receipt),
                    Err(_) => {}
                }
            }
            for (head, body) in got_receipts {
                acked |= self.mail_receipt(&head, &body);
            }
            takes.push([&address[..], &(sealed.len() as u32).to_be_bytes()].concat());
            // Olm needs each sender device's mail in its order (M8).
            mail.sort_by_key(|(head, _)| (head.sender, head.mseq));
            let keys = self.store.as_ref().and_then(|s| s.pair_keys(&id));
            for (sender, group) in group_by_sender(mail) {
                let Ok(from_key) = VerifyingKey::from_bytes(&sender) else {
                    continue;
                };
                let known = self.devices_at.get(&sender).map(|(_, a)| a.clone());
                let Some(from) = known.or_else(|| MeshAddr::from_device(&sender)) else {
                    continue;
                };
                let seqs: Vec<u64> = group.iter().map(|(h, _)| h.mseq).collect();
                let frames = group.into_iter().map(|(_, e)| (e2ee::WAITED, e)).collect();
                let (tx, mut rx) = tokio::sync::oneshot::channel();
                self.envelopes(id, from, frames, Some(tx));
                let answers = rx.try_recv().unwrap_or_default();
                let oks: Vec<u64> = (seqs.iter().zip(&answers))
                    .filter(|(_, a)| **a == 0)
                    .map(|(m, _)| *m)
                    .collect();
                opened_count += oks.len();
                let (Some(keys), Some(store)) = (&keys, &self.store) else {
                    continue;
                };
                let at = mail_address(keys, &id, &from_key);
                let head = MailHead {
                    sender: store.device_key().public().to_bytes(),
                    kind: RECEIPT,
                    mseq: 0,
                };
                if let Ok(receipt) = seal_mail(&from_key, &at, &head, &receipt_body(&oks)) {
                    receipts.push(receipt);
                }
            }
        }
        if opened_count > 0 {
            eprintln!("mesh-node: {opened_count} mailed events collected");
        }
        if acked {
            if let Some(history) = &self.dm
                && let Err(e) = history.save_counters()
            {
                eprintln!("mesh-node: couldn't save the delivery counters: {e}");
            }
            if let Some(open) = self.dm_open {
                let _ = self.emit_page(&open, None);
            }
        }
        if let (Some(net), Some(seed)) = (&self.net, self.seeds.first())
            && !(receipts.is_empty() && takes.is_empty())
        {
            let (anon, seed) = (net.anon.clone(), seed.clone());
            self.mail.pending.retain(|h| !h.is_finished());
            self.mail.pending.push(tokio::spawn(async move {
                if !receipts.is_empty() {
                    let _ = seed::ask_many(&anon, &seed, seed::MAIL_PUT, &receipts).await;
                }
                let _ = seed::ask_many(&anon, &seed, seed::MAIL_TAKE, &takes).await;
            }));
        }
        // Now what waited for the collect goes live.
        let ids: Vec<MeshId> = (self.store.iter())
            .flat_map(|s| std::iter::once(s.id()).chain(s.contacts().iter().map(|c| c.id())))
            .collect();
        for id in ids {
            self.dm_deliver(&id);
        }
    }

    /// A receipt from a reader device: what it took moves its counter.
    /// True if anything moved.
    fn mail_receipt(&mut self, head: &MailHead, body: &[u8]) -> bool {
        let (Some(oks), Some(history)) = (read_receipt(body), self.dm.as_mut()) else {
            return false;
        };
        let mut moved = false;
        for mseq in oks {
            if let Some(number) = self.mail.sent.remove(&(head.sender, mseq)) {
                self.mail.marked.remove(&(head.sender, number));
                history.acked(&head.sender, number, true);
                moved = true;
            }
        }
        moved
    }
}

/// One piece of mail, unsealed: its head and the envelope inside.
type Unsealed = (MailHead, Vec<u8>);

/// Sorted mail, in runs of one sender device.
fn group_by_sender(mail: Vec<Unsealed>) -> Vec<([u8; 32], Vec<Unsealed>)> {
    let mut runs: Vec<([u8; 32], Vec<Unsealed>)> = Vec::new();
    for (head, body) in mail {
        match runs.last_mut() {
            Some((sender, run)) if *sender == head.sender => run.push((head, body)),
            _ => runs.push((head.sender, vec![(head, body)])),
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mseq_only_goes_up() {
        let mut mail = Mail::default();
        let a = mail.next_seq([1; 32]);
        let b = mail.next_seq([1; 32]);
        assert!(b > a && a >= unix_now_ms());
        // Another reader device has its own count, also from the clock.
        assert!(mail.next_seq([2; 32]) >= unix_now_ms());
    }

    #[test]
    fn receipts_read_back() {
        assert_eq!(read_receipt(&receipt_body(&[3, 9])), Some(vec![3, 9]));
        assert_eq!(read_receipt(&[0; 7]), None);
        assert_eq!(read_receipt(&[]), Some(vec![]));
    }
}
