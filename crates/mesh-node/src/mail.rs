//! The helper's side of `mailbox` (SPEC-mailbox). Events waiting for a
//! friend's device with no open connection are encrypted for it as live,
//! sealed in the mail wrapper and put into this week's box for that device
//! on a seed (M1, M2, M5, M7). At unlock the helper collects its own boxes
//! before any live delivery, opens what it finds as if it had come live,
//! stores it, deletes it from the seed, and puts a receipt into the sender's
//! box at its holder: `ok`, `failed` and couldn't-open (M9). A sender that
//! collects it moves its counters on the `ok`s, mails the `failed`s again,
//! and mails a couldn't-open that has no `ok` again on a fresh session
//! (M16). Every wrapper carries the pair's tag; one that fails it, or whose
//! sender isn't a current device of the contact, is dropped (M7).
//!
//! A child of `helper`, as `dm` is.

// ponytail: our only holder is the first `--seed`, and mail goes to the
// first holder a reader's record names (Task 12: the next on failure, and
// `--holder`); marks, `mseq`s and `failed` backoffs live in memory (Task 11
// saves them); friends' devices only (Task 13 adds our own). When we last
// renewed lives in memory too, so a restart renews at its first unlock.

use super::*;
use crate::mailstore;
use mesh_e2ee::{MAIL, MailHead, RECEIPT, open_mail, seal_mail};
use mesh_identity::{PairKeys, VerifyingKey, mail_collect_tag, week_of};
use std::collections::BTreeMap;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// Lock and quit wait this long for puts under way (mailbox *Limits*).
pub(super) const MAIL_FLUSH: Duration = Duration::from_secs(3);
/// A holder silent this long is skipped (mailbox M10).
pub(super) const HOLDER_WAIT: Duration = Duration::from_secs(10);
/// The token a claim or put to an open seed carries: none.
// ponytail: closed seeds' tokens from their tickets come with Task 12.
const OPEN: [u8; 1] = [0];
/// A box and slot, as the seed names a slot.
const ADDRESS: usize = mailstore::BOX + mailstore::SLOT;
/// Weeks claimed beyond this one (mailbox *Limits*): a box for every day
/// of 30 away.
pub(super) const CLAIM_WEEKS_AHEAD: u64 = 5;
/// Weeks collected before this one at unlock: the 30-day promise.
pub(super) const COLLECT_WEEKS_BACK: u64 = 5;
/// Claims, renewals and collects go in buckets of this many boxes a week,
/// the rest dummies (M13).
pub(super) const CLAIM_BUCKET: usize = 64;
/// Claims are renewed this often while unlocked (M6).
const RENEW_EVERY: u64 = 86_400;

/// What mail knows between locks, in this process.
#[derive(Default)]
pub(super) struct Mail {
    /// The last `mseq` used for each reader device.
    seq: HashMap<[u8; 32], u64>,
    /// Each put, by reader device and `mseq`: the event's number.
    sent: HashMap<([u8; 32], u64), u64>,
    /// Events already mailed to a device, so they aren't put again (M15):
    /// by device and event number, the holder and time of the put.
    pub(super) marked: HashMap<([u8; 32], u64), (String, u64)>,
    /// Puts under way, which lock and quit wait for.
    pending: Vec<JoinHandle<()>>,
    /// The unlock's collect hasn't come back: live sending waits for it.
    pub(super) collecting: bool,
    /// When we last claimed every box (0: not since this process started).
    renewed: u64,
    /// Contacts' newest records and our holders' `since` (mailrec).
    pub(super) remembered: mailrec::Remembered,
    /// The remembered file is from a newer mesh-node: never write it.
    pub(super) newer: bool,
    /// Contacts whose records are being read.
    pub(super) reading: HashSet<MeshId>,
    /// When every record was last put and read.
    pub(super) round: u64,
    /// Events a reader device answered `failed` by receipt: how many times,
    /// and not to be mailed again before when (M9).
    retry: HashMap<([u8; 32], u64), (u32, u64)>,
}

/// One of our slots: whose box it is (`None`, a dummy), the box and slot,
/// and the collect secret.
struct Ours {
    id: Option<MeshId>,
    address: [u8; ADDRESS],
    secret: Zeroizing<[u8; 32]>,
}

impl Ours {
    fn claim(&self, expiry: u64) -> Vec<u8> {
        let tag = mail_collect_tag(&self.secret);
        [&OPEN[..], &self.address, &tag, &expiry.to_be_bytes()].concat()
    }

    fn get(&self) -> Vec<u8> {
        [&self.address[..], &self.secret[..]].concat()
    }
}

/// What a collect found in one contact's box for us.
pub(super) struct Found {
    pub id: MeshId,
    pub address: [u8; ADDRESS],
    /// What collects and deletes it.
    pub secret: Zeroizing<[u8; 32]>,
    /// The highest number the get handed over: the take deletes up to it.
    pub upto: u64,
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
    address_in(keys, reader, device, week_of(unix_now()))
}

fn address_in(keys: &PairKeys, reader: &MeshId, device: &VerifyingKey, week: u64) -> [u8; ADDRESS] {
    let mut out = [0u8; ADDRESS];
    out[..mailstore::BOX].copy_from_slice(&keys.mail_box(reader, week));
    out[mailstore::BOX..].copy_from_slice(&keys.mail_slot(device));
    out
}

/// How many boxes a week `real` ones are claimed and collected as (M13).
fn padded(real: usize) -> usize {
    real.div_ceil(CLAIM_BUCKET).max(1) * CLAIM_BUCKET
}

/// The box an address is in.
fn mail_box(address: &[u8; ADDRESS]) -> [u8; mailstore::BOX] {
    address[..mailstore::BOX].try_into().expect("16 bytes")
}

/// What a receipt says (M9): the `mseq`s answered `ok`, `failed`, and
/// those that couldn't be opened (M16).
///
/// ```text
/// receipt = (count u16 | mseq u64 [count]) for ok, failed, couldn't open
/// ```
#[derive(Debug, Default, PartialEq, Eq)]
struct Receipt {
    ok: Vec<u64>,
    failed: Vec<u64>,
    cant_open: Vec<u64>,
}

impl Receipt {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for list in [&self.ok, &self.failed, &self.cant_open] {
            out.extend_from_slice(&(list.len() as u16).to_be_bytes());
            out.extend(list.iter().flat_map(|m| m.to_be_bytes()));
        }
        out
    }

    fn from_bytes(mut body: &[u8]) -> Option<Self> {
        let mut lists: [Vec<u64>; 3] = Default::default();
        for list in &mut lists {
            let (count, rest) = body.split_first_chunk::<2>()?;
            let (seqs, rest) =
                rest.split_at_checked(usize::from(u16::from_be_bytes(*count)) * 8)?;
            list.extend(
                seqs.as_chunks::<8>()
                    .0
                    .iter()
                    .map(|c| u64::from_be_bytes(*c)),
            );
            body = rest;
        }
        let [ok, failed, cant_open] = lists;
        body.is_empty().then_some(Receipt {
            ok,
            failed,
            cant_open,
        })
    }
}

/// A `failed` is mailed again at once, then after 30 minutes, doubling to
/// a day (mailbox `FAILED_BACKOFF`); D5's 30 days bound it.
fn failed_wait(tries: u32) -> u64 {
    const FIRST: u64 = 30 * 60;
    const MOST: u64 = 86_400;
    match tries {
        0 | 1 => 0,
        n => FIRST.saturating_mul(1 << (n - 2).min(16)).min(MOST),
    }
}

/// Whether a wrapper's sender is a current device of the contact whose box
/// it was in (M7): their newest list we hold, or our own for the self pair.
fn current(list: Option<&mesh_identity::DeviceList>, sender: &[u8; 32]) -> bool {
    list.is_some_and(|list| {
        list.devices()
            .iter()
            .any(|c| c.device().as_bytes() == sender)
    })
}

impl Helper {
    /// Mails what waits for each of `id`'s devices that has no open
    /// connection (M2), to the first holder its newest record names (M11).
    /// A device we hold no record for waits, and its record is read.
    pub(super) fn mail_out(&mut self, id: &MeshId) {
        let (Some(store), Some(net), Some(e2ee)) = (&self.store, &self.net, &self.e2ee) else {
            return;
        };
        if store.id() == *id || self.cut.is_some() {
            return;
        }
        let (Some(keys), anon) = (store.pair_keys(id), net.anon.clone()) else {
            return;
        };
        let now = unix_now();
        let me = store.device_key().public().to_bytes();
        let connected: HashSet<[u8; 32]> = (net.node.connected(id).iter())
            .map(|a| *a.device.as_bytes())
            .collect();
        let away: Vec<[u8; 32]> = (e2ee.device_keys(id).into_iter())
            .filter(|d| !connected.contains(d))
            .collect();
        // Each holder's puts, and what they are.
        let mut puts: HashMap<String, (Vec<Vec<u8>>, Vec<Put>)> = HashMap::new();
        let mut unknown = false;
        for device in away {
            let Some(holder) = self.mail.remembered.holder(&device).map(str::to_owned) else {
                unknown = true;
                continue;
            };
            let marked: HashSet<u64> = (self.mail.marked.keys())
                .filter(|(d, _)| *d == device)
                .map(|(_, n)| *n)
                .chain(
                    (self.mail.retry.iter())
                        .filter(|((d, _), (_, at))| *d == device && *at > now)
                        .map(|((_, n), _)| *n),
                )
                .collect();
            let Some((numbers, envelopes)) = self.dm_batch(id, device, |n| marked.contains(&n))
            else {
                continue;
            };
            let Ok(reader) = VerifyingKey::from_bytes(&device) else {
                continue;
            };
            let at = mail_address(&keys, id, &reader);
            let tag_key = keys.mail_tag_key();
            for (number, envelope) in numbers.into_iter().zip(envelopes) {
                let mseq = self.mail.next_seq(device);
                let head = MailHead {
                    sender: me,
                    kind: MAIL,
                    mseq,
                };
                let Ok(sealed) = seal_mail(&reader, &at, &head, &tag_key, &envelope) else {
                    continue;
                };
                self.mail.sent.insert((device, mseq), number);
                self.mail
                    .marked
                    .insert((device, number), (holder.clone(), now));
                let (sealed_puts, numbers) = puts.entry(holder.clone()).or_default();
                numbers.push((device, mseq, number));
                sealed_puts.push([&OPEN[..], &sealed].concat());
            }
        }
        if unknown {
            self.mail_records_missing(id);
        }
        if puts.is_empty() {
            return;
        }
        let count: usize = puts.values().map(|(p, _)| p.len()).sum();
        eprintln!("mesh-node: mailed {count} events");
        self.mail.pending.retain(|h| !h.is_finished());
        for (holder, (sealed, numbers_put)) in puts {
            let (anon, back) = (anon.clone(), self.back.clone());
            self.mail.pending.push(tokio::spawn(async move {
                let taken = match MeshAddr::from_ticket(&holder) {
                    Ok(seed) => seed::ask_many(&anon, &seed, seed::MAIL_PUT, &sealed)
                        .await
                        .is_ok_and(|a| a.iter().all(|a| a == &[mailstore::Answer::Ok as u8])),
                    Err(_) => false,
                };
                if !taken {
                    let _ = back.send(Back::MailUnput(numbers_put));
                }
            }));
        }
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

    /// Our slot in each box for `weeks`: every contact's and the self
    /// pair's, padded with dummies to a whole `CLAIM_BUCKET` a week (M13).
    /// With `only`, that contact's alone, unpadded.
    fn our_slots(&self, weeks: std::ops::RangeInclusive<u64>, only: Option<&MeshId>) -> Vec<Ours> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let (me, device) = (store.id(), store.device_key().public());
        let ids: Vec<MeshId> = std::iter::once(me)
            .chain(store.contacts().iter().map(|c| c.id()))
            .filter(|id| only.is_none_or(|only| only == id))
            .collect();
        let mut out = Vec::new();
        for week in weeks {
            let real = (ids.iter()).filter_map(|id| Some((*id, store.pair_keys(id)?)));
            let real: Vec<Ours> = real
                .map(|(id, keys)| {
                    let address = address_in(&keys, &me, &device, week);
                    let secret = store.device_key().mail_collect_secret(&mail_box(&address));
                    Ours {
                        id: Some(id),
                        address,
                        secret,
                    }
                })
                .collect();
            let padded = if only.is_some() {
                real.len()
            } else {
                padded(real.len())
            };
            for i in real.len()..padded {
                let address = store.device_key().mail_dummy(i as u32, week);
                let secret = store.device_key().mail_collect_secret(&mail_box(&address));
                out.push(Ours {
                    id: None,
                    address,
                    secret,
                });
            }
            out.extend(real);
        }
        out
    }

    /// Renews our claims if a day has passed since the last time.
    pub(super) fn mail_renew(&mut self) {
        if unix_now() >= self.mail.renewed + RENEW_EVERY {
            self.mail_claim(None);
        }
    }

    /// Claims our slot in every box from this week to `CLAIM_WEEKS_AHEAD`
    /// (M6), or with `only`, in that new contact's boxes alone, at once.
    pub(super) fn mail_claim(&mut self, only: Option<&MeshId>) {
        let Some(seed) = self.seeds.first().cloned().filter(|_| self.net.is_some()) else {
            return;
        };
        let now = unix_now();
        let week = week_of(now);
        let expiry = now + mailstore::CLAIM_LIFE;
        let slots = self.our_slots(week..=week + CLAIM_WEEKS_AHEAD, only);
        let claims: Vec<Vec<u8>> = slots.iter().map(|s| s.claim(expiry)).collect();
        if claims.is_empty() {
            return;
        }
        if only.is_none() {
            self.mail.renewed = now;
        }
        // Our claims there are good from the first one (M12).
        if let Some(ticket) = mailrec::ticket_of(&seed)
            && !self.mail.remembered.since.contains_key(&ticket)
        {
            self.mail.remembered.since.insert(ticket, now);
            self.mail_save();
        }
        let Some(net) = &self.net else { return };
        let anon = net.anon.clone();
        tokio::spawn(async move {
            refused(seed::ask_many(&anon, &seed, seed::MAIL_CLAIM, &claims).await);
        });
    }

    /// At unlock: collect this device's mail from every box of this week
    /// and `COLLECT_WEEKS_BACK` before it, dummies too (M13), before any
    /// live sending. Claims follow, once it's back.
    pub(super) fn mail_collect(&mut self) {
        let (Some(net), Some(seed)) = (&self.net, self.seeds.first()) else {
            return;
        };
        let week = week_of(unix_now());
        let asked = self.our_slots(week.saturating_sub(COLLECT_WEEKS_BACK)..=week, None);
        let gets: Vec<Vec<u8>> = asked.iter().map(Ours::get).collect();
        if asked.is_empty() {
            return;
        }
        self.mail.collecting = true;
        let (anon, seed, back) = (net.anon.clone(), seed.clone(), self.back.clone());
        tokio::spawn(async move {
            let collecting = seed::ask_many(&anon, &seed, seed::MAIL_GET, &gets);
            let answers = tokio::time::timeout(HOLDER_WAIT, collecting).await;
            // Every real box answering no-box: our claims there are gone.
            let no_box = [mailstore::Answer::NoBox as u8];
            let wiped = matches!(&answers, Ok(Ok(a)) if {
                let mut real = asked.iter().zip(a).filter(|(ours, _)| ours.id.is_some());
                real.all(|(_, answer)| *answer == no_box)
            });
            let found = match answers {
                Ok(Ok(answers)) => (asked.into_iter().zip(answers))
                    .filter_map(|(ours, answer)| {
                        let (id, address, secret) = (ours.id?, ours.address, ours.secret);
                        let (upto, sealed) = mailstore::read_got(&answer)?;
                        (!sealed.is_empty()).then_some(Found {
                            id,
                            address,
                            secret,
                            upto,
                            sealed,
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let _ = back.send(Back::MailFound(found, wiped));
        });
    }

    /// Collected mail: opened in each sender's order, stored, deleted from
    /// the seed, and answered by receipt; receipts move our counters. Then
    /// live sending starts.
    pub(super) fn mail_found(&mut self, found: Vec<Found>, wiped: bool) {
        self.mail.collecting = false;
        if let Some(ticket) = self.seeds.first().and_then(mailrec::ticket_of)
            && wiped
            && self.mail.remembered.since.contains_key(&ticket)
        {
            // Claim again; our record says the seed is good only since
            // now, so senders mail again what they put there (M12).
            eprintln!("mesh-node: a holder lost our claims; claiming again");
            self.mail.remembered.since.insert(ticket, unix_now());
            self.mail_save();
            self.mail_claim(None);
        }
        self.mail_renew();
        self.mail_records_round(true);
        // Receipts by the holder they go to; takes go to ours.
        let mut receipts: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let mut takes = Vec::new();
        let (mut opened_count, mut dropped) = (0, 0);
        let mut acked = false;
        let mut again = Vec::new();
        // Receipts are acted on once the mail is opened: opening mail on an
        // old session brings it back in front, after a fresh one (M16).
        let mut receipts_got = Vec::new();
        // Each sender device's mail, whichever box or week it was in.
        let mut by_sender: BTreeMap<([u8; 32], [u8; 32]), BySender> = BTreeMap::new();
        for Found {
            id,
            address,
            secret,
            upto,
            sealed,
        } in found
        {
            takes.push([&address[..], &secret[..], &upto.to_be_bytes()].concat());
            let Some(store) = &self.store else { return };
            let Some(keys) = store.pair_keys(&id) else {
                continue;
            };
            let tag_key = keys.mail_tag_key();
            let list = if id == store.id() {
                Some(store.devices().clone())
            } else {
                store.contact(&id).and_then(|c| c.devices())
            };
            // Without their list, the devices e2ee holds keys for.
            let known: HashSet<[u8; 32]> = match (&list, &self.e2ee) {
                (None, Some(e2ee)) => e2ee.device_keys(&id).into_iter().collect(),
                _ => HashSet::new(),
            };
            let me = store.device_key().public().to_bytes();
            let mut got_receipts = Vec::new();
            for bytes in &sealed {
                match open_mail(store.device_key(), ADDRESS, bytes, &tag_key) {
                    // Not a current device of theirs, or not their tag:
                    // dropped, and listed nowhere (M7).
                    Ok((head, _))
                        if !(current(list.as_ref(), &head.sender)
                            || known.contains(&head.sender))
                            || head.sender == me =>
                    {
                        dropped += 1
                    }
                    Ok((head, body)) if head.kind == MAIL => {
                        let (_, mail) = by_sender
                            .entry((id.to_bytes(), head.sender))
                            .or_insert((id, Vec::new()));
                        mail.push((head, body));
                    }
                    Ok(receipt) => got_receipts.push(receipt),
                    Err(_) => dropped += 1,
                }
            }
            receipts_got.extend(
                got_receipts
                    .into_iter()
                    .map(|(head, body)| (id, head, body)),
            );
        }
        // Olm opens each sender device's mail in its `mseq` order (M8); the
        // events wait, to go to dm all together.
        let mut batches = Vec::new();
        for ((_, sender), (id, mut mail)) in by_sender {
            mail.sort_by_key(|(head, _)| head.mseq);
            mail.dedup_by_key(|(head, _)| head.mseq);
            let known = self.devices_at.get(&sender).map(|(_, a)| a.clone());
            let Some(from) = known.or_else(|| MeshAddr::from_device(&sender)) else {
                continue;
            };
            let seqs: Vec<u64> = mail.iter().map(|(h, _)| h.mseq).collect();
            let frames = mail.into_iter().map(|(_, e)| (e2ee::WAITED, e)).collect();
            let (tx, mut rx) = tokio::sync::oneshot::channel();
            let mut events = Vec::new();
            self.envelopes_in(id, from, frames, Some(tx), Some(&mut events));
            let answers = rx
                .try_recv()
                .unwrap_or_else(|_| vec![dm::FAILED; seqs.len()]);
            batches.push(Batch {
                id,
                sender,
                seqs,
                answers,
                events,
            });
        }
        self.mail_take(&mut batches);
        for (id, head, body) in receipts_got {
            acked |= self.mail_receipt(&id, &head, &body, &mut again);
        }
        let cant_open: usize = (batches.iter())
            .map(|b| b.answers.iter().filter(|a| **a == dm::CANT_OPEN).count())
            .sum();
        if cant_open > 0 {
            eprintln!("mesh-node: {cant_open} mail envelopes couldn't be opened");
        }
        for batch in batches {
            let Ok(from_key) = VerifyingKey::from_bytes(&batch.sender) else {
                continue;
            };
            let mut receipt = Receipt::default();
            for (mseq, answer) in batch.seqs.iter().zip(&batch.answers) {
                match *answer {
                    dm::OK => receipt.ok.push(*mseq),
                    dm::CANT_OPEN => receipt.cant_open.push(*mseq),
                    _ => receipt.failed.push(*mseq),
                }
            }
            opened_count += receipt.ok.len();
            // To the sender's holder, as its newest record names it.
            let (Some(store), Some(holder)) =
                (&self.store, self.mail.remembered.holder(&batch.sender))
            else {
                continue;
            };
            let Some(keys) = store.pair_keys(&batch.id) else {
                continue;
            };
            let at = mail_address(&keys, &batch.id, &from_key);
            let head = MailHead {
                sender: store.device_key().public().to_bytes(),
                kind: RECEIPT,
                mseq: 0,
            };
            if let Ok(sealed) = seal_mail(
                &from_key,
                &at,
                &head,
                &keys.mail_tag_key(),
                &receipt.to_bytes(),
            ) {
                receipts
                    .entry(holder.to_owned())
                    .or_default()
                    .push([&OPEN[..], &sealed].concat());
            }
        }
        if dropped > 0 {
            eprintln!("mesh-node: {dropped} mail wrappers dropped");
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
                for (holder, receipts) in receipts {
                    if let Ok(holder) = MeshAddr::from_ticket(&holder) {
                        let _ = seed::ask_many(&anon, &holder, seed::MAIL_PUT, &receipts).await;
                    }
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
        again.sort_unstable_by_key(|id| id.to_bytes());
        again.dedup();
        for id in again {
            self.mail_out(&id);
        }
    }

    /// Hands the opened events of every batch to dm in D2's order across
    /// senders (M8): each chat's events by (`seq`, event ID), whoever sent
    /// them, given in runs of one sender. What's "not a member yet" (or
    /// otherwise `failed`) gets one more try at the end, in the same order.
    fn mail_take(&mut self, batches: &mut [Batch]) {
        let mut all: Vec<(usize, dm::Taking)> = Vec::new();
        for (b, batch) in batches.iter_mut().enumerate() {
            all.extend(
                std::mem::take(&mut batch.events)
                    .into_iter()
                    .map(|t| (b, t)),
            );
        }
        let chat = |b: &Batch, group: &Option<[u8; 16]>| {
            group.map_or(b.id.to_bytes().to_vec(), |g| g.to_vec())
        };
        all.sort_by(|(x, a), (y, b)| {
            (chat(&batches[*x], &a.1), a.2.seq, a.2.id).cmp(&(
                chat(&batches[*y], &b.1),
                b.2.seq,
                b.2.id,
            ))
        });
        let again: Vec<(usize, dm::Taking)> = self.mail_take_runs(batches, all);
        if !again.is_empty() {
            self.mail_take_runs(batches, again);
        }
    }

    /// Takes `events` in runs of one sender; those answered `failed`, back.
    fn mail_take_runs(
        &mut self,
        batches: &mut [Batch],
        events: Vec<(usize, dm::Taking)>,
    ) -> Vec<(usize, dm::Taking)> {
        let kept: Vec<(usize, dm::Taking)> = events.clone();
        let mut runs: Vec<(usize, Vec<dm::Taking>)> = Vec::new();
        for (b, taking) in events {
            match runs.last_mut() {
                Some((last, run)) if *last == b => run.push(taking),
                _ => runs.push((b, vec![taking])),
            }
        }
        for (b, run) in runs {
            let batch = &mut batches[b];
            let (id, sender) = (batch.id, batch.sender);
            let mut answers = std::mem::take(&mut batch.answers);
            self.dm_take(&id, &sender, run, &mut answers);
            batches[b].answers = answers;
        }
        kept.into_iter()
            .filter(|(b, t)| batches[*b].answers[t.0] == dm::FAILED)
            .collect()
    }

    /// A receipt from `id`'s reader device: its `ok`s move our counter; its
    /// `failed`s are mailed again (pushed on `again`), at once the first
    /// time, then on `FAILED_BACKOFF`; its couldn't-opens are counted. True
    /// if a counter moved.
    fn mail_receipt(
        &mut self,
        id: &MeshId,
        head: &MailHead,
        body: &[u8],
        again: &mut Vec<MeshId>,
    ) -> bool {
        let (Some(receipt), Some(history)) = (Receipt::from_bytes(body), self.dm.as_mut()) else {
            return false;
        };
        let (now, reader) = (unix_now(), head.sender);
        let mut moved = false;
        for mseq in receipt.ok {
            if let Some(number) = self.mail.sent.remove(&(reader, mseq)) {
                self.mail.marked.remove(&(reader, number));
                self.mail.retry.remove(&(reader, number));
                history.acked(&reader, number, true);
                moved = true;
            }
        }
        for mseq in &receipt.failed {
            if let Some(number) = self.mail.sent.remove(&(reader, *mseq)) {
                self.mail.marked.remove(&(reader, number));
                let (tries, at) = self.mail.retry.entry((reader, number)).or_insert((0, 0));
                *tries += 1;
                *at = now + failed_wait(*tries);
                again.push(*id);
            }
        }
        if !receipt.failed.is_empty() {
            eprintln!(
                "mesh-node: {} mailed events answered failed",
                receipt.failed.len()
            );
        }
        // Couldn't open (M16): what has an `ok` is left be; the rest goes
        // again at once on a fresh session, if the limits allow one.
        if !receipt.cant_open.is_empty() {
            eprintln!(
                "mesh-node: {} mailed events couldn't be opened",
                receipt.cant_open.len()
            );
        }
        let lost: Vec<(u64, u64)> = (receipt.cant_open.iter())
            .filter_map(|mseq| Some((*mseq, *self.mail.sent.get(&(reader, *mseq))?)))
            .filter(|(_, number)| !history.has_ok(&reader, *number))
            .collect();
        let fresh = match (VerifyingKey::from_bytes(&reader), self.e2ee.as_mut()) {
            (Ok(key), Some(e2ee)) if !lost.is_empty() => e2ee.fresh_session(id, &key, now),
            _ => Ok(false),
        };
        match fresh {
            Ok(true) => {
                eprintln!("mesh-node: a fresh mail session for {} events", lost.len());
                for (mseq, number) in lost {
                    self.mail.sent.remove(&(reader, mseq));
                    self.mail.marked.remove(&(reader, number));
                }
                again.push(*id);
            }
            Ok(false) => {}
            Err(e) => eprintln!("mesh-node: couldn't start a fresh mail session: {e}"),
        }
        moved
    }
}

/// Counts in our log the claims a seed answered with anything but `ok`.
fn refused<E>(answers: Result<Vec<Vec<u8>>, E>) {
    let Ok(answers) = answers else { return };
    let ok = [mailstore::Answer::Ok as u8];
    let refused = answers.iter().filter(|a| **a != ok).count();
    if refused > 0 {
        eprintln!("mesh-node: {refused} mail claims refused");
    }
}

/// A put: reader device, `mseq`, event number.
type Put = ([u8; 32], u64, u64);

/// A sender device's mail before it's opened: whose box, and the mail.
type BySender = (MeshId, Vec<Unsealed>);

/// One sender device's collected mail, opened: whose box, the device,
/// each envelope's `mseq` and answer, and the chat events waiting for dm.
struct Batch {
    id: MeshId,
    sender: [u8; 32],
    seqs: Vec<u64>,
    answers: Vec<u8>,
    events: Vec<dm::Taking>,
}

/// One piece of mail, unsealed: its head and the envelope inside.
type Unsealed = (MailHead, Vec<u8>);

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

    /// A seed sees the same number of claims, renewals and collects with
    /// 70 contacts as with 127 (each with the self pair, so 71 and 128).
    #[test]
    fn boxes_come_in_buckets() {
        assert_eq!(padded(71), padded(128));
        assert_eq!(padded(128), 2 * CLAIM_BUCKET);
        assert_eq!(padded(129), 3 * CLAIM_BUCKET);
        assert_eq!(padded(1), CLAIM_BUCKET, "the self pair alone");
    }

    #[test]
    fn receipts_read_back() {
        let receipt = Receipt {
            ok: vec![3, 9],
            failed: vec![4],
            cant_open: vec![],
        };
        assert_eq!(Receipt::from_bytes(&receipt.to_bytes()), Some(receipt));
        assert_eq!(Receipt::from_bytes(&[0; 7]), None);
        assert_eq!(Receipt::from_bytes(&[0, 1, 0]), None, "cut short");
        assert_eq!(Receipt::from_bytes(&[0; 6]), Some(Receipt::default()));
    }

    #[test]
    fn failed_backs_off() {
        assert_eq!(failed_wait(1), 0, "at once the first time");
        assert_eq!(failed_wait(2), 30 * 60);
        assert_eq!(failed_wait(3), 60 * 60);
        assert_eq!(failed_wait(7), 16 * 3600);
        assert_eq!(failed_wait(8), 86_400, "a day at most");
        assert_eq!(failed_wait(60), 86_400);
    }

    /// Mail from a device that isn't one of the contact's (M7) is dropped.
    #[test]
    fn only_a_contacts_current_device_is_trusted() {
        use mesh_identity::{DeviceCert, DeviceKey, DeviceList, RootKey};
        let root = RootKey::generate().unwrap();
        let (desk, stranger) = (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        );
        let cert = DeviceCert::issue(&root, &desk.public(), "desk", 1).unwrap();
        let list = DeviceList::first(&root, cert).unwrap();
        assert!(current(Some(&list), &desk.public().to_bytes()));
        assert!(!current(Some(&list), &stranger.public().to_bytes()));
        assert!(
            !current(None, &desk.public().to_bytes()),
            "a contact whose list we don't hold"
        );
    }
}
