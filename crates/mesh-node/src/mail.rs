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

// ponytail: friends' devices only (Task 13 adds our own).

use super::*;
use crate::mailstore;
use mesh_e2ee::{MAIL, MailHead, RECEIPT, open_mail, seal_mail};
use mesh_identity::{PairKeys, VerifyingKey, mail_collect_tag, week_of};
use std::collections::BTreeMap;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// The format of the mail state saved with dm's counters (M15).
const MAIL_STATE_FORMAT: u8 = 1;

/// What's saved with dm's counters (M15): `seq`, `sent`, `marked`, `retry`.
type State = (
    HashMap<[u8; 32], u64>,
    HashMap<([u8; 32], u64), u64>,
    HashMap<([u8; 32], u64), (String, u64)>,
    HashMap<([u8; 32], u64), (u32, u64)>,
);

/// Lock and quit wait this long for puts under way (mailbox *Limits*).
pub(super) const MAIL_FLUSH: Duration = Duration::from_secs(3);
/// A holder silent this long is skipped (mailbox M10).
pub(super) const HOLDER_WAIT: Duration = Duration::from_secs(10);
/// The token a claim or put to an open seed carries: none.
pub(super) const OPEN: [u8; 1] = [0];

/// The token a holder's ticket carries (`&mail=…`, M14), as a claim, put
/// or record put starts with it; none for an open seed.
pub(super) fn token_of(ticket: &str) -> Vec<u8> {
    let query = ticket.split_once('?').map_or("", |(_, q)| q);
    match query.split('&').find_map(|p| p.strip_prefix("mail=")) {
        Some(token) if token.len() <= mailstore::MAX_TOKEN => {
            [&[token.len() as u8][..], token.as_bytes()].concat()
        }
        _ => OPEN.to_vec(),
    }
}
/// A box and slot, as the seed names a slot.
const ADDRESS: usize = mailstore::BOX + mailstore::SLOT;
/// Weeks claimed beyond this one (mailbox *Limits*): a box for every day
/// of 30 away.
pub(super) const CLAIM_WEEKS_AHEAD: u64 = 5;
/// Weeks collected before this one at unlock: the 30-day promise.
pub(super) const COLLECT_WEEKS_BACK: u64 = 5;
/// Weeks collected before this one at a refresh: mail put just before a
/// week's edge (test 18).
const REFRESH_WEEKS_BACK: u64 = 1;
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
    /// Puts under way, which lock and quit wait for: whether the seed took
    /// them, and what they put.
    pending: Vec<(JoinHandle<Taken>, Vec<Put>)>,
    /// The saved state is from a newer mesh-node: never write it.
    state_newer: bool,
    /// The unlock's collect hasn't come back: live sending waits for it.
    pub(super) collecting: bool,
    /// Contacts' newest records and our holders' `since` (mailrec).
    pub(super) remembered: mailrec::Remembered,
    /// The remembered file is from a newer mesh-node: never write it.
    pub(super) newer: bool,
    /// Contacts whose records are being read.
    pub(super) reading: HashSet<MeshId>,
    /// Those reads, which lock and quit wait for: what each found.
    pub(super) reads: Vec<JoinHandle<mailrec::Found>>,
    /// When every record was last put, and read, with a seed answering.
    pub(super) put_at: u64,
    pub(super) read_at: u64,
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
    /// A claim, less the holder's token.
    fn claim(&self, expiry: u64) -> Vec<u8> {
        let tag = mail_collect_tag(&self.secret);
        [&self.address[..], &tag, &expiry.to_be_bytes()].concat()
    }

    fn get(&self) -> Vec<u8> {
        [&self.address[..], &self.secret[..]].concat()
    }
}

/// What a collect found in one contact's box for us, at one holder.
pub(super) struct Found {
    pub holder: String,
    pub id: MeshId,
    pub address: [u8; ADDRESS],
    /// What collects and deletes it.
    pub secret: Zeroizing<[u8; 32]>,
    /// The highest number the get handed over: the take deletes up to it.
    pub upto: u64,
    pub sealed: Vec<Vec<u8>>,
}

impl Mail {
    /// What's saved with dm's counters (M15).
    fn state(&self) -> Vec<u8> {
        let state = (&self.seq, &self.sent, &self.marked, &self.retry);
        let mut bytes = vec![MAIL_STATE_FORMAT];
        bytes.extend(postcard::to_allocvec(&state).expect("to memory"));
        bytes
    }

    /// Reads a saved state back: false if it was damaged (nothing read),
    /// `Err` if it's from a newer mesh-node. Nothing saved is nothing to read.
    fn read_state(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        let state = match bytes.split_first() {
            None => return Ok(true),
            Some((&MAIL_STATE_FORMAT, rest)) => postcard::from_bytes::<State>(rest).ok(),
            Some((&v, _)) if v > MAIL_STATE_FORMAT => return Err(()),
            Some(_) => None,
        };
        let Some((seq, sent, marked, retry)) = state else {
            return Ok(false);
        };
        (self.seq, self.sent, self.marked, self.retry) = (seq, sent, marked, retry);
        Ok(true)
    }

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

/// One week's slots, real and dummy, as the seed sees them: in address
/// order, so neither where a slot sits nor which get puts says how many
/// are real (M13).
fn one_week(real: Vec<Ours>, mut dummies: Vec<Ours>) -> Vec<Ours> {
    dummies.extend(real);
    dummies.sort_unstable_by_key(|s| s.address);
    dummies
}

/// Opened mail events in D2's order across senders (M8): each chat's by
/// (`seq`, event ID), whoever sent them. Each is its batch's index and the
/// event; `directs` is each batch's direct chat (the sender's ID), for
/// events with no group.
fn in_d2_order(events: &mut [(usize, dm::Taking)], directs: &[[u8; 32]]) {
    let chat =
        |b: usize, group: &Option<[u8; 16]>| group.map_or(directs[b].to_vec(), |g| g.to_vec());
    events.sort_by(|(x, a), (y, b)| {
        (chat(*x, &a.1), a.2.seq, a.2.id).cmp(&(chat(*y, &b.1), b.2.seq, b.2.id))
    });
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
        if self.cut.is_some() {
            return;
        }
        // Our own other devices get by mail only what this device wrote
        // (its messages and read markers): the rest comes from its authors
        // (SPEC-mailbox, delivers 3).
        let own = store.id() == *id;
        let (Some(keys), anon) = (store.pair_keys(id), net.anon.clone()) else {
            return;
        };
        let now = unix_now();
        let me = store.device_key().public().to_bytes();
        let connected: HashSet<[u8; 32]> = (net.node.connected(id).iter())
            .map(|a| *a.device.as_bytes())
            .collect();
        // Our own list is in the keystore; e2ee lists only devices whose keys
        // it has seen, so a new device of ours would never have its record read.
        let devices: Vec<[u8; 32]> = if own {
            (store.devices().devices().iter())
                .map(|c| c.device().to_bytes())
                .collect()
        } else {
            e2ee.device_keys(id)
        };
        let away: Vec<[u8; 32]> = (devices.into_iter())
            .filter(|d| !connected.contains(d) && *d != me)
            .collect();
        // Each holder's puts, and what they are.
        let mut puts: HashMap<Vec<String>, Puts> = HashMap::new();
        let mut unknown = false;
        for device in away {
            let holders = self.mail.remembered.holders(&device);
            let Some(holder) = holders.first().cloned() else {
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
            let skip = |t: &mesh_dm::history::ToSend| {
                marked.contains(&t.number) || (own && t.from.device != me)
            };
            let Some((numbers, envelopes)) = self.dm_batch(id, device, skip) else {
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
                let (sealed_puts, numbers) = puts.entry(holders.clone()).or_default();
                numbers.push((device, mseq, number));
                sealed_puts.push(sealed);
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
        self.mail.pending.retain(|(h, _)| !h.is_finished());
        for (holders, (sealed, numbers_put)) in puts {
            let (anon, back, put) = (anon.clone(), self.back.clone(), numbers_put.clone());
            let handle = tokio::spawn(async move {
                let took = put_in_order(&anon, &holders, &sealed).await;
                let mut taken = (Vec::new(), Vec::new());
                for (put, took) in put.into_iter().zip(took) {
                    match took {
                        Some(h) => taken.0.push((put, holders[h].clone())),
                        None => taken.1.push(put),
                    }
                }
                // Answered: the marks are saved, less what wasn't taken.
                let _ = back.send(Back::MailPutDone(taken.clone()));
                taken
            });
            self.mail.pending.push((handle, numbers_put));
        }
    }

    /// Mails what waits for every contact and our own other devices.
    pub(super) fn mail_out_all(&mut self) {
        let ids: Vec<MeshId> = (self.store.iter())
            .flat_map(|s| s.contacts().iter().map(|c| c.id()).chain([s.id()]))
            .collect();
        for id in ids {
            self.mail_out(&id);
        }
    }

    /// Puts were answered: each mark names the holder that took it; what
    /// none took may be mailed again (M10). The marks are saved.
    pub(super) fn mail_put_done(&mut self, (taken, untaken): Taken) {
        self.retake(taken, untaken);
        self.mail_state_save();
    }

    fn retake(&mut self, taken: Vec<(Put, String)>, untaken: Vec<Put>) {
        if !untaken.is_empty() {
            eprintln!("mesh-node: {} mailed events weren't taken", untaken.len());
        }
        for ((device, _, number), holder) in taken {
            if let Some((at, _)) = self.mail.marked.get_mut(&(device, number)) {
                *at = holder;
            }
        }
        self.unmark(untaken);
    }

    fn unmark(&mut self, puts: Vec<Put>) {
        for (device, mseq, number) in puts {
            self.mail.sent.remove(&(device, mseq));
            self.mail.marked.remove(&(device, number));
        }
    }

    /// At lock and quit: let record reads under way finish, mail what
    /// waits, then let the puts finish, all within `MAIL_FLUSH`, and save the marks: a put not answered by then isn't
    /// marked, so it's mailed again rather than lost (the reader shows it
    /// once).
    pub(super) async fn mail_flush(&mut self) {
        let deadline = tokio::time::Instant::now() + MAIL_FLUSH;
        // A record read under way may name holders for what waits (a new
        // device of ours, say): it's mailed now rather than next unlock.
        // ponytail: its answer is handled again once we're locked, to no
        // effect; a read still out at the deadline waits for next unlock.
        for reading in std::mem::take(&mut self.mail.reads) {
            if let Ok(Ok(found)) = tokio::time::timeout_at(deadline, reading).await {
                self.mail_records(found);
            }
        }
        self.mail_out_all();
        for (put, numbers) in std::mem::take(&mut self.mail.pending) {
            match tokio::time::timeout_at(deadline, put).await {
                Ok(Ok((taken, untaken))) => self.retake(taken, untaken),
                _ => self.unmark(numbers),
            }
        }
        self.mail_state_save();
    }

    /// At unlock: the mail state saved with dm's counters (M15).
    pub(super) fn mail_state_load(&mut self) {
        let Some(history) = &self.dm else { return };
        let read = self.mail.read_state(history.mail_state());
        match read {
            Ok(true) => {}
            Ok(false) => eprintln!("mesh-node: the mail state was damaged; it starts empty"),
            Err(()) => {
                eprintln!(
                    "mesh-node: the mail state is from a newer mesh-node; it's left as it is"
                );
                self.mail.state_newer = true;
            }
        }
    }

    /// Saves the mail state with dm's counters, once per batch (M15).
    pub(super) fn mail_state_save(&mut self) {
        let Some(history) = self.dm.as_mut().filter(|_| !self.mail.state_newer) else {
            return;
        };
        history.set_mail_state(self.mail.state());
        if let Err(e) = history.save_counters() {
            eprintln!("mesh-node: couldn't save the delivery counters: {e}");
        }
    }

    /// Our slot in each box for `weeks`: every contact's and the self
    /// pair's, padded with dummies to a whole `CLAIM_BUCKET` a week, each
    /// week in address order (M13).
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
            let dummies = (real.len()..padded).map(|i| {
                let address = store.device_key().mail_dummy(i as u32, week);
                let secret = store.device_key().mail_collect_secret(&mail_box(&address));
                Ours {
                    id: None,
                    address,
                    secret,
                }
            });
            out.extend(one_week(real, dummies.collect()));
        }
        out
    }

    /// Our holders' tickets (M3): `--holder`s, or our first seeds'; none
    /// while cut off from the seeds.
    pub(super) fn holder_tickets(&self) -> Vec<String> {
        if self.cut.is_some() {
            return Vec::new();
        }
        if !self.holders.is_empty() {
            return self.holders.clone();
        }
        (self.seeds.iter().take(mesh_identity::MAX_HOLDERS))
            .filter_map(mailrec::ticket_of)
            .collect()
    }

    /// Renews our claims at each holder a day after it last answered one.
    pub(super) fn mail_renew(&mut self) {
        let now = unix_now();
        let due = |ticket: &String| {
            let renewed = self.mail.remembered.renewed.get(ticket);
            now >= renewed.copied().unwrap_or(0) + RENEW_EVERY
        };
        let due: Vec<String> = self.holder_tickets().into_iter().filter(due).collect();
        self.mail_claim_at(None, due);
    }

    /// Claims our slot in every box from this week to `CLAIM_WEEKS_AHEAD`
    /// (M6) at every holder, or with `only`, in that new contact's boxes
    /// alone, at once.
    pub(super) fn mail_claim(&mut self, only: Option<&MeshId>) {
        self.mail_claim_at(only, self.holder_tickets());
    }

    fn mail_claim_at(&mut self, only: Option<&MeshId>, holders: Vec<String>) {
        let Some(net) = &self.net else { return };
        let now = unix_now();
        let week = week_of(now);
        let expiry = now + mailstore::CLAIM_LIFE;
        let slots = self.our_slots(week..=week + CLAIM_WEEKS_AHEAD, only);
        let claims: Arc<Vec<Vec<u8>>> = Arc::new(slots.iter().map(|s| s.claim(expiry)).collect());
        if claims.is_empty() {
            return;
        }
        for ticket in holders {
            let Ok(holder) = MeshAddr::from_ticket(&ticket) else {
                continue;
            };
            let token = token_of(&ticket);
            let claims: Vec<Vec<u8>> = claims.iter().map(|c| [&token[..], c].concat()).collect();
            let (anon, back) = (net.anon.clone(), self.back.clone());
            let full = only.is_none();
            tokio::spawn(async move {
                let claiming = seed::ask_many(&anon, &holder, seed::MAIL_CLAIM, &claims);
                // Renewed only once the holder answers; else at the next
                // refresh.
                let Ok(answers) = tokio::time::timeout(HOLDER_WAIT, claiming).await else {
                    return;
                };
                if let Ok(answers) = &answers {
                    let renewed = full && renewed_by(answers);
                    let _ = back.send(Back::MailClaimed(ticket, now, renewed));
                }
                refused(answers);
            });
        }
    }

    /// A holder answered our claims: renewed, if they were all of them and
    /// none was slowed (`renewed_by`); our
    /// claims there are good from the first it answered (M12), and a new
    /// holder in our records means putting them again.
    pub(super) fn mail_claimed(&mut self, ticket: String, at: u64, full: bool) {
        let remembered = &mut self.mail.remembered;
        if full {
            remembered.renewed.insert(ticket.clone(), at);
        }
        let new = !remembered.since.contains_key(&ticket);
        remembered.since.entry(ticket).or_insert(at);
        self.mail_save();
        if new {
            self.mail_records_put(None);
        }
    }

    /// At unlock: collect this device's mail from every box of this week
    /// and `COLLECT_WEEKS_BACK` before it, dummies too (M13), before any
    /// live sending. Claims follow, once it's back.
    pub(super) fn mail_collect(&mut self) {
        self.mail_collect_weeks(COLLECT_WEEKS_BACK, true);
    }

    /// At each refresh: this week and last, the same way, live sending
    /// going on; renewals follow it, so a wipe is seen before a renewal
    /// could hide it (Behaviour, Receiving 2).
    pub(super) fn mail_refresh(&mut self) {
        // ponytail: skipped while the unlock's collect is out; two
        // refreshes' collects can overlap if a holder takes longer than a
        // refresh, which only takes the same mail twice.
        if !self.mail.collecting {
            self.mail_collect_weeks(REFRESH_WEEKS_BACK, false);
        }
    }

    fn mail_collect_weeks(&mut self, back: u64, unlock: bool) {
        let Some(net) = &self.net else { return };
        let now = unix_now();
        let week = week_of(now);
        let asked = Arc::new(self.our_slots(week.saturating_sub(back)..=week, None));
        let gets: Arc<Vec<Vec<u8>>> = Arc::new(asked.iter().map(Ours::get).collect());
        // Our holders, and those we dropped while our claims there stand
        // (M12): a wipe is only seen at a holder we still claim at.
        let current = self.holder_tickets();
        let mut holders: Vec<(String, bool)> = current.iter().map(|t| (t.clone(), true)).collect();
        for (ticket, until) in &self.mail.remembered.dropped {
            if *until > now && !current.contains(ticket) {
                holders.push((ticket.clone(), false));
            }
        }
        if asked.is_empty() || holders.is_empty() {
            return;
        }
        self.mail.collecting = unlock;
        let (anon, back) = (net.anon.clone(), self.back.clone());
        tokio::spawn(async move {
            let mut each = tokio::task::JoinSet::new();
            for (ticket, claimed) in holders {
                let (anon, gets) = (anon.clone(), gets.clone());
                each.spawn(async move {
                    let answers = match MeshAddr::from_ticket(&ticket) {
                        Ok(holder) => {
                            let collecting = seed::ask_many(&anon, &holder, seed::MAIL_GET, &gets);
                            let answers = tokio::time::timeout(HOLDER_WAIT, collecting).await;
                            answers.ok().and_then(Result::ok)
                        }
                        Err(_) => None,
                    };
                    (ticket, claimed, answers)
                });
            }
            let (mut found, mut wiped) = (Vec::new(), Vec::new());
            while let Some(Ok((ticket, claimed, answers))) = each.join_next().await {
                let Some(answers) = answers else {
                    continue;
                };
                // Every real box answering no-box: our claims there are gone.
                let no_box = [mailstore::Answer::NoBox as u8];
                let mut real = asked
                    .iter()
                    .zip(&answers)
                    .filter(|(ours, _)| ours.id.is_some());
                if claimed && real.all(|(_, answer)| *answer == no_box) {
                    wiped.push(ticket.clone());
                }
                for (ours, answer) in asked.iter().zip(answers) {
                    let Some(id) = ours.id else { continue };
                    let Some((upto, sealed)) = mailstore::read_got(&answer) else {
                        continue;
                    };
                    if !sealed.is_empty() {
                        found.push(Found {
                            holder: ticket.clone(),
                            id,
                            address: ours.address,
                            secret: ours.secret.clone(),
                            upto,
                            sealed,
                        });
                    }
                }
            }
            let _ = back.send(Back::MailFound(found, wiped, unlock));
        });
    }

    /// Collected mail: opened in each sender's order, stored, deleted from
    /// the seed, and answered by receipt; receipts move our counters. Then
    /// live sending starts.
    pub(super) fn mail_found(&mut self, found: Vec<Found>, wiped: Vec<String>, unlock: bool) {
        if unlock {
            self.mail.collecting = false;
        }
        let wiped: Vec<String> = (wiped.into_iter())
            .filter(|t| self.mail.remembered.since.contains_key(t))
            .collect();
        if !wiped.is_empty() {
            // Claim again; our record says the holder is good only since
            // now, so senders mail again what they put there (M12).
            eprintln!(
                "mesh-node: {} holders lost our claims; claiming again",
                wiped.len()
            );
            for ticket in wiped {
                self.mail.remembered.since.insert(ticket, unix_now());
            }
            self.mail_save();
            self.mail_claim(None);
        }
        self.mail_renew();
        self.mail_records_round(unlock);
        // Receipts by the holders they go to; takes by where it was found.
        let mut receipts: HashMap<Vec<String>, Vec<Vec<u8>>> = HashMap::new();
        let mut takes: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let (mut opened_count, mut dropped) = (0, 0);
        let mut acked = false;
        let mut again = Vec::new();
        // Receipts are acted on once the mail is opened: opening mail on an
        // old session brings it back in front, after a fresh one (M16).
        let mut receipts_got = Vec::new();
        // Each sender device's mail, whichever box or week it was in.
        let mut by_sender: BTreeMap<([u8; 32], [u8; 32]), BySender> = BTreeMap::new();
        for Found {
            holder,
            id,
            address,
            secret,
            upto,
            sealed,
        } in found
        {
            let take = [&address[..], &secret[..], &upto.to_be_bytes()].concat();
            takes.entry(holder).or_default().push(take);
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
            // To the sender's holders, as its newest record names them.
            let holders = self.mail.remembered.holders(&batch.sender);
            let Some(store) = self.store.as_ref().filter(|_| !holders.is_empty()) else {
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
                receipts.entry(holders).or_default().push(sealed);
            }
        }
        if dropped > 0 {
            eprintln!("mesh-node: {dropped} mail wrappers dropped");
        }
        if opened_count > 0 {
            eprintln!("mesh-node: {opened_count} mailed events collected");
        }
        // Receipts moved counters, marks and backoffs: one save for them.
        self.mail_state_save();
        if acked && let Some(open) = self.dm_open {
            let _ = self.emit_page(&open, None);
        }
        if let Some(net) = &self.net
            && !(receipts.is_empty() && takes.is_empty())
        {
            let anon = net.anon.clone();
            self.mail.pending.retain(|(h, _)| !h.is_finished());
            let handle = tokio::spawn(async move {
                for (holders, receipts) in receipts {
                    put_in_order(&anon, &holders, &receipts).await;
                }
                for (holder, takes) in takes {
                    if let Ok(holder) = MeshAddr::from_ticket(&holder) {
                        let taking = seed::ask_many(&anon, &holder, seed::MAIL_TAKE, &takes);
                        let _ = tokio::time::timeout(HOLDER_WAIT, taking).await;
                    }
                }
                Taken::default()
            });
            self.mail.pending.push((handle, Vec::new()));
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
        let directs: Vec<[u8; 32]> = batches.iter().map(|b| b.id.to_bytes()).collect();
        in_d2_order(&mut all, &directs);
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
    /// time, then on `FAILED_BACKOFF`; its couldn't-opens go again (M16). True
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
        // again: at once on a fresh session if the limits allow one, else
        // on the newest session with `failed`'s backoff.
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
        let fresh = match fresh {
            Ok(fresh) => fresh,
            Err(e) => {
                eprintln!("mesh-node: couldn't start a fresh mail session: {e}");
                false
            }
        };
        if lost.is_empty() {
            return moved;
        }
        if fresh {
            eprintln!("mesh-node: a fresh mail session for {} events", lost.len());
        } else {
            eprintln!(
                "mesh-node: {} mailed events go again on the newest session",
                lost.len()
            );
        }
        for (mseq, number) in lost {
            self.mail.sent.remove(&(reader, mseq));
            self.mail.marked.remove(&(reader, number));
            if !fresh {
                let (tries, at) = self.mail.retry.entry((reader, number)).or_insert((0, 0));
                *tries += 1;
                *at = now + failed_wait(*tries);
            }
        }
        again.push(*id);
        moved
    }
}

/// Whether a claim round counts as a renewal.
/// Not if any claim was answered `slow-down`: those weren't taken, so the
/// round goes again at the next refresh.
fn renewed_by(answers: &[Vec<u8>]) -> bool {
    let slow = [mailstore::Answer::SlowDown as u8];
    !answers.iter().any(|a| *a == slow)
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
pub(super) type Put = ([u8; 32], u64, u64);

/// Puts to one list of holders: the sealed mail, and what each is.
type Puts = (Vec<Vec<u8>>, Vec<Put>);

/// Answered puts: those taken, with the holder that took each, and those
/// none took.
pub(super) type Taken = (Vec<(Put, String)>, Vec<Put>);

/// Puts each of `sealed` at the first of `holders` that takes it (M10): an
/// answer other than `ok`, none within `HOLDER_WAIT`, or no connection
/// moves it to the next. Which holder took each, if one did.
async fn put_in_order(anon: &Node, holders: &[String], sealed: &[Vec<u8>]) -> Vec<Option<usize>> {
    let mut took = vec![None; sealed.len()];
    for (h, holder) in holders.iter().enumerate() {
        let left: Vec<usize> = (0..sealed.len()).filter(|i| took[*i].is_none()).collect();
        if left.is_empty() {
            break;
        }
        let Ok(seed) = MeshAddr::from_ticket(holder) else {
            continue;
        };
        let token = token_of(holder);
        let asked: Vec<Vec<u8>> = left
            .iter()
            .map(|i| [&token[..], &sealed[*i]].concat())
            .collect();
        let putting = seed::ask_many(anon, &seed, seed::MAIL_PUT, &asked);
        let Ok(Ok(answers)) = tokio::time::timeout(HOLDER_WAIT, putting).await else {
            continue;
        };
        for (i, answer) in left.iter().zip(answers) {
            if answer == [mailstore::Answer::Ok as u8] {
                took[*i] = Some(h);
            }
        }
    }
    took
}

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

    /// Marks, `mseq`s and backoffs read back after a restart (M15), so a
    /// couldn't-open's wait (fix 1) holds across it.
    /// A claim round answered `slow-down` anywhere isn't a renewal: it's
    /// tried again at the next refresh (Task 12b). Other answers are.
    #[test]
    fn a_slowed_round_isnt_renewed() {
        let ok = vec![mailstore::Answer::Ok as u8];
        let slow = vec![mailstore::Answer::SlowDown as u8];
        let full = vec![mailstore::Answer::Full as u8];
        assert!(renewed_by(&[ok.clone(), ok.clone()]));
        assert!(renewed_by(&[ok.clone(), full]));
        assert!(!renewed_by(&[ok, slow]));
    }

    /// A ticket's `&mail=` token goes length-first; none, or one too long
    /// to be a token, is the open seed's.
    #[test]
    fn a_tickets_token() {
        assert_eq!(token_of("mesh://node/ab?relay=x&mail=tok"), b"\x03tok");
        assert_eq!(token_of("mesh://node/ab?mail=tok&relay=x"), b"\x03tok");
        assert_eq!(token_of("mesh://node/ab?relay=x"), OPEN);
        assert_eq!(token_of("mesh://node/ab"), OPEN);
        let long = "t".repeat(mailstore::MAX_TOKEN + 1);
        assert_eq!(token_of(&format!("mesh://node/ab?mail={long}")), OPEN);
    }

    #[test]
    fn the_mail_state_reads_back() {
        let mut mail = Mail::default();
        let seq = mail.next_seq([1; 32]);
        mail.sent.insert(([1; 32], seq), 7);
        mail.marked.insert(([1; 32], 7), ("holder".into(), 100));
        mail.retry.insert(([1; 32], 8), (2, 1900));
        let mut back = Mail::default();
        assert_eq!(back.read_state(&mail.state()), Ok(true));
        assert_eq!(back.seq, mail.seq);
        assert_eq!(back.sent, mail.sent);
        assert_eq!(back.marked, mail.marked);
        assert_eq!(back.retry, mail.retry);
        let mut newer = mail.state();
        newer[0] = MAIL_STATE_FORMAT + 1;
        assert_eq!(back.read_state(&newer), Err(()));
        assert_eq!(
            Mail::default().read_state(&[MAIL_STATE_FORMAT, 9]),
            Ok(false)
        );
    }

    /// A crash between a put and the save: the state saved before has no
    /// mark, so the event is mailed once more; once that put is answered
    /// and saved, it's marked, so never a third time (M15).
    #[test]
    fn a_crash_before_the_save_mails_once_more_at_most() {
        let mut mail = Mail::default();
        let before = mail.state();
        mail.marked.insert(([1; 32], 7), ("holder".into(), 100));
        // Crash: what's read back is `before`.
        let mut again = Mail::default();
        again.read_state(&before).unwrap();
        assert!(
            !again.marked.contains_key(&([1; 32], 7)),
            "mailed once more"
        );
        again.marked.insert(([1; 32], 7), ("holder".into(), 200));
        let saved = again.state();
        let mut after = Mail::default();
        after.read_state(&saved).unwrap();
        assert!(after.marked.contains_key(&([1; 32], 7)), "and not again");
    }

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

    /// Where a real box sits says nothing: the same addresses, whichever
    /// are real, go in the same order (M13).
    #[test]
    fn a_weeks_slots_dont_say_which_are_real() {
        let slot = |n: u8, real: bool| Ours {
            id: real.then(|| mesh_identity::RootKey::from_secret_bytes([n; 32]).id()),
            address: [n.wrapping_mul(37); ADDRESS],
            secret: Zeroizing::new([0; 32]),
        };
        let order = |real: &[u8]| {
            let (r, d): (Vec<u8>, Vec<u8>) = (0..8).partition(|n| real.contains(n));
            let slots = one_week(
                r.iter().map(|n| slot(*n, true)).collect(),
                d.iter().map(|n| slot(*n, false)).collect(),
            );
            slots.iter().map(|s| s.address).collect::<Vec<_>>()
        };
        assert_eq!(order(&[0, 1]), order(&[6, 7]));
        assert_eq!(order(&[]), order(&[2, 3, 5]));
    }

    /// A removal from one sender and the removed member's earlier messages
    /// from another, in one collect: the messages first (M8, test 16).
    #[test]
    fn a_removal_goes_after_the_messages_it_saw() {
        use mesh_dm::event::{Body, Change, Event, GroupChange};
        let event = |seq: u64, body: Body| Event {
            version: 1,
            id: [seq as u8; 16],
            time: seq,
            seq,
            n: 1,
            body,
        };
        let text = |t: &str| Body::Text {
            text: t.into(),
            reply_to: None,
            attachments: Vec::new(),
        };
        let group = Some([9; 16]);
        let removal = Body::Group(GroupChange {
            after: None,
            change: Change::Remove([4; 32]),
            signed: None,
        });
        // Alice's batch (the removal) comes first, as a collect may give it.
        let mut events = vec![(0, (0, group, event(106, removal)))];
        events.extend((1..=5).map(|i| (1, (i - 1, group, event(100 + i as u64, text("d"))))));
        // A direct message from Dave, its own chat, wherever it sorts.
        events.push((1, (5, None, event(1, text("dm")))));
        in_d2_order(&mut events, &[[1; 32], [2; 32]]);
        let group_seqs: Vec<u64> = (events.iter())
            .filter(|(_, t)| t.1 == group)
            .map(|(_, t)| t.2.seq)
            .collect();
        assert_eq!(group_seqs, [101, 102, 103, 104, 105, 106]);
        assert_eq!(events.len(), 7);
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
