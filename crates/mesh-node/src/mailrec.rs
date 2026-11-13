//! Mail records in the helper (SPEC-mailbox M11, M12): this device's record
//! for each contact says where to mail it and with what keys; each contact
//! device's newest record, read or remembered, says where to mail them.
//!
//! Put at unlock, daily and for a new contact, on every seed, as address
//! records are. Read for every contact at unlock and daily (this week's
//! lookup, then last week's for contacts with nothing this week), for a new
//! contact, and for a contact we hold no record for when we meet them or
//! have mail for them. What's read is remembered, sealed in
//! `<data>/mail/remembered`, for `REMEMBER_LIFE` after it lapses; a read
//! that finds nothing leaves it. The e2ee keys a record carries go to e2ee,
//! which keeps them with its sessions.
//!
//! A child of `helper`, as `mail` is.

use super::*;
use mesh_identity::{
    Holder, MAIL_RECORD_LIFE, MAX_HOLDERS, PairKeys, SealedError, open_mail_record, read_sealed,
    seal_mail_record, week_of, write_sealed,
};
use serde::Serialize;

/// A lapsed record is remembered this long (mailbox *Limits*): the promise.
pub(super) const REMEMBER_LIFE: u64 = 30 * 86_400;
/// Every contact's record is read again this often (`MAIL_RECORD_READ`).
pub(super) const MAIL_RECORD_READ: u64 = 86_400;
/// The remembered records' file, under `<data>/mail/`, and its format
/// (mailbox *Formats*).
const REMEMBERED: &str = "remembered";
const REMEMBERED_FORMAT: u8 = 1;
const REMEMBERED_CONTEXT: &str = "mesh/v1/mail-remembered";

/// What the newest record read from one contact device said.
#[derive(Serialize, Deserialize, Clone)]
pub(super) struct Known {
    pub id: [u8; 32],
    /// Its holders, in the order to try, each with its `since`.
    pub holders: Vec<(String, u64)>,
    pub created: u64,
    pub expires: u64,
}

/// What mail keeps across locks and restarts.
#[derive(Serialize, Deserialize, Default)]
pub(super) struct Remembered {
    /// Per contact device.
    pub known: HashMap<[u8; 32], Known>,
    /// Since when our claims at each of our holders are good, by ticket.
    pub since: HashMap<String, u64>,
    /// When each of our holders last answered a renewal of all our claims,
    /// in this process: a restart renews at its first unlock.
    #[serde(skip)]
    pub renewed: HashMap<String, u64>,
    /// Holders we've dropped, and when our claims there end: we collect
    /// there until then, and claim nothing (M12).
    pub dropped: HashMap<String, u64>,
}

impl Remembered {
    /// The holders `device`'s newest record names, in the order to try.
    pub fn holders(&self, device: &[u8; 32]) -> Vec<String> {
        let known = self.known.get(device);
        known.map_or(Vec::new(), |k| {
            k.holders.iter().map(|(ticket, _)| ticket.clone()).collect()
        })
    }

    /// Holders we no longer list move to `dropped` until our claims there
    /// end; dropped ones whose claims have ended are forgotten.
    fn drop_unlisted(&mut self, holders: &[String], now: u64) {
        let unlisted: Vec<String> = (self.since.keys())
            .filter(|t| !holders.contains(t))
            .cloned()
            .collect();
        for ticket in unlisted {
            self.since.remove(&ticket);
            // Not renewed in this process: now bounds the last renewal.
            let renewed = self.renewed.remove(&ticket).unwrap_or(now);
            self.dropped
                .insert(ticket, renewed + crate::mailstore::CLAIM_LIFE);
        }
        self.dropped
            .retain(|t, until| *until > now && !holders.contains(t));
    }

    /// Takes `known` as `device`'s newest record if it's newer than what's
    /// held. True if it was.
    fn take(&mut self, device: [u8; 32], known: Known) -> bool {
        if self
            .known
            .get(&device)
            .is_some_and(|k| k.created >= known.created)
        {
            return false;
        }
        self.known.insert(device, known);
        true
    }

    fn knows(&self, id: &MeshId) -> bool {
        self.known.values().any(|k| k.id == id.to_bytes())
    }

    fn forget_lapsed(&mut self, now: u64) {
        self.known.retain(|_, k| k.expires + REMEMBER_LIFE > now);
    }
}

/// What `path` remembers, lapsed records forgotten, and whether it's from a
/// newer mesh-node: then it's left as it is, never written over, and mail
/// starts from nothing. A damaged file starts empty.
fn load(path: &Path, data_key: &[u8; 32], now: u64) -> (Remembered, bool) {
    let (mut remembered, newer) = match read_sealed(
        path,
        data_key,
        REMEMBERED_CONTEXT,
        REMEMBERED_FORMAT,
    ) {
        Ok(Some((_, bytes))) => match postcard::from_bytes(&bytes) {
            Ok(remembered) => (remembered, false),
            Err(_) => {
                eprintln!("mesh-node: the remembered mail records were damaged; they start empty");
                (Remembered::default(), false)
            }
        },
        Ok(None) => (Remembered::default(), false),
        Err(SealedError::Newer) => {
            eprintln!(
                "mesh-node: the remembered mail records are from a newer mesh-node; they're left as they are"
            );
            (Remembered::default(), true)
        }
        Err(e) => {
            eprintln!(
                "mesh-node: the remembered mail records couldn't be read ({e}); they start empty"
            );
            (Remembered::default(), false)
        }
    };
    remembered.forget_lapsed(now);
    (remembered, newer)
}

fn save(
    path: &Path,
    data_key: &[u8; 32],
    remembered: &mut Remembered,
    now: u64,
) -> Result<(), String> {
    remembered.forget_lapsed(now);
    let bytes = postcard::to_allocvec(remembered).map_err(|e| e.to_string())?;
    write_sealed(
        path,
        data_key,
        REMEMBERED_CONTEXT,
        REMEMBERED_FORMAT,
        &bytes,
    )
    .map_err(|e| e.to_string())
}

/// A seed's ticket, as a holder is named in records.
pub(super) fn ticket_of(seed: &MeshAddr) -> Option<String> {
    seed.ticket_with_direct().ok()
}

/// Whether a put at `at` (our clock) may be lost to a holder whose claims
/// are good only since `since` (the reader's clock) (M12). The clocks may
/// be `CLOCK_ROOM` apart, as for claims; a put mailed twice is shown once.
fn lost(since: u64, at: u64) -> bool {
    since + crate::mailstore::CLOCK_ROOM >= at
}

/// What a record read found: each contact's sealed records.
pub(super) type Found = Vec<(MeshId, Vec<Vec<u8>>)>;

impl Helper {
    fn remembered_path(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or(Path::new("."))
            .join("mail")
            .join(REMEMBERED)
    }

    /// At unlock: what was remembered.
    pub(super) fn mail_load(&mut self) {
        let Some(store) = &self.store else { return };
        let path = self.remembered_path();
        let now = unix_now();
        (self.mail.remembered, self.mail.newer) = load(&path, store.data_key(), now);
        let holders = self.holder_tickets();
        // ponytail: with `--cut seed` there are no holders, so nothing is
        // dropped; a cut device holds the list it had.
        if !holders.is_empty() {
            self.mail.remembered.drop_unlisted(&holders, now);
        }
        self.mail_state_load();
    }

    /// Writes what's remembered, unless the file is from a newer mesh-node.
    pub(super) fn mail_save(&mut self) {
        let Some(store) = &self.store else { return };
        if self.mail.newer {
            return;
        }
        let path = self.remembered_path();
        if let Err(e) = save(
            &path,
            store.data_key(),
            &mut self.mail.remembered,
            unix_now(),
        ) {
            eprintln!("mesh-node: couldn't save the remembered mail records: {e}");
        }
    }

    /// Our holders, as our records list them: those that have answered a
    /// claim.
    fn our_holders(&self) -> Vec<Holder> {
        (self.holder_tickets().into_iter().take(MAX_HOLDERS))
            .filter_map(|ticket| {
                let since = *self.mail.remembered.since.get(&ticket)?;
                Some(Holder { ticket, since })
            })
            .collect()
    }

    /// Puts this device's mail record for every contact and the self pair,
    /// or `only` that one, on every seed.
    pub(super) fn mail_records_put(&mut self, only: Option<&MeshId>) {
        let holders = self.our_holders();
        let (Some(store), Some(net), Some(e2ee)) = (&self.store, &self.net, self.e2ee.as_mut())
        else {
            return;
        };
        if holders.is_empty() || self.seeds.is_empty() {
            return;
        }
        let now = unix_now();
        let field = match e2ee.mail_field(now) {
            Ok(field) => field,
            Err(e) => return eprintln!("mesh-node: couldn't make e2ee keys: {e}"),
        };
        let ids = std::iter::once(store.id()).chain(store.contacts().iter().map(|c| c.id()));
        let records: Vec<Vec<u8>> = ids
            .filter(|id| only.is_none_or(|only| only == id))
            .filter_map(|id| {
                let keys = store.pair_keys(&id)?;
                let sealed = seal_mail_record(
                    &keys,
                    store.device_key(),
                    store.devices(),
                    &field,
                    &holders,
                    now,
                    MAIL_RECORD_LIFE,
                );
                sealed
                    .inspect_err(|e| eprintln!("mesh-node: couldn't make a mail record: {e}"))
                    .ok()
            })
            .collect();
        // On every seed, where senders read them, and every holder, with
        // its token if it has one (M14); a seed that's a holder once.
        let mut to: Vec<(MeshAddr, Vec<u8>)> = Vec::new();
        for ticket in self.holder_tickets() {
            if let Ok(addr) = MeshAddr::from_ticket(&ticket) {
                to.push((addr, mail::token_of(&ticket)));
            }
        }
        for seed in self.seeds.iter() {
            if !to.iter().any(|(a, _)| a.device == seed.device) {
                to.push((seed.clone(), mail::OPEN.to_vec()));
            }
        }
        let (anon, back) = (net.anon.clone(), self.back.clone());
        let only_round = only.is_none();
        tokio::spawn(async move {
            let mut answered = false;
            for (seed, token) in &to {
                let records: Vec<Vec<u8>> =
                    records.iter().map(|r| [&token[..], r].concat()).collect();
                let putting = seed::ask_many(&anon, seed, seed::MREC_PUT, &records);
                answered |= matches!(
                    tokio::time::timeout(mail::HOLDER_WAIT, putting).await,
                    Ok(Ok(_))
                );
            }
            // The round's puts count once a seed answers; else the next refresh.
            if answered && only_round {
                let _ = back.send(Back::MailPut(now));
            }
        });
    }

    /// Reads every contact's mail record, or `only` that one's, unless a
    /// read for them is under way.
    pub(super) fn mail_records_read(&mut self, only: Option<&MeshId>) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        // Our own other devices' records too, under the self pair.
        let ids: Vec<MeshId> = (store.contacts().iter().map(|c| c.id()))
            .chain([store.id()])
            .filter(|id| only.is_none_or(|only| only == id))
            .filter(|id| !self.mail.reading.contains(id))
            .collect();
        let asked: Vec<(MeshId, PairKeys)> = ids
            .iter()
            .filter_map(|id| Some((*id, store.pair_keys(id)?)))
            .collect();
        if asked.is_empty() || self.seeds.is_empty() {
            return;
        }
        self.mail.reading.extend(asked.iter().map(|(id, _)| *id));
        let (round, now) = (only.is_none(), unix_now());
        let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
        let week = week_of(unix_now());
        self.mail.reads.retain(|h| !h.is_finished());
        let reading = tokio::spawn(async move {
            let mut answered = false;
            let mut found: Vec<(MeshId, Vec<Vec<u8>>)> =
                asked.iter().map(|(id, _)| (*id, Vec::new())).collect();
            // This week's lookup for everyone, then last week's for those
            // with nothing this week.
            for week in [week, week.saturating_sub(1)] {
                let wanted: Vec<usize> = (0..asked.len())
                    .filter(|i| found[*i].1.is_empty())
                    .collect();
                let lookups: Vec<Vec<u8>> = wanted
                    .iter()
                    .map(|i| asked[*i].1.mail_lookup(&asked[*i].0, week).to_vec())
                    .collect();
                if lookups.is_empty() {
                    break;
                }
                for seed in seeds.iter() {
                    let getting = seed::ask_many(&anon, seed, seed::MREC_GET, &lookups);
                    let Ok(Ok(answers)) = tokio::time::timeout(mail::HOLDER_WAIT, getting).await
                    else {
                        continue;
                    };
                    answered = true;
                    for (i, answer) in wanted.iter().zip(answers) {
                        if let Some(crate::addrs::Get::Found(sealed)) =
                            crate::addrs::Get::from_bytes(&answer)
                        {
                            found[*i].1.extend(sealed);
                        }
                    }
                }
            }
            let round = (round && answered).then_some(now);
            let _ = back.send(Back::MailRecords(found.clone(), round));
            found
        });
        self.mail.reads.push(reading);
    }

    /// Records read: each one that opens and checks is the newest for its
    /// device if it's newer than what we hold; its keys go to e2ee. Mail
    /// put to a holder its record no longer lists, or before its `since`,
    /// goes again (M12); and what waited for a record goes.
    pub(super) fn mail_records(&mut self, found: Found) {
        let now = unix_now();
        let mut changed = false;
        let mut to_mail = Vec::new();
        // Holders whose `since` moved in what we just read: only those can
        // have lost what we put (M12).
        let mut moved: HashSet<([u8; 32], String)> = HashSet::new();
        let me = (self.store.as_ref()).map(|s| s.device_key().public().to_bytes());
        for (id, sealed) in found {
            self.mail.reading.remove(&id);
            let Some(keys) = self.store.as_ref().and_then(|s| s.pair_keys(&id)) else {
                continue;
            };
            for bytes in sealed {
                let Ok(record) = open_mail_record(&keys, &id, &bytes, now) else {
                    continue;
                };
                if let Some(e2ee) = self.e2ee.as_mut()
                    && e2ee
                        .learn(&id, &record.devices, &record.device, &record.e2ee)
                        .is_err()
                {
                    eprintln!(
                        "mesh-node: a contact's mail record had e2ee keys that didn't check out"
                    );
                }
                let device = record.device.to_bytes();
                // Our own record, read under the self pair: nothing to mail
                // to, and remembering it would stop our other devices'
                // records being read (`knows`).
                if Some(device) == me {
                    continue;
                }
                let before = (self.mail.remembered.known.get(&device))
                    .map(|k| k.holders.clone())
                    .unwrap_or_default();
                let holders: Vec<(String, u64)> = record
                    .holders
                    .into_iter()
                    .map(|h| (h.ticket, h.since))
                    .collect();
                let known = Known {
                    id: id.to_bytes(),
                    holders,
                    created: record.created_at,
                    expires: record.expires_at,
                };
                let news: Vec<(String, u64)> = (known.holders.iter())
                    .filter(|h| !before.contains(h))
                    .cloned()
                    .collect();
                if !self.mail.remembered.take(device, known) {
                    continue;
                }
                moved.extend(news.into_iter().map(|(ticket, _)| (device, ticket)));
                changed = true;
                to_mail.push(id);
            }
        }
        if !changed {
            return;
        }
        let remembered = &self.mail.remembered;
        let again: Vec<([u8; 32], u64)> = (self.mail.marked.iter())
            .filter(|((device, _), (holder, at))| {
                remembered.known.get(device).is_some_and(|k| {
                    match k.holders.iter().find(|(ticket, _)| ticket == holder) {
                        None => true,
                        Some((ticket, since)) => {
                            moved.contains(&(*device, ticket.clone())) && lost(*since, *at)
                        }
                    }
                })
            })
            .map(|(mark, _)| *mark)
            .collect();
        if !again.is_empty() {
            eprintln!(
                "mesh-node: {} mailed events go again (a holder lost or dropped them)",
                again.len()
            );
        }
        for mark in again {
            self.mail.marked.remove(&mark);
        }
        // Marks first: a crash before the records are saved leaves this
        // record unread, so it moves `since` again after the restart (M15).
        self.mail_state_save();
        if self.crash_at_records {
            eprintln!("mesh-node: crashing between the saves (--crash-at)");
            std::process::exit(3);
        }
        self.mail_save();
        to_mail.sort_unstable_by_key(|id| id.to_bytes());
        to_mail.dedup();
        for id in to_mail {
            self.mail_out(&id);
        }
    }

    /// Reads `id`'s record if we hold none of theirs.
    pub(super) fn mail_records_missing(&mut self, id: &MeshId) {
        if !self.mail.remembered.knows(id) {
            self.mail_records_read(Some(id));
        }
    }

    /// The daily round, and the unlock's: our records put, everyone's read.
    pub(super) fn mail_records_round(&mut self, force: bool) {
        // Each half counts as done when a seed answers it (mail.rs Back).
        let now = unix_now();
        if force || now >= self.mail.put_at + MAIL_RECORD_READ {
            self.mail_records_put(None);
        }
        if force || now >= self.mail.read_at + MAIL_RECORD_READ {
            self.mail_records_read(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const KEY: [u8; 32] = [5; 32];

    fn known(created: u64) -> Known {
        Known {
            id: [1; 32],
            holders: vec![("mesh://node/seed".to_owned(), created)],
            created,
            expires: created + MAIL_RECORD_LIFE,
        }
    }

    fn path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mesh-remembered-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("mail").join(REMEMBERED)
    }

    /// A holder no longer listed is collected from until our claims there
    /// end, then forgotten; one listed again isn't dropped.
    #[test]
    fn a_dropped_holder_lasts_as_long_as_its_claims() {
        let (s1, s2) = ("mesh://node/s1".to_owned(), "mesh://node/s2".to_owned());
        let mut r = Remembered::default();
        r.since.insert(s1.clone(), NOW);
        r.since.insert(s2.clone(), NOW);
        r.renewed.insert(s1.clone(), NOW - 10);
        r.drop_unlisted(std::slice::from_ref(&s2), NOW);
        assert_eq!(r.dropped[&s1], NOW - 10 + crate::mailstore::CLAIM_LIFE);
        assert!(r.since.contains_key(&s2) && !r.since.contains_key(&s1));
        r.drop_unlisted(
            std::slice::from_ref(&s2),
            NOW - 10 + crate::mailstore::CLAIM_LIFE,
        );
        assert!(r.dropped.is_empty(), "its claims have ended");
        r.dropped.insert(s1.clone(), NOW + 1);
        r.drop_unlisted(&[s1, s2], NOW);
        assert!(r.dropped.is_empty(), "listed again");
    }

    /// What's read and remembered survives a restart, and only a newer
    /// record replaces it; a read that finds nothing changes nothing.
    #[test]
    fn kept_until_a_newer_record_and_a_month_after_it_lapses() {
        let path = path("kept");
        let mut r = Remembered::default();
        assert!(r.take([2; 32], known(NOW)));
        assert!(!r.take([2; 32], known(NOW - 1)), "an older record");
        r.since.insert("mesh://node/seed".to_owned(), NOW);
        save(&path, &KEY, &mut r, NOW).unwrap();
        let (back, newer) = load(&path, &KEY, NOW + MAIL_RECORD_LIFE + 1);
        assert!(!newer);
        assert_eq!(
            back.holders(&[2; 32]).first().map(String::as_str),
            Some("mesh://node/seed"),
            "kept after it lapsed"
        );
        assert_eq!(back.since.get("mesh://node/seed"), Some(&NOW));
        let gone = NOW + MAIL_RECORD_LIFE + REMEMBER_LIFE;
        assert!(
            load(&path, &KEY, gone).0.holders(&[2; 32]).is_empty(),
            "forgotten a month on"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// A remembered-records file from a newer mesh-node is refused, left on
    /// disk as it was, and never written over.
    /// The reader's clock against ours: a `since` up to `CLOCK_ROOM` before
    /// a put still mails it again (M12).
    #[test]
    fn since_has_an_hours_room() {
        assert!(lost(NOW, NOW - 1));
        assert!(
            lost(NOW - 30 * 60, NOW),
            "the reader's clock half an hour behind"
        );
        assert!(lost(NOW - crate::mailstore::CLOCK_ROOM, NOW));
        assert!(!lost(NOW - crate::mailstore::CLOCK_ROOM - 1, NOW));
    }

    #[test]
    fn a_newer_file_is_refused_and_left() {
        let path = path("newer");
        write_sealed(
            &path,
            &KEY,
            REMEMBERED_CONTEXT,
            REMEMBERED_FORMAT + 1,
            b"from later",
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let (r, newer) = load(&path, &KEY, NOW);
        assert!(newer && r.known.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Damaged: starts empty, and may be written.
        std::fs::write(&path, [REMEMBERED_FORMAT, 0, 1, 2]).unwrap();
        assert!(!load(&path, &KEY, NOW).1);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }
}
