//! Routing (SPEC-routing): reaching a contact by ID. Each device leaves an
//! encrypted address record per contact on the seeds (D2–D4), and finds a
//! contact by trying the address that last worked, then the seeds' records
//! for them (D8). Seed requests go from the throwaway node (seed D7b).

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::addrs::{Get, Put};
use crate::seed;
use mesh_identity::{
    AddrRecord, DeviceList, Keystore, LastAddr, MeshId, PairKeys, day_of, open_addr, seal_addr,
};
use mesh_transport::{MeshAddr, Node, Pong, RelayUrl};

/// How long a record lasts (D4); `--record-ttl` shortens it for tests.
pub const RECORD_TTL: u64 = 2 * 3600;
/// How often records are refreshed, at most (D4).
pub const REFRESH_EVERY: u64 = 30 * 60;

/// Address gets this device makes in any 60 s, at most: under the seed's
/// `GETS_PER_DEVICE` with room for clocks and the link's own (S14).
pub const GETS_A_MINUTE: usize = 110;
/// Gets one `find` costs a seed: today's lookup and yesterday's.
pub const GETS_PER_FIND: usize = 2;
/// Gets the spare side (the hello) leaves for sends and key lookups.
pub const SPARE_KEEPS: usize = 20;
/// A get the seed refused anyway is asked again after this, this many times.
const SLOWED_AGAIN: Duration = Duration::from_secs(10);
const SLOWED_TRIES: u32 = 3;

/// The address-get budgets a helper's gets come from (S14): one per seed,
/// each seed counting its own limit. A cheap clone shares them.
#[derive(Clone, Default)]
pub struct Gets {
    seeds: Arc<Mutex<HashMap<[u8; 32], Shared>>>,
    /// Left free for others: `spare`'s takes stop this short.
    keep: usize,
    /// What finds through this clone are for (`spaceCounts`).
    purpose: &'static str,
    /// Finds by purpose and result, shared by every clone.
    finds: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl Gets {
    /// The same budgets, taking only what leaves `SPARE_KEEPS` free.
    pub fn spare(&self) -> Gets {
        Gets {
            keep: SPARE_KEEPS,
            ..self.for_("hello")
        }
    }

    /// The same budgets, its finds counted as for `purpose`.
    pub fn for_(&self, purpose: &'static str) -> Gets {
        Gets {
            purpose,
            ..self.clone()
        }
    }

    /// Counts a find's result under this clone's purpose.
    fn counted<T>(&self, found: &Result<T, ReachError>) {
        let result = match found {
            Ok(_) => "found",
            Err(ReachError::Unreachable) => "not found",
            Err(ReachError::Slowed) => "slowed",
            Err(ReachError::RevokedDevice) => "revoked",
        };
        let purpose = if self.purpose.is_empty() {
            "other"
        } else {
            self.purpose
        };
        let mut finds = self.finds.lock().unwrap_or_else(|e| e.into_inner());
        *finds.entry(format!("{purpose} {result}")).or_default() += 1;
    }

    /// Finds so far, by purpose and result.
    pub fn finds(&self) -> BTreeMap<String, u64> {
        self.finds.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The budget for gets at the seed `device`.
    pub fn at(&self, device: &[u8; 32]) -> SeedGets {
        let mut seeds = self.seeds.lock().unwrap_or_else(|e| e.into_inner());
        SeedGets {
            window: seeds.entry(*device).or_default().clone(),
            keep: self.keep,
        }
    }
}

type Shared = Arc<Mutex<Window>>;

/// One seed's budget for every address get a helper makes there: a sliding
/// minute, so it holds whenever the seed's own minute starts. Waiters take
/// their turn in the order they came, the hello's apart from the rest.
pub struct SeedGets {
    window: Arc<Mutex<Window>>,
    keep: usize,
}

#[derive(Default)]
struct Window {
    sent: VecDeque<Instant>,
    /// Waiting turns, oldest first: the rest's, then the hello's.
    queue: [VecDeque<u64>; 2],
    next: u64,
}

/// A place in the queue; leaves it when dropped (its task ended).
pub struct Turn {
    window: Arc<Mutex<Window>>,
    class: usize,
    id: u64,
}

impl Drop for Turn {
    fn drop(&mut self) {
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        w.queue[self.class].retain(|id| *id != self.id);
    }
}

/// How often a waiter that isn't first looks again.
const TURN_AGAIN: Duration = Duration::from_millis(100);

impl Window {
    /// Takes `n` gets now leaving `keep` free, or says how long until
    /// they'd fit.
    fn fit(&mut self, n: usize, keep: usize, now: Instant) -> Option<Duration> {
        let minute = Duration::from_secs(60);
        while (self.sent.front()).is_some_and(|t| now.saturating_duration_since(*t) >= minute) {
            self.sent.pop_front();
        }
        let n = n.min(GETS_A_MINUTE - keep);
        let over = (self.sent.len() + n + keep).saturating_sub(GETS_A_MINUTE);
        if over == 0 {
            self.sent.extend(std::iter::repeat_n(now, n));
            return None;
        }
        // The `over`th oldest leaving frees enough.
        Some((self.sent[over - 1] + minute).saturating_duration_since(now))
    }
}

impl SeedGets {
    /// The same budget, taking only what leaves `SPARE_KEEPS` free.
    #[cfg(test)]
    fn spare(&self) -> SeedGets {
        SeedGets {
            window: self.window.clone(),
            keep: SPARE_KEEPS,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        self.window.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn class(&self) -> usize {
        usize::from(self.keep > 0)
    }

    /// Takes `n` gets now if nobody waits ahead, or says how long to wait.
    pub fn try_take(&self, n: usize, now: Instant) -> Option<Duration> {
        let mut w = self.lock();
        if !w.queue[self.class()].is_empty() {
            return Some(TURN_AGAIN);
        }
        w.fit(n, self.keep, now)
    }

    /// A place at the back of the queue.
    pub fn join(&self) -> Turn {
        let mut w = self.lock();
        let id = w.next;
        w.next += 1;
        w.queue[self.class()].push_back(id);
        Turn {
            window: self.window.clone(),
            class: self.class(),
            id,
        }
    }

    /// Takes `n` gets for `turn` if it's first and they fit (it then
    /// leaves the queue), or says how long to wait.
    pub fn turn(&self, turn: &Turn, n: usize, now: Instant) -> Option<Duration> {
        let mut w = self.lock();
        if w.queue[turn.class].front() != Some(&turn.id) {
            return Some(TURN_AGAIN);
        }
        let wait = w.fit(n, self.keep, now);
        if wait.is_none() {
            w.queue[turn.class].pop_front();
        }
        wait
    }

    /// Takes `n` gets, waiting its turn.
    pub async fn take(&self, n: usize) {
        if self.try_take(n, Instant::now()).is_none() {
            return;
        }
        let turn = self.join();
        while let Some(wait) = self.turn(&turn, n, Instant::now()) {
            tokio::time::sleep(wait.max(Duration::from_millis(50))).await;
        }
    }
}

/// This device's record for each contact, and one under the self pair for
/// our other devices (SPEC-social D11), on `relay`. `field` gives each one's
/// e2ee field (SPEC-e2ee D4). With `only`, just that contact's record.
pub fn records(
    store: &Keystore,
    relay: &RelayUrl,
    now: u64,
    ttl: u64,
    only: Option<&MeshId>,
    mut field: impl FnMut(&MeshId) -> Vec<u8>,
) -> Vec<Vec<u8>> {
    let ids = store.reachable().map(|c| c.id());
    std::iter::once(store.id())
        .chain(ids)
        .filter(|id| only.is_none_or(|only| only == id))
        .filter_map(|id| {
            let keys = store.pair_keys(&id)?;
            let sealed = seal_addr(
                &keys,
                store.device_key(),
                store.devices(),
                relay.as_str(),
                &field(&id),
                now,
                ttl,
            );
            sealed
                .inspect_err(|e| eprintln!("mesh-node: couldn't make an address record: {e}"))
                .ok()
        })
        .collect()
}

/// Puts the records on every seed: true when a seed took all of them.
pub async fn publish(anon: &Node, seeds: &[MeshAddr], records: &[Vec<u8>]) -> bool {
    let mut published = false;
    for addr in seeds {
        if let Ok(answers) = seed::ask_many(anon, addr, seed::ADDR_PUT, records).await {
            let took = |a: &Vec<u8>| a.first().copied().and_then(Put::from_byte) == Some(Put::Ok);
            published |= answers.iter().all(took);
        }
    }
    published
}

/// What the helper knows about a contact, taken from the keystore so the
/// search can run off the main loop.
pub struct Target {
    pub id: MeshId,
    pub keys: PairKeys,
    pub last: Option<LastAddr>,
    pub known: Option<DeviceList>,
}

impl Target {
    pub fn of(store: &Keystore, id: &MeshId) -> Option<Self> {
        let contact = store.reachable_contact(id)?;
        Some(Self {
            id: *id,
            keys: store.pair_keys(id)?,
            last: contact.last.clone(),
            known: contact.devices(),
        })
    }

    /// Our own identity, to find our other devices.
    pub fn own(store: &Keystore) -> Option<Self> {
        Some(Self {
            id: store.id(),
            keys: store.pair_keys(&store.id())?,
            last: None,
            known: Some(store.devices().clone()),
        })
    }
}

pub struct Reached {
    pub pong: Pong,
    /// The address that worked; `None` through an already open connection.
    pub last: Option<LastAddr>,
    /// Their device list, when the seeds gave a newer one.
    pub list: Option<DeviceList>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReachError {
    /// No record, or no device answered.
    Unreachable,
    /// The seed refused the lookup for its limit: not away, ask again soon.
    Slowed,
    /// Records came back, but only for devices their newest list removed.
    RevokedDevice,
}

/// Pings one of the contact's devices: an open connection first, then the
/// cached address, then every device the seeds know of, together; the first
/// to answer wins (D8).
/// `reach` without the seed: an open connection, or the last address that
/// worked.
pub async fn reach_known(node: &Node, target: &Target) -> Option<Reached> {
    let current = |list: &Option<DeviceList>, device: &[u8; 32]| {
        list.as_ref()
            .is_none_or(|l| l.devices().iter().any(|c| c.device().as_bytes() == device))
    };
    for addr in node.connected(&target.id) {
        if let Ok(pong) = node.ping(&addr).await {
            // An open connection has no relay to remember; the cache keeps
            // what it had.
            return Some(Reached {
                pong,
                last: None,
                list: None,
            });
        }
    }
    if let Some(last) = &target.last
        && current(&target.known, &last.device)
        && let Some(addr) = MeshAddr::from_parts(&last.device, &last.relay)
        && let Ok(pong) = node.ping(&addr).await
        && pong.peer.id == target.id
    {
        return Some(Reached {
            pong,
            last: Some(last.clone()),
            list: None,
        });
    }
    None
}

/// The records a lookup found are put in `found`, reached or not: one
/// find gives their keys too (SPEC-spaces S14).
pub async fn reach(
    node: Arc<Node>,
    anon: &Node,
    gets: &Gets,
    seeds: &[MeshAddr],
    target: &Target,
    now: u64,
    found: &mut Vec<AddrRecord>,
) -> Result<Reached, ReachError> {
    if let Some(reached) = reach_known(&node, target).await {
        return Ok(reached);
    }
    let (records, newest) = find(anon, gets, seeds, target, now).await?;
    found.extend(records.iter().cloned());
    let mut pings = tokio::task::JoinSet::new();
    for record in records {
        let device = *record.device.as_bytes();
        let Some(addr) = MeshAddr::from_parts(&device, &record.relay) else {
            continue;
        };
        let node = node.clone();
        pings.spawn(async move {
            let last = LastAddr {
                device,
                relay: record.relay,
            };
            node.ping(&addr).await.map(|pong| (pong, last))
        });
    }
    while let Some(done) = pings.join_next().await {
        if let Ok(Ok((pong, last))) = done
            && pong.peer.id == target.id
        {
            return Ok(Reached {
                pong,
                last: Some(last),
                list: newest,
            });
        }
    }
    Err(ReachError::Unreachable)
}

/// Our other devices the seeds have records for (under the self pair), not
/// counting this one.
pub async fn own_devices(
    anon: &Node,
    gets: &Gets,
    seeds: &[MeshAddr],
    own: &Target,
    this: &[u8; 32],
    now: u64,
) -> Vec<MeshAddr> {
    let Ok((records, _)) = find(anon, gets, seeds, own, now).await else {
        return Vec::new();
    };
    records
        .into_iter()
        .filter(|r| r.device.as_bytes() != this)
        .filter_map(|r| MeshAddr::from_parts(r.device.as_bytes(), &r.relay))
        .collect()
}

/// The contact's records on the seeds for today and yesterday (midnight, and
/// clocks that disagree), opened and checked: one per device, newest first,
/// only devices their newest known list still has. Also that list.
pub async fn find(
    anon: &Node,
    gets: &Gets,
    seeds: &[MeshAddr],
    target: &Target,
    now: u64,
) -> Result<(Vec<AddrRecord>, Option<DeviceList>), ReachError> {
    let found = find_counted(anon, gets, seeds, target, now).await;
    gets.counted(&found);
    found
}

async fn find_counted(
    anon: &Node,
    gets: &Gets,
    seeds: &[MeshAddr],
    target: &Target,
    now: u64,
) -> Result<(Vec<AddrRecord>, Option<DeviceList>), ReachError> {
    let today = day_of(now);
    let lookups =
        [today, today.saturating_sub(1)].map(|day| target.keys.lookup(&target.id, day).to_vec());
    let mut found: Vec<AddrRecord> = Vec::new();
    for tried in 1..=SLOWED_TRIES {
        let mut slowed = false;
        for addr in seeds {
            gets.at(addr.device.as_bytes()).take(GETS_PER_FIND).await;
            let Ok(answers) = seed::ask_many(anon, addr, seed::ADDR_GET, &lookups).await else {
                continue;
            };
            for answer in answers {
                match Get::from_bytes(&answer) {
                    // Anything that doesn't open is someone else's, or junk.
                    Some(Get::Found(sealed)) => found.extend(
                        sealed
                            .iter()
                            .filter_map(|r| open_addr(&target.keys, &target.id, r, now).ok()),
                    ),
                    Some(Get::SlowDown) => slowed = true,
                    None => {}
                }
            }
        }
        if !found.is_empty() || !slowed {
            break;
        }
        if tried == SLOWED_TRIES {
            return Err(ReachError::Slowed);
        }
        tokio::time::sleep(SLOWED_AGAIN).await;
    }
    if found.is_empty() {
        return Err(ReachError::Unreachable);
    }
    let newest = found
        .iter()
        .map(|r| &r.devices)
        .chain(&target.known)
        .max_by_key(|l| l.seq())
        .cloned();
    if let Some(list) = &newest {
        found.retain(|r| list.is_current(&r.device));
    }
    if found.is_empty() {
        return Err(ReachError::RevokedDevice);
    }
    found.sort_by_key(|r| (*r.device.as_bytes(), Reverse(r.created_at)));
    found.dedup_by_key(|r| *r.device.as_bytes());
    found.sort_by_key(|r| Reverse(r.created_at));
    // A newer list than the one already known goes back to the keystore.
    let newer = newest.filter(|l| target.known.as_ref().is_none_or(|k| l.seq() > k.seq()));
    Ok((found, newer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_identity::RootKey;
    use std::time::Instant;

    /// Every address get a helper makes fits the seed's limit in any
    /// minute, however the seed's minute falls; what doesn't fit waits.
    /// The spare side (the hello) leaves `SPARE_KEEPS` for the rest.
    /// Waiters go in the order they came: one that's waiting gets the next
    /// room, not a newcomer that asks just as it frees (a ping starved
    /// behind refreshes asking every 2 s). A waiter given up leaves.
    #[test]
    fn address_gets_wait_in_turn() {
        let t0 = Instant::now();
        let gets = Gets::default().at(&[0; 32]);
        while gets.try_take(GETS_PER_FIND, t0).is_none() {}
        let first = gets.join();
        assert!(gets.turn(&first, GETS_PER_FIND, t0).is_some(), "full");
        let later = t0 + Duration::from_secs(61);
        assert!(
            gets.try_take(GETS_PER_FIND, later).is_some(),
            "a newcomer waits behind it"
        );
        let second = gets.join();
        assert!(
            gets.turn(&second, GETS_PER_FIND, later).is_some(),
            "not its turn"
        );
        assert!(gets.turn(&first, GETS_PER_FIND, later).is_none());
        assert!(
            gets.turn(&second, GETS_PER_FIND, later).is_none(),
            "then its own"
        );
        // A waiter whose task ended doesn't hold up the rest.
        let gone = gets.join();
        drop(gone);
        assert!(gets.try_take(GETS_PER_FIND, later).is_none());
        // The hello's queue is its own: sends never wait behind it.
        let hello = gets.spare().join();
        assert!(gets.try_take(GETS_PER_FIND, later).is_none());
        drop(hello);
    }

    /// Finds are counted by what they were for and what came back
    /// (`spaceCounts`): numbers only.
    #[test]
    fn finds_are_counted_by_purpose_and_result() {
        let gets = Gets::default();
        gets.for_("keys").counted(&Err::<(), _>(ReachError::Slowed));
        gets.spare().counted(&Ok(()));
        gets.spare().counted(&Err::<(), _>(ReachError::Unreachable));
        gets.for_("send").for_("send").counted(&Ok(()));
        let want = [
            ("hello found", 1),
            ("hello not found", 1),
            ("keys slowed", 1),
            ("send found", 1),
        ];
        let want: std::collections::BTreeMap<String, u64> =
            want.into_iter().map(|(k, n)| (k.to_owned(), n)).collect();
        assert_eq!(gets.finds(), want);
    }

    /// Each seed has its own limit, so a find that asks two seeds takes
    /// from each one's budget: a second seed doesn't halve the pace.
    #[test]
    fn each_seed_has_its_own_budget() {
        let t0 = Instant::now();
        let gets = Gets::default();
        let (a, b) = (gets.at(&[1; 32]), gets.at(&[2; 32]));
        let mut finds = 0;
        while a.try_take(GETS_PER_FIND, t0).is_none() && b.try_take(GETS_PER_FIND, t0).is_none() {
            finds += 1;
        }
        assert_eq!(finds * GETS_PER_FIND, GETS_A_MINUTE);
        assert!(
            gets.at(&[1; 32]).try_take(GETS_PER_FIND, t0).is_some(),
            "shared"
        );
        assert!(
            gets.spare()
                .at(&[2; 32])
                .try_take(GETS_PER_FIND, t0)
                .is_some(),
            "the hello's too"
        );
    }

    #[test]
    fn address_gets_keep_under_the_seeds_limit() {
        let t0 = Instant::now();
        let gets = Gets::default().at(&[0; 32]);
        let mut at = t0;
        let mut taken = Vec::new();
        // Asking every second for three minutes.
        while at < t0 + Duration::from_secs(180) {
            while gets.try_take(GETS_PER_FIND, at).is_none() {
                taken.push(at);
            }
            at += Duration::from_secs(1);
        }
        for start in &taken {
            let in_minute = (taken.iter())
                .filter(|t| **t >= *start && **t < *start + Duration::from_secs(60))
                .count();
            assert!(in_minute * GETS_PER_FIND <= GETS_A_MINUTE);
        }
        const _: () = assert!(GETS_A_MINUTE < crate::addrs::GETS_PER_DEVICE as usize);
        assert_eq!(taken.len() * GETS_PER_FIND, 3 * GETS_A_MINUTE);
        let wait = (gets.try_take(GETS_PER_FIND, t0 + Duration::from_secs(150))).unwrap();
        assert!(wait > Duration::ZERO && wait <= Duration::from_secs(60));

        let gets = Gets::default().at(&[0; 32]);
        let spare = gets.spare();
        let mut people = 0;
        while spare.try_take(GETS_PER_FIND, t0).is_none() {
            people += 1;
        }
        assert_eq!(people * GETS_PER_FIND, GETS_A_MINUTE - SPARE_KEEPS);
        assert!(
            gets.try_take(GETS_PER_FIND, t0).is_none(),
            "a send still fits"
        );
    }

    /// A change to one contact puts only their record, not everyone's
    /// (audit finding 9); a refresh still puts them all, and ours.
    #[test]
    fn one_contact_or_all_of_them() {
        let dir = std::env::temp_dir().join(format!("mesh-routing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let password = "correct horse battery staple";
        let mut store = Keystore::create(&dir.join("keystore"), "alice", password, "pc").unwrap();
        let ids: Vec<MeshId> = (0..3).map(|_| RootKey::generate().unwrap().id()).collect();
        for id in &ids {
            store.add_contact(*id, "").unwrap();
        }
        let relay: RelayUrl = "https://relay.example/".parse().unwrap();
        let all = records(&store, &relay, 1_800_000_000, RECORD_TTL, None, |_| {
            Vec::new()
        });
        assert_eq!(
            all.len(),
            ids.len() + 1,
            "every contact and our own devices"
        );
        let one = records(
            &store,
            &relay,
            1_800_000_000,
            RECORD_TTL,
            Some(&ids[1]),
            |_| Vec::new(),
        );
        assert_eq!(one.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
