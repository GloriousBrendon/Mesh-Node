//! Spaces in the helper (SPEC-spaces). Task 5: who the Spaces held make
//! reachable. Peers aren't account entries (S2 as changed 2026-11-14): at
//! unlock they're worked out from each Space's chain alone, without its
//! log (S11), and handed to the keystore beside the contacts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use mesh_dm::space::SpaceId;
use mesh_dm::space_store::{SpaceHistory, SpaceList};
use mesh_identity::MeshId;

use super::{Back, Helper, Reached, Target, routing, unix_now};

/// Every current member of every Space in `spaces`, from their chains alone.
/// A Space whose chain doesn't read is left out and said so (counts only).
pub(super) fn space_members(root: &Path, data_key: &[u8; 32], spaces: &[SpaceId]) -> Vec<MeshId> {
    let mut members: Vec<MeshId> = Vec::new();
    for space in spaces {
        let chain = match SpaceHistory::read_chain(root, data_key, space) {
            Ok(chain) => chain,
            Err(e) => {
                eprintln!("mesh-node: a Space's changes didn't read: {e}");
                continue;
            }
        };
        let Some(version) = chain.version(space) else {
            continue;
        };
        let ids = version.state.members.keys();
        members.extend(ids.filter_map(|m| MeshId::from_bytes(m).ok()));
    }
    members.sort_by_key(|m| m.to_bytes());
    members.dedup();
    members
}

/// A connection to someone who's only a Space peer closes this long after
/// it was last used (S14).
pub const PEER_IDLE: Duration = Duration::from_secs(60);
/// An away peer isn't looked up again at the seed for this long (S14).
pub(super) const PEER_RETRY: Duration = Duration::from_secs(30 * 60);
/// How often idle peers are closed and the hello paced, at most.
pub(super) const PEER_TICK: Duration = Duration::from_secs(5);
/// Hello lookups a minute: under the seed's `GETS_PER_DEVICE` (S14).
pub(super) const HELLO_LOOKUPS: u32 = 100;
/// Hello dials under way at once (S14).
pub(super) const HELLO_DIALS: usize = 32;
/// Hello pauses while more connections than this are open (S14): three
/// quarters of transport's 256.
pub(super) const HELLO_ROOM: usize = 192;
const _: () = assert!(HELLO_LOOKUPS < crate::addrs::GETS_PER_DEVICE);

/// Peers on the wire (S14): when each was last used, who may be looked up
/// again when, and the hello's queue and pace. Times are passed in.
pub(super) struct PeerWire {
    idle: Duration,
    used: HashMap<[u8; 32], Instant>,
    retry: HashMap<[u8; 32], Instant>,
    hello: VecDeque<MeshId>,
    /// The minute the hello's lookups are counted in, and how many so far.
    minute: Option<(Instant, u32)>,
    dialling: usize,
}

impl PeerWire {
    pub(super) fn new(idle: Duration) -> Self {
        Self {
            idle,
            used: HashMap::new(),
            retry: HashMap::new(),
            hello: VecDeque::new(),
            minute: None,
            dialling: 0,
        }
    }

    /// Traffic with `who` (a connection, a send, a receive).
    pub(super) fn used(&mut self, who: &MeshId, now: Instant) {
        self.used.insert(who.to_bytes(), now);
    }

    /// Peers not used for `idle`: their connections close. Forgotten here.
    pub(super) fn idle_now(&mut self, now: Instant) -> Vec<MeshId> {
        let idle = self.idle;
        let gone: Vec<[u8; 32]> = (self.used.iter())
            .filter(|(_, at)| now.saturating_duration_since(**at) > idle)
            .map(|(who, _)| *who)
            .collect();
        gone.iter()
            .filter_map(|who| {
                self.used.remove(who);
                MeshId::from_bytes(who).ok()
            })
            .collect()
    }

    /// Whether `who` may be looked up at the seed now.
    pub(super) fn may_look_up(&self, who: &MeshId, now: Instant) -> bool {
        self.retry.get(&who.to_bytes()).is_none_or(|at| now >= *at)
    }

    /// A lookup or dial of `who` found nobody: not again for `PEER_RETRY`.
    pub(super) fn missed(&mut self, who: &MeshId, now: Instant) {
        self.retry.insert(who.to_bytes(), now + PEER_RETRY);
    }

    /// `who` connected to us: their retry clears (the hello's other side).
    pub(super) fn heard(&mut self, who: &MeshId, now: Instant) {
        self.retry.remove(&who.to_bytes());
        self.used(who, now);
    }

    /// Everyone to say hello to, once each.
    pub(super) fn queue_hello(&mut self, ids: impl IntoIterator<Item = MeshId>) {
        let mut queued: HashSet<[u8; 32]> = self.hello.iter().map(|m| m.to_bytes()).collect();
        for id in ids {
            if queued.insert(id.to_bytes()) {
                self.hello.push_back(id);
            }
        }
    }

    /// The next hellos to dial: at most `HELLO_LOOKUPS` a minute and
    /// `HELLO_DIALS` under way, none while `open` is above `HELLO_ROOM`.
    pub(super) fn next_hellos(&mut self, now: Instant, open: usize) -> Vec<MeshId> {
        if open > HELLO_ROOM {
            return Vec::new();
        }
        let minute = Duration::from_secs(60);
        let (start, count) = match self.minute {
            Some((start, count)) if now.saturating_duration_since(start) < minute => (start, count),
            _ => (now, 0),
        };
        let room = (HELLO_LOOKUPS - count) as usize;
        let take = room
            .min(HELLO_DIALS.saturating_sub(self.dialling))
            .min(self.hello.len());
        let out: Vec<MeshId> = self.hello.drain(..take).collect();
        self.dialling += out.len();
        self.minute = Some((start, count + out.len() as u32));
        out
    }

    /// A hello dial came back.
    pub(super) fn hello_done(&mut self) {
        self.dialling = self.dialling.saturating_sub(1);
    }

    pub(super) fn idle(&self) -> Duration {
        self.idle
    }
}

impl Helper {
    fn is_peer(&self, id: &MeshId) -> bool {
        (self.store.iter()).any(|s| s.peers().iter().any(|c| c.id() == *id))
    }

    /// Traffic with a peer: its connection stays open a while longer.
    pub(super) fn peer_used(&mut self, id: &MeshId) {
        if self.is_peer(id) {
            self.wire.used(id, Instant::now());
        }
    }

    /// A peer connected to us: their retry clears (S14's hello, other side).
    pub(super) fn peer_heard(&mut self, id: &MeshId) {
        if self.is_peer(id) {
            self.wire.heard(id, Instant::now());
        }
    }

    /// Closes idle peer-only connections and sends the next hellos (S14).
    pub(super) fn peer_tick(&mut self) {
        let now = Instant::now();
        let Some(net) = &self.net else { return };
        for id in self.wire.idle_now(now) {
            // Friends and our own devices keep theirs (presence, sync).
            if self.is_peer(&id) {
                net.node.close_idle(&id);
            }
        }
        let open = net.node.open_connections();
        for id in self.wire.next_hellos(now, open) {
            self.dial_back(&id, true);
        }
    }

    /// Dials a peer to send them something (S14), unless they were found
    /// away less than `PEER_RETRY` ago: then it waits for mail or a hello.
    #[expect(dead_code, reason = "Task 7's send path dials peers through this")]
    pub(super) fn dial_peer(&self, id: &MeshId) {
        if self.wire.may_look_up(id, Instant::now()) {
            self.dial_back(id, false);
        }
    }

    /// An ordinary dial, reported back either way: a hello, or a send's.
    fn dial_back(&self, id: &MeshId, hello: bool) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let back = self.back.clone();
        let Some(target) = Target::of(store, id) else {
            let _ = back.send(Back::Hello(*id, false, hello));
            return;
        };
        let (node, anon) = (net.node.clone(), net.anon.clone());
        let (seeds, id) = (self.seeds.clone(), *id);
        tokio::spawn(async move {
            let reached = routing::reach(node, &anon, &seeds, target, unix_now()).await;
            let ok = reached.is_ok();
            if let Ok(Reached { last, list, .. }) = reached {
                let _ = back.send(Back::Reached(Box::new((id, last, list))));
            }
            let _ = back.send(Back::Hello(id, ok, hello));
        });
    }

    pub(super) fn hello_back(&mut self, id: &MeshId, reached: bool, hello: bool) {
        if hello {
            self.wire.hello_done();
        }
        if !reached {
            self.wire.missed(id, Instant::now());
        }
    }

    /// Opens the list of Spaces and works out the peers, as networking
    /// starts: before the allow-list and the first records.
    pub(super) fn open_spaces(&mut self) {
        let Some(store) = &mut self.store else { return };
        let data = self.path.parent().unwrap_or(Path::new("."));
        let root = data.join("dm");
        let list = SpaceList::open(&root, store.data_key())
            .inspect_err(|e| eprintln!("mesh-node: the list of Spaces didn't open: {e}"))
            .ok();
        let members = list
            .as_ref()
            .map(|l| space_members(&root, store.data_key(), l.spaces()))
            .unwrap_or_default();
        if let Err(e) = store.set_peers(members) {
            eprintln!("mesh-node: the Spaces' members didn't fit: {e}");
        }
        let peers: Vec<MeshId> = store.peers().iter().map(|c| c.id()).collect();
        self.wire.queue_hello(peers);
        self.spaces = list;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_dm::Sender;
    use mesh_dm::space::{Change, SpaceBody, SpaceChange, SpaceEvent, space_id};
    use mesh_identity::{DeviceCert, DeviceKey, RootKey};

    const KEY: [u8; 32] = [7; 32];
    const NOW: u64 = 1_800_000_000_000;

    /// A Space made by a new owner with `members` added, stored under `root`.
    fn space_with(root: &Path, members: &[MeshId]) -> (SpaceId, MeshId) {
        let owner = RootKey::generate().unwrap();
        let device = DeviceKey::generate().unwrap();
        let cert = DeviceCert::issue(&owner, &device.public(), "d", 1).unwrap();
        let nonce = mesh_dm::space::nonce().unwrap();
        let id = space_id(&owner.id().to_bytes(), &nonce);
        let me = Sender {
            person: owner.id().to_bytes(),
            device: device.public().to_bytes(),
        };
        let mut h = SpaceHistory::open(root, &KEY, me, id).unwrap();
        let mut changes = vec![Change::Create {
            name: "s".into(),
            nonce,
            display: "o".into(),
        }];
        changes.extend(members.iter().map(|m| Change::Add {
            who: m.to_bytes(),
            display: "m".into(),
        }));
        let mut after = None;
        for (i, change) in changes.into_iter().enumerate() {
            let event_id = [i as u8 + 1; 16];
            let body = SpaceBody::Change(SpaceChange { after, change });
            let seq = NOW + i as u64;
            let e =
                SpaceEvent::signed(id, event_id, (seq, seq, i as u64 + 1), body, &device, &cert);
            h.store(&e, me, NOW, NOW).unwrap();
            after = Some(event_id);
        }
        (id, owner.id())
    }

    #[test]
    fn the_members_of_every_space_held() {
        let root = std::env::temp_dir().join(format!("mesh-node-spaces-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (a, b, c) = (
            RootKey::generate().unwrap().id(),
            RootKey::generate().unwrap().id(),
            RootKey::generate().unwrap().id(),
        );
        let (one, owner_one) = space_with(&root, &[a, b]);
        let (two, owner_two) = space_with(&root, &[b, c]);
        let mut members = space_members(&root, &KEY, &[one, two, [9; 16]]);
        members.sort_by_key(|m| m.to_bytes());
        let mut expected = vec![a, b, c, owner_one, owner_two];
        expected.sort_by_key(|m| m.to_bytes());
        expected.dedup();
        assert_eq!(members, expected, "both Spaces' members, once each");
        assert!(space_members(&root, &KEY, &[]).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn ids(n: usize) -> Vec<MeshId> {
        (0..n).map(|_| RootKey::generate().unwrap().id()).collect()
    }

    #[test]
    fn a_peer_connection_closes_when_idle() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let [a, b] = ids(2).try_into().unwrap();
        wire.used(&a, t0);
        wire.used(&b, t0 + Duration::from_secs(30));
        assert!(wire.idle_now(t0 + Duration::from_secs(59)).is_empty());
        assert_eq!(wire.idle_now(t0 + Duration::from_secs(61)), [a]);
        assert!(
            wire.idle_now(t0 + Duration::from_secs(62)).is_empty(),
            "forgotten once closed"
        );
        wire.used(&b, t0 + Duration::from_secs(80));
        assert!(
            wire.idle_now(t0 + Duration::from_secs(100)).is_empty(),
            "used again"
        );
        assert_eq!(wire.idle_now(t0 + Duration::from_secs(141)), [b]);
    }

    #[test]
    fn an_away_peer_is_looked_up_once_per_retry_until_heard() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let [a] = ids(1).try_into().unwrap();
        assert!(wire.may_look_up(&a, t0));
        wire.missed(&a, t0);
        assert!(!wire.may_look_up(&a, t0 + PEER_RETRY - Duration::from_secs(1)));
        assert!(wire.may_look_up(&a, t0 + PEER_RETRY));
        wire.missed(&a, t0);
        wire.heard(&a, t0 + Duration::from_secs(5));
        assert!(
            wire.may_look_up(&a, t0 + Duration::from_secs(5)),
            "the hello clears it"
        );
    }

    #[test]
    fn the_hello_keeps_to_its_pace() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let people = ids(250);
        wire.queue_hello(people.iter().copied().chain(people.iter().copied()));
        // At most HELLO_DIALS under way.
        let first = wire.next_hellos(t0, 0);
        assert_eq!(first.len(), HELLO_DIALS);
        assert!(wire.next_hellos(t0, 0).is_empty(), "all under way");
        for _ in 0..HELLO_DIALS {
            wire.hello_done();
        }
        // At most HELLO_LOOKUPS in a minute, whatever comes back.
        let mut this_minute = first.len();
        loop {
            let next = wire.next_hellos(t0 + Duration::from_secs(1), 0);
            if next.is_empty() {
                break;
            }
            this_minute += next.len();
            for _ in 0..next.len() {
                wire.hello_done();
            }
        }
        assert_eq!(this_minute, HELLO_LOOKUPS as usize);
        // A new minute goes on, but not while connections are near the cap.
        assert!(
            wire.next_hellos(t0 + Duration::from_secs(61), HELLO_ROOM + 1)
                .is_empty()
        );
        assert_eq!(
            wire.next_hellos(t0 + Duration::from_secs(61), 0).len(),
            HELLO_DIALS
        );
        // Each person once, however often queued.
        let mut all = first;
        let mut seen: HashSet<[u8; 32]> = all.iter().map(|m| m.to_bytes()).collect();
        assert_eq!(seen.len(), all.len());
        all.clear();
        seen.clear();
        let mut wire = PeerWire::new(PEER_IDLE);
        wire.queue_hello(people.iter().copied().chain(people.iter().copied()));
        let mut at = t0;
        loop {
            let next = wire.next_hellos(at, 0);
            if next.is_empty() && wire.hello.is_empty() {
                break;
            }
            for m in &next {
                assert!(seen.insert(m.to_bytes()), "said hello twice");
                wire.hello_done();
            }
            at += Duration::from_secs(61);
        }
        assert_eq!(seen.len(), people.len());
    }
}
