//! Spaces in the helper (SPEC-spaces). Task 5: who the Spaces held make
//! reachable. Peers aren't account entries (S2 as changed 2026-11-14): at
//! unlock they're worked out from each Space's chain alone, without its
//! log (S11), and handed to the keystore beside the contacts.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use mesh_dm::space::SpaceId;
use mesh_dm::space_store::{SpaceHistory, SpaceList};
use mesh_identity::MeshId;

use mesh_dm::chat::Taken;
use mesh_dm::space::SpaceEvent;
use mesh_dm::space::{
    Change, ChannelId, Role, SpaceBody, SpaceChange, SpaceVersion, check_history, space_id,
    to_redo, would_count,
};
use mesh_dm::space_store::{
    SPACE_BATCH, from_batch, from_member, from_own, to_batch, to_member, to_own,
};
use mesh_dm::{Person, Sender};
use mesh_e2ee::Kind as NoteKind;
use mesh_e2ee::{MAIL, MailHead, seal_mail};
use mesh_identity::{DeviceCert, DeviceKey, VerifyingKey};
use mesh_transport::MeshAddr;
use serde_json::{Value, json};

use super::{
    Back, Fail, Helper, ReachError, Reached, Target, dm, e2ee, emit, mail, parse_id, routing,
    unix_now,
};

/// A device's answer to a batch of Space events: who, which device, each
/// event's Space and number, and the answers (none if it didn't answer).
/// Its answers, or why none came (`no_answer`).
pub(super) type Answered = (
    MeshId,
    MeshAddr,
    Vec<(SpaceId, u64)>,
    Result<Vec<bool>, &'static str>,
);

/// Why a Space send got no answer (`spaceCounts`): the connection's error,
/// if it didn't open, else whether the answer timed out.
pub(super) fn no_answer(
    open: Option<&mesh_transport::TransportError>,
    timed_out: bool,
) -> &'static str {
    use mesh_transport::TransportError as E;
    match open {
        Some(E::Timeout) => "connect timed out",
        Some(E::Handshake(_) | E::CertNotOurs) => "handshake failed",
        Some(_) => "couldn't connect",
        None if timed_out => "answer timed out",
        None => "stream broke",
    }
}

/// One piece of Space mail: the reader device and its `mseq`.
pub(super) type MailPut = ([u8; 32], u64);
/// One holder list's sealed Space mail, and which pieces they are.
type HolderPuts = (Vec<Vec<u8>>, Vec<MailPut>);
/// What each piece of Space mail in flight carries, by `MailPut`.
pub(super) type MailSent = HashMap<MailPut, Vec<(SpaceId, u64)>>;

/// Spaces one account may be in (SPEC-spaces *Limits*).
pub(super) const SPACES_PER_ACCOUNT: usize = 10;

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
/// Hello dials under way at once (S14).
pub(super) const HELLO_DIALS: usize = 32;
/// Hello pauses while more connections than this are open (S14): three
/// quarters of transport's 256.
pub(super) const HELLO_ROOM: usize = 192;
/// A hello whose lookup the seed refused for its limit is dialled again
/// after this (no miss: it costs no back-off step).
pub(super) const HELLO_AGAIN: Duration = Duration::from_secs(10);

/// The first wait after a failed Space send or a hello that found nobody
/// (their record may not be at the seed yet, as when both sides were just
/// added); each miss doubles it (S14, 2026-11-16). Neither starts
/// `PEER_RETRY`.
pub(super) const BACK_OFF_FIRST: Duration = Duration::from_secs(10);

/// The wait after `misses` misses in a row, or `None` once it would reach
/// the refresh, which then takes over.
pub(super) fn back_off(misses: u32) -> Option<Duration> {
    let wait = BACK_OFF_FIRST.checked_mul(1u32.checked_shl(misses.checked_sub(1)?)?)?;
    (wait < Duration::from_secs(crate::routing::REFRESH_EVERY)).then_some(wait)
}

/// How a dial came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialled {
    Reached,
    /// No record, or no device answered.
    Away,
    /// The seed refused the lookup for its limit.
    Slowed,
    /// A hello not made: a send's dial to them was under way, and its
    /// answer covers the hello.
    Covered,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PeerDial {
    LookUp,
    LastOnly,
}

/// Peers on the wire (S14): when each was last used, who may be looked up
/// again when, and the hello's queue and pace. Times are passed in.
pub(super) struct PeerWire {
    idle: Duration,
    used: HashMap<[u8; 32], Instant>,
    retry: HashMap<[u8; 32], Instant>,
    hello: VecDeque<MeshId>,
    dialling: usize,
    /// Hellos that found nobody: how many tries each has had, and those
    /// due again.
    hello_tries: HashMap<[u8; 32], u32>,
    hello_later: Vec<(Instant, MeshId)>,
}

impl PeerWire {
    pub(super) fn new(idle: Duration) -> Self {
        Self {
            idle,
            used: HashMap::new(),
            retry: HashMap::new(),
            hello: VecDeque::new(),
            dialling: 0,
            hello_tries: HashMap::new(),
            hello_later: Vec::new(),
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

    /// How a send dials `who`: in full, or, while their retry runs, at
    /// their last address only, which costs the seed nothing.
    pub(super) fn dial_kind(&self, who: &MeshId, now: Instant) -> PeerDial {
        if self.may_look_up(who, now) {
            PeerDial::LookUp
        } else {
            PeerDial::LastOnly
        }
    }

    /// A dial of `who` came back: reached, their retry clears (as when they
    /// reach us); a send's miss starts it; a hello's miss tries again soon.
    /// A lookup the seed refused is no miss: dialled again soon, no try
    /// counted.
    pub(super) fn dialled(&mut self, who: &MeshId, how: Dialled, hello: bool, now: Instant) {
        if hello {
            self.hello_done();
        }
        match (how, hello) {
            (Dialled::Reached, _) => self.heard(who, now),
            (Dialled::Slowed, _) => self.hello_later.push((now + HELLO_AGAIN, *who)),
            (Dialled::Covered, _) => {}
            (Dialled::Away, true) => self.hello_missed(who, now),
            (Dialled::Away, false) => self.missed(who, now),
        }
    }

    /// A lookup or dial of `who` found nobody: not again for `PEER_RETRY`.
    pub(super) fn missed(&mut self, who: &MeshId, now: Instant) {
        self.retry.insert(who.to_bytes(), now + PEER_RETRY);
    }

    /// How many peers are in `PEER_RETRY` (`spaceCounts`).
    pub(super) fn in_retry(&self, now: Instant) -> usize {
        self.retry.values().filter(|until| **until > now).count()
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

    /// The next hellos to dial: `HELLO_DIALS` under way at most, none
    /// while `open` is above `HELLO_ROOM`. Their lookups wait their turn
    /// in the address-get budget's spare (`routing::Gets::spare`).
    pub(super) fn next_hellos(&mut self, _now: Instant, open: usize) -> Vec<MeshId> {
        if open > HELLO_ROOM {
            return Vec::new();
        }
        let take = HELLO_DIALS
            .saturating_sub(self.dialling)
            .min(self.hello.len());
        let out: Vec<MeshId> = self.hello.drain(..take).collect();
        self.dialling += out.len();
        out
    }

    /// A hello dial came back.
    pub(super) fn hello_done(&mut self) {
        self.dialling = self.dialling.saturating_sub(1);
    }

    /// A hello found nobody: queued again after its `back_off`, until the
    /// refresh takes over.
    pub(super) fn hello_missed(&mut self, who: &MeshId, now: Instant) {
        let misses = self.hello_tries.entry(who.to_bytes()).or_insert(0);
        *misses += 1;
        if let Some(wait) = back_off(*misses) {
            self.hello_later.push((now + wait, *who));
        }
    }

    /// Hellos due again by `now`, back in the queue.
    pub(super) fn hellos_due(&mut self, now: Instant) {
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.hello_later)
            .into_iter()
            .partition(|(at, _)| *at <= now);
        self.hello_later = later;
        self.queue_hello(due.into_iter().map(|(_, id)| id));
    }

    pub(super) fn idle(&self) -> Duration {
        self.idle
    }
}

/// Devices tried a round at most (their key lookups wait in the get
/// budget anyway: this keeps one round from filling it).
pub(super) const SOON_PER_ROUND: usize = 16;

/// Space sends to try again soon (your review, 2026-11-15): a batch not
/// taken, or one with no keys for the device yet. Both happen at every join,
/// and the refresh is 30 minutes away.
#[derive(Default)]
pub(super) struct Soon {
    due: HashMap<[u8; 32], (Instant, u32)>,
}

impl Soon {
    /// A send to `device` didn't go: again after its `back_off`. `true`
    /// when the refresh takes over.
    pub(super) fn missed(&mut self, device: [u8; 32], now: Instant) -> bool {
        let (at, misses) = self.due.entry(device).or_insert((now, 0));
        *misses += 1;
        let Some(wait) = back_off(*misses) else {
            self.due.remove(&device);
            return true;
        };
        *at = now + wait;
        false
    }

    /// Devices waiting for a try.
    pub(super) fn len(&self) -> usize {
        self.due.len()
    }

    /// How many tries `device` has had, if it's waiting.
    pub(super) fn tries(&self, device: &[u8; 32]) -> Option<u32> {
        self.due.get(device).map(|(_, tries)| *tries)
    }

    /// It went.
    pub(super) fn done(&mut self, device: &[u8; 32]) {
        self.due.remove(device);
    }

    /// The devices due by `now`, `SOON_PER_ROUND` at most; each then waits
    /// for its answer (`missed` or `done`).
    pub(super) fn take_due(&mut self, now: Instant) -> Vec<[u8; 32]> {
        let mut due: Vec<([u8; 32], Instant)> = (self.due.iter())
            .filter(|(_, (at, _))| *at <= now)
            .map(|(d, (at, _))| (*d, *at))
            .collect();
        due.sort_by_key(|(_, at)| *at);
        due.truncate(SOON_PER_ROUND);
        for (d, _) in &due {
            if let Some((at, _)) = self.due.get_mut(d) {
                // Parked until its answer says `missed` or `done`.
                *at = now + Duration::from_secs(crate::routing::REFRESH_EVERY);
            }
        }
        due.into_iter().map(|(d, _)| d).collect()
    }
}

/// Away devices in S9's order at the limit: the one mailed longest ago (or
/// never) first, so none starves when the seed says `slow-down`.
fn longest_ago_first(away: &mut [(MeshId, [u8; 32])], mailed: &HashMap<[u8; 32], Instant>) {
    away.sort_by_key(|(_, d)| mailed.get(d).copied());
}

/// Space mail's readers: each away device of `people` (not connected, not
/// this one), and the members we know no device of, whose mail record is
/// read so the next round mails them. Without that a peer whose record we
/// read too early (before they'd put one for us) is never mailed.
fn away_devices(
    people: Vec<(MeshId, Vec<[u8; 32]>)>,
    connected: &HashSet<[u8; 32]>,
    me: &[u8; 32],
) -> (Vec<(MeshId, [u8; 32])>, Vec<MeshId>) {
    let (mut away, mut look_up) = (Vec::new(), Vec::new());
    for (id, devices) in people {
        if devices.is_empty() {
            look_up.push(id);
        }
        away.extend(
            (devices.into_iter())
                .filter(|d| !connected.contains(d) && d != me)
                .map(|d| (id, d)),
        );
    }
    (away, look_up)
}

/// The clock in real milliseconds, for Space events' `seq` and `time`
/// (dm D2): two lines a few ms apart then order by time, not by ID.
/// `--clock-offset` moves it, as it moves the rest of the process's clock.
fn now_ms() -> u64 {
    mesh_identity::unix_now_ms()
}

/// How far behind the adder's clock a post's author's may be and its post,
/// in history, still be told as news after our add (ms; S10, dated
/// 2026-11-16). Clocks differ; a post from well before the add isn't told.
pub(super) const JOIN_CLOCK_TOLERANCE: u64 = 2 * 60 * 1000;

/// The stream new members pull a Space's history on (S10).
pub(super) const SPACE_HISTORY: &str = "space-history";
/// Events in one history frame (S10, dm D8's batch).
pub(super) const HISTORY_BATCH: usize = 200;
/// How long either side of a history stream waits for the other.
const HISTORY_WAIT: Duration = Duration::from_secs(10);

/// A history request: one part of one Space (`None`: its changes).
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoryAsk {
    version: u8,
    space: SpaceId,
    part: Option<ChannelId>,
}

/// What the loop is asked by a history stream: who, which part, and where
/// to answer (`None`: not theirs to have).
pub(super) type HistoryAsked = (
    MeshId,
    SpaceId,
    Option<ChannelId>,
    tokio::sync::oneshot::Sender<Option<Vec<Vec<u8>>>>,
);

/// Answers a `space-history` stream: one request per part, each answered
/// newest first in frames of `HISTORY_BATCH` events, then an empty frame.
// ponytail: a part's whole history is read into memory to serve it (about 30 MB at 100,000 events); stream it by segment if Spaces grow past that.
pub(super) async fn serve_history(
    mut stream: mesh_transport::ServiceStream,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    loop {
        let read = mesh_transport::frame::read_frame(&mut stream.recv);
        let Ok(Ok(Some(frame))) = tokio::time::timeout(HISTORY_WAIT, read).await else {
            break;
        };
        let Ok(ask) = postcard::from_bytes::<HistoryAsk>(&frame) else {
            break;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let asked = (stream.peer.id, ask.space, ask.part, tx);
        let _ = back.send(Back::HistoryAsk(Box::new(asked)));
        let events = rx.await.ok().flatten().unwrap_or_default();
        for batch in events.chunks(HISTORY_BATCH) {
            let frame = postcard::to_stdvec(&batch.to_vec()).expect("to memory");
            if mesh_transport::frame::write_frame(&mut stream.send, &frame)
                .await
                .is_err()
            {
                return;
            }
        }
        let end = postcard::to_stdvec(&Vec::<Vec<u8>>::new()).expect("to memory");
        if mesh_transport::frame::write_frame(&mut stream.send, &end)
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = stream.send.finish();
}

/// Space send and receive counts for test 9 (`spaceCounts`, debug builds):
/// numbers only, by reason.
#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Counts {
    /// Sends that didn't go: no keys for the device yet, no answer (no
    /// connection, or it timed out), or a `failed` answer.
    sends_failed: BTreeMap<&'static str, u64>,
    /// Devices whose short retries ran out (the refresh takes over).
    given_up: u64,
    /// Events taken in and dropped: answered `ok`, so never sent again.
    refused: BTreeMap<String, u64>,
    /// Events answered `failed`: the sender keeps them.
    kept: BTreeMap<&'static str, u64>,
    /// `sends_failed` for each person (`spaceCounts <id>`).
    #[serde(skip)]
    per_person: HashMap<[u8; 32], BTreeMap<&'static str, u64>>,
}

impl Counts {
    fn refuse(&mut self, why: &str) {
        *self.refused.entry(why.to_owned()).or_default() += 1;
    }

    fn keep(&mut self, why: &'static str) {
        *self.kept.entry(why).or_default() += 1;
    }
}

/// A history pull in this unlock: which devices were asked, how many
/// events came back refused (then the next member is asked, S10), and
/// whether it's settled.
#[derive(Default)]
pub(super) struct Pull {
    asked: HashSet<[u8; 32]>,
    refused: usize,
    under_way: bool,
    settled: bool,
    /// When the change that added us was made: a post in history after it
    /// is news, told as a live one is.
    joined_at: Option<u64>,
}

/// What `spaceForge` makes this helper do when serving history (the
/// dishonest member of tests 5 and 7). Debug builds only.
#[cfg(debug_assertions)]
#[derive(Default)]
pub(super) struct Forge {
    /// Others' posts served with their text altered (bad signatures).
    alter: bool,
    /// A post of ours forged into a channel, served as if it belonged there.
    inject: Option<(SpaceId, ChannelId, String)>,
    /// Our own checks skipped: what we send is for others to refuse.
    unchecked: bool,
    /// Our next changes in a Space go on a fork from an older version.
    fork: Option<Fork>,
}

/// A forged fork (tests 7): each change follows `after`, the one before,
/// and with `low`, has a low event ID and `seq` so its branch would win
/// any tie it can.
#[cfg(debug_assertions)]
struct Fork {
    space: SpaceId,
    after: mesh_dm::event::EventId,
    seq: u64,
    low: bool,
    made: u8,
}

/// A Space's or channel's 16 bytes as hex, for Mesh-Voice.
/// `meshSpaceNotify`: someone else's post, new to us.
fn notify_post(space: &SpaceId, channel: &ChannelId, author: &Person, text: &str) {
    if let Ok(who) = MeshId::from_bytes(author) {
        emit(
            "meshSpaceNotify",
            json!({ "space": hex16(space), "channel": hex16(channel), "from": who.to_string(), "text": text }),
        );
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse16(text: &str, what: &str) -> Result<[u8; 16], Fail> {
    let bad = || Fail("bad-args", format!("that isn't a {what} ID"));
    if text.len() != 32 {
        return Err(bad());
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn role_text(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

fn locked() -> Fail {
    Fail("locked", "unlock Mesh first".to_owned())
}

fn not_found() -> Fail {
    Fail("not-found", "no such Space here".to_owned())
}

fn not_allowed() -> Fail {
    Fail(
        "not-allowed",
        "your role in this Space doesn't allow that".to_owned(),
    )
}

fn space_fail(e: impl std::fmt::Display) -> Fail {
    Fail("space", e.to_string())
}

/// A Space event's body, read from the wire: from a member, or forwarded by
/// another of our devices with its author and first arrival.
pub(super) struct SpaceIn {
    pub frame: usize,
    pub own: bool,
    pub body: Vec<u8>,
}

impl Helper {
    fn spaces_root(&self) -> std::path::PathBuf {
        self.path.parent().unwrap_or(Path::new(".")).join("dm")
    }

    fn me_sender(&self) -> Result<Sender, Fail> {
        let store = self.store.as_ref().ok_or_else(locked)?;
        Ok(Sender {
            person: store.id().to_bytes(),
            device: store.device_key().public().to_bytes(),
        })
    }

    /// This device's key and certificate, to sign Space events with (S5).
    fn signing(&self) -> Result<(DeviceKey, DeviceCert), Fail> {
        let store = self.store.as_ref().ok_or_else(locked)?;
        let this = store.device_key().public();
        let cert = (store.devices().devices().iter())
            .find(|d| *d.device() == this)
            .cloned()
            .ok_or_else(|| space_fail("this device isn't in its own device list"))?;
        let key = DeviceKey::from_secret_bytes(*store.device_key().secret_bytes());
        Ok((key, cert))
    }

    /// A Space's history, opened the first time it's used (S11).
    fn space_mut(&mut self, space: &SpaceId) -> Result<&mut SpaceHistory, Fail> {
        if !self.space_open.contains_key(space) {
            let me = self.me_sender()?;
            let store = self.store.as_ref().ok_or_else(locked)?;
            let history = SpaceHistory::open(&self.spaces_root(), store.data_key(), me, *space)
                .map_err(space_fail)?;
            self.space_open.insert(*space, history);
        }
        Ok(self.space_open.get_mut(space).expect("opened"))
    }

    fn held_spaces(&self) -> Vec<SpaceId> {
        self.spaces
            .as_ref()
            .map(|l| l.spaces().to_vec())
            .unwrap_or_default()
    }

    /// A Space's version: from its opened history, else its chain alone.
    fn space_version(&self, space: &SpaceId) -> Option<SpaceVersion> {
        if let Some(h) = self.space_open.get(space) {
            return h.version();
        }
        let store = self.store.as_ref()?;
        let chain = SpaceHistory::read_chain(&self.spaces_root(), store.data_key(), space).ok()?;
        chain.version(space)
    }

    /// Works the peers out again from the Spaces we're a member of, and
    /// lets in exactly them and the contacts.
    pub(super) fn refresh_peers(&mut self) {
        let Some(me) = self.store.as_ref().map(|s| s.id().to_bytes()) else {
            return;
        };
        let mut members = Vec::new();
        for space in self.held_spaces() {
            let Some(v) = self.space_version(&space) else {
                continue;
            };
            if !v.state.members.contains_key(&me) {
                continue;
            }
            members.extend(
                v.state
                    .members
                    .keys()
                    .filter_map(|m| MeshId::from_bytes(m).ok()),
            );
        }
        let before: HashSet<[u8; 32]> = (self.store.iter())
            .flat_map(|s| s.peers().iter().map(|c| c.id().to_bytes()))
            .collect();
        if let Some(store) = self.store.as_mut()
            && let Err(e) = store.set_peers(members)
        {
            eprintln!("mesh-node: the Spaces' members didn't fit: {e}");
        }
        self.allow_contacts();
        // A new peer: our records and claims for them go out now, and we say
        // hello, so whichever of us speaks first finds the other (S14).
        let new: Vec<MeshId> = (self.store.iter())
            .flat_map(|s| s.peers().iter().map(|c| c.id()))
            .filter(|id| !before.contains(&id.to_bytes()))
            .collect();
        let now = Instant::now();
        for id in &new {
            self.wire.heard(id, now);
            self.contacts_changed(Some(id));
            // Their keys come only from their records: looked up now, not
            // at the next refresh or the first send that fails.
            self.keys_for(id);
        }
        self.wire.queue_hello(new);
    }

    /// `meshSpaces`: every Space held, with its channels and members.
    pub(super) fn emit_spaces(&self) {
        let me = self.store.as_ref().map(|s| s.id().to_bytes());
        let mut spaces = Vec::new();
        for space in self.held_spaces() {
            let Some(v) = self.space_version(&space) else {
                continue;
            };
            let st = &v.state;
            let mut channels: Vec<_> = st.channels.iter().collect();
            channels.sort_by_key(|(id, c)| (c.category, c.position, **id));
            let channels: Vec<Value> = (channels.into_iter())
                .map(|(id, c)| {
                    json!({
                        "id": hex16(id),
                        "name": c.name,
                        "category": c.category.as_ref().map(hex16),
                        "adminsPost": c.admins_post,
                    })
                })
                .collect();
            let members: Vec<Value> = (st.members.iter())
                .filter_map(|(p, m)| {
                    let id = MeshId::from_bytes(p).ok()?;
                    Some(json!({ "id": id.to_string(), "name": m.display, "role": role_text(m.role) }))
                })
                .collect();
            let role = me.and_then(|me| st.role(&me)).map(role_text);
            let changes = self.space_open.get(&space).map(SpaceHistory::changes_held);
            spaces.push(json!({
                "id": hex16(&space),
                "name": st.name,
                "role": role,
                "channels": channels,
                "members": members,
                "changes": changes,
            }));
        }
        emit("meshSpaces", json!({ "spaces": spaces }));
    }

    /// `meshSpaceMessages`: a channel as it shows.
    fn emit_channel(&mut self, space: &SpaceId, channel: &ChannelId) -> Result<(), Fail> {
        let now = now_ms();
        let history = self.space_mut(space)?;
        let chat = history.channel(channel, now).map_err(space_fail)?;
        let events: Vec<Value> = (chat.messages().iter())
            .filter_map(|m| {
                let from = MeshId::from_bytes(&m.author).ok()?;
                Some(json!({ "id": hex16(&m.id), "from": from.to_string(), "text": m.text, "edited": m.edited }))
            })
            .collect();
        self.space_view = Some((*space, *channel));
        emit(
            "meshSpaceMessages",
            json!({ "space": hex16(space), "channel": hex16(channel), "events": events }),
        );
        Ok(())
    }

    /// Signs and stores a change of ours, if our role allows it, and sends
    /// it to every member.
    fn space_change(&mut self, space: &SpaceId, change: Change) -> Result<(), Fail> {
        let me = self.me_sender()?.person;
        let v = self.space_mut(space)?.version().ok_or_else(not_found)?;
        if !would_count(space, &v.state, &me, &change) && !self.unchecked() {
            return Err(not_allowed());
        }
        let (key, cert) = self.signing()?;
        let body = SpaceBody::Change(SpaceChange {
            after: Some(v.head),
            change,
        });
        let now = now_ms();
        self.space_mut(space)?
            .send(body, &key, &cert, now)
            .map_err(space_fail)?;
        self.space_changed(space);
        Ok(())
    }

    /// The chain may have moved: tell Mesh-Voice, work out the peers, and
    /// pass it on to every member.
    fn space_changed(&mut self, space: &SpaceId) {
        let me = self.store.as_ref().map(|s| s.id().to_bytes());
        let member = self
            .space_version(space)
            .is_some_and(|v| me.is_some_and(|me| v.state.members.contains_key(&me)));
        let held = self.held_spaces().contains(space);
        let joined = member && !held;
        if joined
            && let Some(list) = self.spaces.as_mut()
            && let Err(e) = list.add(*space)
        {
            eprintln!("mesh-node: couldn't save the list of Spaces: {e}");
        }
        self.refresh_peers();
        self.emit_spaces();
        if joined {
            // Just joined: what was said before comes from a member (S10).
            self.space_pull(space);
        }
        self.space_send_all(space);
        if member {
            self.space_redo(space);
        }
    }

    /// Our changes a fork dropped are made again after the winner's newest,
    /// if they still count and change something (S7); a redo dropped again
    /// is redone again, since it's a new change.
    fn space_redo(&mut self, space: &SpaceId) {
        let (Some(v), Some(me)) = (self.space_version(space), self.store.as_ref()) else {
            return;
        };
        let me = me.id().to_bytes();
        let done = self.space_redone.entry(*space).or_default();
        let redo = to_redo(space, &v, &me, done);
        done.extend(redo.iter().map(|(id, _)| *id));
        for (_, change) in redo {
            if let Err(Fail(kind, _)) = self.space_change(space, change) {
                eprintln!("mesh-node: a Space change to redo didn't go: {kind}");
            }
        }
    }

    /// Debug builds' `spaceForge unchecked`: our own checks skipped.
    fn unchecked(&self) -> bool {
        #[cfg(debug_assertions)]
        return self.forge.unchecked;
        #[cfg(not(debug_assertions))]
        false
    }

    /// A change from a command: on the forged fork if one is set (debug
    /// builds), else as `space_change` makes it. Redos never fork.
    fn space_command_change(&mut self, space: &SpaceId, change: Change) -> Result<(), Fail> {
        #[cfg(debug_assertions)]
        if self.forge.fork.as_ref().is_some_and(|f| f.space == *space) {
            return self.space_forked(space, change);
        }
        self.space_change(space, change)
    }

    /// The forged fork's next change, unchecked by us.
    #[cfg(debug_assertions)]
    fn space_forked(&mut self, space: &SpaceId, change: Change) -> Result<(), Fail> {
        let (key, cert) = self.signing()?;
        let device = key.public().to_bytes();
        let fork = self.forge.fork.as_mut().expect("checked");
        fork.made += 1;
        let (after, made, low) = (fork.after, fork.made, fork.low);
        let mut id = [0u8; 16];
        if low {
            id[15] = made;
        } else {
            id = mesh_dm::space::nonce().ok_or_else(|| space_fail("no randomness"))?;
        }
        let seq = if low {
            u64::from(made)
        } else {
            fork.seq + u64::from(made)
        };
        let body = SpaceBody::Change(SpaceChange {
            after: Some(after),
            change,
        });
        let history = self.space_mut(space)?;
        let n = history.next_change_n(&device);
        history
            .send_at(body, &key, &cert, now_ms(), id, seq, n)
            .map_err(space_fail)?;
        if let Some(f) = self.forge.fork.as_mut() {
            f.after = id;
        }
        self.space_changed(space);
        Ok(())
    }

    /// Every member's devices (and our own) get what waits for them in
    /// `space`: on open connections now; the rest are dialled.
    fn space_send_all(&mut self, space: &SpaceId) {
        let Some(v) = self.space_version(space) else {
            return;
        };
        let Some(me) = self.store.as_ref().map(|s| s.id()) else {
            return;
        };
        // Those just removed get the change that removed them too.
        let mut people: Vec<MeshId> = (v.state.members.keys())
            .chain(v.audience.get(&v.head).into_iter().flatten())
            .filter_map(|p| MeshId::from_bytes(p).ok())
            .collect();
        people.push(me);
        people.sort_by_key(|p| p.to_bytes());
        people.dedup();
        for id in people {
            let connected = self
                .net
                .as_ref()
                .map(|n| n.node.connected(&id))
                .unwrap_or_default();
            if connected.is_empty() {
                if id == me {
                    continue;
                }
                if self.is_peer(&id) {
                    self.dial_peer(&id);
                } else {
                    self.dial(&id);
                }
                continue;
            }
            for addr in connected {
                self.space_deliver_to(&id, addr);
            }
        }
    }

    /// What each of `id`'s connected devices hasn't taken, in every Space.
    pub(super) fn space_deliver(&mut self, id: &MeshId) {
        let Some(net) = &self.net else { return };
        for addr in net.node.connected(id) {
            self.space_deliver_to(id, addr);
        }
    }

    /// One device's next batch of Space events, if none is in flight to it.
    fn space_deliver_to(&mut self, id: &MeshId, addr: MeshAddr) {
        let device = *addr.device.as_bytes();
        if self.space_flight.contains(&device) || self.net.is_none() {
            return;
        }
        let Some(me) = self.store.as_ref().map(|s| s.id()) else {
            return;
        };
        let own = me == *id;
        let now = now_ms();
        let mut numbers = Vec::new();
        let mut bodies = Vec::new();
        for space in self.held_spaces() {
            let shared = own
                || self.space_version(&space).is_some_and(|v| {
                    v.state.members.contains_key(&id.to_bytes())
                        || v.audience.values().any(|a| a.contains(&id.to_bytes()))
                });
            if !shared {
                continue;
            }
            let Ok(history) = self.space_mut(&space) else {
                continue;
            };
            history.add_device(device, id.to_bytes());
            let out = match history.outgoing(&device, now) {
                Ok(out) => out,
                Err(e) => {
                    eprintln!("mesh-node: couldn't read a Space's history: {e}");
                    continue;
                }
            };
            for (number, from, received, event) in out {
                if bodies.len() >= e2ee::MAX_FRAMES {
                    break;
                }
                bodies.push(if own {
                    to_own(&space, from, received, &event)
                } else {
                    to_member(&space, &event)
                });
                numbers.push((space, number));
            }
        }
        if bodies.is_empty() {
            return;
        }
        let Some(e2ee) = self.e2ee.as_mut() else {
            return;
        };
        let envelopes = match e2ee.encrypt_device_batch(id, &device, NoteKind::Message, &bodies) {
            Ok(envelopes) => envelopes,
            Err(e) => {
                eprintln!("mesh-node: couldn't encrypt for a device: {e}");
                // No keys for them yet: look, and send once they come; the
                // refresh tries again if their record wasn't there yet.
                self.keys_for(id);
                self.space_retry.insert(device, (*id, addr));
                self.space_missed(id, device, "no keys");
                return;
            }
        };
        self.peer_used(id);
        let Some(net) = &self.net else { return };
        self.space_flight.insert(device);
        let (node, back, id) = (net.node.clone(), self.back.clone(), *id);
        tokio::spawn(async move {
            let frames: Vec<Vec<u8>> = (envelopes.iter())
                .map(|e| [&[dm::ANSWER][..], e].concat())
                .collect();
            let answers = match node.open(&addr, e2ee::SERVICE).await {
                Ok((_, send, recv)) => {
                    let started = Instant::now();
                    let answers = dm::exchange(send, recv, &frames).await;
                    answers.ok_or_else(|| no_answer(None, started.elapsed() >= e2ee::SEND_TIMEOUT))
                }
                Err(e) => Err(no_answer(Some(&e), false)),
            };
            let _ = back.send(Back::SpaceAnswered(Box::new((id, addr, numbers, answers))));
        });
    }

    /// A device answered a batch (or didn't): move its counters, and send
    /// the next batch if it took this one; else try again at the refresh.
    pub(super) fn space_answered(
        &mut self,
        id: MeshId,
        addr: MeshAddr,
        numbers: Vec<(SpaceId, u64)>,
        answers: Result<Vec<bool>, &'static str>,
    ) {
        let device = *addr.device.as_bytes();
        self.space_flight.remove(&device);
        let answers = match answers {
            Ok(answers) => answers,
            Err(why) => {
                self.space_retry.insert(device, (id, addr));
                self.space_missed(&id, device, why);
                return;
            }
        };
        let mut touched = HashSet::new();
        for ((space, number), ok) in numbers.iter().zip(&answers) {
            if let Some(h) = self.space_open.get_mut(space) {
                h.acked(&device, *number, *ok);
                touched.insert(*space);
            }
        }
        for space in touched {
            if let Some(h) = self.space_open.get(&space)
                && let Err(e) = h.save_counters()
            {
                eprintln!("mesh-node: couldn't save a Space's counters: {e}");
            }
        }
        if answers.iter().all(|ok| *ok) {
            self.space_retry.remove(&device);
            self.space_soon.done(&device);
            self.space_deliver_to(&id, addr);
        } else {
            self.space_retry.insert(device, (id, addr));
            self.space_missed(&id, device, "failed answer");
        }
    }

    /// A send to `device` didn't go, for `why`: it's tried again soon.
    fn space_missed(&mut self, who: &MeshId, device: [u8; 32], why: &'static str) {
        *self.space_counts.sends_failed.entry(why).or_default() += 1;
        let theirs = self
            .space_counts
            .per_person
            .entry(who.to_bytes())
            .or_default();
        *theirs.entry(why).or_default() += 1;
        if self.space_soon.missed(device, Instant::now()) {
            self.space_counts.given_up += 1;
        }
    }

    /// The refresh: each device that didn't take everything gets another try.
    pub(super) fn space_retry_all(&mut self) {
        let waiting: Vec<_> = self.space_retry.values().cloned().collect();
        for (id, addr) in waiting {
            self.space_deliver_to(&id, addr);
        }
    }

    /// Takes in the Space events of one stream from `id`'s `device` (S5,
    /// live): each frame's answer is `ok` once stored or dropped, `failed`
    /// when the sender should keep it (a chain we don't have yet).
    pub(super) fn space_take(
        &mut self,
        id: &MeshId,
        device: &[u8; 32],
        events: Vec<SpaceIn>,
        answers: &mut [u8],
    ) {
        let Some(me) = self.store.as_ref().map(|s| s.id()) else {
            return;
        };
        let friend = self
            .store
            .as_ref()
            .is_some_and(|s| s.account().kind(id) == Some(mesh_identity::Kind::Friend));
        let now = now_ms();
        let mut changed = Vec::new();
        let mut refused = 0;
        // A mail batch (S9) is one frame with many events: unpacked here,
        // and answered `failed` if any of them is.
        let mut unpacked = Vec::new();
        for SpaceIn { frame, own, body } in events {
            let read = if body.first() == Some(&SPACE_BATCH) {
                from_batch(&body).map(|events| {
                    (events.into_iter())
                        .map(|(s, e)| (s, None, e))
                        .collect::<Vec<_>>()
                })
            } else if own {
                from_own(&body).map(|(s, from, received, e)| vec![(s, Some((from, received)), e)])
            } else {
                from_member(&body).map(|(s, e)| vec![(s, None, e)])
            };
            match read {
                Ok(read) => unpacked.extend(read.into_iter().map(|r| (frame, own, r))),
                Err(mesh_dm::history::Unread::Newer) => {
                    self.space_counts.keep("newer format");
                    answers[frame] = dm::FAILED
                }
                Err(_) => {
                    self.space_counts.refuse("unreadable");
                    refused += 1
                }
            }
        }
        for (frame, own, (space, synced, event)) in unpacked {
            if event.space != space {
                self.space_counts.refuse("wrong Space");
                refused += 1;
                continue;
            }
            let Some(author) = event.author() else {
                self.space_counts.refuse("no author");
                refused += 1;
                continue;
            };
            let is_change = matches!(event.body, SpaceBody::Change(_));
            let held = self.held_spaces().contains(&space) || self.space_open.contains_key(&space);
            // A Space we don't hold yet comes only from a friend, who adds us
            // (S6), or from our own devices.
            if !held && !(own || (friend && is_change)) {
                // By kind: a change only a friend's add would bring, passed
                // on by a member who isn't one; or a post or other line.
                self.space_counts.refuse(match (&event.body, friend) {
                    (SpaceBody::Change(_), _) => "Space not held: a change from a non-friend",
                    (SpaceBody::Post { .. }, true) => "Space not held: a post from a friend",
                    (SpaceBody::Post { .. }, false) => "Space not held: a post from a non-friend",
                    (_, _) => "Space not held: another line",
                });
                refused += 1;
                continue;
            }
            let (from, received) = match synced {
                Some(synced) => synced,
                None => {
                    // Live: a post comes from its author's own device, which
                    // the handshake proved; a change may be passed on.
                    let direct = author.person == id.to_bytes() && author.device == *device;
                    if !is_change && !direct {
                        self.space_counts.refuse("not from its author");
                        refused += 1;
                        continue;
                    }
                    (author, now)
                }
            };
            if !is_change && !own {
                let Ok(history) = self.space_mut(&space) else {
                    self.space_counts.keep("no store");
                    answers[frame] = dm::FAILED;
                    continue;
                };
                let Some(v) = history.version() else {
                    // Its changes haven't come yet: the sender keeps it.
                    self.space_counts.keep("no changes yet");
                    answers[frame] = dm::FAILED;
                    continue;
                };
                let posting = match &event.body {
                    SpaceBody::Post { channel, .. } | SpaceBody::Edit { channel, .. } => {
                        Some(channel)
                    }
                    _ => None,
                };
                let member = v.state.members.contains_key(&author.person);
                if !member || posting.is_some_and(|c| !v.state.may_post(&author.person, c)) {
                    self.space_counts.keep(if member {
                        "may not post"
                    } else {
                        "not a member yet"
                    });
                    answers[frame] = dm::FAILED;
                    continue;
                }
            }
            let Ok(history) = self.space_mut(&space) else {
                self.space_counts.keep("no store");
                answers[frame] = dm::FAILED;
                continue;
            };
            match history.store(&event, from, received, now) {
                Ok(Taken::Shown) => {
                    if is_change {
                        changed.push(space);
                    } else if let SpaceBody::Post { channel, text, .. } = &event.body
                        && author.person != me.to_bytes()
                    {
                        notify_post(&space, channel, &author.person, text);
                        if self.space_view == Some((space, *channel)) {
                            let _ = self.emit_channel(&space, channel);
                        }
                    }
                }
                Ok(Taken::Refused(why)) => {
                    self.space_counts.refuse(&format!("{why:?}"));
                    refused += 1
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("mesh-node: couldn't store a Space event: {e}");
                    self.space_counts.keep("store error");
                    answers[frame] = dm::FAILED;
                }
            }
        }
        if refused > 0 {
            eprintln!("mesh-node: {refused} Space events refused");
        }
        changed.sort();
        changed.dedup();
        for space in changed {
            self.space_changed(&space);
        }
    }

    /// Space mail (S9): for each reader device with no open connection, the
    /// events waiting for it from every Space we share go in one envelope, at
    /// the refresh and at lock and quit. DMs went first (`mail_out_all`);
    /// the devices mailed longest ago go first here.
    pub(super) fn space_mail_out(&mut self) {
        let (Some(store), Some(net), Some(e2ee)) = (&self.store, &self.net, &self.e2ee) else {
            return;
        };
        if self.cut.is_some() {
            return;
        }
        let me = store.id();
        let my_device = store.device_key().public().to_bytes();
        // Everyone we share a Space with, and ourselves.
        let mut people: Vec<MeshId> = vec![me];
        let held = self.held_spaces();
        let versions: Vec<(SpaceId, SpaceVersion)> = (held.iter())
            .filter_map(|s| Some((*s, self.space_version(s)?)))
            .filter(|(_, v)| v.state.members.contains_key(&me.to_bytes()))
            .collect();
        for (_, v) in &versions {
            people.extend(
                v.state
                    .members
                    .keys()
                    .filter_map(|p| MeshId::from_bytes(p).ok()),
            );
        }
        people.sort_by_key(|p| p.to_bytes());
        people.dedup();
        let connected: HashSet<[u8; 32]> = (people.iter())
            .flat_map(|id| net.node.connected(id))
            .map(|a| *a.device.as_bytes())
            .collect();
        let devices = (people.iter()).map(|id| {
            let devices: Vec<[u8; 32]> = if *id == me {
                (store.devices().devices().iter())
                    .map(|c| c.device().to_bytes())
                    .collect()
            } else {
                e2ee.device_keys(id)
            };
            (*id, devices)
        });
        let (mut away, mut missing) = away_devices(devices.collect(), &connected, &my_device);
        longest_ago_first(&mut away, &self.space_mailed);
        let now = now_ms();
        let anon = net.anon.clone();
        let mut puts: HashMap<Vec<String>, HolderPuts> = HashMap::new();
        for (id, device) in away {
            let holders = self.mail.remembered.holders(&device);
            if holders.is_empty() {
                missing.push(id);
                continue;
            }
            let own = id == me;
            let mut waiting: Vec<(SpaceId, u64, SpaceEvent)> = Vec::new();
            for (space, v) in &versions {
                if !own && !v.state.members.contains_key(&id.to_bytes()) {
                    continue;
                }
                let Ok(history) = self.space_mut(space) else {
                    continue;
                };
                history.add_device(device, id.to_bytes());
                let Ok(out) = history.outgoing(&device, now) else {
                    continue;
                };
                for (number, from, _, event) in out {
                    // Our own devices get by mail only what this one wrote.
                    if self.space_marked.contains(&(device, *space, number))
                        || (own && from.device != my_device)
                    {
                        continue;
                    }
                    waiting.push((*space, number, event));
                }
            }
            if waiting.is_empty() {
                continue;
            }
            let refs: Vec<(SpaceId, &SpaceEvent)> =
                waiting.iter().map(|(s, _, e)| (*s, e)).collect();
            let (body, n) = to_batch(&refs);
            let (Some(store), Some(e2ee)) = (&self.store, self.e2ee.as_mut()) else {
                return;
            };
            let Some(keys) = store.pair_keys(&id) else {
                continue;
            };
            let Ok(reader) = VerifyingKey::from_bytes(&device) else {
                continue;
            };
            let envelope = match e2ee.encrypt_device_batch(&id, &device, NoteKind::Message, &[body])
            {
                Ok(mut envelopes) => envelopes.remove(0),
                Err(e) => {
                    eprintln!("mesh-node: couldn't encrypt Space mail: {e}");
                    continue;
                }
            };
            let mseq = self.mail.next_seq(device);
            let head = MailHead {
                sender: my_device,
                kind: MAIL,
                mseq,
            };
            let at = mail::mail_address(&keys, &id, &reader);
            let Ok(sealed) = seal_mail(&reader, &at, &head, &keys.mail_tag_key(), &envelope) else {
                continue;
            };
            let carried: Vec<(SpaceId, u64)> =
                waiting[..n].iter().map(|(s, num, _)| (*s, *num)).collect();
            for (space, number) in &carried {
                self.space_marked.insert((device, *space, *number));
            }
            self.space_sent.insert((device, mseq), carried);
            self.space_mailed.insert(device, Instant::now());
            let (sealed_puts, sent) = puts.entry(holders).or_default();
            sealed_puts.push(sealed);
            sent.push((device, mseq));
        }
        missing.sort_by_key(|id| id.to_bytes());
        missing.dedup();
        for id in missing {
            self.mail_records_missing(&id);
        }
        if puts.is_empty() {
            return;
        }
        let count: usize = puts.values().map(|(p, _)| p.len()).sum();
        eprintln!("mesh-node: mailed {count} Space batches");
        self.mail.pending.retain(|(h, _)| !h.is_finished());
        for (holders, (sealed, sent)) in puts {
            let (anon, back) = (anon.clone(), self.back.clone());
            let handle = tokio::spawn(async move {
                let took = mail::put_in_order(&anon, &holders, &sealed).await;
                let untaken: Vec<([u8; 32], u64)> = (sent.into_iter().zip(took))
                    .filter(|(_, took)| took.is_none())
                    .map(|(put, _)| put)
                    .collect();
                if !untaken.is_empty() {
                    let _ = back.send(Back::SpaceMailUntaken(untaken));
                }
                mail::Taken::default()
            });
            self.mail.pending.push((handle, Vec::new()));
        }
    }

    /// Space mail no holder took: unmarked, so the refresh mails it again.
    pub(super) fn space_mail_untaken(&mut self, untaken: Vec<([u8; 32], u64)>) {
        for (device, mseq) in untaken {
            for (space, number) in self.space_sent.remove(&(device, mseq)).unwrap_or_default() {
                self.space_marked.remove(&(device, space, number));
            }
        }
    }

    /// A receipt's `ok` for Space mail: the events it carried are taken.
    pub(super) fn space_mail_acked(&mut self, reader: [u8; 32], events: Vec<(SpaceId, u64)>) {
        let mut touched = HashSet::new();
        for (space, number) in events {
            self.space_marked.remove(&(reader, space, number));
            if let Ok(h) = self.space_mut(&space) {
                h.acked(&reader, number, true);
                touched.insert(space);
            }
        }
        for space in touched {
            if let Some(h) = self.space_open.get(&space)
                && let Err(e) = h.save_counters()
            {
                eprintln!("mesh-node: couldn't save a Space's counters: {e}");
            }
        }
    }

    /// Starts a history pull of `space` from one of its members' connected
    /// devices not asked yet (S10): on joining, and again after a pull that
    /// came back with refused events.
    pub(super) fn space_pull(&mut self, space: &SpaceId) {
        let Some(me) = self.store.as_ref().map(|s| s.id()) else {
            return;
        };
        let Some(v) = self.space_version(space) else {
            return;
        };
        let Some(net) = &self.net else { return };
        let pull = self.space_pulls.entry(*space).or_default();
        if pull.under_way || pull.settled {
            return;
        }
        let candidates: Vec<MeshAddr> = (v.state.members.keys())
            .filter_map(|p| MeshId::from_bytes(p).ok())
            .filter(|p| *p != me)
            .flat_map(|p| net.node.connected(&p))
            .collect();
        let Some(addr) =
            (candidates.into_iter()).find(|a| !pull.asked.contains(a.device.as_bytes()))
        else {
            return;
        };
        pull.asked.insert(*addr.device.as_bytes());
        pull.under_way = true;
        let mut parts: Vec<Option<ChannelId>> = vec![None];
        parts.extend(v.state.channels.keys().copied().map(Some));
        let (node, back, space) = (net.node.clone(), self.back.clone(), *space);
        tokio::spawn(async move {
            if let Ok((_, mut send, mut recv)) = node.open(&addr, SPACE_HISTORY).await {
                'parts: for part in parts {
                    let ask = HistoryAsk {
                        version: 1,
                        space,
                        part,
                    };
                    let ask = postcard::to_stdvec(&ask).expect("to memory");
                    if mesh_transport::frame::write_frame(&mut send, &ask)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    loop {
                        let read = mesh_transport::frame::read_frame(&mut recv);
                        let Ok(Ok(Some(frame))) = tokio::time::timeout(HISTORY_WAIT, read).await
                        else {
                            break 'parts;
                        };
                        let Ok(batch) = postcard::from_bytes::<Vec<Vec<u8>>>(&frame) else {
                            break 'parts;
                        };
                        if batch.is_empty() {
                            break;
                        }
                        let _ = back.send(Back::HistoryBatch(Box::new((space, batch))));
                    }
                }
                let _ = send.finish();
            }
            let _ = back.send(Back::HistoryDone(space));
        });
    }

    /// A history request from `id` (S10): only a current member gets a
    /// Space's events, as this device stored them, newest first.
    pub(super) fn history_asked(&mut self, asked: HistoryAsked) {
        let (id, space, part, tx) = asked;
        let member = self
            .space_version(&space)
            .is_some_and(|v| v.state.members.contains_key(&id.to_bytes()));
        if !member {
            let _ = tx.send(None);
            return;
        }
        let events = self
            .space_mut(&space)
            .ok()
            .and_then(|h| h.events(part.as_ref()).ok());
        let Some(mut events) = events else {
            let _ = tx.send(None);
            return;
        };
        events.reverse();
        #[cfg(debug_assertions)]
        self.forge_history(&space, part.as_ref(), &mut events);
        let bytes = (events.iter()).filter_map(|e| e.to_bytes().ok()).collect();
        let _ = tx.send(Some(bytes));
    }

    /// The dishonest member of tests 5 and 7 (debug builds only).
    #[cfg(debug_assertions)]
    fn forge_history(
        &mut self,
        space: &SpaceId,
        part: Option<&ChannelId>,
        events: &mut Vec<SpaceEvent>,
    ) {
        let me = self.store.as_ref().map(|s| s.id().to_bytes());
        if self.forge.alter {
            for e in events.iter_mut() {
                let theirs = e.author().map(|a| a.person) != me;
                if let SpaceBody::Post { text, .. } = &mut e.body
                    && theirs
                {
                    *text = format!("{text} (altered)");
                }
            }
        }
        if let Some((s, channel, text)) = self.forge.inject.clone()
            && s == *space
            && part == Some(&channel)
            && let Ok((key, cert)) = self.signing()
            && let Some(id) = mesh_dm::space::nonce()
        {
            let body = SpaceBody::Post {
                channel,
                text,
                reply_to: None,
                attachments: Vec::new(),
                mentions: Vec::new(),
                everyone: false,
            };
            let now = now_ms();
            let forged = SpaceEvent::signed(*space, id, (now, now, 1_000_000), body, &key, &cert);
            events.insert(0, forged);
        }
    }

    /// One frame of a history pull: each event checked by its certificate,
    /// membership and post right in the chain held (S5), then stored in one
    /// batch.
    pub(super) fn history_batch(&mut self, space: SpaceId, batch: Vec<Vec<u8>>) {
        let now = now_ms();
        let Some(v) = self.space_version(&space) else {
            return;
        };
        let mut good = Vec::new();
        let mut refused = 0;
        for bytes in batch {
            let Ok(e) = SpaceEvent::from_bytes(&bytes) else {
                refused += 1;
                continue;
            };
            match check_history(&e, &v) {
                Ok(author) if e.space == space => good.push((e, author)),
                _ => refused += 1,
            }
        }
        if refused > 0 {
            eprintln!("mesh-node: {refused} history events refused");
            self.space_pulls.entry(space).or_default().refused += refused;
        }
        let changes = good
            .iter()
            .any(|(e, _)| matches!(e.body, SpaceBody::Change(_)));
        let joined_at = self.joined_at(&space);
        let me = self.store.as_ref().map(|s| s.id().to_bytes());
        // Posts written after our add, by others: news, however it came.
        let news: Vec<Option<(ChannelId, Person, String)>> = (good.iter())
            .map(|(e, author)| match &e.body {
                SpaceBody::Post { channel, text, .. }
                    if Some(author.person) != me
                        && joined_at.is_some_and(|t| e.time + JOIN_CLOCK_TOLERANCE >= t) =>
                {
                    Some((*channel, author.person, text.clone()))
                }
                _ => None,
            })
            .collect();
        let Ok(history) = self.space_mut(&space) else {
            return;
        };
        match history.store_batch(good, now, now) {
            Ok(taken) => {
                for (taken, news) in taken.iter().zip(news) {
                    if let (Taken::Shown, Some((channel, author, text))) = (taken, news) {
                        notify_post(&space, &channel, &author, &text);
                    }
                }
            }
            Err(e) => eprintln!("mesh-node: couldn't store a Space's history: {e}"),
        }
        if changes {
            self.refresh_peers();
            self.emit_spaces();
        }
        if let Some((s, channel)) = self.space_view
            && s == space
        {
            let _ = self.emit_channel(&s, &channel);
        }
    }

    /// When the change that added us to `space` was made (its author's
    /// clock), read once per pull.
    fn joined_at(&mut self, space: &SpaceId) -> Option<u64> {
        if let Some(at) = self.space_pulls.get(space).and_then(|p| p.joined_at) {
            return Some(at);
        }
        let me = self.store.as_ref()?.id().to_bytes();
        let add = self.space_version(space)?.state.members.get(&me)?.joined;
        let changes = self.space_mut(space).ok()?.events(None).ok()?;
        let at = changes.iter().find(|e| e.id == add)?.time;
        self.space_pulls.entry(*space).or_default().joined_at = Some(at);
        Some(at)
    }

    /// A pull ended: if anything came back refused, the next member's
    /// device is asked too (now, or when one connects); else it's settled.
    pub(super) fn history_done(&mut self, space: SpaceId) {
        let pull = self.space_pulls.entry(space).or_default();
        pull.under_way = false;
        if pull.refused > 0 {
            pull.refused = 0;
            self.space_pull(&space);
        } else {
            pull.settled = true;
        }
    }

    /// A member connected: a Space whose last pull had refusals asks them.
    pub(super) fn history_again(&mut self, id: &MeshId) {
        let waiting: Vec<SpaceId> = (self.space_pulls.iter())
            .filter(|(_, p)| !p.under_way && !p.settled)
            .map(|(s, _)| *s)
            .collect();
        for space in waiting {
            let member = self
                .space_version(&space)
                .is_some_and(|v| v.state.members.contains_key(&id.to_bytes()));
            if member {
                self.space_pull(&space);
            }
        }
    }

    /// The `space…` commands.
    pub(super) fn space_command(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} needs more arguments")))
        };
        match func {
            "spaceList" => self.emit_spaces(),
            "spaceCreate" => {
                let name = arg(0)?.trim().to_owned();
                let store = self.store.as_ref().ok_or_else(locked)?;
                if self.held_spaces().len() >= SPACES_PER_ACCOUNT {
                    return Err(Fail(
                        "too-many",
                        format!("you can be in at most {SPACES_PER_ACCOUNT} Spaces"),
                    ));
                }
                let display = store.username().to_owned();
                let me = store.id().to_bytes();
                let nonce = mesh_dm::space::nonce().ok_or_else(|| space_fail("no randomness"))?;
                let space = space_id(&me, &nonce);
                let (key, cert) = self.signing()?;
                let body = SpaceBody::Change(SpaceChange {
                    after: None,
                    change: Change::Create {
                        name,
                        nonce,
                        display,
                    },
                });
                let now = now_ms();
                self.space_mut(&space)?
                    .send(body, &key, &cert, now)
                    .map_err(space_fail)?;
                if let Some(list) = self.spaces.as_mut() {
                    list.add(space).map_err(space_fail)?;
                }
                self.space_changed(&space);
            }
            "spaceChannel" => {
                let space = parse16(arg(0)?, "Space")?;
                let nonce = mesh_dm::space::nonce().ok_or_else(|| space_fail("no randomness"))?;
                let admins_post = match arg(2)? {
                    "admins" => true,
                    "everyone" => false,
                    _ => return Err(Fail("bad-args", "who posts: admins or everyone".to_owned())),
                };
                let change = Change::ChannelCreate {
                    nonce,
                    name: arg(1)?.trim().to_owned(),
                    category: None,
                    admins_post,
                };
                self.space_change(&space, change)?;
            }
            "spaceAdd" => {
                let space = parse16(arg(0)?, "Space")?;
                let who = parse_id(arg(1)?)?;
                let store = self.store.as_ref().ok_or_else(locked)?;
                let entry = store.account().get(&who);
                if entry.is_none_or(|e| e.kind != mesh_identity::Kind::Friend) {
                    return Err(Fail(
                        "not-a-friend",
                        "you can add only your friends".to_owned(),
                    ));
                }
                if !store.room_for(&[who]) {
                    return Err(Fail(
                        "too-many",
                        "that would pass the 1,000 people you can reach".to_owned(),
                    ));
                }
                let display = entry
                    .map(|e| {
                        if e.name.is_empty() {
                            e.nick.clone()
                        } else {
                            e.name.clone()
                        }
                    })
                    .unwrap_or_default();
                self.space_change(
                    &space,
                    Change::Add {
                        who: who.to_bytes(),
                        display,
                    },
                )?;
            }
            "spaceLeave" => {
                let space = parse16(arg(0)?, "Space")?;
                self.space_change(&space, Change::Leave)?;
            }
            "spaceKick" | "spaceBan" | "spaceUnban" => {
                let space = parse16(arg(0)?, "Space")?;
                let who = parse_id(arg(1)?)?.to_bytes();
                let change = match func {
                    "spaceKick" => Change::Kick(who),
                    "spaceBan" => Change::Ban(who),
                    _ => Change::Unban(who),
                };
                self.space_command_change(&space, change)?;
            }
            "spaceRename" => {
                let space = parse16(arg(0)?, "Space")?;
                let name = arg(1)?.trim().to_owned();
                let change = match args.get(2) {
                    Some(channel) => Change::ChannelRename {
                        channel: parse16(channel, "channel")?,
                        name,
                    },
                    None => Change::Rename(name),
                };
                self.space_command_change(&space, change)?;
            }
            "spaceDelete" => {
                let space = parse16(arg(0)?, "Space")?;
                let channel = parse16(arg(1)?, "channel")?;
                let target = parse16(arg(2)?, "message")?;
                let me = self.me_sender()?.person;
                let v = self.space_mut(&space)?.version().ok_or_else(not_found)?;
                let now = now_ms();
                let chat = self
                    .space_mut(&space)?
                    .channel(&channel, now)
                    .map_err(space_fail)?;
                let author = (chat.messages().iter())
                    .find(|m| m.id == target)
                    .map(|m| m.author)
                    .ok_or_else(not_found)?;
                // The author's own, or an admin's (S8).
                let admin = v.state.role(&me).is_some_and(|r| r >= Role::Admin);
                if author != me && !admin && !self.unchecked() {
                    return Err(not_allowed());
                }
                let (key, cert) = self.signing()?;
                let body = SpaceBody::Delete { channel, target };
                self.space_mut(&space)?
                    .send(body, &key, &cert, now)
                    .map_err(space_fail)?;
                self.emit_channel(&space, &channel)?;
                self.space_send_all(&space);
            }
            "spaceRole" => {
                let space = parse16(arg(0)?, "Space")?;
                let who = parse_id(arg(1)?)?.to_bytes();
                let change = match arg(2)? {
                    "admin" => Change::MakeAdmin(who),
                    "member" => Change::Demote(who),
                    _ => return Err(Fail("bad-args", "a role: admin or member".to_owned())),
                };
                self.space_command_change(&space, change)?;
            }
            "spaceSend" => {
                let space = parse16(arg(0)?, "Space")?;
                let channel = parse16(arg(1)?, "channel")?;
                let me = self.me_sender()?.person;
                let v = self.space_mut(&space)?.version().ok_or_else(not_found)?;
                if !v.state.may_post(&me, &channel) && !self.unchecked() {
                    return Err(not_allowed());
                }
                let (key, cert) = self.signing()?;
                let body = SpaceBody::Post {
                    channel,
                    text: arg(2)?.to_owned(),
                    reply_to: None,
                    attachments: Vec::new(),
                    mentions: Vec::new(),
                    everyone: false,
                };
                let now = now_ms();
                self.space_mut(&space)?
                    .send(body, &key, &cert, now)
                    .map_err(space_fail)?;
                self.emit_channel(&space, &channel)?;
                self.space_send_all(&space);
            }
            #[cfg(debug_assertions)]
            "spaceCounts" if !args.is_empty() => {
                let who = parse_id(arg(0)?)?;
                let theirs = self.space_counts.per_person.get(&who.to_bytes());
                emit(
                    "meshSpaceCounts",
                    json!({ "sendsFailed": theirs.cloned().unwrap_or_default() }),
                );
            }
            #[cfg(debug_assertions)]
            "spaceCounts" => {
                let me = self.store.as_ref().map(|s| s.id());
                let mut people = HashSet::new();
                for space in self.held_spaces() {
                    if let Some(v) = self.space_version(&space) {
                        people.extend(v.state.members.keys().copied());
                    }
                }
                let no_keys = (people.iter())
                    .filter_map(|p| MeshId::from_bytes(p).ok())
                    .filter(|id| Some(*id) != me)
                    .filter(|id| self.e2ee.as_ref().is_some_and(|e| !e.knows(id)))
                    .count();
                let mut counts = serde_json::to_value(&self.space_counts).unwrap_or_default();
                counts["peersNoKeys"] = json!(no_keys);
                counts["outstanding"] = json!(self.space_retry.len());
                counts["soonWaiting"] = json!(self.space_soon.len());
                counts["peersInRetry"] = json!(self.wire.in_retry(Instant::now()));
                let finds = self
                    .net
                    .as_ref()
                    .map(|n| n.gets.finds())
                    .unwrap_or_default();
                counts["finds"] = json!(finds);
                emit("meshSpaceCounts", counts);
            }
            #[cfg(debug_assertions)]
            "spaceForge" => {
                match arg(0)? {
                    "alter" => self.forge.alter = true,
                    "inject" => {
                        let space = parse16(arg(1)?, "Space")?;
                        let channel = parse16(arg(2)?, "channel")?;
                        self.forge.inject = Some((space, channel, arg(3)?.to_owned()));
                    }
                    "unchecked" => self.forge.unchecked = true,
                    // fork <space> <back> <low|same>: our next changes follow
                    // the change `back` steps behind the newest on the line.
                    "fork" => {
                        let space = parse16(arg(1)?, "Space")?;
                        let back: usize = (arg(2)?.parse())
                            .map_err(|_| Fail("bad-args", "how far back".to_owned()))?;
                        let low = arg(3)? == "low";
                        let history = self.space_mut(&space)?;
                        let v = history.version().ok_or_else(not_found)?;
                        let changes = history.read_changes();
                        let mut at = v.head;
                        for _ in 0..back {
                            at = (changes.get(&at).copied().flatten())
                                .ok_or_else(|| Fail("bad-args", "not that far back".to_owned()))?;
                        }
                        let seq = history.change_seq(&at).unwrap_or(0);
                        self.forge.fork = Some(Fork {
                            space,
                            after: at,
                            seq,
                            low,
                            made: 0,
                        });
                    }
                    _ => self.forge = Forge::default(),
                }
                emit("meshForge", json!({}));
            }
            "spaceOpen" => {
                let space = parse16(arg(0)?, "Space")?;
                let channel = parse16(arg(1)?, "channel")?;
                self.emit_channel(&space, &channel)?;
            }
            _ => return Err(Fail("unknown-fn", format!("unknown command {func}"))),
        }
        Ok(())
    }

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
        self.wire.hellos_due(now);
        let open = net.node.open_connections();
        for id in self.wire.next_hellos(now, open) {
            self.dial_back(&id, true);
        }
        // Failed sends, again before the refresh: their keys looked up if
        // still missing (the answer delivers), and the batch tried.
        for device in self.space_soon.take_due(now) {
            match self.space_retry.get(&device).cloned() {
                Some((id, addr)) => {
                    self.keys_for(&id);
                    let tries = self.space_soon.tries(&device);
                    self.space_deliver_to(&id, addr);
                    // Nothing left to send (and no new miss): done.
                    let sending = self.space_flight.contains(&device);
                    if !sending && self.space_soon.tries(&device) == tries {
                        self.space_soon.done(&device);
                    }
                }
                None => self.space_soon.done(&device),
            }
        }
    }

    /// Dials a peer to send them something (S14), unless they were found
    /// away less than `PEER_RETRY` ago: then it waits for mail or a hello.
    pub(super) fn dial_peer(&self, id: &MeshId) {
        match self.wire.dial_kind(id, Instant::now()) {
            PeerDial::LookUp => self.dial_back(id, false),
            PeerDial::LastOnly => self.dial_last(id),
        }
    }

    /// A dial to `id`'s last known address only, no lookup; a miss changes
    /// nothing (their retry runs on).
    fn dial_last(&self, id: &MeshId) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let Some(target) = Target::of(store, id).filter(|t| t.last.is_some()) else {
            return;
        };
        let (node, back, id) = (net.node.clone(), self.back.clone(), *id);
        tokio::spawn(async move {
            if let Some(Reached { last, list, .. }) = routing::reach_known(&node, &target).await {
                let _ = back.send(Back::Reached(Box::new((id, last, list))));
                let _ = back.send(Back::Hello(id, Dialled::Reached, false));
            }
        });
    }

    /// An ordinary dial, reported back either way: a hello, or a send's.
    fn dial_back(&self, id: &MeshId, hello: bool) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let back = self.back.clone();
        let Some(mut target) = Target::of(store, id) else {
            let _ = back.send(Back::Hello(*id, Dialled::Away, hello));
            return;
        };
        // An address a key lookup (or a connection) gave is tried before
        // looking them up again (S14).
        if target.last.is_none() {
            target.last = self.known_last(id);
        }
        // One dial to a person at a time, hellos too, so each looks them up
        // once: a send's dial while one is under way runs once more if that
        // one misses; a hello while one is under way is left to it.
        if self.dialling.claim(vec![*id]).is_empty() {
            if hello {
                let _ = back.send(Back::Hello(*id, Dialled::Covered, true));
            }
            return;
        }
        let (node, anon) = (net.node.clone(), net.anon.clone());
        // The hello takes only spare gets: sends and key lookups go first.
        let gets = if hello {
            net.gets.spare()
        } else {
            net.gets.for_("send")
        };
        let (seeds, id, dialling) = (self.seeds.clone(), *id, self.dialling.clone());
        tokio::spawn(async move {
            let reached = loop {
                let mut found = Vec::new();
                let reached = routing::reach(
                    node.clone(),
                    &anon,
                    &gets,
                    &seeds,
                    &target,
                    unix_now(),
                    &mut found,
                )
                .await;
                // Their keys too, whether or not a device answered.
                if !found.is_empty() {
                    let _ = back.send(Back::Records(vec![(id, found)]));
                }
                // A send's dial asked again meanwhile, and missed: once more.
                let again = dialling.done(&id);
                if reached.is_ok() && again {
                    dialling.done(&id);
                }
                if reached.is_ok() || !again {
                    break reached;
                }
            };
            let how = match reached {
                Ok(Reached { last, list, .. }) => {
                    let _ = back.send(Back::Reached(Box::new((id, last, list))));
                    Dialled::Reached
                }
                Err(ReachError::Slowed) => Dialled::Slowed,
                Err(_) => Dialled::Away,
            };
            let _ = back.send(Back::Hello(id, how, hello));
        });
    }

    pub(super) fn hello_back(&mut self, id: &MeshId, how: Dialled, hello: bool) {
        self.wire.dialled(id, how, hello, Instant::now());
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

    /// Reaching a peer clears their retry, as their reaching us does; and
    /// while it runs, a send still tries their last address (no lookup).
    #[test]
    fn reaching_a_peer_clears_their_retry() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let [a] = ids(1).try_into().unwrap();
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LookUp);
        wire.dialled(&a, Dialled::Away, false, t0);
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LastOnly);
        // A send's dial to their last address got through.
        wire.dialled(&a, Dialled::Reached, false, t0);
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LookUp);
        // So does a hello that reaches them; one that misses starts no retry.
        wire.dialled(&a, Dialled::Away, false, t0);
        wire.dialled(&a, Dialled::Reached, true, t0);
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LookUp);
        wire.dialled(&a, Dialled::Away, true, t0);
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LookUp);
    }

    /// A lookup the seed refused for its limit isn't "away": no retry
    /// starts, and they're dialled again soon, however often it happens
    /// (it costs no hello try).
    #[test]
    fn a_slowed_lookup_is_not_away() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let [a, b] = ids(2).try_into().unwrap();
        wire.dialled(&a, Dialled::Slowed, false, t0);
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LookUp, "no PEER_RETRY");
        let mut at = t0;
        for _ in 0..5 {
            at += HELLO_AGAIN;
            wire.hellos_due(at);
            let next = wire.next_hellos(at, 0);
            assert_eq!(next, [a], "dialled again soon");
            wire.dialled(&a, Dialled::Slowed, true, at);
        }
        wire.dialled(&b, Dialled::Away, false, t0);
        assert_eq!(wire.dial_kind(&b, t0), PeerDial::LastOnly);
    }

    /// A send that got no answer says why: couldn't connect (and how), the
    /// answer timed out, or the stream broke first.
    #[test]
    fn no_answer_says_why() {
        use mesh_transport::TransportError as E;
        let cases = [
            (Err(E::Unreachable("x".into())), false, "couldn't connect"),
            (Err(E::Timeout), false, "connect timed out"),
            (Err(E::CertNotOurs), false, "handshake failed"),
            (Ok(()), true, "answer timed out"),
            (Ok(()), false, "stream broke"),
        ];
        for (opened, timed_out, want) in cases {
            assert_eq!(no_answer(opened.as_ref().err(), timed_out), want);
        }
    }

    /// A hello to someone a send's dial is already reaching leaves it to
    /// that dial, which looks them up once for both: nothing is queued
    /// again and no retry starts.
    #[test]
    fn a_hello_a_send_is_dialling_is_left_to_it() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let [a] = ids(1).try_into().unwrap();
        wire.queue_hello([a]);
        assert_eq!(wire.next_hellos(t0, 0), [a]);
        wire.dialled(&a, Dialled::Covered, true, t0);
        let later = t0 + Duration::from_secs(3600);
        wire.hellos_due(later);
        assert!(wire.next_hellos(later, 0).is_empty());
        assert_eq!(wire.dial_kind(&a, t0), PeerDial::LookUp);
    }

    /// A failed Space send and a hello that found nobody back off the
    /// same way: 10 s, then doubling each miss, until the next wait would
    /// reach the refresh, which takes over (S14, 2026-11-16: a flat few
    /// tries ended after a minute, and a member who joined later was left
    /// for the refresh).
    #[test]
    fn failed_sends_and_hellos_back_off_up_to_the_refresh() {
        let waits: Vec<u64> = (1..).map_while(back_off).map(|w| w.as_secs()).collect();
        assert_eq!(waits, [10, 20, 40, 80, 160, 320, 640, 1280]);
        assert!(back_off(0).is_none());

        let t0 = Instant::now();
        let mut soon = Soon::default();
        let mut at = t0;
        for wait in &waits {
            assert!(!soon.missed([1; 32], at));
            let wait = Duration::from_secs(*wait);
            assert!(soon.take_due(at + wait - Duration::from_secs(1)).is_empty());
            assert_eq!(soon.take_due(at + wait), [[1; 32]]);
            assert!(
                soon.take_due(at + wait * 2).is_empty(),
                "taken: waits for its answer"
            );
            at += wait;
        }
        assert!(soon.missed([1; 32], at), "the refresh's now");
        assert!(soon.take_due(at + Duration::from_secs(3600)).is_empty());
        soon.missed([2; 32], t0);
        soon.done(&[2; 32]);
        assert!(soon.take_due(t0 + Duration::from_secs(10)).is_empty());
        for d in 0..SOON_PER_ROUND as u8 + 5 {
            soon.missed([d + 10; 32], t0);
        }
        assert_eq!(
            soon.take_due(t0 + Duration::from_secs(10)).len(),
            SOON_PER_ROUND
        );
        assert_eq!(soon.take_due(t0 + Duration::from_secs(10)).len(), 5);

        let mut wire = PeerWire::new(PEER_IDLE);
        let [a] = ids(1).try_into().unwrap();
        wire.queue_hello([a]);
        let mut tried = Vec::new();
        let mut at = t0;
        while at < t0 + Duration::from_secs(3 * 3600) {
            wire.hellos_due(at);
            for id in wire.next_hellos(at, 0) {
                tried.push(at.duration_since(t0).as_secs());
                wire.dialled(&id, Dialled::Away, true, at);
            }
            at += Duration::from_secs(1);
        }
        assert_eq!(tried, [0, 10, 30, 70, 150, 310, 630, 1270, 2550]);
        assert!(wire.may_look_up(&a, at), "a hello's miss starts no retry");
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
        // The pace a minute is the address-get budget's (routing::Gets);
        // none while connections are near the cap.
        assert!(wire.next_hellos(t0, HELLO_ROOM + 1).is_empty());
        assert_eq!(wire.next_hellos(t0, 0).len(), HELLO_DIALS);
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

    #[test]
    fn space_mail_goes_to_the_longest_waiting_first() {
        let t0 = Instant::now();
        let id = RootKey::generate().unwrap().id();
        let mut away = vec![(id, [1; 32]), (id, [2; 32]), (id, [3; 32])];
        let mailed = HashMap::from([
            ([1; 32], t0 + Duration::from_secs(10)),
            ([3; 32], t0 + Duration::from_secs(5)),
        ]);
        longest_ago_first(&mut away, &mailed);
        let order: Vec<u8> = away.iter().map(|(_, d)| d[0]).collect();
        assert_eq!(order, [2, 3, 1], "never mailed, then oldest");
    }

    /// A member we know no device of (their keys and mail record not read
    /// yet) isn't skipped: they're looked up, so the next round mails them.
    #[test]
    fn a_member_with_no_known_device_is_looked_up_not_skipped() {
        let (known, unknown) = (
            RootKey::generate().unwrap().id(),
            RootKey::generate().unwrap().id(),
        );
        let people = vec![(known, vec![[1; 32], [2; 32]]), (unknown, vec![])];
        let connected = HashSet::from([[2; 32]]);
        let (away, look_up) = away_devices(people, &connected, &[9; 32]);
        assert_eq!(away, [(known, [1; 32])]);
        assert_eq!(look_up, [unknown]);
    }
}
