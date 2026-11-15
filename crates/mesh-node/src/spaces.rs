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

use mesh_dm::Sender;
use mesh_dm::chat::Taken;
use mesh_dm::space::SpaceEvent;
use mesh_dm::space::{
    Change, ChannelId, Role, SpaceBody, SpaceChange, SpaceVersion, check_history, space_id,
    would_count,
};
use mesh_dm::space_store::{
    SPACE_BATCH, from_batch, from_member, from_own, to_batch, to_member, to_own,
};
use mesh_e2ee::Kind as NoteKind;
use mesh_e2ee::{MAIL, MailHead, seal_mail};
use mesh_identity::{DeviceCert, DeviceKey, VerifyingKey};
use mesh_transport::MeshAddr;
use serde_json::{Value, json};

use super::{
    Back, Fail, Helper, Reached, Target, dm, e2ee, emit, mail, parse_id, routing, unix_now,
};

/// A device's answer to a batch of Space events: who, which device, each
/// event's Space and number, and the answers (none if it didn't answer).
pub(super) type Answered = (MeshId, MeshAddr, Vec<(SpaceId, u64)>, Option<Vec<bool>>);

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
/// Hello lookups a minute: under the seed's `GETS_PER_DEVICE` (S14).
pub(super) const HELLO_LOOKUPS: u32 = 100;
/// Hello dials under way at once (S14).
pub(super) const HELLO_DIALS: usize = 32;
/// Hello pauses while more connections than this are open (S14): three
/// quarters of transport's 256.
pub(super) const HELLO_ROOM: usize = 192;
const _: () = assert!(HELLO_LOOKUPS < crate::addrs::GETS_PER_DEVICE);
/// A hello that found nobody (their record may not be at the seed yet, as
/// when both sides were just added) is tried again after this, at most
/// `HELLO_TRIES` times in all. It doesn't start `PEER_RETRY`.
pub(super) const HELLO_AGAIN: Duration = Duration::from_secs(10);
pub(super) const HELLO_TRIES: u32 = 3;

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
            minute: None,
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

    /// A hello found nobody: queued again after `HELLO_AGAIN`, up to
    /// `HELLO_TRIES` tries in all.
    pub(super) fn hello_missed(&mut self, who: &MeshId, now: Instant) {
        let tries = self.hello_tries.entry(who.to_bytes()).or_insert(0);
        *tries += 1;
        if *tries < HELLO_TRIES {
            self.hello_later.push((now + HELLO_AGAIN, *who));
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

/// Away devices in S9's order at the limit: the one mailed longest ago (or
/// never) first, so none starves when the seed says `slow-down`.
fn longest_ago_first(away: &mut [(MeshId, [u8; 32])], mailed: &HashMap<[u8; 32], Instant>) {
    away.sort_by_key(|(_, d)| mailed.get(d).copied());
}

/// The clock in real milliseconds, for Space events' `seq` and `time`
/// (dm D2): two lines a few ms apart then order by time, not by ID.
fn now_ms() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |d| d.as_millis() as u64)
}

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

/// A history pull in this unlock: which devices were asked, how many
/// events came back refused (then the next member is asked, S10), and
/// whether it's settled.
#[derive(Default)]
pub(super) struct Pull {
    asked: HashSet<[u8; 32]>,
    refused: usize,
    under_way: bool,
    settled: bool,
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
}

/// A Space's or channel's 16 bytes as hex, for Mesh-Voice.
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
            spaces.push(json!({
                "id": hex16(&space),
                "name": st.name,
                "role": role,
                "channels": channels,
                "members": members,
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
        if !would_count(space, &v.state, &me, &change) {
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
                Ok((_, send, recv)) => dm::exchange(send, recv, &frames).await,
                Err(_) => None,
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
        answers: Option<Vec<bool>>,
    ) {
        let device = *addr.device.as_bytes();
        self.space_flight.remove(&device);
        let Some(answers) = answers else {
            self.space_retry.insert(device, (id, addr));
            return;
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
            self.space_deliver_to(&id, addr);
        } else {
            self.space_retry.insert(device, (id, addr));
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
                Err(mesh_dm::history::Unread::Newer) => answers[frame] = dm::FAILED,
                Err(_) => refused += 1,
            }
        }
        for (frame, own, (space, synced, event)) in unpacked {
            if event.space != space {
                refused += 1;
                continue;
            }
            let Some(author) = event.author() else {
                refused += 1;
                continue;
            };
            let is_change = matches!(event.body, SpaceBody::Change(_));
            let held = self.held_spaces().contains(&space) || self.space_open.contains_key(&space);
            // A Space we don't hold yet comes only from a friend, who adds us
            // (S6), or from our own devices.
            if !held && !(own || (friend && is_change)) {
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
                        refused += 1;
                        continue;
                    }
                    (author, now)
                }
            };
            if !is_change && !own {
                let Ok(history) = self.space_mut(&space) else {
                    answers[frame] = dm::FAILED;
                    continue;
                };
                let Some(v) = history.version() else {
                    // Its changes haven't come yet: the sender keeps it.
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
                    answers[frame] = dm::FAILED;
                    continue;
                }
            }
            let Ok(history) = self.space_mut(&space) else {
                answers[frame] = dm::FAILED;
                continue;
            };
            match history.store(&event, from, received, now) {
                Ok(Taken::Shown) => {
                    if is_change {
                        changed.push(space);
                    } else if let SpaceBody::Post { channel, text, .. } = &event.body
                        && author.person != me.to_bytes()
                        && let Ok(who) = MeshId::from_bytes(&author.person)
                    {
                        emit(
                            "meshSpaceNotify",
                            json!({ "space": hex16(&space), "channel": hex16(channel), "from": who.to_string(), "text": text }),
                        );
                        if self.space_view == Some((space, *channel)) {
                            let _ = self.emit_channel(&space, channel);
                        }
                    }
                }
                Ok(Taken::Refused(_)) => refused += 1,
                Ok(_) => {}
                Err(e) => {
                    eprintln!("mesh-node: couldn't store a Space event: {e}");
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
        let mut away: Vec<(MeshId, [u8; 32])> = Vec::new();
        for id in &people {
            let connected: HashSet<[u8; 32]> = (net.node.connected(id).iter())
                .map(|a| *a.device.as_bytes())
                .collect();
            let devices: Vec<[u8; 32]> = if *id == me {
                (store.devices().devices().iter())
                    .map(|c| c.device().to_bytes())
                    .collect()
            } else {
                e2ee.device_keys(id)
            };
            away.extend(
                (devices.into_iter())
                    .filter(|d| !connected.contains(d) && *d != my_device)
                    .map(|d| (*id, d)),
            );
        }
        longest_ago_first(&mut away, &self.space_mailed);
        let now = now_ms();
        let anon = net.anon.clone();
        let mut puts: HashMap<Vec<String>, HolderPuts> = HashMap::new();
        let mut missing = Vec::new();
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
        let Ok(history) = self.space_mut(&space) else {
            return;
        };
        if let Err(e) = history.store_batch(good, now, now) {
            eprintln!("mesh-node: couldn't store a Space's history: {e}");
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
            "spaceRole" => {
                let space = parse16(arg(0)?, "Space")?;
                let who = parse_id(arg(1)?)?.to_bytes();
                let change = match arg(2)? {
                    "admin" => Change::MakeAdmin(who),
                    "member" => Change::Demote(who),
                    _ => return Err(Fail("bad-args", "a role: admin or member".to_owned())),
                };
                self.space_change(&space, change)?;
            }
            "spaceSend" => {
                let space = parse16(arg(0)?, "Space")?;
                let channel = parse16(arg(1)?, "channel")?;
                let me = self.me_sender()?.person;
                let v = self.space_mut(&space)?.version().ok_or_else(not_found)?;
                if !v.state.may_post(&me, &channel) {
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
            "spaceForge" => {
                match arg(0)? {
                    "alter" => self.forge.alter = true,
                    "inject" => {
                        let space = parse16(arg(1)?, "Space")?;
                        let channel = parse16(arg(2)?, "channel")?;
                        self.forge.inject = Some((space, channel, arg(3)?.to_owned()));
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
    }

    /// Dials a peer to send them something (S14), unless they were found
    /// away less than `PEER_RETRY` ago: then it waits for mail or a hello.
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
        let now = Instant::now();
        if hello {
            self.wire.hello_done();
            // Their record may not be at the seed yet: again soon, a few
            // times; a hello's miss starts no `PEER_RETRY`.
            if !reached {
                self.wire.hello_missed(id, now);
            }
        } else if !reached {
            self.wire.missed(id, now);
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

    #[test]
    fn a_hello_that_finds_nobody_tries_again_a_few_times() {
        let t0 = Instant::now();
        let mut wire = PeerWire::new(PEER_IDLE);
        let [a] = ids(1).try_into().unwrap();
        wire.queue_hello([a]);
        let mut tries = 0;
        let mut at = t0;
        for _ in 0..10 {
            wire.hellos_due(at);
            for id in wire.next_hellos(at, 0) {
                tries += 1;
                wire.hello_done();
                wire.hello_missed(&id, at);
            }
            at += HELLO_AGAIN;
        }
        assert_eq!(tries, HELLO_TRIES, "then it waits for a send or mail");
        assert!(wire.may_look_up(&a, at), "a hello's miss starts no retry");
    }
}
