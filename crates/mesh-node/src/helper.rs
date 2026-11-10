//! Helper mode: identity and network commands over JSON lines on stdio. stdin
//! is read on its own thread and fed into the async loop (SPEC-transport D8),
//! so the node's connections keep running while a command is handled. The
//! node runs while the identity is unlocked (D7).
//!
//! Friend codes go to seeds (SPEC-seed) from a second node with a throwaway
//! identity made at each unlock (D7b), so a seed can't tell whose codes it
//! holds or who looks them up.
//!
//! Routing (SPEC-routing): this device's address records for its contacts go
//! to the seeds from the same throwaway node, and only contacts and our own
//! devices may connect to us (D9).
//!
//! Social (SPEC-social): friend requests go through a live friend code and
//! wait on the seeds until the code's owner collects them; a connection with
//! someone you've added means they added you too, so you're friends.
//!
//! E2ee (SPEC-e2ee): each record carries this device's e2ee field, friends'
//! fields feed the bundle directory, and envelopes travel on the `e2ee`
//! service.
//!
//! Commands are never logged or echoed: passwords travel in them. Each
//! command answers with one event; a failure is a `meshError` with a stable
//! `kind` the UI switches on, the `fn` it answers, and a message to show.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::codes::{Get, Hold};
use crate::e2ee;
use crate::routing::{self, ReachError, Reached, Target};
use crate::{knocks, seed};
use mesh_e2ee::{Conversation, E2ee, E2eeError, Kind as NoteKind, Opened};
use mesh_identity::{
    Account, AddrRecord, CodeError, DEFAULT_EXPIRY, DEFAULT_USES, DeviceCert, DeviceKey,
    DeviceList, FriendCode, HeldCode, IdError, Keystore, KeystoreError, Kind, KnockFrom, LastAddr,
    Link, MAX_DEVICE_NAME, MAX_NOTE, MeshId, RootKey, SafetyNumber, Status as Chosen,
    check_password, is_kept, keyring_status, open_knock, seal_knock,
};
use mesh_transport::{
    Allow, Config, HandshakeError, MeshAddr, Node, Path as NetPath, Pong, Relays, Status,
    TransportError,
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

const KEYSTORE_FILE: &str = "identity.mks";
/// How often the node's state is checked for a change to report.
const NET_POLL: Duration = Duration::from_secs(1);
/// How often codes no seed holds yet are offered again.
const HOLD_RETRY: Duration = Duration::from_secs(600);
/// A failed publish is tried again after this, doubling up to the refresh.
const PUBLISH_RETRY: Duration = Duration::from_secs(60);
/// How often friend requests left with our codes are collected (D7).
const COLLECT_EVERY: Duration = Duration::from_secs(300);
/// Seeds every install knows (SPEC-seed D6); `--seed` replaces them.
// ponytail: the homelab seed is home-only for now (its relay answers on the LAN and Tailscale only); add a VPS seed when friends outside need codes.
pub const SEEDS: &[&str] = &[
    "mesh://node/1191ccb55a67bcf6fe9408ccd615fce54ff8af653b19a4909f4dbdc967e9533e?relay=https://relay.nagbreeklabs.co.za/",
];

#[derive(Deserialize)]
struct Cmd {
    #[serde(rename = "fn")]
    func: String,
    #[serde(default)]
    args: Vec<String>,
}

/// Why a command failed: a stable kind for the UI, and a message to show.
struct Fail(&'static str, String);

impl From<KeystoreError> for Fail {
    fn from(e: KeystoreError) -> Self {
        let kind = match &e {
            KeystoreError::CannotUnlock => "cannot-unlock",
            KeystoreError::NotFound => "not-found",
            KeystoreError::AlreadyExists => "already-exists",
            KeystoreError::NewerVersion => "newer-version",
            KeystoreError::BadUsername => "bad-username",
            KeystoreError::WeakPassword(_) => "weak-password",
            KeystoreError::Device(_) => "device",
            KeystoreError::Code(c) => code_kind(c),
            KeystoreError::Link(_) => "link",
            KeystoreError::OwnId => "self",
            KeystoreError::AlreadyContact => "already-contact",
            KeystoreError::NotAContact => "not-a-contact",
            KeystoreError::BadContactName => "bad-name",
            KeystoreError::TooManyContacts => "too-many-contacts",
            KeystoreError::Blocked => "blocked",
            KeystoreError::TooManyBlocks => "too-many-blocks",
            KeystoreError::NoRequest => "no-request",
            KeystoreError::Keyring(_) => "keyring",
            KeystoreError::Random(_) => "random",
            KeystoreError::Io(_) => "io",
        };
        Fail(kind, e.to_string())
    }
}

impl From<IdError> for Fail {
    fn from(e: IdError) -> Self {
        let kind = match &e {
            IdError::Checksum => "id-checksum",
            IdError::NotMesh => "id-not-mesh",
            IdError::Length => "id-length",
            IdError::MixedCase => "id-mixed-case",
            IdError::NotAKey => "id-not-a-key",
            IdError::NotALink => "not-a-link",
            IdError::Code(c) => code_kind(c),
        };
        Fail(kind, e.to_string())
    }
}

impl From<CodeError> for Fail {
    fn from(e: CodeError) -> Self {
        Fail(code_kind(&e), e.to_string())
    }
}

fn code_kind(e: &CodeError) -> &'static str {
    match e {
        CodeError::Length => "code-length",
        CodeError::BadCharacter(_) => "code-bad-character",
        CodeError::NotAChoice => "code-not-a-choice",
        CodeError::WrongCode => "code-wrong",
        CodeError::BadSignature => "code-bad-signature",
        CodeError::Expired => "code-expired",
        CodeError::Malformed => "code-malformed",
        CodeError::Random => "random",
    }
}

/// One stdout line: the payload travels as a JSON string inside the frame.
fn emit(binding: &str, payload: Value) {
    let line = json!({ "binding": binding, "payload": payload.to_string() });
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Commands read but not yet handled; the reader waits past this.
const QUEUED_COMMANDS: usize = 16;

/// Reads commands until stdin closes (Mesh quit or restarted us).
pub async fn run(dir: &Path, relays: Relays, seeds: Vec<MeshAddr>, record_ttl: u64) {
    let (back, mut answers) = tokio::sync::mpsc::unbounded_channel();
    let mut helper = Helper::new(dir.join(KEYSTORE_FILE), relays, seeds, back);
    helper.record_ttl = record_ttl;
    helper.emit_identity();
    // Kept unlocked: the identity is already open.
    helper.start_net().await;
    let (tx, mut lines) = tokio::sync::mpsc::channel::<String>(QUEUED_COMMANDS);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.blocking_send(line).is_err() {
                break;
            }
        }
    });
    let mut retry = tokio::time::interval(HOLD_RETRY);
    retry.tick().await;
    let mut refresh = tokio::time::interval(Duration::from_secs(
        routing::REFRESH_EVERY.min(record_ttl / 4).max(1),
    ));
    refresh.tick().await;
    let mut collect = tokio::time::interval(COLLECT_EVERY);
    collect.tick().await;
    loop {
        let mut line = tokio::select! {
            line = lines.recv() => match line {
                Some(line) => line,
                None => break,
            },
            Some(back) = answers.recv() => {
                helper.answered(back);
                continue;
            }
            _ = retry.tick() => {
                helper.hold_codes(true);
                continue;
            }
            _ = refresh.tick() => {
                helper.publish();
                helper.dial_contacts();
                helper.sync_own();
                helper.fetch_keys(None);
                continue;
            }
            _ = collect.tick() => {
                helper.collect();
                continue;
            }
        };
        match serde_json::from_str::<Cmd>(line.trim()) {
            Ok(mut cmd) => {
                if let Err(Fail(kind, message)) = helper.handle(&cmd.func, &cmd.args).await {
                    emit(
                        "meshError",
                        json!({ "fn": cmd.func, "kind": kind, "message": message }),
                    );
                }
                // ponytail: best effort; serde_json's own buffers may still hold copies.
                cmd.args.iter_mut().for_each(Zeroize::zeroize);
            }
            Err(_) => {
                eprintln!("mesh-node: unreadable command line");
                emit(
                    "meshError",
                    json!({ "fn": "", "kind": "bad-command", "message": "unreadable command" }),
                );
            }
        }
        line.zeroize();
    }
    helper.stop_net().await;
}

/// Each allowed ID, with the device keys its newest list removed.
type Allowed = HashMap<[u8; 32], HashSet<[u8; 32]>>;

struct Helper {
    path: PathBuf,
    store: Option<Keystore>,
    /// Why "keep unlocked" can't be used here, if it can't.
    keyring: Result<(), String>,
    relays: Relays,
    seeds: Arc<Vec<MeshAddr>>,
    /// The node, while the identity is unlocked and networking started.
    net: Option<Net>,
    /// Codes a seed confirmed holding since the node started.
    held: HashSet<FriendCode>,
    /// Where background seed requests report back to the loop.
    back: tokio::sync::mpsc::UnboundedSender<Back>,
    /// Whose devices may connect: our own identity and our contacts (D9).
    /// Who may connect: our ID and our contacts', each with the devices its
    /// newest known list removed (D9; audit finding 2).
    allowed: Arc<RwLock<Allowed>>,
    /// How long address records last (D4).
    record_ttl: u64,
    /// The wait before the next publish after a failed one.
    publish_retry: Duration,
    /// Each friend's devices and what each last said (D12).
    presence: HashMap<[u8; 32], HashMap<[u8; 32], Presence>>,
    /// Mesh-Voice saw no input for a while (D13: auto-idle, per device).
    idle: bool,
    /// What we show friends now; the presence streams follow it.
    shown: tokio::sync::watch::Sender<Presence>,
    /// This device's e2ee state, while unlocked.
    e2ee: Option<E2ee>,
    /// Where each contact device was last seen (its record's relay, or its
    /// connection), to send it envelopes.
    devices_at: HashMap<[u8; 32], (MeshId, MeshAddr)>,
    /// Envelopes from devices whose keys we haven't seen yet, tried again
    /// when their keys come: who sent them, the device, the frame.
    unopened: Vec<(MeshId, MeshAddr, (u8, Vec<u8>))>,
    /// Envelopes for devices we couldn't reach, until they connect. In memory
    /// only: locking drops them (`mailbox` keeps them later).
    waiting: HashMap<[u8; 32], Vec<Vec<u8>>>,
}

/// What a friend's device shows: on the wire, one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Presence {
    Offline = 0,
    Idle = 1,
    Online = 2,
    Dnd = 3,
}

impl Presence {
    fn from_byte(byte: u8) -> Option<Self> {
        [Self::Offline, Self::Idle, Self::Online, Self::Dnd]
            .into_iter()
            .find(|p| *p as u8 == byte)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Idle => "idle",
            Self::Online => "online",
            Self::Dnd => "dnd",
        }
    }
}

struct Net {
    node: Arc<Node>,
    /// The throwaway identity's node, for seeds only (D7b).
    anon: Arc<Node>,
    /// Reports the node's state as it changes.
    watch: tokio::task::JoinHandle<()>,
    /// Reports who connected to us.
    peers: tokio::task::JoinHandle<()>,
    /// Answers the streams they open.
    streams: tokio::task::JoinHandle<()>,
    /// Every contact's record is on a seed (`meshNet`'s `published`).
    published: Arc<AtomicBool>,
    /// And those records carry our e2ee keys (`meshNet`'s `keys`).
    keys: Arc<AtomicBool>,
    /// Friends' devices we're sending presence to.
    presenting: Arc<std::sync::Mutex<HashSet<[u8; 32]>>>,
}

/// What a background request found out.
enum Back {
    /// Each code, and the best answer any seed gave (`None`: none answered).
    Held(Vec<(FriendCode, Option<Hold>)>),
    /// The home relay changed (or came up): records go out again.
    Relay,
    /// Whether the seeds took every record, and whether they carried keys.
    Published(bool, bool),
    Republish,
    /// Contacts' records, for their e2ee keys.
    Records(Vec<(MeshId, Vec<AddrRecord>)>),
    /// Envelopes another device sent us: who, which device, each frame.
    Envelopes(Box<(MeshId, MeshAddr, e2ee::Frames)>),
    /// A device didn't take these envelopes: they wait for it.
    Unsent(Box<([u8; 32], Vec<Vec<u8>>)>),
    /// A contact answered through this address.
    Reached(Box<(MeshId, Option<LastAddr>, Option<DeviceList>)>),
    /// Someone's device connected to us and passed the handshake.
    Connected(MeshId),
    /// A friend code resolved to its owner and lookup ID, for a request with
    /// this note.
    Resolved(Box<(MeshId, [u8; 16], String)>),
    /// A seed took our request to them.
    Requested(MeshId),
    /// What the seeds hold for our codes.
    Collected(Vec<Collected>),
    /// Another of our devices sent its account state.
    Synced(Box<(Account, MeshAddr)>),
    /// A device of someone's said what it shows, or went quiet.
    /// Their username comes with it (empty from an older helper).
    Presence(Box<(MeshId, [u8; 32], Option<Presence>, String)>),
}

/// One code's requests, from every seed that answered.
struct Collected {
    code: FriendCode,
    lookup_id: [u8; 16],
    /// A seed says the code is still live.
    live: bool,
    /// A seed knows the code and says it's gone.
    gone: bool,
    knocks: Vec<Vec<u8>>,
}

impl Helper {
    fn new(
        path: PathBuf,
        relays: Relays,
        seeds: Vec<MeshAddr>,
        back: tokio::sync::mpsc::UnboundedSender<Back>,
    ) -> Self {
        let mut helper = Self {
            store: None,
            keyring: keyring_status(),
            path,
            relays,
            seeds: Arc::new(seeds),
            net: None,
            held: HashSet::new(),
            back,
            allowed: Arc::default(),
            record_ttl: routing::RECORD_TTL,
            publish_retry: PUBLISH_RETRY,
            presence: HashMap::new(),
            idle: false,
            shown: tokio::sync::watch::Sender::new(Presence::Online),
            e2ee: None,
            devices_at: HashMap::new(),
            waiting: HashMap::new(),
            unopened: Vec::new(),
        };
        if Keystore::exists(&helper.path) {
            match Keystore::open_kept(&helper.path) {
                Ok(store) => helper.store = store,
                Err(e) => eprintln!("mesh-node: couldn't open the kept identity: {e}"),
            }
        }
        helper
    }

    async fn handle(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} is missing argument {}", i + 1)))
        };
        match func {
            "idStatus" => self.emit_identity(),
            "idCreate" => {
                self.store = Some(Keystore::create(
                    &self.path,
                    arg(0)?,
                    arg(1)?,
                    &device_name(),
                )?);
                self.emit_unlocked();
                self.start_net().await;
            }
            "idUnlock" => {
                self.store = Some(Keystore::unlock(&self.path, arg(0)?, arg(1)?)?);
                self.emit_unlocked();
                self.start_net().await;
            }
            "idLock" => {
                self.store = None;
                self.stop_net().await;
                self.emit_identity();
            }
            "idChangePassword" => {
                self.unlocked()?
                    .change_password(arg(0)?, arg(1)?, arg(2)?)?;
                emit("meshDone", json!({ "fn": func }));
            }
            "idKeepUnlocked" => {
                let on = arg(0)? == "true";
                if on && let Err(reason) = &self.keyring {
                    return Err(Fail("keyring", reason.clone()));
                }
                self.unlocked()?.keep_unlocked(on)?;
                self.emit_identity();
            }
            "idCheckPassword" => {
                let verdict = check_password(arg(0)?, arg(1)?);
                emit(
                    "meshPassword",
                    json!({ "ok": verdict.is_ok(), "message": verdict.message() }),
                );
            }
            "idExport" => {
                let store = self.unlocked()?;
                // The backup opens with this identity's username; a different one typed
                // here would leave the user believing it opens with that.
                if mesh_identity::normalize_username(arg(1)?)
                    != mesh_identity::normalize_username(store.username())
                {
                    return Err(Fail(
                        "wrong-username",
                        "that isn't this identity's username".to_owned(),
                    ));
                }
                store.export(Path::new(arg(0)?), arg(2)?)?;
                emit("meshDone", json!({ "fn": func }));
            }
            "idImport" => {
                self.store = Some(Keystore::import(
                    Path::new(arg(0)?),
                    &self.path,
                    arg(1)?,
                    arg(2)?,
                    arg(3)?,
                    &device_name(),
                )?);
                self.emit_unlocked();
                self.start_net().await;
            }
            "codeCreate" => {
                let expiry = match arg(0).unwrap_or("") {
                    "" => DEFAULT_EXPIRY,
                    "never" => None,
                    s => Some(s.parse().map_err(|_| CodeError::NotAChoice)?),
                };
                let uses = match arg(1).unwrap_or("") {
                    "" => DEFAULT_USES,
                    "unlimited" => None,
                    s => Some(s.parse().map_err(|_| CodeError::NotAChoice)?),
                };
                // The held record waits for `seed`, which will hold it; nothing takes it yet.
                let (code, _) = self.unlocked()?.create_code(expiry, uses)?;
                self.emit_codes(Some(code));
                self.hold_codes(true);
            }
            "codeRevoke" => {
                let code = FriendCode::parse(arg(0)?)?;
                let revoke = self.unlocked()?.revoke_code(&code)?;
                self.held.remove(&code);
                self.emit_codes(None);
                if let Some(net) = &self.net {
                    let (anon, seeds) = (net.anon.clone(), self.seeds.clone());
                    tokio::spawn(async move {
                        for addr in seeds.iter() {
                            let _ = seed::ask(&anon, addr, seed::REVOKE, &revoke.to_bytes()).await;
                        }
                    });
                }
            }
            "codeResolve" => {
                let code = parse_code(arg(0)?)?;
                let (anon, seeds) = self.seed_node()?;
                tokio::spawn(async move {
                    match find_code(&anon, &seeds, code).await {
                        Ok((id, _)) => emit(
                            "meshResolved",
                            json!({ "code": code.to_string(), "id": id.to_string(), "link": id.link() }),
                        ),
                        Err((kind, message)) => emit_fail("codeResolve", kind, message),
                    }
                });
            }
            "friendRequest" => {
                let code = parse_code(arg(0)?)?;
                let note = arg(1).unwrap_or("").trim().to_owned();
                if note.len() > MAX_NOTE {
                    return Err(Fail(
                        "bad-note",
                        format!("a note is at most {MAX_NOTE} bytes"),
                    ));
                }
                let (anon, seeds) = self.seed_node()?;
                let back = self.back.clone();
                tokio::spawn(async move {
                    match find_code(&anon, &seeds, code).await {
                        Ok((id, lookup_id)) => {
                            let _ = back.send(Back::Resolved(Box::new((id, lookup_id, note))));
                        }
                        Err((kind, message)) => emit_fail("friendRequest", kind, message),
                    }
                });
            }
            "friendAdd" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.add_contact(id, arg(1).unwrap_or(""))?;
                self.contacts_changed();
                self.dial(&id);
                self.changed(Some(func));
            }
            "friendAccept" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.accept(&id)?;
                self.contacts_changed();
                // Their device lets us in (they asked), so this connection
                // makes us friends on their side too (D8, D9).
                self.dial(&id);
                self.changed(Some(func));
            }
            "friendDecline" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.decline(&id)?;
                self.changed(Some(func));
            }
            "friendCancel" | "friendRemove" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.remove_contact(&id)?;
                self.cut_off(&id);
                self.changed(Some(func));
            }
            "friendRename" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.rename_contact(&id, arg(1)?)?;
                self.changed(Some(func));
            }
            "friendVerify" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.verify(&id, arg(1)? == "true")?;
                self.changed(Some(func));
            }
            "block" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.block(&id)?;
                self.cut_off(&id);
                self.changed(Some(func));
            }
            "unblock" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.unblock(&id)?;
                self.changed(Some(func));
            }
            "statusSet" => {
                let status = Chosen::parse(arg(0)?)
                    .ok_or_else(|| Fail("bad-args", "online, idle, dnd or invisible".to_owned()))?;
                self.unlocked()?.set_status(status)?;
                self.update_shown();
                self.changed(Some(func));
            }
            "activity" => {
                self.idle = match arg(0)? {
                    "idle" => true,
                    "active" => false,
                    _ => return Err(Fail("bad-args", "active or idle".to_owned())),
                };
                self.update_shown();
                self.unlocked()?;
                self.emit_social(Some(func));
            }
            "socialList" => {
                self.unlocked()?;
                self.emit_social(Some(func));
            }
            "codeList" => {
                self.unlocked()?;
                self.emit_codes(None);
            }
            "safetyNumber" => {
                let Link::Id(other) = Link::parse(arg(0)?)? else {
                    return Err(Fail(
                        "not-an-id",
                        "that's a friend code, not an ID".to_owned(),
                    ));
                };
                let number = SafetyNumber::new(&self.unlocked()?.id(), &other);
                emit(
                    "meshSafety",
                    json!({
                        "id": other.to_string(),
                        "number": number.to_string(),
                        "qr": number.qr_payload(),
                    }),
                );
            }
            "parseId" => {
                let parsed = match Link::parse(arg(0)?)? {
                    Link::Id(id) => {
                        json!({ "kind": "id", "id": id.to_string(), "link": id.link() })
                    }
                    Link::Code(code) => {
                        json!({ "kind": "code", "code": code.to_string(), "link": code.link() })
                    }
                };
                emit("meshParsed", parsed);
            }
            "netPingId" => {
                let id = parse_id(arg(0)?)?;
                let target = Target::of(self.unlocked()?, &id).ok_or_else(|| {
                    Fail("not-a-contact", "add them as a friend first".to_owned())
                })?;
                let (node, anon) = (self.node()?, self.anon()?);
                if !node.status().online {
                    return Err(Fail("offline", "not connected to a relay yet".to_owned()));
                }
                let (seeds, back) = (self.seeds.clone(), self.back.clone());
                tokio::spawn(async move {
                    match routing::reach(node, &anon, &seeds, target, unix_now()).await {
                        Ok(Reached { pong, last, list }) => {
                            emit_pong(&pong);
                            let _ = back.send(Back::Reached(Box::new((id, last, list))));
                        }
                        Err(e) => {
                            let (kind, message) = match e {
                                ReachError::Unreachable => {
                                    ("unreachable", "couldn't reach any of their devices")
                                }
                                ReachError::RevokedDevice => {
                                    ("revoked-device", "only devices they've removed answered")
                                }
                            };
                            emit(
                                "meshError",
                                json!({ "fn": "netPingId", "kind": kind, "message": message }),
                            );
                        }
                    }
                });
            }
            "e2eeNote" => self.note(arg(0)?, arg(1)?, args.get(2).map(String::as_str))?,
            "deviceRemove" => self.remove_device(arg(0)?)?,
            "netStatus" => self.emit_net(),
            "netTicket" => {
                let ticket = self
                    .node()?
                    .addr()
                    .ticket()
                    .map_err(|_| Fail("offline", "not connected to a relay yet".to_owned()))?;
                emit("meshTicket", json!({ "ticket": ticket }));
            }
            "netPing" => {
                let addr = MeshAddr::from_ticket(arg(0)?.trim())
                    .map_err(|e| Fail("bad-ticket", e.to_string()))?;
                let node = self.node()?;
                if !node.status().online {
                    return Err(Fail("offline", "not connected to a relay yet".to_owned()));
                }
                // Up to 20 s: answered when done, while other commands carry on.
                let back = self.back.clone();
                tokio::spawn(async move {
                    match node.ping(&addr).await {
                        Ok(pong) => {
                            emit_pong(&pong);
                            let _ = back.send(Back::Connected(pong.peer.id));
                        }
                        Err(e) => {
                            let Fail(kind, message) = ping_fail(e);
                            emit(
                                "meshError",
                                json!({ "fn": "netPing", "kind": kind, "message": message }),
                            );
                        }
                    }
                });
            }
            _ => {
                eprintln!("mesh-node: unknown command {func}");
                return Err(Fail("unknown-fn", format!("unknown command {func}")));
            }
        }
        Ok(())
    }

    fn unlocked(&mut self) -> Result<&mut Keystore, Fail> {
        self.store
            .as_mut()
            .ok_or_else(|| Fail("locked", "unlock Mesh first".to_owned()))
    }

    /// The running node; the identity must be unlocked.
    fn node(&mut self) -> Result<Arc<Node>, Fail> {
        self.unlocked()?;
        self.net
            .as_ref()
            .map(|n| n.node.clone())
            .ok_or_else(|| Fail("offline", "networking didn't start".to_owned()))
    }

    fn anon(&self) -> Result<Arc<Node>, Fail> {
        self.net
            .as_ref()
            .map(|n| n.anon.clone())
            .ok_or_else(|| Fail("offline", "networking didn't start".to_owned()))
    }

    /// The throwaway node and the seeds, for a request to them.
    fn seed_node(&mut self) -> Result<(Arc<Node>, Arc<Vec<MeshAddr>>), Fail> {
        let anon = self.node().and(self.anon())?;
        if self.seeds.is_empty() {
            return Err(Fail("offline", "no seed to ask".to_owned()));
        }
        Ok((anon, self.seeds.clone()))
    }

    /// The contacts changed: let in exactly them, and leave records for them.
    fn contacts_changed(&mut self) {
        self.allow_contacts();
        self.publish();
    }

    /// They're no longer let in; their records lapse (routing D4).
    fn cut_off(&self, id: &MeshId) {
        self.allow_contacts();
        if let Some(net) = &self.net {
            net.node.disconnect(id);
        }
    }

    /// Tries every friend and `outgoing` contact in the background (D12): a
    /// connection with one we asked makes them a friend.
    fn dial_contacts(&self) {
        let Some(store) = &self.store else { return };
        for contact in store.contacts() {
            self.dial(&contact.id());
        }
    }

    fn dial(&self, id: &MeshId) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let Some(target) = Target::of(store, id) else {
            return;
        };
        let (node, anon) = (net.node.clone(), net.anon.clone());
        let (seeds, back, id) = (self.seeds.clone(), self.back.clone(), *id);
        tokio::spawn(async move {
            if let Ok(Reached { last, list, .. }) =
                routing::reach(node, &anon, &seeds, target, unix_now()).await
            {
                let _ = back.send(Back::Reached(Box::new((id, last, list))));
            }
        });
    }

    /// Collects the friend requests left with our codes, in the background.
    fn collect(&self) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if self.seeds.is_empty() || store.collect_codes().is_empty() {
            return;
        }
        let codes: Vec<_> = store
            .collect_codes()
            .iter()
            .map(|c| (c.code, store.code_revoke(&c.code)))
            .collect();
        let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
        tokio::spawn(async move {
            let requests: Vec<Vec<u8>> = codes.iter().map(|(_, r)| r.to_bytes().to_vec()).collect();
            let mut found: Vec<Collected> = codes
                .iter()
                .map(|(code, revoke)| Collected {
                    code: *code,
                    lookup_id: revoke.lookup_id(),
                    live: false,
                    gone: false,
                    knocks: Vec::new(),
                })
                .collect();
            for addr in seeds.iter() {
                let Ok(answers) = seed::ask_many(&anon, addr, seed::KNOCK_GET, &requests).await
                else {
                    continue;
                };
                for (got, answer) in found.iter_mut().zip(answers) {
                    if let Some(knocks::Get::Found { live, knocks }) =
                        knocks::Get::from_bytes(&answer)
                    {
                        got.live |= live;
                        got.gone |= !live;
                        got.knocks.extend(knocks);
                    }
                }
            }
            let _ = back.send(Back::Collected(found));
        });
    }

    /// Seals our request to the owner of a code we resolved, and puts it on
    /// every seed.
    fn request(&mut self, id: MeshId, lookup_id: [u8; 16], note: &str) -> Result<(), Fail> {
        let store = self.unlocked()?;
        if id == store.id() {
            return Err(Fail("self", "that's your own code".to_owned()));
        }
        match store.account().kind(&id) {
            Some(Kind::Blocked) => {
                return Err(Fail(
                    "blocked",
                    "you've blocked them; unblock them first".to_owned(),
                ));
            }
            Some(Kind::Friend) => {
                return Err(Fail("already-friend", "you're already friends".to_owned()));
            }
            _ => {}
        }
        let from = KnockFrom {
            root: store.root_key(),
            device: store.device_key(),
            devices: store.devices(),
            name: store.username(),
        };
        let knock = seal_knock(&from, &id, &lookup_id, note, unix_now())
            .map_err(|e| Fail("bad-request", e.to_string()))?;
        let (anon, seeds) = self.seed_node()?;
        let back = self.back.clone();
        tokio::spawn(async move {
            let mut best = None;
            for addr in seeds.iter() {
                let answer =
                    seed::ask_many(&anon, addr, seed::KNOCK_PUT, std::slice::from_ref(&knock))
                        .await
                        .ok()
                        .and_then(|a| knocks::Put::from_byte(*a.first()?.first()?));
                best = match (best, answer) {
                    (_, Some(knocks::Put::Ok)) | (Some(knocks::Put::Ok), _) => {
                        Some(knocks::Put::Ok)
                    }
                    (best, answer) => answer.or(best),
                };
            }
            match best {
                Some(knocks::Put::Ok) => drop(back.send(Back::Requested(id))),
                Some(knocks::Put::Gone) => emit_fail(
                    "friendRequest",
                    "not-found",
                    "no such code: it may have expired, been used or been revoked",
                ),
                Some(knocks::Put::SlowDown) => emit_fail(
                    "friendRequest",
                    "slow-down",
                    "too many requests; wait a while",
                ),
                _ => emit_fail("friendRequest", "offline", "couldn't reach a seed"),
            }
        });
        Ok(())
    }

    /// Offers this device's codes to the seeds in the background: all of them,
    /// or only those no seed has confirmed yet.
    fn hold_codes(&self, only_missing: bool) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if self.seeds.is_empty() {
            return;
        }
        let codes: Vec<(FriendCode, HeldCode)> = store
            .codes()
            .iter()
            .filter(|c| !only_missing || !self.held.contains(&c.code))
            .filter_map(|c| Some((c.code, store.held_record(c).ok()?)))
            .collect();
        if codes.is_empty() {
            return;
        }
        let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
        tokio::spawn(async move {
            let mut answers = Vec::new();
            for (code, held) in codes {
                answers.push((code, hold(&anon, &seeds, &held).await));
            }
            let _ = back.send(Back::Held(answers));
        });
    }

    /// A background request's answer, back on the loop.
    fn answered(&mut self, back: Back) {
        let answers = match back {
            Back::Held(answers) => answers,
            Back::Relay => {
                self.publish();
                self.sync_own();
                self.fetch_keys(None);
                return self.dial_contacts();
            }
            Back::Records(found) => {
                self.own_lists(&found);
                let Some(e2ee) = self.e2ee.as_mut() else {
                    return;
                };
                let mut learned = Vec::new();
                for (id, records) in &found {
                    if e2ee::learn(e2ee, id, records) {
                        learned.push(*id);
                    }
                    for r in records {
                        let device = *r.device.as_bytes();
                        if let Some(addr) = MeshAddr::from_parts(&device, &r.relay) {
                            self.devices_at.insert(device, (*id, addr));
                        }
                    }
                }
                // What came before their keys can open now.
                let unopened = std::mem::take(&mut self.unopened);
                for (id, from, frame) in unopened {
                    if learned.contains(&id) {
                        self.envelopes(id, from, vec![frame]);
                    } else {
                        self.unopened.push((id, from, frame));
                    }
                }
                return;
            }
            Back::Envelopes(got) => {
                let (id, from, frames) = *got;
                return self.envelopes(id, from, frames);
            }
            Back::Unsent(unsent) => {
                let (device, envelopes) = *unsent;
                if self.net.is_some() {
                    self.waiting.entry(device).or_default().extend(envelopes);
                }
                return;
            }
            Back::Republish => return self.publish(),
            Back::Published(ok, keys) => {
                if let Some(net) = &self.net {
                    net.published.store(ok, Ordering::Relaxed);
                    net.keys.store(ok && keys, Ordering::Relaxed);
                }
                if ok {
                    self.publish_retry = PUBLISH_RETRY;
                } else if self.net.is_some() {
                    let (wait, back) = (self.publish_retry, self.back.clone());
                    let most = Duration::from_secs(routing::REFRESH_EVERY);
                    self.publish_retry = (wait * 2).min(most);
                    tokio::spawn(async move {
                        tokio::time::sleep(wait).await;
                        let _ = back.send(Back::Republish);
                    });
                }
                return;
            }
            Back::Reached(reached) => {
                let (id, last, list) = *reached;
                if let Some(store) = self.store.as_mut()
                    && let Some(last) = last
                    && let Err(e) = store.contact_reached(&id, last, list.as_ref())
                {
                    eprintln!("mesh-node: couldn't save a contact's address: {e}");
                }
                if list.is_some() {
                    // A newer list of theirs may have removed a device.
                    self.allow_contacts();
                }
                let promoted = self.connected(&id);
                self.present_to(&id);
                self.keys_for(&id);
                self.send_waiting(&id);
                if promoted {
                    return self.changed(None);
                }
                return self.emit_social(None);
            }
            Back::Connected(id) => {
                self.send_waiting(&id);
                if self.store.as_ref().is_some_and(|s| s.id() == id) {
                    // Another of our devices: it sends its state; we answer
                    // with ours if it's missing something (`Back::Synced`).
                    return;
                }
                if self.connected(&id) {
                    self.changed(None);
                }
                self.keys_for(&id);
                return self.present_to(&id);
            }
            Back::Synced(synced) => {
                let (theirs, from) = *synced;
                let own = self.store.as_ref().map(Keystore::id);
                if let Some(own) = own {
                    self.send_waiting(&own);
                }
                return self.synced(&theirs, &from);
            }
            Back::Presence(heard) => {
                let (id, device, heard, name) = *heard;
                if heard.is_some() {
                    self.send_waiting(&id);
                }
                return self.presence_heard(id, device, heard, &name);
            }
            Back::Resolved(resolved) => {
                let (id, lookup_id, note) = *resolved;
                if let Err(Fail(kind, message)) = self.request(id, lookup_id, &note) {
                    emit_fail("friendRequest", kind, &message);
                }
                return;
            }
            Back::Requested(id) => {
                let Some(store) = self.store.as_mut() else {
                    return;
                };
                match store.add_contact(id, "") {
                    // A resend, or they'd asked us (then this accepted).
                    Ok(()) | Err(KeystoreError::AlreadyContact) => {}
                    Err(e) => {
                        let Fail(kind, message) = e.into();
                        return emit_fail("friendRequest", kind, &message);
                    }
                }
                self.contacts_changed();
                self.dial(&id);
                return self.changed(Some("friendRequest"));
            }
            Back::Collected(found) => return self.collected(found),
        };
        let mut gone = false;
        for (code, answer) in answers {
            match answer {
                Some(Hold::Ok) => {
                    self.held.insert(code);
                }
                // Used up or revoked: it leaves the list once the requests
                // left with it are collected (D7).
                Some(Hold::Gone) => {
                    self.held.remove(&code);
                    gone = true;
                }
                Some(Hold::Taken) => eprintln!("mesh-node: a friend code collided; make another"),
                _ => {}
            }
        }
        self.emit_codes(None);
        if gone {
            self.collect();
        }
    }

    /// Takes in the requests left with our codes, and drops codes that are
    /// gone once their requests are in.
    fn collected(&mut self, found: Vec<Collected>) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let (now, mut changed, mut dropped) = (unix_now(), false, false);
        for got in found {
            for bytes in &got.knocks {
                // Anything that doesn't open is junk: the seed can't make one.
                let Ok(knock) = open_knock(store.root_key(), &got.lookup_id, bytes, now) else {
                    continue;
                };
                match store.knocked(&knock) {
                    Ok(c) => changed |= c,
                    Err(e) => eprintln!("mesh-node: couldn't save a friend request: {e}"),
                }
            }
            if got.gone && !got.live {
                dropped = true;
                if let Err(e) = store.drop_code(&got.code) {
                    eprintln!("mesh-node: couldn't drop a used code: {e}");
                }
            }
        }
        if changed {
            // A request from someone we'd asked made them a friend.
            self.contacts_changed();
            self.dial_contacts();
            self.changed(None);
        }
        if dropped {
            self.emit_codes(None);
        }
    }

    /// A friend's best device (D13): DND beats online, which beats idle.
    fn presence_of(&self, id: &MeshId) -> Presence {
        self.presence
            .get(&id.to_bytes())
            .and_then(|devices| devices.values().max().copied())
            .unwrap_or(Presence::Offline)
    }

    /// What friends see of this device: invisible shows as offline, but we
    /// stay reachable (D13).
    fn update_shown(&self) {
        let Some(store) = &self.store else { return };
        let shown = match store.account().status() {
            Chosen::Invisible => Presence::Offline,
            Chosen::Dnd => Presence::Dnd,
            Chosen::Idle => Presence::Idle,
            Chosen::Online if self.idle => Presence::Idle,
            Chosen::Online => Presence::Online,
        };
        self.shown
            .send_if_modified(|p| std::mem::replace(p, shown) != shown);
    }

    /// Starts sending our presence to each of a friend's connected devices
    /// that doesn't have it yet (D12).
    fn present_to(&self, id: &MeshId) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if store.account().kind(id) != Some(Kind::Friend) {
            return;
        }
        for addr in net.node.connected(id) {
            let key = *addr.device.as_bytes();
            if !lock(&net.presenting).insert(key) {
                continue;
            }
            let (node, presenting) = (net.node.clone(), net.presenting.clone());
            let mut shown = self.shown.subscribe();
            let name = store.username().as_bytes().to_vec();
            tokio::spawn(async move {
                let sent = async {
                    let (_, mut send, _recv) = node.open(&addr, PRESENCE).await.ok()?;
                    loop {
                        // The status byte, then our username (SPEC-social D12).
                        let now = [&[*shown.borrow_and_update() as u8][..], &name].concat();
                        mesh_transport::frame::write_frame(&mut send, &now)
                            .await
                            .ok()?;
                        tokio::select! {
                            changed = shown.changed() => changed.ok()?,
                            () = tokio::time::sleep(HEARTBEAT) => {}
                        }
                    }
                };
                let _: Option<()> = sent.await;
                lock(&presenting).remove(&key);
            });
        }
    }

    /// A friend's device said what it shows, or went quiet (`None`).
    fn presence_heard(
        &mut self,
        id: MeshId,
        device: [u8; 32],
        heard: Option<Presence>,
        name: &str,
    ) {
        // Their stream came over a connection that passed the handshake, which
        // may get here before our own dial's answer does.
        if heard.is_some() && self.connected(&id) {
            self.changed(None);
        }
        let friend = self
            .store
            .as_ref()
            .is_some_and(|s| s.account().kind(&id) == Some(Kind::Friend));
        let renamed = match self.store.as_mut() {
            Some(store) if friend && heard.is_some() => match store.heard_name(&id, name) {
                Ok(renamed) => renamed,
                Err(e) => {
                    eprintln!("mesh-node: couldn't save a friend's name: {e}");
                    false
                }
            },
            _ => false,
        };
        let before = self.presence_of(&id);
        let devices = self.presence.entry(id.to_bytes()).or_default();
        match heard {
            Some(p) if friend => drop(devices.insert(device, p)),
            _ => drop(devices.remove(&device)),
        }
        // One `meshSocial` for both: a rename also goes to our other devices.
        if renamed {
            self.changed(None);
        } else if self.presence_of(&id) != before {
            self.emit_social(None);
        }
        // They hear from us too, whoever connected first.
        if heard.is_some() {
            self.present_to(&id);
        }
    }

    /// The account state changed here: tell Mesh-Voice, and our other
    /// devices that are connected (D11).
    fn changed(&self, answers: Option<&str>) {
        self.emit_social(answers);
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        for addr in net.node.connected(&store.id()) {
            push_account(net.node.clone(), addr, store.account().to_bytes());
        }
    }

    /// Another of our devices sent its account state: take in what's newer,
    /// and send ours back if it's missing something.
    fn synced(&mut self, theirs: &Account, from: &MeshAddr) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let merged = match store.merge_account(theirs) {
            Ok(merged) => merged,
            Err(e) => return eprintln!("mesh-node: couldn't save a synced change: {e}"),
        };
        let ours = store.account().clone();
        if merged {
            self.contacts_changed();
            // Whoever is no longer a contact (removed, blocked elsewhere) goes.
            if let Some(net) = &self.net {
                for e in ours.entries() {
                    if !matches!(e.kind, Kind::Outgoing | Kind::Friend) {
                        net.node.disconnect(&e.id());
                    }
                }
            }
            self.dial_contacts();
            // Our chosen status may have changed on the other device.
            self.update_shown();
            self.changed(None);
        }
        if ours != *theirs
            && let Some(net) = &self.net
        {
            push_account(net.node.clone(), from.clone(), ours.to_bytes());
        }
    }

    /// Finds our other devices through the seeds and sends each our account
    /// state; they answer with theirs if it's newer (D11).
    fn sync_own(&self) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let Some(own) = Target::own(store) else {
            return;
        };
        let this = *store.device_key().public().as_bytes();
        let account = store.account().to_bytes();
        let (node, anon, seeds) = (net.node.clone(), net.anon.clone(), self.seeds.clone());
        tokio::spawn(async move {
            for addr in routing::own_devices(&anon, &seeds, &own, &this, unix_now()).await {
                push_account(node.clone(), addr, account.clone());
            }
        });
    }

    /// Someone we know connected: an `outgoing` contact becomes a friend (D8).
    /// True if that changed anything.
    fn connected(&mut self, id: &MeshId) -> bool {
        let Some(store) = self.store.as_mut() else {
            return false;
        };
        match store.connected(id) {
            Ok(changed) => changed,
            Err(e) => {
                eprintln!("mesh-node: couldn't save a new friend: {e}");
                false
            }
        }
    }

    /// Looks up the records of every contact (or only `id`) and our own,
    /// for their e2ee keys, in the background.
    fn fetch_keys(&self, only: Option<&MeshId>) {
        let (Some(store), Some(net), Some(_)) = (&self.store, &self.net, &self.e2ee) else {
            return;
        };
        if self.seeds.is_empty() {
            return;
        }
        let ids: Vec<MeshId> = match only {
            Some(id) => vec![*id],
            None => store.contacts().iter().map(|c| c.id()).collect(),
        };
        let mut targets: Vec<Target> = ids.iter().filter_map(|id| Target::of(store, id)).collect();
        if only.is_none() {
            targets.extend(Target::own(store));
        }
        let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
        tokio::spawn(async move {
            let found = e2ee::fetch(&anon, &seeds, targets, unix_now()).await;
            let _ = back.send(Back::Records(found));
        });
    }

    /// Our own records may carry a newer list of our devices (one restored
    /// from a backup adds itself): the keystore takes it, so this device can
    /// remove that one.
    fn own_lists(&mut self, found: &[(MeshId, Vec<AddrRecord>)]) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let own = store.id();
        let lists = found.iter().filter(|(id, _)| *id == own);
        let newest = lists
            .flat_map(|(_, r)| r)
            .map(|r| &r.devices)
            .max_by_key(|l| l.seq());
        // Quietly: an unasked `meshIdentity` would read as an answer.
        // Mesh-Voice sees the new device at its next `idStatus`.
        match newest.map(|list| store.own_list_seen(list)) {
            Some(Ok(true)) => self.allow_contacts(),
            Some(Err(e)) => eprintln!("mesh-node: couldn't save our device list: {e}"),
            _ => {}
        }
    }

    /// Removes another of our devices: a new list, which our records carry
    /// to everyone, and which e2ee follows at once (SPEC-e2ee D11).
    fn remove_device(&mut self, key: &str) -> Result<(), Fail> {
        let store = self.unlocked()?;
        let cert = store
            .devices()
            .devices()
            .iter()
            .find(|d| e2ee::hex(d.device().as_bytes()) == key);
        let device = *cert
            .ok_or_else(|| Fail("not-linked", "that device isn't linked".to_owned()))?
            .device();
        store.remove_device(&device)?;
        let (me, devices) = (store.id(), store.devices().clone());
        if let Some(e2ee) = self.e2ee.as_mut()
            && let Err(e) = e2ee.learn_devices(&me, &devices)
        {
            eprintln!("mesh-node: couldn't save e2ee state: {e}");
        }
        self.allow_contacts();
        self.emit_identity();
        self.publish();
        Ok(())
    }

    /// We're in touch with `id`: if we have no keys for them yet, look.
    fn keys_for(&self, id: &MeshId) {
        if self.e2ee.as_ref().is_some_and(|e| !e.knows(id)) {
            self.fetch_keys(Some(id));
        }
    }

    /// Envelopes a device sent over a live connection: open each, check it
    /// came from that device (the connection says who it is), and send back
    /// what opening asks for (key shares, key requests).
    fn envelopes(&mut self, id: MeshId, from: MeshAddr, frames: e2ee::Frames) {
        let device = *from.device.as_bytes();
        // A relay we read in a record beats a bare connection address.
        self.devices_at.entry(device).or_insert((id, from.clone()));
        let Some(e2ee) = self.e2ee.as_mut() else {
            return;
        };
        let mut replies = Vec::new();
        let mut notes = Vec::new();
        let mut unknown = false;
        for (flags, envelope) in frames {
            match e2ee.decrypt(&envelope, unix_now()) {
                Err(E2eeError::UnknownSender) => {
                    // ponytail: kept in memory, 256 at most; `mailbox` keeps mail for real.
                    if self.unopened.len() < 256 {
                        self.unopened.push((id, from.clone(), (flags, envelope)));
                    }
                    unknown = true;
                }
                Ok(got) => {
                    for opened in got.opened {
                        // On a live connection the sender is the device at
                        // the other end; nobody passes envelopes on yet.
                        if opened.sender != id || opened.device.to_bytes() != device {
                            eprintln!(
                                "mesh-node: an envelope's sender wasn't the device that sent it"
                            );
                            continue;
                        }
                        notes.push((opened, flags & e2ee::WAITED != 0));
                    }
                    replies.extend(got.replies);
                }
                Err(e) => eprintln!("mesh-node: couldn't open an envelope: {e}"),
            }
        }
        if unknown {
            self.fetch_keys(Some(&id));
        }
        for (opened, waited) in notes {
            self.emit_note(&opened, waited);
        }
        for (device, envelope) in replies {
            self.deliver(device.to_bytes(), vec![envelope]);
        }
    }

    /// `meshNote`: a test note that opened, on the reader's devices and the
    /// sender's other ones.
    fn emit_note(&self, opened: &Opened, waited: bool) {
        let (Some(store), Some(e2ee)) = (&self.store, &self.e2ee) else {
            return;
        };
        if opened.kind != NoteKind::TestNote {
            return;
        }
        let Some((at, text)) = e2ee::read_note(&opened.body) else {
            return eprintln!("mesh-node: a test note didn't read");
        };
        let (with, group, conversation) = match opened.conversation {
            Conversation::Direct(peer) => (Some(peer.to_string()), None, None),
            Conversation::Group(c) => {
                let members = e2ee.members(&c).unwrap_or_default();
                let members: Vec<String> = members.iter().map(ToString::to_string).collect();
                (None, Some(members), Some(e2ee::hex(&c)))
            }
        };
        let list = if opened.sender == store.id() {
            Some(store.devices().clone())
        } else {
            store.contact(&opened.sender).and_then(|c| c.devices())
        };
        let device = list.and_then(|l| {
            let cert = l.devices().iter().find(|d| *d.device() == opened.device)?;
            Some(cert.name().to_owned())
        });
        emit(
            "meshNote",
            json!({
                "from": opened.sender.to_string(),
                "device": device,
                "with": with,
                "group": group,
                "conversation": conversation,
                "text": text,
                "at": at,
                "path": if waited { "waited" } else { "live" },
            }),
        );
    }

    /// Sends a test note: one ID is 1:1, several a test group of them (or
    /// `group`, an existing one, with them as its members now).
    fn note(&mut self, ids: &str, text: &str, group: Option<&str>) -> Result<(), Fail> {
        let store = self.unlocked()?;
        let ids = ids
            .split_whitespace()
            .map(parse_id)
            .collect::<Result<Vec<_>, _>>()?;
        if ids.is_empty() {
            return Err(Fail("bad-args", "say who the note is for".to_owned()));
        }
        if let Some(id) = ids
            .iter()
            .find(|id| store.account().kind(id) != Some(Kind::Friend))
        {
            return Err(Fail("not-a-friend", format!("{id} isn't your friend")));
        }
        if text.len() > e2ee::MAX_NOTE {
            return Err(Fail("too-long", "that note is too long".to_owned()));
        }
        let Some(e2ee) = self.e2ee.as_mut() else {
            return Err(Fail(
                "offline",
                "end-to-end encryption didn't start".to_owned(),
            ));
        };
        let now = unix_now();
        let body = e2ee::note_body(now, text);
        let fail = |e: E2eeError| match e {
            E2eeError::NoKeys => Fail(
                "no-keys",
                "no keys from them yet; try again soon".to_owned(),
            ),
            E2eeError::TooLong => Fail("too-long", "that note is too long".to_owned()),
            e => Fail("e2ee", e.to_string()),
        };
        let (deliveries, conversation) = match (group, &ids[..]) {
            (None, [one]) => {
                let out = e2ee.encrypt_direct(one, NoteKind::TestNote, &body);
                if matches!(out, Err(E2eeError::NoKeys)) {
                    self.fetch_keys(Some(one));
                }
                let out = out.map_err(fail)?;
                (out.into_iter().map(|(d, e)| (d, vec![e])).collect(), None)
            }
            (group, _) => {
                let conversation = match group {
                    Some(text) => {
                        let c = e2ee::parse_conversation(text)
                            .ok_or_else(|| Fail("bad-args", "that isn't a group".to_owned()))?;
                        if e2ee.members(&c).is_none() {
                            return Err(Fail(
                                "not-a-member",
                                "you're not in that group".to_owned(),
                            ));
                        }
                        e2ee.set_members(c, &ids, now).map_err(fail)?;
                        c
                    }
                    None => e2ee.new_group(&ids, now).map_err(fail)?,
                };
                let out = e2ee.encrypt_group(conversation, NoteKind::TestNote, &body, now);
                (out.map_err(fail)?, Some(e2ee::hex(&conversation)))
            }
        };
        let devices = deliveries.len();
        for (device, envelopes) in deliveries {
            self.deliver(device.to_bytes(), envelopes);
        }
        emit(
            "meshNoteSent",
            json!({ "fn": "e2eeNote", "conversation": conversation, "devices": devices }),
        );
        Ok(())
    }

    /// Sends envelopes to a device where we last saw it. Without a live
    /// connection they count as waited, and we try its address anyway; if
    /// it doesn't take them, they wait until it connects.
    fn deliver(&mut self, device: [u8; 32], envelopes: Vec<Vec<u8>>) {
        let (Some(net), Some((owner, addr))) = (&self.net, self.devices_at.get(&device).cloned())
        else {
            return self.waiting.entry(device).or_default().extend(envelopes);
        };
        let connected = net.node.connected(&owner);
        let live = connected.iter().any(|a| *a.device.as_bytes() == device);
        let flags = if live { 0 } else { e2ee::WAITED };
        let (node, back) = (net.node.clone(), self.back.clone());
        tokio::spawn(async move {
            let frames: Vec<Vec<u8>> = envelopes
                .iter()
                .map(|e| [&[flags][..], e].concat())
                .collect();
            if !e2ee::send(&node, &addr, &frames).await {
                let _ = back.send(Back::Unsent(Box::new((device, envelopes))));
            }
        });
    }

    /// `id`'s devices are connected: what waited for them goes now.
    fn send_waiting(&mut self, id: &MeshId) {
        let Some(net) = &self.net else { return };
        for addr in net.node.connected(id) {
            let device = *addr.device.as_bytes();
            let Some(envelopes) = self.waiting.remove(&device) else {
                continue;
            };
            let (node, back) = (net.node.clone(), self.back.clone());
            tokio::spawn(async move {
                let waited = [e2ee::WAITED];
                let frames: Vec<Vec<u8>> = envelopes
                    .iter()
                    .map(|e| [&waited[..], e].concat())
                    .collect();
                if !e2ee::send(&node, &addr, &frames).await {
                    let _ = back.send(Back::Unsent(Box::new((device, envelopes))));
                }
            });
        }
    }

    /// Starts this device's node for the open identity (replacing any running).
    async fn start_net(&mut self) {
        self.stop_net().await;
        let Some(store) = &self.store else { return };
        let data = self.path.parent().unwrap_or(Path::new("."));
        let opened = E2ee::open(
            data,
            store.data_key(),
            store.root_key(),
            store.device_key(),
            store.devices(),
            unix_now(),
        );
        self.e2ee = opened
            .inspect_err(|e| eprintln!("mesh-node: end-to-end encryption didn't start: {e}"))
            .ok();
        let Some(store) = &self.store else { return };
        let this = store.device_key().public();
        let Some(cert) = store
            .devices()
            .devices()
            .iter()
            .find(|d| *d.device() == this)
        else {
            eprintln!("mesh-node: this device isn't in its identity's device list");
            return;
        };
        let allowed = self.allowed.clone();
        let config = Config {
            relays: self.relays.clone(),
            allow: Allow::only(move |id, device| {
                // A device not in the newest list we hold may be newly linked;
                // only one that list removed is refused.
                let allowed = allowed
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                allowed
                    .get(&id.to_bytes())
                    .is_some_and(|revoked| !revoked.contains(device.as_bytes()))
            }),
            services: vec![
                SYNC.to_owned(),
                PRESENCE.to_owned(),
                e2ee::SERVICE.to_owned(),
            ],
            ..Config::default()
        };
        self.allow_contacts();
        let Some(store) = &self.store else { return };
        let started = match Node::start(store.device_key(), cert, config).await {
            Ok(node) => anon_node(self.relays.clone())
                .await
                .map(|anon| (node, anon)),
            Err(e) => Err(e.to_string()),
        };
        match started {
            Ok((node, anon)) => {
                let node = Arc::new(node);
                let published = Arc::new(AtomicBool::new(false));
                let keys = Arc::new(AtomicBool::new(false));
                let watch = tokio::spawn(watch_net(
                    node.clone(),
                    published.clone(),
                    keys.clone(),
                    self.back.clone(),
                ));
                let peers = tokio::spawn(watch_peers(node.clone(), self.back.clone()));
                let own = self.store.as_ref().map(Keystore::id).expect("unlocked");
                let streams = tokio::spawn(serve_streams(node.clone(), own, self.back.clone()));
                self.net = Some(Net {
                    node,
                    anon: Arc::new(anon),
                    watch,
                    peers,
                    streams,
                    published,
                    keys,
                    presenting: Arc::default(),
                });
                self.update_shown();
                self.hold_codes(false);
                self.collect();
            }
            Err(e) => eprintln!("mesh-node: networking didn't start: {e}"),
        }
    }

    /// Closes every connection (they're told it's locked) and the node.
    async fn stop_net(&mut self) {
        if let Some(net) = self.net.take() {
            net.watch.abort();
            net.peers.abort();
            net.streams.abort();
            net.anon.close().await;
            net.node.close().await;
            self.held.clear();
            self.publish_retry = PUBLISH_RETRY;
            self.presence.clear();
            emit_net(None, false, false);
        }
        self.e2ee = None;
        self.devices_at.clear();
        self.waiting.clear();
        self.unopened.clear();
    }

    fn emit_unlocked(&self) {
        self.emit_identity();
        self.emit_codes(None);
    }

    /// Lets in exactly our own identity and our contacts (D9), but no device
    /// their newest list removed, and closes what that no longer lets in.
    fn allow_contacts(&self) {
        let revoked = |list: Option<DeviceList>| -> HashSet<[u8; 32]> {
            let Some(list) = list else {
                return HashSet::new();
            };
            list.revoked().iter().map(|d| d.to_bytes()).collect()
        };
        let ids = self.store.iter().flat_map(|store| {
            std::iter::once((
                store.id().to_bytes(),
                revoked(Some(store.devices().clone())),
            ))
            .chain((store.contacts().iter()).map(|c| (c.id().to_bytes(), revoked(c.devices()))))
        });
        *self
            .allowed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ids.collect();
        if let Some(net) = &self.net {
            net.node.prune();
        }
    }

    /// Sends this device's record for every contact to the seeds, in the
    /// background; `meshNet` says when they're there.
    fn publish(&mut self) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        // Without a home relay there's nothing to say yet; `Back::Relay` comes once there is.
        let Some(relay) = net.node.addr().relay else {
            return;
        };
        if self.seeds.is_empty() {
            return;
        }
        let (now, keys) = (unix_now(), self.e2ee.is_some());
        let mut e2ee = self.e2ee.as_mut();
        let records = routing::records(store, &relay, now, self.record_ttl, |id| {
            let field = e2ee.as_mut().map(|e| e.record_field(id, now));
            field
                .and_then(|f| {
                    f.inspect_err(|e| eprintln!("mesh-node: couldn't make e2ee keys: {e}"))
                        .ok()
                })
                .unwrap_or_default()
        });
        let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
        tokio::spawn(async move {
            let ok = routing::publish(&anon, &seeds, &records).await;
            let _ = back.send(Back::Published(ok, keys));
        });
    }

    fn emit_net(&self) {
        match &self.net {
            Some(net) => emit_net(
                Some(&net.node.status()),
                net.published.load(Ordering::Relaxed),
                net.keys.load(Ordering::Relaxed),
            ),
            None => emit_net(None, false, false),
        }
    }

    /// `meshSocial`: friends, requests both ways, blocks and our status.
    /// `answers` names the command it answers; `None` when something changed
    /// by itself (a request came, someone connected).
    fn emit_social(&self, answers: Option<&str>) {
        let Some(store) = &self.store else { return };
        let (mut friends, mut incoming, mut outgoing, mut blocked) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for e in store.account().entries() {
            let id = e.id();
            match e.kind {
                Kind::Friend => friends.push(json!({
                    "id": id.to_string(),
                    "name": e.name,
                    "nick": e.nick,
                    "verified": e.verified,
                    "presence": self.presence_of(&id).as_str(),
                    "seen": store.contact(&id).and_then(|c| c.seen),
                })),
                Kind::Incoming => incoming.push(json!({
                    "id": id.to_string(), "name": e.name, "note": e.note, "at": e.at,
                })),
                Kind::Outgoing => outgoing.push(json!({
                    "id": id.to_string(), "nick": e.nick, "at": e.at,
                })),
                Kind::Blocked => blocked.push(json!({
                    "id": id.to_string(), "nick": e.nick, "at": e.at,
                })),
                Kind::Removed => {}
            }
        }
        emit(
            "meshSocial",
            json!({
                "fn": answers,
                "friends": friends,
                "incoming": incoming,
                "outgoing": outgoing,
                "blocked": blocked,
                "status": store.account().status().as_str(),
            }),
        );
    }

    /// `meshIdentity`: nothing about the identity unless it's unlocked.
    fn emit_identity(&self) {
        let keyring = self.keyring.as_ref().err();
        let Some(store) = &self.store else {
            let state = if Keystore::exists(&self.path) {
                "locked"
            } else {
                "none"
            };
            emit(
                "meshIdentity",
                json!({ "state": state, "keyring": keyring }),
            );
            return;
        };
        let this = store.device_key().public();
        let devices: Vec<Value> = store
            .devices()
            .devices()
            .iter()
            .map(|d| {
                json!({
                    "name": d.name(),
                    "key": e2ee::hex(d.device().as_bytes()),
                    "createdAt": d.created_at(),
                    "thisDevice": *d.device() == this,
                })
            })
            .collect();
        emit(
            "meshIdentity",
            json!({
                "state": "unlocked",
                "id": store.id().to_string(),
                "link": store.id().link(),
                "username": store.username(),
                "devices": devices,
                "keepUnlocked": is_kept(&self.path),
                "keyring": keyring,
            }),
        );
    }

    /// `meshCodes`: this device's live codes; `created` names a new one.
    fn emit_codes(&self, created: Option<FriendCode>) {
        let Some(store) = &self.store else { return };
        let codes: Vec<Value> = store
            .codes()
            .iter()
            .map(|c| {
                json!({
                    "code": c.code.to_string(),
                    "link": c.code.link(),
                    "createdAt": c.created_at,
                    "expiresAt": c.expires_at,
                    "maxUses": c.max_uses,
                    "held": self.held.contains(&c.code),
                })
            })
            .collect();
        emit(
            "meshCodes",
            json!({ "codes": codes, "created": created.map(|c| c.to_string()) }),
        );
    }
}

/// A node with a fresh identity nobody knows, for talking to seeds (D7b).
async fn anon_node(relays: Relays) -> Result<Node, String> {
    let (root, key) = RootKey::generate()
        .and_then(|r| Ok((r, DeviceKey::generate()?)))
        .map_err(|e| format!("no randomness: {e}"))?;
    // A generic name and no date, so it says nothing about this device.
    let cert = DeviceCert::issue(&root, &key.public(), "mesh", 0).map_err(|e| e.to_string())?;
    let config = Config {
        relays,
        ..Config::default()
    };
    Node::start(&key, &cert, config)
        .await
        .map_err(|e| e.to_string())
}

/// Offers one record to every seed. A seed that saw it used up or revoked
/// wins over one that holds it.
async fn hold(anon: &Node, seeds: &[MeshAddr], held: &HeldCode) -> Option<Hold> {
    let mut best = None;
    for addr in seeds {
        let answer = seed::ask(anon, addr, seed::HOLD, held.as_bytes())
            .await
            .ok()
            .and_then(|a| Hold::from_byte(*a.first()?));
        best = match (best, answer) {
            (_, Some(Hold::Gone)) | (Some(Hold::Gone), _) => Some(Hold::Gone),
            (_, Some(Hold::Ok)) | (Some(Hold::Ok), _) => Some(Hold::Ok),
            (best, answer) => answer.or(best),
        };
    }
    best
}

/// Asks the seeds for a code's record and opens it: the ID it points to and
/// its lookup ID, or a failure's kind and message.
async fn find_code(
    anon: &Node,
    seeds: &[MeshAddr],
    code: FriendCode,
) -> Result<(MeshId, [u8; 16]), (&'static str, &'static str)> {
    let Ok(lookup_id) = tokio::task::spawn_blocking(move || code.lookup_id()).await else {
        return Err(("offline", "couldn't work the code out"));
    };
    let (mut not_found, mut slowed) = (false, false);
    for addr in seeds {
        let Ok(answer) = seed::ask(anon, addr, seed::GET, &lookup_id).await else {
            continue;
        };
        match Get::from_bytes(&answer) {
            Some(Get::Found(record)) => {
                // Expired, forged or for another code: as good as not there.
                match HeldCode::from_bytes(&record).and_then(|h| h.open(&code, unix_now())) {
                    Ok(record) => return Ok((record.root(), lookup_id)),
                    Err(_) => not_found = true,
                }
            }
            Some(Get::None) => not_found = true,
            Some(Get::SlowDown) => slowed = true,
            None => {}
        }
    }
    Err(match (slowed, not_found) {
        (true, _) => ("slow-down", "too many tries; wait a minute"),
        (_, true) => (
            "not-found",
            "no such code: it may have expired, been used or been revoked",
        ),
        _ => ("offline", "couldn't reach a seed"),
    })
}

/// A typed `K7QM-3XPA`, or a pasted `mesh://code/…` link.
fn parse_code(text: &str) -> Result<FriendCode, Fail> {
    let text = text.trim();
    if !text
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("mesh://"))
    {
        return Ok(FriendCode::parse(text)?);
    }
    match Link::parse(text)? {
        Link::Code(code) => Ok(code),
        Link::Id(_) => Err(Fail(
            "not-a-code",
            "that's an ID, not a friend code".to_owned(),
        )),
    }
}

/// A `meshError` for a command answered in the background.
fn emit_fail(func: &str, kind: &str, message: &str) {
    emit(
        "meshError",
        json!({ "fn": func, "kind": kind, "message": message }),
    );
}

/// The account-state service between our own devices (D11).
const SYNC: &str = "sync";
/// What a device shows its friends (D12).
const PRESENCE: &str = "presence";
/// Presence is sent again this often, even unchanged.
const HEARTBEAT: Duration = Duration::from_secs(60);
/// A friend's device silent this long counts as offline.
const PRESENCE_SILENCE: Duration = Duration::from_secs(150);

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
/// How long a device has to send its state.
const SYNC_TIMEOUT: Duration = Duration::from_secs(20);

/// Sends our account state to another of our devices, in the background.
fn push_account(node: Arc<Node>, addr: MeshAddr, account: Vec<u8>) {
    tokio::spawn(async move {
        let sent = async {
            let (_, mut send, _recv) = node.open(&addr, SYNC).await.ok()?;
            mesh_transport::frame::write_frame(&mut send, &account)
                .await
                .ok()?;
            send.finish().ok()?;
            send.stopped().await.ok()
        };
        // ponytail: a state over a frame (1 MiB, ~10,000 entries) can't sync; split it if lists get that long.
        if tokio::time::timeout(SYNC_TIMEOUT, sent).await.is_err() {
            eprintln!("mesh-node: another of our devices didn't take our lists");
        }
    });
}

/// Answers the streams other devices open to us: presence from friends (the
/// loop drops anyone else's), and sync from our own devices, one frame each.
async fn serve_streams(
    node: Arc<Node>,
    own: MeshId,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    while let Some(mut stream) = node.next_stream().await {
        let back = back.clone();
        if stream.service == PRESENCE && stream.peer.id != own {
            tokio::spawn(async move {
                let (id, device) = (stream.peer.id, *stream.peer.device.as_bytes());
                loop {
                    let read = mesh_transport::frame::read_frame(&mut stream.recv);
                    let (heard, name) = match tokio::time::timeout(PRESENCE_SILENCE, read).await {
                        Ok(Ok(Some(frame))) => match &frame[..] {
                            [byte, name @ ..] => (
                                Presence::from_byte(*byte),
                                String::from_utf8_lossy(name).into_owned(),
                            ),
                            [] => (None, String::new()),
                        },
                        _ => (None, String::new()),
                    };
                    let _ = back.send(Back::Presence(Box::new((id, device, heard, name))));
                    if heard.is_none() {
                        break;
                    }
                }
            });
            continue;
        }
        if stream.service == e2ee::SERVICE {
            tokio::spawn(async move {
                let from = MeshAddr {
                    device: stream.peer.device,
                    relay: None,
                    direct: Vec::new(),
                };
                let frames = e2ee::read(&mut stream).await;
                if !frames.is_empty() {
                    let _ = back.send(Back::Envelopes(Box::new((stream.peer.id, from, frames))));
                }
            });
            continue;
        }
        if stream.service != SYNC || stream.peer.id != own {
            let _ = stream.send.reset(0u32.into());
            continue;
        }
        tokio::spawn(async move {
            let read = mesh_transport::frame::read_frame(&mut stream.recv);
            let Ok(Ok(Some(bytes))) = tokio::time::timeout(SYNC_TIMEOUT, read).await else {
                return;
            };
            let Some(theirs) = Account::from_bytes(&bytes) else {
                return eprintln!("mesh-node: another of our devices sent unreadable lists");
            };
            let from = MeshAddr {
                device: stream.peer.device,
                relay: None,
                direct: Vec::new(),
            };
            let _ = back.send(Back::Synced(Box::new((theirs, from))));
        });
    }
}

/// Reports every device that connects to us and passes the handshake.
async fn watch_peers(node: Arc<Node>, back: tokio::sync::mpsc::UnboundedSender<Back>) {
    while let Some(peer) = node.next_peer().await {
        let _ = back.send(Back::Connected(peer.id));
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Sends `meshNet` whenever the node's state changes.
// ponytail: polls once a second; switch to iroh's watchers if idle CPU says so.
async fn watch_net(
    node: Arc<Node>,
    published: Arc<AtomicBool>,
    keys: Arc<AtomicBool>,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    let mut last: Option<(Status, bool, bool)> = None;
    loop {
        let flag = |f: &AtomicBool| f.load(Ordering::Relaxed);
        let now = (node.status(), flag(&published), flag(&keys));
        if last.as_ref() != Some(&now) {
            if now.0.relay.is_some() && last.as_ref().map(|l| &l.0.relay) != Some(&now.0.relay) {
                let _ = back.send(Back::Relay);
            }
            emit_net(Some(&now.0), now.1, now.2);
            last = Some(now);
        }
        tokio::time::sleep(NET_POLL).await;
    }
}

/// `meshNet`: never any IP address (SPEC-transport "Endpoint"). `keys`:
/// our published records carry our e2ee keys (SPEC-e2ee).
fn emit_net(status: Option<&Status>, published: bool, keys: bool) {
    let payload = match status {
        None => json!({
            "state": "off", "relay": null, "direct": false, "connections": 0, "published": false,
            "keys": false,
        }),
        Some(s) => json!({
            "state": if s.online { "online" } else { "connecting" },
            "relay": s.relay.as_ref().map(ToString::to_string),
            "direct": s.direct,
            "connections": s.connections,
            "published": published,
            "keys": keys,
        }),
    };
    emit("meshNet", payload);
}

/// `meshPing`: who answered, which device, the path and round-trip time.
fn emit_pong(pong: &Pong) {
    emit(
        "meshPing",
        json!({
            "id": pong.peer.id.to_string(),
            "name": pong.peer.name,
            "path": match pong.path {
                NetPath::Direct => "direct",
                NetPath::Relay => "relay",
            },
            "ms": (pong.rtt.as_secs_f64() * 10_000.0).round() / 10.0,
        }),
    );
}

/// An ID typed or pasted: `mesh1…` or a `mesh://id/…` link, not a code.
fn parse_id(text: &str) -> Result<MeshId, Fail> {
    match Link::parse(text)? {
        Link::Id(id) => Ok(id),
        Link::Code(_) => Err(Fail(
            "not-an-id",
            "that's a friend code; resolve it first".to_owned(),
        )),
    }
}

/// A failed ping's kind. The messages are fixed: iroh's own errors can
/// name addresses, which stay out of the UI.
fn ping_fail(e: TransportError) -> Fail {
    let kind = match e {
        TransportError::Timeout | TransportError::Handshake(HandshakeError::Timeout) => "timeout",
        TransportError::Handshake(HandshakeError::BadCert) => "bad-cert",
        TransportError::Handshake(HandshakeError::KeyMismatch) => "key-mismatch",
        // Their device doesn't take us: to us that's the same as not there.
        TransportError::Handshake(HandshakeError::NotAllowed) => "unreachable",
        _ => "unreachable",
    };
    let message = match kind {
        "timeout" => "that device didn't answer in time".to_owned(),
        "unreachable" => "couldn't reach that device".to_owned(),
        _ => e.to_string(),
    };
    Fail(kind, message)
}

/// This machine's name, for its device certificate.
fn device_name() -> String {
    let name = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|n| n.trim().to_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "This device".to_owned());
    let mut end = name.len().min(MAX_DEVICE_NAME);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}
