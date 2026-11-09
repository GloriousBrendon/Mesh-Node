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
//! Commands are never logged or echoed: passwords travel in them. Each
//! command answers with one event; a failure is a `meshError` with a stable
//! `kind` the UI switches on, the `fn` it answers, and a message to show.

use std::collections::HashSet;
use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::codes::{Get, Hold};
use crate::routing::{self, ReachError, Reached, Target};
use crate::seed;
use mesh_identity::{
    CodeError, DEFAULT_EXPIRY, DEFAULT_USES, DeviceCert, DeviceKey, DeviceList, FriendCode,
    HeldCode, IdError, Keystore, KeystoreError, LastAddr, Link, MAX_DEVICE_NAME, MeshId, RootKey,
    SafetyNumber, check_password, is_kept, keyring_status,
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
/// Seeds every install knows (SPEC-seed D6); `--seed` replaces them.
// ponytail: empty until the homelab seed runs (seed Task 7).
pub const SEEDS: &[&str] = &[];

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
    allowed: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// How long address records last (D4).
    record_ttl: u64,
    /// The wait before the next publish after a failed one.
    publish_retry: Duration,
}

struct Net {
    node: Arc<Node>,
    /// The throwaway identity's node, for seeds only (D7b).
    anon: Arc<Node>,
    /// Reports the node's state as it changes.
    watch: tokio::task::JoinHandle<()>,
    /// Every contact's record is on a seed (`meshNet`'s `published`).
    published: Arc<AtomicBool>,
}

/// What a background request found out.
enum Back {
    /// Each code, and the best answer any seed gave (`None`: none answered).
    Held(Vec<(FriendCode, Option<Hold>)>),
    /// The home relay changed (or came up): records go out again.
    Relay,
    Published(bool),
    Republish,
    /// A contact answered through this address.
    Reached(Box<(MeshId, LastAddr, Option<DeviceList>)>),
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
                // A typed `K7QM-3XPA`, or a pasted `mesh://code/…` link.
                let text = arg(0)?.trim();
                let code = if text
                    .get(..7)
                    .is_some_and(|s| s.eq_ignore_ascii_case("mesh://"))
                {
                    let Link::Code(code) = Link::parse(text)? else {
                        return Err(Fail(
                            "not-a-code",
                            "that's an ID, not a friend code".to_owned(),
                        ));
                    };
                    code
                } else {
                    FriendCode::parse(text)?
                };
                let anon = self.node().and(self.anon())?;
                if self.seeds.is_empty() {
                    return Err(Fail("offline", "no seed to ask".to_owned()));
                }
                tokio::spawn(resolve(anon, self.seeds.clone(), code));
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
            "contactAdd" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.add_contact(id, arg(1)?)?;
                self.allow_contacts();
                self.emit_contacts();
                self.publish();
            }
            "contactRemove" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.remove_contact(&id)?;
                self.allow_contacts();
                if let Some(net) = &self.net {
                    net.node.disconnect(&id);
                }
                // Their records aren't refreshed again, so they lapse (D4).
                self.emit_contacts();
            }
            "contactRename" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.rename_contact(&id, arg(1)?)?;
                self.emit_contacts();
            }
            "contactList" => {
                self.unlocked()?;
                self.emit_contacts();
            }
            "netPingId" => {
                let id = parse_id(arg(0)?)?;
                let target = Target::of(self.unlocked()?, &id).ok_or_else(|| {
                    Fail("not-a-contact", "add them as a contact first".to_owned())
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
                tokio::spawn(async move {
                    match node.ping(&addr).await {
                        Ok(pong) => emit_pong(&pong),
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
            Back::Relay => return self.publish(),
            Back::Republish => return self.publish(),
            Back::Published(ok) => {
                if let Some(net) = &self.net {
                    net.published.store(ok, Ordering::Relaxed);
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
                    && let Err(e) = store.contact_reached(&id, last, list.as_ref())
                {
                    eprintln!("mesh-node: couldn't save a contact's address: {e}");
                }
                return self.emit_contacts();
            }
        };
        let Some(store) = self.store.as_mut() else {
            return;
        };
        for (code, answer) in answers {
            match answer {
                Some(Hold::Ok) => {
                    self.held.insert(code);
                }
                // Used up or revoked: it's no use any more, so it leaves the list.
                Some(Hold::Gone) => {
                    self.held.remove(&code);
                    if let Err(e) = store.revoke_code(&code) {
                        eprintln!("mesh-node: couldn't drop a used code: {e}");
                    }
                }
                Some(Hold::Taken) => eprintln!("mesh-node: a friend code collided; make another"),
                _ => {}
            }
        }
        self.emit_codes(None);
    }

    /// Starts this device's node for the open identity (replacing any running).
    async fn start_net(&mut self) {
        self.stop_net().await;
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
            allow: Allow::only(move |id| {
                allowed
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&id.to_bytes())
            }),
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
                let watch = tokio::spawn(watch_net(
                    node.clone(),
                    published.clone(),
                    self.back.clone(),
                ));
                self.net = Some(Net {
                    node,
                    anon: Arc::new(anon),
                    watch,
                    published,
                });
                self.hold_codes(false);
            }
            Err(e) => eprintln!("mesh-node: networking didn't start: {e}"),
        }
    }

    /// Closes every connection (they're told it's locked) and the node.
    async fn stop_net(&mut self) {
        if let Some(net) = self.net.take() {
            net.watch.abort();
            net.anon.close().await;
            net.node.close().await;
            self.held.clear();
            self.publish_retry = PUBLISH_RETRY;
            emit_net(None, false);
        }
    }

    fn emit_unlocked(&self) {
        self.emit_identity();
        self.emit_codes(None);
    }

    /// Lets in exactly our own identity and our contacts (D9).
    fn allow_contacts(&self) {
        let ids = self.store.iter().flat_map(|store| {
            std::iter::once(store.id().to_bytes())
                .chain(store.contacts().iter().map(|c| c.id().to_bytes()))
        });
        *self
            .allowed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ids.collect();
    }

    /// Sends this device's record for every contact to the seeds, in the
    /// background; `meshNet` says when they're there.
    fn publish(&self) {
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
        let records = routing::records(store, &relay, unix_now(), self.record_ttl);
        let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
        tokio::spawn(async move {
            let ok = routing::publish(&anon, &seeds, &records).await;
            let _ = back.send(Back::Published(ok));
        });
    }

    fn emit_net(&self) {
        match &self.net {
            Some(net) => emit_net(
                Some(&net.node.status()),
                net.published.load(Ordering::Relaxed),
            ),
            None => emit_net(None, false),
        }
    }

    /// `meshContacts`: every contact, and when one of their devices last answered.
    fn emit_contacts(&self) {
        let Some(store) = &self.store else { return };
        let contacts: Vec<Value> = store
            .contacts()
            .iter()
            .map(|c| {
                json!({
                    "id": c.id().to_string(),
                    "name": c.name,
                    "added": c.added,
                    "seen": c.seen,
                })
            })
            .collect();
        emit("meshContacts", json!({ "contacts": contacts }));
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

/// Asks the seeds for a code's record and opens it: `meshResolved` with the
/// ID it points to, or a `meshError` for `codeResolve`.
async fn resolve(anon: Arc<Node>, seeds: Arc<Vec<MeshAddr>>, code: FriendCode) {
    let fail = |kind: &str, message: &str| {
        emit(
            "meshError",
            json!({ "fn": "codeResolve", "kind": kind, "message": message }),
        );
    };
    let Ok(lookup_id) = tokio::task::spawn_blocking(move || code.lookup_id()).await else {
        return fail("offline", "couldn't work the code out");
    };
    let (mut not_found, mut slowed) = (false, false);
    for addr in seeds.iter() {
        let Ok(answer) = seed::ask(&anon, addr, seed::GET, &lookup_id).await else {
            continue;
        };
        match Get::from_bytes(&answer) {
            Some(Get::Found(record)) => {
                // Expired, forged or for another code: as good as not there.
                match HeldCode::from_bytes(&record).and_then(|h| h.open(&code, unix_now())) {
                    Ok(record) => {
                        let id = record.root();
                        return emit(
                            "meshResolved",
                            json!({ "code": code.to_string(), "id": id.to_string(), "link": id.link() }),
                        );
                    }
                    Err(_) => not_found = true,
                }
            }
            Some(Get::None) => not_found = true,
            Some(Get::SlowDown) => slowed = true,
            None => {}
        }
    }
    match (slowed, not_found) {
        (true, _) => fail("slow-down", "too many tries; wait a minute"),
        (_, true) => fail(
            "not-found",
            "no such code: it may have expired, been used or been revoked",
        ),
        _ => fail("offline", "couldn't reach a seed"),
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
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    let mut last: Option<(Status, bool)> = None;
    loop {
        let now = (node.status(), published.load(Ordering::Relaxed));
        if last.as_ref() != Some(&now) {
            if now.0.relay.is_some() && last.as_ref().map(|l| &l.0.relay) != Some(&now.0.relay) {
                let _ = back.send(Back::Relay);
            }
            emit_net(Some(&now.0), now.1);
            last = Some(now);
        }
        tokio::time::sleep(NET_POLL).await;
    }
}

/// `meshNet`: never any IP address (SPEC-transport "Endpoint").
fn emit_net(status: Option<&Status>, published: bool) {
    let payload = match status {
        None => json!({
            "state": "off", "relay": null, "direct": false, "connections": 0, "published": false,
        }),
        Some(s) => json!({
            "state": if s.online { "online" } else { "connecting" },
            "relay": s.relay.as_ref().map(ToString::to_string),
            "direct": s.direct,
            "connections": s.connections,
            "published": published,
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
