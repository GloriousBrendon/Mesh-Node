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
    Account, AddrRecord, CodeError, DEFAULT_EXPIRY, DEFAULT_USES, DIRECT_CERT_LEN, DeviceCert,
    DeviceKey, DeviceList, DirectCert, FriendCode, HeldCode, IdError, Keystore, KeystoreError,
    Kind, KnockFrom, LastAddr, Link, MAX_DEVICE_NAME, MAX_NOTE, MeshId, RootKey, SafetyNumber,
    Status as Chosen, check_password, is_kept, keyring_status, open_knock, seal_knock, unix_now,
};
use mesh_transport::{
    Allow, Config, HandshakeError, MeshAddr, Node, Path as NetPath, Pong, Relays, Status,
    TransportError,
};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

#[path = "calls.rs"]
mod calls;
#[path = "dm.rs"]
mod dm;
#[path = "files.rs"]
mod files;
#[path = "link.rs"]
mod link;
#[path = "mail.rs"]
mod mail;
#[path = "mailrec.rs"]
mod mailrec;
#[path = "profile.rs"]
mod profile;
#[path = "reports.rs"]
mod reports;
#[path = "social.rs"]
mod social;
#[path = "spaces.rs"]
mod spaces;
#[path = "top8.rs"]
mod top8;
use social::{
    COLLECT_EVERY, Collected, PRESENCE, PRESENCE_SILENCE, Presence, SYNC, SYNC_TIMEOUT,
    push_account,
};
pub use spaces::PEER_IDLE;

const KEYSTORE_FILE: &str = "identity.mks";
/// How long a new home relay must hold before records go out for it.
const RELAY_SETTLE: Duration = Duration::from_secs(10);
/// How often the node's state is checked for a change to report.
const NET_POLL: Duration = Duration::from_secs(1);
/// How often codes no seed holds yet are offered again.
const HOLD_RETRY: Duration = Duration::from_secs(600);
/// How often every code is held again, so a seed keeps it (it drops a code
/// `codes::HOLD_LIFE` after its last hold).
const REHOLD_EVERY: Duration = Duration::from_secs(24 * 3600);
const _: () = assert!(REHOLD_EVERY.as_secs() * 7 <= crate::codes::HOLD_LIFE);
/// A failed publish is tried again after this, doubling up to the refresh.
const PUBLISH_RETRY: Duration = Duration::from_secs(60);
/// Seeds every install knows (SPEC-seed D6); `--seed` replaces them.
/// The homelab seed: relay-only, on n0's EU relay (the closest n0 region to
/// it); it takes no direct callers and shows no address (D8c as changed).
pub const SEEDS: &[&str] = &[
    "mesh://node/1191ccb55a67bcf6fe9408ccd615fce54ff8af653b19a4909f4dbdc967e9533e?relay=https://euc1-1.relay.n0.iroh.link./",
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

/// `--cut` (test-only, SPEC-mailbox decided Q16): what starts cut off,
/// until a `cutOff` command.
#[derive(Default)]
pub struct Cut {
    pub seed: bool,
    pub live: bool,
}

/// The helper's flags beyond its relays and seeds.
pub struct Options {
    pub record_ttl: u64,
    /// `--peer-idle`: how long an idle Space peer's connection stays open.
    pub peer_idle: Duration,
    pub cut: Cut,
    /// `--holder` or `MESH_HOLDERS`: the tickets of who keeps our mail
    /// (SPEC-mailbox), each with its `&mail=` token if it has one.
    pub holders: Vec<String>,
    /// `--crash-at records` (tests only).
    pub crash_at_records: bool,
    /// `--no-calls` (tests only): no `call` service, as an engine from
    /// before calls (SPEC-calls C11).
    pub no_calls: bool,
    /// `--hide-ip`: start with Hide my IP on (P6); `netPrivacy` changes it.
    pub hide_ip: bool,
    /// `--tone`, `--heard` and `--drop` (tests only, SPEC-calls).
    #[cfg(feature = "audio")]
    pub audio: crate::media::Io,
}

/// Reads commands until stdin closes (Mesh quit or restarted us).
pub async fn run(dir: &Path, relays: Relays, seeds: Vec<MeshAddr>, options: Options) {
    let (back, mut answers) = tokio::sync::mpsc::unbounded_channel();
    let mut helper = Helper::new(dir.join(KEYSTORE_FILE), relays, seeds, back);
    helper.record_ttl = options.record_ttl;
    helper.wire = spaces::PeerWire::new(options.peer_idle);
    helper.holders = options.holders;
    helper.cut_live = options.cut.live;
    helper.crash_at_records = options.crash_at_records;
    helper.no_calls = options.no_calls;
    helper.hide_ip = options.hide_ip;
    #[cfg(feature = "audio")]
    {
        helper.calls.io = options.audio;
    }
    if options.cut.seed {
        helper.cut = Some(std::mem::take(&mut helper.seeds));
    }
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
    let mut rehold = tokio::time::interval(REHOLD_EVERY);
    rehold.tick().await;
    let mut refresh = tokio::time::interval(Duration::from_secs(
        routing::REFRESH_EVERY.min(helper.record_ttl / 4).max(1),
    ));
    refresh.tick().await;
    let mut collect = tokio::time::interval(COLLECT_EVERY);
    collect.tick().await;
    let mut peers = tokio::time::interval(
        (helper.wire.idle() / 2).clamp(Duration::from_millis(500), spaces::PEER_TICK),
    );
    peers.tick().await;
    let mut calls = tokio::time::interval(Duration::from_secs(1));
    calls.tick().await;
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
            _ = rehold.tick() => {
                helper.hold_codes(false);
                continue;
            }
            _ = refresh.tick() => {
                helper.dm_retry_all();
                helper.space_retry_all();
                // Renewals and the daily records round follow the collect.
                helper.mail_refresh();
                helper.mail_out_all();
                helper.space_mail_out();
                helper.publish();
                helper.dial_contacts();
                helper.sync_own();
                helper.fetch_keys(None);
                helper.rotate_if_old();
                helper.report_retry();
                continue;
            }
            _ = collect.tick() => {
                helper.collect();
                continue;
            }
            _ = peers.tick() => {
                helper.peer_tick();
                continue;
            }
            _ = calls.tick() => {
                helper.call_tick();
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
    helper.mail_flush().await;
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
    /// Reports waiting for a Space's owner, and those we hold as one (P11).
    reports: reports::Reports,
    /// Who the direct node lets in: our ID and our friends' (P3).
    friends: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// The direct key's certificate while networking runs: what friends are told.
    direct_cert: Option<DirectCert>,
    /// How long address records last (D4).
    record_ttl: u64,
    /// `--cut seed`: the seeds, held back until `cutOff`.
    cut: Option<Arc<Vec<MeshAddr>>>,
    /// `--cut live`: no live connections with contacts until `cutOff`.
    cut_live: bool,
    /// `--crash-at records`: exit between a record read's two saves.
    crash_at_records: bool,
    /// `--holder` tickets; none means our first seeds' (mail.rs
    /// `holder_tickets`).
    holders: Vec<String>,
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
    /// This device's chat history, while unlocked (SPEC-dm).
    dm: Option<mesh_dm::history::History>,
    /// Devices a batch of chat events is on its way to.
    dm_flight: HashSet<[u8; 32]>,
    /// Devices that answered `failed` to some events: sent again soon, then
    /// on each refresh, until a batch goes through whole.
    dm_retry: HashMap<[u8; 32], (MeshId, MeshAddr)>,
    /// The chat open on screen (`dmOpen`), which gets its page again when
    /// it changes; others get a note.
    dm_open: Option<mesh_dm::Where>,
    /// The Spaces this device is in, opened at unlock (SPEC-spaces S11).
    spaces: Option<mesh_dm::space_store::SpaceList>,
    /// Space peers on the wire: idle closes, retries, the hello (S14).
    wire: spaces::PeerWire,
    /// Spaces opened this unlock (S11), by ID.
    space_open: HashMap<mesh_dm::space::SpaceId, mesh_dm::space_store::SpaceHistory>,
    /// Devices with a batch of Space events in flight.
    space_flight: HashSet<[u8; 32]>,
    /// Devices that didn't take everything: tried again at the refresh.
    space_retry: HashMap<[u8; 32], (MeshId, MeshAddr)>,
    /// Of those, the ones tried again soon, before the refresh.
    space_soon: spaces::Soon,
    /// Test 9's counts (`spaceCounts`).
    space_counts: spaces::Counts,
    /// The channel Mesh-Voice has open.
    space_view: Option<(mesh_dm::space::SpaceId, mesh_dm::space::ChannelId)>,
    /// Space mail (S9) in flight, by reader device and `mseq`: the events
    /// each envelope carries. And what's marked as mailed, so it isn't
    /// mailed twice; and when each device was last mailed.
    // ponytail: in memory only; after a restart, unanswered Space mail is mailed again and readers drop the copies by event ID. Save it with the mail state if that's seen to cost.
    space_sent: spaces::MailSent,
    space_marked: HashSet<([u8; 32], mesh_dm::space::SpaceId, u64)>,
    /// History pulls this unlock (S10).
    space_pulls: HashMap<mesh_dm::space::SpaceId, spaces::Pull>,
    /// Key lookups under way, one per person.
    keys_fetching: e2ee::Fetching,
    /// Dials under way to send or for presence, one per person (and our
    /// own devices' sync), so refreshes can't pile lookups up.
    dialling: e2ee::Fetching,
    /// Our changes already redone after a fork dropped them (S7), this unlock.
    space_redone: HashMap<mesh_dm::space::SpaceId, std::collections::BTreeSet<[u8; 16]>>,
    /// What `spaceForge` set (debug builds only).
    #[cfg(debug_assertions)]
    forge: spaces::Forge,
    space_mailed: HashMap<[u8; 32], std::time::Instant>,
    /// When each device last said it was typing (rate limit, D10).
    typing_last: HashMap<[u8; 32], std::time::Instant>,
    /// The call, if any (SPEC-calls).
    calls: calls::Calls,
    /// `--no-calls`.
    no_calls: bool,
    /// Hide my IP (P6): no direct node, everyone relayed.
    hide_ip: bool,
    /// A device link in progress (PLAN-link), and which session it is.
    link: Option<link::Linking>,
    link_session: u64,
    /// Mail's marks and puts under way (SPEC-mailbox).
    mail: mail::Mail,
}

struct Net {
    node: crate::nodes::Nodes,
    /// What a rotated direct node starts with (P4), besides its key.
    direct_config: Config,
    /// The direct node's loops, stopped when it's replaced.
    direct_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The throwaway identity's node, for seeds only (D7b).
    anon: Arc<Node>,
    /// Its address gets' budget, shared by every lookup (S14).
    gets: routing::Gets,
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

/// Envelopes another device sent: who, which device, each frame, and where
/// to send each frame's answer if it asked (dm).
type Incoming = (
    MeshId,
    MeshAddr,
    e2ee::Frames,
    Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
);
/// Chat events sent to a device: whose, which device, their numbers, and
/// each one's answer (`None`: no answer came).
type Answered = (MeshId, MeshAddr, Vec<u64>, Option<Vec<bool>>);

/// What a background request found out.
enum Back {
    /// A device told us its direct key (connection-privacy P3): who, the
    /// cert (its device is the one that sent it) and its relay.
    Direct(Box<(MeshId, DirectCert, String)>),
    /// A rotated direct key's node started (P4).
    DirectStarted(Box<(Node, DirectCert)>),
    /// One of this owner's devices took these reports (P11).
    ReportTaken(Box<(MeshId, Vec<reports::Report>)>),
    /// The direct node has a relay now, so friends can be told it.
    DirectOnline,
    /// A history stream's request (SPEC-spaces S10).
    HistoryAsk(Box<spaces::HistoryAsked>),
    /// One frame of a history pull.
    HistoryBatch(Box<(mesh_dm::space::SpaceId, Vec<Vec<u8>>)>),
    /// A history pull ended.
    HistoryDone(mesh_dm::space::SpaceId),
    /// Space mail none of the holders took: mailed again at the refresh.
    SpaceMailUntaken(Vec<([u8; 32], u64)>),
    /// A device answered a batch of Space events (or didn't).
    SpaceAnswered(Box<spaces::Answered>),
    /// A peer's dial (SPEC-spaces S14) came back: how it went,
    /// and whether it was a hello.
    Hello(MeshId, spaces::Dialled, bool),
    /// Each code, and the best answer any seed gave (`None`: none answered).
    Held(Vec<(FriendCode, Option<Hold>)>),
    /// The home relay changed (or came up): records go out again.
    Relay,
    /// Whether the seeds took every record, whether they carried keys, and
    /// whether that was all our records or one contact's.
    Published {
        ok: bool,
        keys: bool,
        all: bool,
    },
    Republish,
    /// Contacts' records, for their e2ee keys.
    Records(Vec<(MeshId, Vec<AddrRecord>)>),
    /// Envelopes another device sent us: who, which device, each frame, and
    /// where to send the answers if it asked for them (dm).
    Envelopes(Box<Incoming>),
    /// A device answered a batch of chat events, or didn't (`None`).
    DmAnswered(Box<Answered>),
    /// Time to send again to a device that answered `failed`.
    DmRetry([u8; 32]),
    /// How a call's invites went (SPEC-calls C7).
    CallInvited([u8; 8], Vec<([u8; 32], calls::Invited)>),
    /// A call control message: whose, which device, what.
    Call(Box<(MeshId, [u8; 32], calls::CallMsg)>),
    /// Who's speaking in the call changed (device keys); only with audio.
    #[cfg_attr(not(feature = "audio"), allow(dead_code))]
    Speaking(Vec<[u8; 32]>),
    /// A typing signal: whose, which device, the frame (D10).
    Typing(Box<(MeshId, [u8; 32], Vec<u8>)>),
    /// Someone asks for a kept file's chunks: whose, the file's hash, and
    /// where to say whether they may (D12).
    BlobAsk(Box<(MeshId, [u8; 32], tokio::sync::oneshot::Sender<bool>)>),
    /// A file came, or didn't: where it's wanted for (D12).
    Fetched(Box<files::Fetched>),
    /// A device offers its person's profile at this version: whose, the
    /// version, where to say whether we want it (SPEC-profile PR3).
    ProfileOffer(Box<(MeshId, u64, tokio::sync::oneshot::Sender<bool>)>),
    /// A device sent its person's profile manifest: whose, the device, the bytes.
    Profile(Box<(MeshId, [u8; 32], Vec<u8>)>),
    /// A profile file came, or didn't.
    ProfileFetched(Box<profile::ProfileFetched>),
    /// A friend's Top 8 message (SPEC-profile PR11).
    Top8(Box<(MeshId, top8::Msg)>),
    /// A friend's device took our Top 8 message.
    Top8Sent(Box<(MeshId, top8::Msg)>),
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
    /// What a mail collect found (mailbox), the holders where our claims
    /// were gone, whether it was the unlock's (not a refresh's), and the
    /// holders that answered all six weeks.
    MailFound(Vec<mail::Found>, Vec<String>, bool, Vec<String>),
    /// Mail records read: whose, and the sealed records found; with a
    /// time, it was the round's read and a seed answered.
    MailRecords(Vec<(MeshId, Vec<Vec<u8>>)>, Option<u64>),
    /// A holder answered our claims: which, when they were sent, and
    /// whether that renews them (all of them, none slowed).
    MailClaimed(String, u64, bool),
    /// A seed answered the round's record puts (when they were sent).
    MailPut(u64),
    /// Puts answered: where each was taken, and what none took.
    MailPutDone(mail::Taken),
    /// Another of our devices sent its account state.
    Synced(Box<(Account, MeshAddr)>),
    /// A device of someone's said what it shows, or went quiet.
    /// Their username comes with it (empty from an older helper).
    Presence(Box<(MeshId, [u8; 32], Option<Presence>, String)>),
    /// A link session's news, with the session it's from.
    Link(u64, link::LinkEvent),
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
            friends: Arc::default(),
            reports: reports::Reports::default(),
            direct_cert: None,
            record_ttl: routing::RECORD_TTL,
            cut: None,
            cut_live: false,
            crash_at_records: false,
            holders: Vec::new(),
            publish_retry: PUBLISH_RETRY,
            presence: HashMap::new(),
            idle: false,
            shown: tokio::sync::watch::Sender::new(Presence::Online),
            e2ee: None,
            devices_at: HashMap::new(),
            waiting: HashMap::new(),
            unopened: Vec::new(),
            link: None,
            link_session: 0,
            dm: None,
            dm_flight: HashSet::new(),
            dm_retry: HashMap::new(),
            dm_open: None,
            spaces: None,
            wire: spaces::PeerWire::new(spaces::PEER_IDLE),
            space_open: HashMap::new(),
            space_flight: HashSet::new(),
            space_retry: HashMap::new(),
            space_soon: spaces::Soon::default(),
            space_counts: spaces::Counts::default(),
            space_view: None,
            space_sent: HashMap::new(),
            space_marked: HashSet::new(),
            space_pulls: HashMap::new(),
            keys_fetching: e2ee::Fetching::default(),
            dialling: e2ee::Fetching::default(),
            space_redone: HashMap::new(),
            #[cfg(debug_assertions)]
            forge: spaces::Forge::default(),
            space_mailed: HashMap::new(),
            typing_last: HashMap::new(),
            mail: mail::Mail::default(),
            calls: calls::Calls::default(),
            no_calls: false,
            hide_ip: false,
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
            "cutOff" => {
                // Test-only: the seeds come back (`--cut seed`).
                if let Some(seeds) = self.cut.take() {
                    self.seeds = seeds;
                }
                self.cut_live = false;
                self.allow_contacts();
                self.dial_contacts();
                self.publish();
                self.mail_renew();
                self.mail_out_all();
                self.emit_net();
            }
            "idLock" => {
                self.mail_flush().await;
                self.store = None;
                self.link = None;
                self.stop_net().await;
                self.emit_identity();
            }
            "idRemove" => self.remove_identity(arg(0)?).await?,
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
                self.contacts_changed(Some(&id));
                self.dial(&id);
                self.changed(Some(func));
            }
            "friendAccept" => {
                let id = parse_id(arg(0)?)?;
                self.unlocked()?.accept(&id)?;
                self.contacts_changed(Some(&id));
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
                let gets = self
                    .net
                    .as_ref()
                    .map(|n| n.gets.for_("contact"))
                    .unwrap_or_default();
                if !node.status().online {
                    return Err(Fail("offline", "not connected to a relay yet".to_owned()));
                }
                let (seeds, back) = (self.seeds.clone(), self.back.clone());
                tokio::spawn(async move {
                    let mut found = Vec::new();
                    let reached =
                        routing::reach(node, &anon, &gets, &seeds, &target, unix_now(), &mut found)
                            .await;
                    if !found.is_empty() {
                        let _ = back.send(Back::Records(vec![(id, found)]));
                    }
                    match reached {
                        Ok(Reached { pong, last, list }) => {
                            emit_pong(&pong);
                            let _ = back.send(Back::Reached(Box::new((id, last, list))));
                        }
                        Err(e) => {
                            let (kind, message) = match e {
                                ReachError::Unreachable => {
                                    ("unreachable", "couldn't reach any of their devices")
                                }
                                ReachError::Slowed => (
                                    "slow-down",
                                    "the seed asked us to slow down; try again soon",
                                ),
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
            "linkStart" => self.link_start()?,
            "fxScan" => self.fx_scan(args.first().map_or("{}", String::as_str))?,
            f if f.starts_with("dm") => self.dm_command(f, args)?,
            f if f.starts_with("call")
                || f.starts_with("voice")
                || matches!(f, "audioTest" | "fxChain" | "fxRestart" | "fxEdit" | "fxEditClose" | "fxParams" | "fxParam" | "fxSave") =>
            {
                self.call_command(f, args)?
            }
            f if f.starts_with("space") || f.starts_with("card") => self.space_command(f, args)?,
            f if f.starts_with("profile") => self.profile_command(f, args)?,
            f if f.starts_with("top8") => self.top8_command(f, args)?,
            "linkJoin" => self.link_join(arg(0)?, arg(1)?)?,
            "linkConfirm" => self.link_confirm(arg(0)? == "true")?,
            "linkCancel" => self.link_cancel()?,
            "linkFinish" => self.link_finish(arg(0)?, arg(1)?).await?,
            "netStatus" => self.emit_net(),
            "netPrivacy" => {
                let hide = match arg(0)? {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(Fail(
                            "bad-argument",
                            "netPrivacy takes true or false".into(),
                        ));
                    }
                };
                self.set_hide_ip(hide);
                emit("meshDone", json!({ "fn": func }));
            }
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
    fn node(&mut self) -> Result<crate::nodes::Nodes, Fail> {
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

    fn publish(&mut self) {
        self.publish_only(None);
    }

    /// The contacts changed: let in exactly them, and leave records for them
    /// (`only` the one that changed, when it's one).
    fn contacts_changed(&mut self, only: Option<&MeshId>) {
        self.allow_contacts();
        // A former friend's profile goes (SPEC-profile PR15).
        self.profile_prune();
        self.publish_only(only);
        // Mail for them must have somewhere to go before the next renewal,
        // and where to mail them must be known before it's needed.
        self.mail_claim(only);
        self.mail_records_put(only);
        self.mail_records_read(only);
    }

    /// They're no longer let in; their records lapse (routing D4).
    fn cut_off(&self, id: &MeshId) {
        self.allow_contacts();
        self.profile_prune();
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

    /// A device address of `id`'s from their records or a connection, as
    /// a last address to try before a lookup.
    pub(super) fn known_last(&self, id: &MeshId) -> Option<LastAddr> {
        let (device, (_, addr)) = self.devices_at.iter().find(|(_, (owner, _))| owner == id)?;
        Some(LastAddr {
            device: *device,
            relay: addr.relay.as_ref()?.to_string(),
        })
    }

    fn dial(&self, id: &MeshId) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if self.cut_live {
            return;
        }
        let Some(target) = Target::of(store, id) else {
            return;
        };
        if self.dialling.claim(vec![*id]).is_empty() {
            return;
        }
        let (node, anon, gets) = (net.node.clone(), net.anon.clone(), net.gets.for_("contact"));
        let (seeds, back, id) = (self.seeds.clone(), self.back.clone(), *id);
        let dialling = self.dialling.clone();
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
                if !found.is_empty() {
                    let _ = back.send(Back::Records(vec![(id, found)]));
                }
                let again = dialling.done(&id);
                if reached.is_ok() && again {
                    dialling.done(&id);
                }
                if reached.is_ok() || !again {
                    break reached;
                }
            };
            if let Ok(Reached { last, list, .. }) = reached {
                let _ = back.send(Back::Reached(Box::new((id, last, list))));
            }
        });
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
            Back::Link(session, event) => return self.link_back(session, event),
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
                        self.envelopes(id, from, vec![frame], None);
                    } else {
                        self.unopened.push((id, from, frame));
                    }
                }
                // Space events that waited for their keys go now (a peer we
                // never met: their keys come only from records).
                for id in learned {
                    self.space_deliver(&id);
                    self.report_deliver(&id);
                }
                return;
            }
            Back::Envelopes(got) => {
                let (id, from, frames, reply) = *got;
                return self.envelopes(id, from, frames, reply);
            }
            Back::BlobAsk(got) => {
                let (id, hash, answer) = *got;
                let may = self.may_fetch(&id, &hash) || self.may_fetch_profile(&id, &hash);
                let _ = answer.send(may);
                return;
            }
            Back::Fetched(got) => return self.fetched(*got),
            Back::ProfileOffer(got) => {
                let (id, version, answer) = *got;
                let _ = answer.send(self.profile_offered(&id, version));
                return;
            }
            Back::Profile(got) => {
                let (id, device, bytes) = *got;
                return self.profile_heard(id, device, &bytes);
            }
            Back::ProfileFetched(got) => return self.profile_fetched(*got),
            Back::Top8(got) => {
                let (id, msg) = *got;
                return self.top8_heard(id, msg);
            }
            Back::Top8Sent(got) => return self.top8_sent(*got),
            Back::Typing(got) => {
                let (id, device, frame) = *got;
                return self.typing_heard(id, device, frame);
            }
            Back::CallInvited(id, rang) => return self.call_invited(id, rang),
            Back::Call(got) => {
                let (id, device, msg) = *got;
                return self.call_heard(id, device, msg);
            }
            Back::Speaking(who) => return self.call_speaking(who),
            Back::DmAnswered(got) => {
                let (id, addr, numbers, answers) = *got;
                return self.dm_answered(id, addr, numbers, answers);
            }
            Back::DmRetry(device) => {
                if let Some((id, addr)) = self.dm_retry.get(&device).cloned() {
                    self.dm_deliver_to(&id, addr);
                }
                return;
            }
            Back::Unsent(unsent) => {
                let (device, envelopes) = *unsent;
                if self.net.is_some() {
                    e2ee::wait(&mut self.waiting, device, envelopes);
                }
                return;
            }
            Back::Republish => return self.publish(),
            Back::Published { ok, keys, all } => {
                // One contact's record going up says nothing about the rest.
                if let Some(net) = self.net.as_ref().filter(|_| all || !ok) {
                    net.published.store(ok, Ordering::Relaxed);
                    net.keys.store(ok && keys, Ordering::Relaxed);
                }
                if ok {
                    if all {
                        self.publish_retry = PUBLISH_RETRY;
                        // The seeds answer: a holder still owed the unlock's
                        // weeks is collected now, not at the refresh.
                        self.mail_seeds_answer();
                    }
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
            Back::Hello(id, how, hello) => return self.hello_back(&id, how, hello),
            Back::SpaceMailUntaken(untaken) => return self.space_mail_untaken(untaken),
            Back::HistoryAsk(asked) => return self.history_asked(*asked),
            Back::HistoryBatch(batch) => {
                let (space, events) = *batch;
                return self.history_batch(space, events);
            }
            Back::HistoryDone(space) => return self.history_done(space),
            Back::SpaceAnswered(answered) => {
                let (id, addr, numbers, answers) = *answered;
                return self.space_answered(id, addr, numbers, answers);
            }
            Back::Reached(reached) => {
                let (id, last, list) = *reached;
                self.peer_used(&id);
                // Over an open connection there's no address to keep, but
                // it's a handshake: seen (SPEC-routing `seen`).
                let saved = (self.store.as_mut()).map(|store| match last {
                    Some(last) => store.contact_reached(&id, last, list.as_ref()),
                    None => match store.contact_seen(&id) {
                        Err(mesh_identity::KeystoreError::NotAContact) => Ok(()),
                        seen => seen,
                    },
                });
                if let Some(Err(e)) = saved {
                    eprintln!("mesh-node: couldn't save a contact's address: {e}");
                }
                if list.is_some() {
                    // A newer list of theirs may have removed a device.
                    self.allow_contacts();
                }
                let promoted = self.connected(&id);
                self.present_to(&id);
                self.offer_profile(&id);
                self.top8_deliver(&id);
                self.keys_for(&id);
                self.mail_records_missing(&id);
                self.send_waiting(&id);
                self.dm_deliver(&id);
                self.space_deliver(&id);
                self.history_again(&id);
                if promoted {
                    return self.changed(None);
                }
                return self.emit_social(None);
            }
            Back::MailFound(found, wiped, unlock, paid) => {
                return self.mail_found(found, wiped, unlock, paid);
            }
            Back::MailRecords(found, round) => {
                if let Some(at) = round {
                    self.mail.read_at = at;
                }
                return self.mail_records(found);
            }
            Back::MailClaimed(ticket, at, full) => return self.mail_claimed(ticket, at, full),
            Back::MailPut(at) => return self.mail.put_at = at,
            Back::MailPutDone(taken) => return self.mail_put_done(taken),
            Back::Connected(id) => {
                self.peer_heard(&id);
                self.send_waiting(&id);
                self.dm_deliver(&id);
                self.space_deliver(&id);
                self.report_deliver(&id);
                self.history_again(&id);
                if self.store.as_ref().is_some_and(|s| s.id() == id) {
                    // Another of our devices: it sends its state; we answer
                    // with ours if it's missing something (`Back::Synced`).
                    self.offer_profile(&id);
                    return self.tell_direct(&id);
                }
                if self.connected(&id) {
                    self.changed(None);
                }
                self.keys_for(&id);
                self.mail_records_missing(&id);
                self.offer_profile(&id);
                self.top8_deliver(&id);
                return self.present_to(&id);
            }
            Back::Synced(synced) => {
                let (theirs, from) = *synced;
                let own = self.store.as_ref().map(Keystore::id);
                if let Some(own) = own {
                    self.send_waiting(&own);
                    self.dm_deliver(&own);
                }
                return self.synced(&theirs, &from);
            }
            Back::Direct(told) => {
                let (id, cert, relay) = *told;
                return self.direct_heard(&id, &cert, &relay);
            }
            Back::DirectOnline => return self.tell_direct_all(),
            Back::ReportTaken(taken) => {
                let (owner, sent) = *taken;
                return self.report_taken(&owner, &sent);
            }
            Back::DirectStarted(started) => {
                let (node, cert) = *started;
                return self.direct_started(node, cert);
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
                self.contacts_changed(Some(&id));
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

    /// Looks up the records of every contact (or only `id`) and our own,
    /// for their e2ee keys, in the background.
    fn fetch_keys(&self, only: Option<&MeshId>) {
        let (Some(store), Some(net), Some(e2ee)) = (&self.store, &self.net, &self.e2ee) else {
            return;
        };
        if self.seeds.is_empty() {
            return;
        }
        // Every contact; and Space peers whose keys we haven't got yet, whose
        // only source is their records (SPEC-spaces S2).
        let ids: Vec<MeshId> = match only {
            Some(id) => vec![*id],
            None => (store.contacts().iter().map(|c| c.id()))
                .chain(
                    store
                        .peers()
                        .iter()
                        .map(|c| c.id())
                        .filter(|id| !e2ee.knows(id)),
                )
                .collect(),
        };
        let mut ids = ids;
        if only.is_none() {
            ids.push(store.id());
        }
        // Not those whose lookup is under way: its answer covers them.
        let ids = self.keys_fetching.claim(ids);
        let me = store.id();
        // One task per person, each waiting its turn in the get budget: a
        // slow one holds up nobody else, and each is released when its own
        // answer comes.
        for id in ids {
            let target = match id == me {
                true => Target::own(store),
                false => Target::of(store, &id),
            };
            let Some(target) = target else {
                self.keys_fetching.forget(&id);
                continue;
            };
            let (anon, seeds, back) = (net.anon.clone(), self.seeds.clone(), self.back.clone());
            let (gets, fetching) = (net.gets.for_("keys"), self.keys_fetching.clone());
            tokio::spawn(async move {
                // Again if asked meanwhile and nothing came: their record may
                // not have been put when this one read.
                loop {
                    let found = e2ee::fetch(
                        &anon,
                        &gets,
                        &seeds,
                        std::slice::from_ref(&target),
                        unix_now(),
                    )
                    .await;
                    let again = fetching.done(&id);
                    if !found.is_empty() && again {
                        fetching.done(&id);
                    }
                    if !found.is_empty() || !again {
                        let _ = back.send(Back::Records(found));
                        break;
                    }
                }
            });
        }
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
    fn envelopes(
        &mut self,
        id: MeshId,
        from: MeshAddr,
        frames: e2ee::Frames,
        reply: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
    ) {
        self.envelopes_in(id, from, frames, reply, None);
    }

    /// `envelopes`, and with `mail`, as collected mail is opened (SPEC-mailbox
    /// M8): no fresh session is sent back for what can't be opened, nothing
    /// is logged per envelope, and the chat events are put on `mail` (by
    /// frame) for the caller to hand to dm in order, rather than taken here.
    pub(super) fn envelopes_in(
        &mut self,
        id: MeshId,
        from: MeshAddr,
        frames: e2ee::Frames,
        reply: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
        mut mail: Option<&mut Vec<dm::Taking>>,
    ) {
        let device = *from.device.as_bytes();
        // A relay we read in a record beats a bare connection address.
        self.devices_at.entry(device).or_insert((id, from.clone()));
        // Each frame's answer, if the sender asked (dm): ok unless it fails.
        let mut answers = vec![0u8; frames.len()];
        let Some(e2ee) = self.e2ee.as_mut() else {
            if let Some(reply) = reply {
                let _ = reply.send(vec![1; answers.len()]);
            }
            return;
        };
        let mut replies = Vec::new();
        let mut notes = Vec::new();
        let mut events = Vec::new();
        let mut synced = Vec::new();
        let mut space_in = Vec::new();
        let mut reports_in = Vec::new();
        let (mut unknown, mut fresh) = (false, false);
        let envelopes: Vec<Vec<u8>> = frames.iter().map(|(_, e)| e.clone()).collect();
        // One save for the whole stream (PLAN-dm Task 8).
        let opened = match mail {
            Some(_) => e2ee.decrypt_mail_batch(&envelopes, unix_now()),
            None => e2ee.decrypt_batch(&envelopes, unix_now()),
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(e) => {
                eprintln!("mesh-node: couldn't save e2ee state: {e}");
                if let Some(reply) = reply {
                    let _ = reply.send(vec![1; answers.len()]);
                }
                return;
            }
        };
        for (i, ((flags, envelope), result)) in frames.into_iter().zip(opened).enumerate() {
            match result {
                Err(E2eeError::UnknownSender) => {
                    // ponytail: kept in memory, 256 at most; `mailbox` keeps mail for real.
                    if self.unopened.len() < 256 && mail.is_none() {
                        self.unopened.push((id, from.clone(), (flags, envelope)));
                    }
                    unknown = true;
                    answers[i] = 1;
                }
                Ok(got) => {
                    // Opened, but nothing in it: a fresh session (e2ee D4).
                    fresh |= got.opened.is_empty() && got.replies.is_empty();
                    for opened in got.opened {
                        // On a live connection the sender is the device at
                        // the other end; nobody passes envelopes on yet.
                        if opened.sender != id || opened.device.to_bytes() != device {
                            eprintln!(
                                "mesh-node: an envelope's sender wasn't the device that sent it"
                            );
                            continue;
                        }
                        if opened.kind == NoteKind::Message {
                            // A Space event (SPEC-spaces): its own layout.
                            let first = opened.body.first().copied();
                            if first == Some(reports::REPORT_LAYOUT) {
                                reports_in.push(opened.body);
                                continue;
                            }
                            if first == Some(mesh_dm::space_store::SPACE_LAYOUT)
                                || first == Some(mesh_dm::space_store::SPACE_BATCH)
                            {
                                let own = self.store.as_ref().is_some_and(|s| s.id() == id);
                                space_in.push(spaces::SpaceIn {
                                    frame: i,
                                    own,
                                    body: opened.body,
                                });
                                continue;
                            }
                            // History from another of our devices (dm D8)
                            // carries its chat, author and first arrival.
                            if opened.conversation == Conversation::Direct(id)
                                && opened.sender == id
                                && self.store.as_ref().is_some_and(|s| s.id() == id)
                            {
                                match dm::read_forward(&opened.body) {
                                    Ok(forwarded) => synced.push((i, forwarded)),
                                    Err(answer) => {
                                        eprintln!("mesh-node: synced history didn't read");
                                        answers[i] = answer;
                                    }
                                }
                                continue;
                            }
                            // A bad event is dropped and counted (dm D14);
                            // a newer one waits on its sender.
                            match dm::read_friend(&opened.body) {
                                Ok((group, event)) => events.push((i, group, event)),
                                Err(answer) => {
                                    eprintln!("mesh-node: a chat event didn't read");
                                    answers[i] = answer;
                                }
                            }
                            continue;
                        }
                        notes.push((opened, flags & e2ee::WAITED != 0));
                    }
                    replies.extend(got.replies);
                }
                Err(e) => {
                    // Mail that can't be opened is counted by the caller.
                    if mail.is_none() {
                        eprintln!("mesh-node: couldn't open an envelope: {e}");
                    }
                    answers[i] = dm::CANT_OPEN;
                }
            }
        }
        match mail.as_mut() {
            Some(mail) => mail.extend(events),
            None if !events.is_empty() => self.dm_take(&id, &device, events, &mut answers),
            None => {}
        }
        if !synced.is_empty() {
            self.dm_take_synced(&device, synced, &mut answers);
        }
        for body in reports_in {
            self.report_heard(&id, &body);
        }
        if !space_in.is_empty() {
            self.space_take(&id, &device, space_in, &mut answers);
        }
        if let Some(reply) = reply {
            let _ = reply.send(answers);
        }
        if fresh {
            // What they haven't acknowledged goes again on the new session.
            self.dm_deliver(&id);
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
            store
                .reachable_contact(&opened.sender)
                .and_then(|c| c.devices())
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
            return e2ee::wait(&mut self.waiting, device, envelopes);
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
        self.open_dm();
        self.open_spaces();
        self.reports_load();
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
        let admits = move |id: &MeshId, device: &mesh_transport::PublicKey| {
            // A device not in the newest list we hold may be newly linked;
            // only one that list removed is refused.
            let allowed = allowed
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            allowed
                .get(&id.to_bytes())
                .is_some_and(|revoked| !revoked.contains(device.as_bytes()))
        };
        let (admitted, friends) = (admits.clone(), self.friends.clone());
        // The direct node lets in only our own devices and friends (P3).
        let direct_allow = Allow::only(move |id, device| {
            admitted(id, device)
                && (friends.read())
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&id.to_bytes())
        });
        let config = Config {
            relays: self.relays.clone(),
            allow: Allow::only(admits),
            // The device key everyone may know never goes direct (P2, P3).
            relay_only: true,
            services: vec![
                crate::nodes::DIRECT.to_owned(),
                SYNC.to_owned(),
                PRESENCE.to_owned(),
                e2ee::SERVICE.to_owned(),
                dm::TYPING.to_owned(),
                files::BLOB.to_owned(),
                profile::SERVICE.to_owned(),
                top8::SERVICE.to_owned(),
                spaces::SPACE_HISTORY.to_owned(),
            ]
            .into_iter()
            .chain((!self.no_calls).then(|| calls::CALL.to_owned()))
            .collect(),
            ..Config::default()
        };
        self.allow_contacts();
        let Some(store) = &self.store else { return };
        let (direct_key, direct_cert) = DirectCert::issue(store.device_key(), self.direct_issued());
        let direct_config = Config {
            relay_only: false,
            allow: direct_allow,
            direct: Some(direct_cert.clone()),
            ..config.clone()
        };
        let hide_ip = self.hide_ip;
        let started = async {
            let relay = Node::start(store.device_key(), cert, config).await;
            // Hide my IP (P6): no direct node at all, so nothing can reach one.
            let direct = match hide_ip {
                true => None,
                false => Some(Node::start(&direct_key, cert, direct_config.clone()).await),
            };
            let anon = anon_node(self.relays.clone()).await?;
            Ok::<_, String>((
                relay.map_err(|e| e.to_string())?,
                direct.transpose().map_err(|e| e.to_string())?,
                anon,
            ))
        };
        match started.await {
            Ok((relay, direct, anon)) => {
                let (relay, direct) = (Arc::new(relay), direct.map(Arc::new));
                let node = crate::nodes::Nodes::new(relay.clone(), direct.clone());
                self.direct_cert = direct.is_some().then_some(direct_cert);
                let published = Arc::new(AtomicBool::new(false));
                let keys = Arc::new(AtomicBool::new(false));
                let watch = tokio::spawn(watch_net(
                    node.clone(),
                    published.clone(),
                    keys.clone(),
                    self.back.clone(),
                ));
                let peers = tokio::spawn(watch_peers(relay.clone(), self.back.clone()));
                let own = self.store.as_ref().map(Keystore::id).expect("unlocked");
                let streams = tokio::spawn(serve_streams(
                    relay,
                    own,
                    self.blobs_dir(),
                    self.back.clone(),
                ));
                // Friends who connect before the direct node has a relay
                // aren't told it then; they are once it has one.
                let direct_tasks = match direct {
                    Some(direct) => {
                        let (back, waiting) = (self.back.clone(), direct.clone());
                        tokio::spawn(async move {
                            if waiting.online(Duration::from_secs(30)).await {
                                let _ = back.send(Back::DirectOnline);
                            }
                        });
                        self.direct_tasks(direct)
                    }
                    None => Vec::new(),
                };
                self.net = Some(Net {
                    direct_config,
                    direct_tasks,
                    node,
                    anon: Arc::new(anon),
                    gets: routing::Gets::default(),
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
                self.mail_load();
                self.mail_collect();
            }
            Err(e) => eprintln!("mesh-node: networking didn't start: {e}"),
        }
    }

    /// The loops a direct node needs: who connects, and their streams.
    fn direct_tasks(&self, direct: Arc<Node>) -> Vec<tokio::task::JoinHandle<()>> {
        let own = self.store.as_ref().map(Keystore::id).expect("unlocked");
        vec![
            tokio::spawn(watch_peers(direct.clone(), self.back.clone())),
            tokio::spawn(serve_streams(
                direct,
                own,
                self.blobs_dir(),
                self.back.clone(),
            )),
        ]
    }

    /// A new direct key (P4): when someone stops being a friend, and every
    /// 7 days. The new node starts in the background (`Back::DirectStarted`).
    fn rotate_direct(&self) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if self.hide_ip {
            return;
        }
        let now = unix_now();
        let path = self.path.with_file_name("direct-issued");
        if let Err(e) = std::fs::write(&path, now.to_string()) {
            eprintln!("mesh-node: couldn't keep the direct key's time: {e}");
        }
        let this = store.device_key().public();
        let Some(cert) = (store.devices().devices().iter())
            .find(|d| *d.device() == this)
            .cloned()
        else {
            return;
        };
        let (key, direct) = DirectCert::issue(store.device_key(), now);
        let config = Config {
            direct: Some(direct.clone()),
            ..net.direct_config.clone()
        };
        let back = self.back.clone();
        tokio::spawn(async move {
            match Node::start(&key, &cert, config).await {
                // Friends are told its relay, so it needs one first.
                Ok(node) if node.online(Duration::from_secs(10)).await => {
                    let _ = back.send(Back::DirectStarted(Box::new((node, direct))));
                }
                Ok(node) => {
                    eprintln!("mesh-node: the new direct key's node found no relay");
                    node.close().await;
                }
                Err(e) => eprintln!("mesh-node: the new direct key's node didn't start: {e}"),
            }
        });
    }

    /// The rotated direct node is up: it replaces the old one, friends and
    /// our devices are told, and the old one closes once they've heard.
    fn direct_started(&mut self, node: Node, cert: DirectCert) {
        if self.net.is_none() || self.hide_ip {
            // Locked, or Hide my IP turned on, meanwhile.
            tokio::spawn(async move { node.close().await });
            return;
        }
        let node = Arc::new(node);
        let tasks = self.direct_tasks(node.clone());
        let net = self.net.as_mut().expect("checked");
        let old = net.node.swap_direct(Some(node));
        let old_tasks = std::mem::replace(&mut net.direct_tasks, tasks);
        self.direct_cert = Some(cert);
        self.tell_direct_all();
        // Friends were just told the new key; the old one reaches nothing now.
        tokio::spawn(async move {
            for task in old_tasks {
                task.abort();
            }
            if let Some(old) = old {
                old.close().await;
            }
        });
    }

    /// Hide my IP on or off (P6). On: the direct node closes, so the key
    /// friends hold reaches nothing, and everyone is relayed. Off: a new
    /// direct key (rotation's path), which friends are told.
    fn set_hide_ip(&mut self, hide: bool) {
        if hide == self.hide_ip {
            return;
        }
        self.hide_ip = hide;
        let Some(net) = &mut self.net else { return };
        if hide {
            let old = net.node.swap_direct(None);
            let tasks = std::mem::take(&mut net.direct_tasks);
            self.direct_cert = None;
            tokio::spawn(async move {
                for task in tasks {
                    task.abort();
                }
                if let Some(old) = old {
                    old.close().await;
                }
            });
        } else {
            self.rotate_direct();
        }
        self.emit_net();
    }

    /// Tells our connected devices and friends our direct key (P3).
    fn tell_direct_all(&self) {
        let told: Vec<MeshId> = self
            .store
            .iter()
            .flat_map(|store| {
                std::iter::once(store.id()).chain(
                    (store.account().entries().iter())
                        .filter(|e| e.kind == Kind::Friend)
                        .map(|e| e.id()),
                )
            })
            .collect();
        for id in &told {
            self.tell_direct(id);
        }
    }

    /// Rotates the direct key once it's 7 days old (P4).
    fn rotate_if_old(&self) {
        let issued = self.direct_cert.as_ref().map(DirectCert::issued_at);
        if issued.is_some_and(|at| unix_now().saturating_sub(at) >= DIRECT_LIFE) {
            self.rotate_direct();
        }
    }

    /// When the direct key in use was issued (P4): kept beside the identity,
    /// so the key stays the same across restarts. A missing or unreadable
    /// file, or a key 7 days old, starts a new key, which is the safe side.
    fn direct_issued(&self) -> u64 {
        let path = self.path.with_file_name("direct-issued");
        let kept = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|at| unix_now().saturating_sub(*at) < DIRECT_LIFE);
        kept.unwrap_or_else(|| {
            let now = unix_now();
            if let Err(e) = std::fs::write(&path, now.to_string()) {
                eprintln!("mesh-node: couldn't keep the direct key's time: {e}");
            }
            now
        })
    }

    /// Closes every connection (they're told it's locked) and the node.
    async fn stop_net(&mut self) {
        // Locking or quitting hangs up.
        self.call_hangup_now();
        if let Some(net) = self.net.take() {
            net.watch.abort();
            net.peers.abort();
            net.streams.abort();
            for task in &net.direct_tasks {
                task.abort();
            }
            net.anon.close().await;
            net.node.close().await;
            self.held.clear();
            self.publish_retry = PUBLISH_RETRY;
            self.presence.clear();
            emit_net(None, false, false, self.hide_ip);
        }
        self.e2ee = None;
        if self.dm.take().is_some() {
            self.clear_opened(|_| true);
        }
        self.dm_flight.clear();
        self.dm_retry.clear();
        self.dm_open = None;
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
            .chain((store.reachable()).map(|c| (c.id().to_bytes(), revoked(c.devices()))))
        });
        // `--cut live`: our own devices still connect; contacts don't.
        let ids = ids.take(if self.cut_live { 1 } else { usize::MAX });
        *self
            .allowed
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ids.collect();
        let friends = self.store.iter().flat_map(|store| {
            std::iter::once(store.id().to_bytes()).chain(
                (store.account().entries().iter())
                    .filter(|e| e.kind == mesh_identity::Kind::Friend)
                    .map(|e| e.id().to_bytes()),
            )
        });
        let friends: HashSet<[u8; 32]> = friends
            .take(if self.cut_live { 1 } else { usize::MAX })
            .collect();
        let before = std::mem::replace(
            &mut *self
                .friends
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            friends.clone(),
        );
        // Someone stopped being a friend: they knew the direct key (P4, P5).
        if before.iter().any(|id| !friends.contains(id)) {
            if let Some(net) = &self.net {
                net.node
                    .forget_all_but(|id| friends.contains(&id.to_bytes()));
            }
            self.rotate_direct();
        }
        if let Some(net) = &self.net {
            net.node.prune();
        }
    }

    /// Sends this device's record for every contact to the seeds, in the
    /// background; `meshNet` says when they're there.
    /// With `only`, just that contact's record: one change mustn't put
    /// every record again (audit finding 9).
    fn publish_only(&mut self, only: Option<&MeshId>) {
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
        let (now, keys, all) = (unix_now(), self.e2ee.is_some(), only.is_none());
        let mut e2ee = self.e2ee.as_mut();
        let records = routing::records(store, &relay, now, self.record_ttl, only, |id| {
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
            let _ = back.send(Back::Published { ok, keys, all });
        });
    }

    fn emit_net(&self) {
        match &self.net {
            Some(net) => emit_net(
                Some(&net.node.status()),
                net.published.load(Ordering::Relaxed),
                net.keys.load(Ordering::Relaxed),
                self.hide_ip,
            ),
            None => emit_net(None, false, false, self.hide_ip),
        }
    }

    /// `fxScan {"dirs": [...], "fresh": bool}`: finds plugins in the
    /// standard folders and `dirs` on a thread of its own, then
    /// `meshFxPlugins`. `fresh` forgets the cache (Rescan).
    fn fx_scan(&self, options: &str) -> Result<(), Fail> {
        static SCANNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        let options: Value = serde_json::from_str(options)
            .map_err(|e| Fail("bad-argument", format!("fxScan takes a JSON object: {e}")))?;
        if SCANNING.swap(true, Ordering::SeqCst) {
            return Err(Fail("busy", "a plugin scan is already running".into()));
        }
        let mut dirs = crate::fxscan::standard_dirs();
        dirs.extend(
            options["dirs"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(PathBuf::from),
        );
        let cache_file = self.path.with_file_name("fx").join("scan.json");
        let fresh = options["fresh"] == true;
        std::thread::spawn(move || {
            let cache = std::fs::read(&cache_file)
                .ok()
                .filter(|_| !fresh)
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let files = crate::fxscan::find(&dirs);
            let scanner = crate::fx::mesh_fx_path();
            let (cache, _) =
                crate::fxscan::scan(&scanner, &files, &cache, crate::fxscan::SCAN_LIMIT);
            if let Some(dir) = cache_file.parent()
                && let Err(e) = std::fs::create_dir_all(dir)
                    .and_then(|()| std::fs::write(&cache_file, cache.to_string()))
            {
                eprintln!("mesh-node: couldn't save the plugin scan: {e}");
            }
            emit("meshFxPlugins", crate::fxscan::event(&cache));
            SCANNING.store(false, Ordering::SeqCst);
        });
        Ok(())
    }

    /// `idRemove <password>`: deletes this device's copy of the identity
    /// and everything it keeps (`fx/`, the computer's plugin list, stays).
    /// For good unless another device or a backup has it, so the password
    /// must be right. Ends the process afterwards, so nothing still held in
    /// memory writes a file back; Aflos starts a fresh one, which finds none.
    async fn remove_identity(&mut self, password: &str) -> Result<(), Fail> {
        let username = self.unlocked()?.username().to_owned();
        Keystore::unlock(&self.path, &username, password)?;
        if is_kept(&self.path) {
            self.unlocked()?.keep_unlocked(false)?;
        }
        self.mail_flush().await;
        self.store = None;
        self.link = None;
        self.stop_net().await;
        let dir = self.path.parent().unwrap_or(Path::new("."));
        remove_except(dir, &["fx"])
            .map_err(|e| Fail("io", format!("couldn't remove everything: {e}")))?;
        self.emit_identity();
        std::process::exit(0);
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
    throwaway_node(relays, Vec::new()).await
}

/// A node with a fresh, unsaved identity that admits anyone and answers
/// `services`: for seeds (D7b) and linking (PLAN-link L2, L3).
async fn throwaway_node(relays: Relays, services: Vec<String>) -> Result<Node, String> {
    let (root, key) = RootKey::generate()
        .and_then(|r| Ok((r, DeviceKey::generate()?)))
        .map_err(|e| format!("no randomness: {e}"))?;
    // A generic name and no date, so it says nothing about this device.
    let cert = DeviceCert::issue(&root, &key.public(), "mesh", 0).map_err(|e| e.to_string())?;
    // Relay-only, so a seed or the other device never gets this machine's
    // addresses as hole-punch candidates (SPEC-connection-privacy P9).
    let config = Config {
        relays,
        services,
        relay_only: true,
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
/// Deletes everything in `dir` but the entries named in `keep`.
fn remove_except(dir: &Path, keep: &[&str]) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if keep.iter().any(|k| entry.file_name() == *k) {
            continue;
        }
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn emit_fail(func: &str, kind: &str, message: &str) {
    emit(
        "meshError",
        json!({ "fn": func, "kind": kind, "message": message }),
    );
}

/// How long a direct key lasts before it's replaced (P4).
const DIRECT_LIFE: u64 = 7 * 86_400;

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Answers the streams other devices open to us: presence from friends (the
/// loop drops anyone else's), and sync from our own devices, one frame each.
async fn serve_streams(
    node: Arc<Node>,
    own: MeshId,
    blobs: PathBuf,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    // `blob` streams open per device (files::MAX_BLOB_STREAMS).
    let blob_streams = Arc::new(std::sync::Mutex::new(HashMap::new()));
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
        if stream.service == spaces::SPACE_HISTORY {
            tokio::spawn(spaces::serve_history(stream, back));
            continue;
        }
        if stream.service == files::BLOB {
            let (dir, open) = (blobs.clone(), blob_streams.clone());
            tokio::spawn(files::serve_blob(stream, dir, back, open));
            continue;
        }
        if stream.service == profile::SERVICE {
            tokio::spawn(profile::serve(stream, back));
            continue;
        }
        if stream.service == top8::SERVICE {
            tokio::spawn(top8::serve(stream, back));
            continue;
        }
        if stream.service == calls::CALL {
            tokio::spawn(calls::serve(stream, back.clone(), SYNC_TIMEOUT));
            continue;
        }
        if stream.service == dm::TYPING {
            tokio::spawn(async move {
                let read = mesh_transport::frame::read_frame(&mut stream.recv);
                // Nothing (a 1:1), a group's ID, or a Space's and a channel's.
                if let Ok(Ok(Some(frame))) = tokio::time::timeout(SYNC_TIMEOUT, read).await
                    && frame.len() <= 32
                {
                    let (id, device) = (stream.peer.id, *stream.peer.device.as_bytes());
                    let _ = back.send(Back::Typing(Box::new((id, device, frame))));
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
                let frames = e2ee::read(&mut stream.recv).await;
                if frames.is_empty() {
                    return;
                }
                let id = stream.peer.id;
                // Chat events want each frame answered once it's stored.
                if !frames.iter().any(|(flags, _)| flags & dm::ANSWER != 0) {
                    let _ = back.send(Back::Envelopes(Box::new((id, from, frames, None))));
                    return;
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = back.send(Back::Envelopes(Box::new((id, from, frames, Some(tx)))));
                if let Ok(Ok(answers)) = tokio::time::timeout(e2ee::SEND_TIMEOUT, rx).await {
                    dm::answer(stream.send, &answers).await;
                }
            });
            continue;
        }
        if stream.service == crate::nodes::DIRECT {
            tokio::spawn(async move {
                let read = mesh_transport::frame::read_frame(&mut stream.recv);
                let Ok(Ok(Some(frame))) = tokio::time::timeout(SYNC_TIMEOUT, read).await else {
                    return;
                };
                let Some((cert, relay)) = frame.split_at_checked(DIRECT_CERT_LEN) else {
                    return;
                };
                let (Ok(cert), Ok(relay)) =
                    (DirectCert::from_bytes(cert), std::str::from_utf8(relay))
                else {
                    return;
                };
                // Only a device's own key, said by that device.
                if cert.device().as_bytes() == stream.peer.device.as_bytes() {
                    let told = (stream.peer.id, cert, relay.to_owned());
                    let _ = back.send(Back::Direct(Box::new(told)));
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

/// Sends `meshNet` whenever the node's state changes.
// ponytail: polls once a second; switch to iroh's watchers if idle CPU says so.
async fn watch_net(
    node: crate::nodes::Nodes,
    published: Arc<AtomicBool>,
    keys: Arc<AtomicBool>,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    let mut last: Option<(Status, bool, bool)> = None;
    // The relay records last went out for, and a new one waiting to settle.
    let (mut acted, mut settling) = (None, None);
    loop {
        let flag = |f: &AtomicBool| f.load(Ordering::Relaxed);
        let now = (node.status(), flag(&published), flag(&keys));
        let relay = now.0.relay.clone();
        if relay.is_some() && relay != acted {
            // The first relay goes at once; a change waits until it holds,
            // so a flapping relay doesn't put every record each time
            // (audit finding 9).
            let since = match &settling {
                Some((r, at)) if *r == relay => *at,
                _ => tokio::time::Instant::now(),
            };
            settling = Some((relay.clone(), since));
            if acted.is_none() || since.elapsed() >= RELAY_SETTLE {
                let _ = back.send(Back::Relay);
                (acted, settling) = (relay, None);
            }
        }
        if last.as_ref() != Some(&now) {
            emit_net(Some(&now.0), now.1, now.2, node.direct().is_none());
            last = Some(now);
        }
        tokio::time::sleep(NET_POLL).await;
    }
}

/// `meshNet`: never any IP address (SPEC-transport "Endpoint"). `keys`:
/// our published records carry our e2ee keys (SPEC-e2ee).
/// `meshNet`. `paths` is each connected person's path, `direct` or `relay`
/// (connection-privacy P8), and `hideIp` whether Hide my IP is on; never
/// an address.
fn emit_net(status: Option<&Status>, published: bool, keys: bool, hide_ip: bool) {
    let payload = match status {
        None => json!({
            "state": "off", "relay": null, "direct": false, "connections": 0, "published": false,
            "keys": false, "directCount": 0, "relayedCount": 0, "paths": {}, "hideIp": hide_ip,
        }),
        Some(s) => {
            let path = |p: &NetPath| {
                if *p == NetPath::Direct {
                    "direct"
                } else {
                    "relay"
                }
            };
            let paths: serde_json::Map<String, Value> = (s.paths.iter())
                .filter_map(|(id, p)| {
                    Some((MeshId::from_bytes(id).ok()?.to_string(), json!(path(p))))
                })
                .collect();
            let direct = s
                .paths
                .iter()
                .filter(|(_, p)| *p == NetPath::Direct)
                .count();
            json!({
                "state": if s.online { "online" } else { "connecting" },
                "relay": s.relay.as_ref().map(ToString::to_string),
                "direct": s.direct,
                "connections": s.connections,
                "published": published,
                "keys": keys,
                "directCount": direct,
                "relayedCount": s.paths.len() - direct,
                "paths": paths,
                "hideIp": hide_ip,
            })
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The node for seeds and linking opens no socket, so it has no
    /// addresses to hand out as hole-punch candidates (P9).
    #[tokio::test]
    async fn the_throwaway_node_is_relay_only() {
        // A relay that never answers: enough to start, and nothing is reached.
        let relays = Relays::Custom(vec!["http://127.0.0.1:9".parse().unwrap()]);
        let node = throwaway_node(relays, Vec::new()).await.unwrap();
        assert!(node.bound_sockets().is_empty());
        assert!(node.addr().direct.is_empty());
        node.close().await;
    }
}
