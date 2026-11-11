//! The helper's side of device linking (PLAN-link). An existing device E
//! shows a link code; the new device N types it. E leaves its link node's
//! address on the seeds in an ordinary address record, keyed by Argon2id
//! from the code (L1). E's link node is a throwaway that admits anyone but
//! serves only `link` and takes one session (L2); the main node's allow
//! list never opens. N uses a throwaway node too (L3).
//!
//! The state machines (`mesh_identity::link`) run on the helper's loop; a
//! background task only carries their frames over the session's stream. A
//! child of `helper`, so it works on the same `Helper`. Nothing about a
//! link (code, address, device name) is logged.

use super::*;
use crate::addrs::Get as AddrGet;
use mesh_identity::{
    LINK_CODE_LIFETIME, LinkError, LinkInitiator, LinkRendezvous, LinkResponder, LinkedIdentity,
    normalize_username,
};
use mesh_transport::frame;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// The link node's one service.
const LINK: &str = "link";
/// Each network step's limit (L4).
const STEP: Duration = Duration::from_secs(30);
/// How long E waits for you to say yes to the new device.
const CONFIRM_WAIT: Duration = Duration::from_secs(120);
/// How long N waits for each frame. The identity comes only after you
/// confirm on E, so this must outlast E's wait for you.
const NEW_READ_WAIT: Duration = Duration::from_secs(CONFIRM_WAIT.as_secs() + STEP.as_secs());
/// How long a throwaway node has to reach its relay.
const ONLINE_WAIT: Duration = Duration::from_secs(15);

/// What the loop sends a session: a frame to write, or `None` to end it.
type ToPeer = UnboundedSender<Option<Vec<u8>>>;

/// A link in progress on this device.
pub(super) enum Linking {
    /// E: the state machine, the session's pipe, and which frame comes next.
    Existing {
        initiator: LinkInitiator,
        to_peer: ToPeer,
        step: ExistingStep,
    },
    /// N: the same, until the identity arrives.
    New {
        responder: Box<LinkResponder>,
        to_peer: ToPeer,
        step: NewStep,
    },
    /// N has the identity and waits for its username and a new password.
    Received(Box<LinkedIdentity>),
}

pub(super) enum ExistingStep {
    Hello,
    Device,
    /// The device's name, shown to you to confirm.
    Confirming(String),
}

pub(super) enum NewStep {
    Reply,
    Identity,
}

/// What a session's task reports to the loop.
pub(super) enum LinkEvent {
    /// E's record is on a seed: show the code.
    Shown { code: FriendCode, expires: u64 },
    /// A frame from the other device.
    Frame(Vec<u8>),
    /// The session ended: why, if it ended early.
    Ended(&'static str, &'static str),
}

/// A link failure as a command error.
fn link_fail(e: LinkError) -> Fail {
    let kind = match &e {
        LinkError::WrongCode => "wrong-code",
        LinkError::CodeUsed => "code-used",
        LinkError::Expired => "expired",
        LinkError::Cancelled => "cancelled",
        LinkError::Unexpected | LinkError::Malformed => "link-failed",
        LinkError::Code(c) => code_kind(c),
        LinkError::Device(_) => "device",
        LinkError::Random => "random",
    };
    Fail(kind, e.to_string())
}

fn emit_link_error(Fail(kind, message): Fail) {
    emit(
        "meshError",
        json!({ "fn": "link", "kind": kind, "message": message }),
    );
}

impl Helper {
    /// `linkStart`: E makes a code and leaves its link node's address on
    /// the seeds; `meshLink {code, expires}` once it's there.
    pub(super) fn link_start(&mut self) -> Result<(), Fail> {
        self.unlocked()?;
        let anon = self.anon()?;
        if self.seeds.is_empty() {
            return Err(Fail("no-seed", "linking needs a seed".to_owned()));
        }
        let now = unix_now();
        let (initiator, code) = LinkInitiator::new(now).map_err(link_fail)?;
        let (to_peer, from_loop) = unbounded_channel();
        let session = self.next_link();
        self.link = Some(Linking::Existing {
            initiator,
            to_peer,
            step: ExistingStep::Hello,
        });
        let (seeds, relays, back) = (self.seeds.clone(), self.relays.clone(), self.back.clone());
        let report = Report { session, back };
        tokio::spawn(async move {
            let ended = existing_session(&report, code, now, anon, seeds, relays, from_loop).await;
            report.ended(ended);
        });
        Ok(())
    }

    /// `linkJoin(code, deviceName)`: N, with no identity yet, finds E
    /// through the seeds and starts SPAKE2.
    pub(super) fn link_join(&mut self, code: &str, name: &str) -> Result<(), Fail> {
        if self.store.is_some() || Keystore::exists(&self.path) {
            return Err(Fail(
                "already-exists",
                "this device already has an identity".to_owned(),
            ));
        }
        if self.seeds.is_empty() {
            return Err(Fail("no-seed", "linking needs a seed".to_owned()));
        }
        let parsed = FriendCode::parse(code)?;
        let (responder, hello) = LinkResponder::new(code, name).map_err(link_fail)?;
        let (to_peer, from_loop) = unbounded_channel();
        let session = self.next_link();
        self.link = Some(Linking::New {
            responder: Box::new(responder),
            to_peer,
            step: NewStep::Reply,
        });
        let (seeds, relays, back) = (self.seeds.clone(), self.relays.clone(), self.back.clone());
        let report = Report { session, back };
        tokio::spawn(async move {
            let ended = new_session(&report, parsed, hello, seeds, relays, from_loop).await;
            report.ended(ended);
        });
        Ok(())
    }

    /// `linkConfirm(true|false)`: you said yes or no to the device E showed.
    pub(super) fn link_confirm(&mut self, yes: bool) -> Result<(), Fail> {
        let Some(Linking::Existing {
            mut initiator,
            to_peer,
            step: ExistingStep::Confirming(name),
        }) = self.link.take()
        else {
            return Err(no_link());
        };
        if !yes {
            if let Ok(message) = initiator.cancel() {
                let _ = to_peer.send(Some(message));
            }
            let _ = to_peer.send(None);
            emit("meshDone", json!({ "fn": "linkConfirm" }));
            return Ok(());
        }
        // The session ended a moment ago and the loop hasn't heard yet.
        if to_peer.is_closed() {
            return Err(Fail(
                "gone",
                "the new device stopped waiting; start again".to_owned(),
            ));
        }
        let message = initiator.confirm(self.unlocked()?, unix_now())?;
        let _ = to_peer.send(Some(message));
        let store = self.unlocked()?;
        let (me, devices) = (store.id(), store.devices().clone());
        if let Some(e2ee) = self.e2ee.as_mut()
            && let Err(e) = e2ee.learn_devices(&me, &devices)
        {
            eprintln!("mesh-node: couldn't save e2ee state: {e}");
        }
        self.allow_contacts();
        emit("meshLinkDone", json!({ "name": name }));
        self.emit_identity();
        self.publish();
        self.sync_own();
        Ok(())
    }

    /// `linkCancel`: stops a link on either side.
    pub(super) fn link_cancel(&mut self) -> Result<(), Fail> {
        match self.link.take() {
            Some(Linking::Existing {
                mut initiator,
                to_peer,
                step,
            }) => {
                if matches!(step, ExistingStep::Confirming(_))
                    && let Ok(message) = initiator.cancel()
                {
                    let _ = to_peer.send(Some(message));
                }
                let _ = to_peer.send(None);
            }
            Some(Linking::New { to_peer, .. }) => {
                let _ = to_peer.send(None);
            }
            Some(Linking::Received(_)) => {}
            None => return Err(no_link()),
        }
        emit("meshDone", json!({ "fn": "linkCancel" }));
        Ok(())
    }

    /// `linkFinish(username, password)`: N saves the identity it received
    /// under a password of its own (identity D11), then unlocks.
    pub(super) async fn link_finish(&mut self, username: &str, password: &str) -> Result<(), Fail> {
        let Some(Linking::Received(linked)) = self.link.take() else {
            return Err(no_link());
        };
        // Checked first, so a mistake doesn't lose the identity received.
        if normalize_username(username) != normalize_username(linked.username()) {
            self.link = Some(Linking::Received(linked));
            return Err(Fail(
                "wrong-username",
                "that isn't this identity's username".to_owned(),
            ));
        }
        let verdict = check_password(username, password);
        if !verdict.is_ok() {
            self.link = Some(Linking::Received(linked));
            return Err(Fail("weak-password", verdict.message()));
        }
        self.store = Some(Keystore::create_from_link(
            &self.path, *linked, username, password,
        )?);
        self.emit_unlocked();
        self.start_net().await;
        Ok(())
    }

    /// A session's report, back on the loop.
    pub(super) fn link_back(&mut self, session: u64, event: LinkEvent) {
        if session != self.link_session {
            return;
        }
        match event {
            LinkEvent::Shown { code, expires } if self.link.is_some() => emit(
                "meshLink",
                json!({ "code": code.to_string(), "expires": expires }),
            ),
            LinkEvent::Shown { .. } => {}
            LinkEvent::Frame(frame) => self.link_frame(&frame),
            // Finished links are already gone; anything else failed.
            LinkEvent::Ended(kind, message) => {
                if matches!(
                    self.link,
                    Some(Linking::Existing { .. } | Linking::New { .. })
                ) {
                    self.link = None;
                    emit_link_error(Fail(kind, message.to_owned()));
                }
            }
        }
    }

    /// The next frame of the session: through the state machine, and its
    /// answer back to the other device.
    fn link_frame(&mut self, frame: &[u8]) {
        let now = unix_now();
        let failed = |to_peer: &ToPeer, e: LinkError| {
            let _ = to_peer.send(None);
            emit_link_error(link_fail(e));
        };
        match self.link.take() {
            Some(Linking::Existing {
                mut initiator,
                to_peer,
                step,
            }) => {
                let step = match step {
                    ExistingStep::Hello => match initiator.receive_hello(frame, now) {
                        Ok(reply) => {
                            let _ = to_peer.send(Some(reply));
                            ExistingStep::Device
                        }
                        Err(e) => return failed(&to_peer, e),
                    },
                    ExistingStep::Device => match initiator.receive_device(frame) {
                        Ok(device) => {
                            emit("meshLinkConfirm", json!({ "name": device.name }));
                            ExistingStep::Confirming(device.name)
                        }
                        Err(e) => return failed(&to_peer, e),
                    },
                    ExistingStep::Confirming(_) => {
                        return failed(&to_peer, LinkError::Unexpected);
                    }
                };
                self.link = Some(Linking::Existing {
                    initiator,
                    to_peer,
                    step,
                });
            }
            Some(Linking::New {
                mut responder,
                to_peer,
                step,
            }) => match step {
                NewStep::Reply => match responder.receive_reply(frame) {
                    Ok(device) => {
                        let _ = to_peer.send(Some(device));
                        self.link = Some(Linking::New {
                            responder,
                            to_peer,
                            step: NewStep::Identity,
                        });
                    }
                    Err(e) => failed(&to_peer, e),
                },
                NewStep::Identity => {
                    let _ = to_peer.send(None);
                    match responder.receive_identity(frame) {
                        Ok(linked) => {
                            emit("meshLinkReceived", json!({ "username": linked.username() }));
                            self.link = Some(Linking::Received(Box::new(linked)));
                        }
                        Err(e) => emit_link_error(link_fail(e)),
                    }
                }
            },
            other => self.link = other,
        }
    }

    fn next_link(&mut self) -> u64 {
        self.link_session += 1;
        self.link_session
    }
}

fn no_link() -> Fail {
    Fail("no-link", "no link is waiting for that".to_owned())
}

/// Where a session's task reports to.
struct Report {
    session: u64,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
}

impl Report {
    fn send(&self, event: LinkEvent) {
        let _ = self.back.send(Back::Link(self.session, event));
    }

    fn ended(&self, ended: Result<(), (&'static str, &'static str)>) {
        let (kind, message) = ended.err().unwrap_or(("ended", "linking ended"));
        self.send(LinkEvent::Ended(kind, message));
    }
}

type Ended = Result<(), (&'static str, &'static str)>;

const OFFLINE: (&str, &str) = ("offline", "not connected to a relay yet");
const NO_RANDOM: (&str, &str) = ("random", "couldn't get randomness from the system");

/// The rendezvous keys, off the async threads (Argon2id, about 100 ms).
async fn rendezvous(code: FriendCode) -> Result<LinkRendezvous, (&'static str, &'static str)> {
    tokio::task::spawn_blocking(move || LinkRendezvous::new(&code))
        .await
        .map_err(|_| ("link-failed", "linking stopped"))
}

/// E: put the record, wait for N's one session, and carry its frames.
async fn existing_session(
    report: &Report,
    code: FriendCode,
    now: u64,
    anon: Arc<Node>,
    seeds: Arc<Vec<MeshAddr>>,
    relays: Relays,
    from_loop: UnboundedReceiver<Option<Vec<u8>>>,
) -> Ended {
    let rendezvous = rendezvous(code).await?;
    let node = throwaway_node(relays, vec![LINK.to_owned()])
        .await
        .map_err(|_| NO_RANDOM)?;
    let ended = async {
        if !node.online(ONLINE_WAIT).await {
            return Err(OFFLINE);
        }
        let ticket = node.addr().ticket().map_err(|_| OFFLINE)?;
        let record = rendezvous
            .seal(ticket.as_bytes(), now)
            .map_err(|_| NO_RANDOM)?;
        if !routing::publish(&anon, &seeds, &[record]).await {
            return Err(("unreachable", "no seed took the link code"));
        }
        let expires = now + LINK_CODE_LIFETIME;
        report.send(LinkEvent::Shown { code, expires });
        let left = Duration::from_secs(expires.saturating_sub(unix_now()));
        // One session: whoever comes first with the code (it's burned then).
        let stream = match tokio::time::timeout(left, node.next_stream()).await {
            Ok(Some(stream)) => stream,
            _ => return Err(("expired", "the link code expired; make a new one")),
        };
        pipe(report, stream.send, stream.recv, from_loop, STEP).await
    }
    .await;
    node.close().await;
    ended
}

/// N: find E's record on the seeds, open a session, send Hello, and carry
/// the frames.
async fn new_session(
    report: &Report,
    code: FriendCode,
    hello: Vec<u8>,
    seeds: Arc<Vec<MeshAddr>>,
    relays: Relays,
    from_loop: UnboundedReceiver<Option<Vec<u8>>>,
) -> Ended {
    let rendezvous = rendezvous(code).await?;
    let node = throwaway_node(relays, Vec::new())
        .await
        .map_err(|_| NO_RANDOM)?;
    let ended = async {
        if !node.online(ONLINE_WAIT).await {
            return Err(OFFLINE);
        }
        let addr = find_existing(&node, &seeds, &rendezvous).await.ok_or((
            "not-found",
            "no device is showing that link code; check it, or make a new one",
        ))?;
        let unreachable = ("unreachable", "couldn't reach the other device");
        let (_, mut send, recv) = node.open(&addr, LINK).await.map_err(|_| unreachable)?;
        frame::write_frame(&mut send, &hello)
            .await
            .map_err(|_| unreachable)?;
        pipe(report, send, recv, from_loop, NEW_READ_WAIT).await
    }
    .await;
    node.close().await;
    ended
}

/// E's link node, from the first seed that holds a record for this code.
async fn find_existing(
    node: &Node,
    seeds: &[MeshAddr],
    rendezvous: &LinkRendezvous,
) -> Option<MeshAddr> {
    let lookup = vec![rendezvous.lookup().to_vec()];
    for seed_addr in seeds {
        let Ok(answers) = seed::ask_many(node, seed_addr, seed::ADDR_GET, &lookup).await else {
            continue;
        };
        let found = answers.first().and_then(|a| AddrGet::from_bytes(a));
        let Some(AddrGet::Found(records)) = found else {
            continue;
        };
        let now = unix_now();
        let addr = records
            .iter()
            .filter_map(|r| rendezvous.open(r, now).ok())
            .filter_map(|t| String::from_utf8(t).ok())
            .find_map(|t| MeshAddr::from_ticket(&t).ok());
        if addr.is_some() {
            return addr;
        }
    }
    None
}

/// Carries frames between the session and the loop: each frame read goes
/// to the loop, and each answer the loop sends is written, until the loop
/// sends `None`, the other side finishes, or a step times out.
async fn pipe(
    report: &Report,
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    mut from_loop: UnboundedReceiver<Option<Vec<u8>>>,
    read_wait: Duration,
) -> Ended {
    let quiet = ("timeout", "the other device stopped answering");
    loop {
        match tokio::time::timeout(read_wait, frame::read_frame(&mut recv)).await {
            Ok(Ok(Some(frame))) => report.send(LinkEvent::Frame(frame)),
            Ok(Ok(None)) => return Ok(()),
            _ => return Err(quiet),
        }
        // A person may be deciding on this end. If the other side leaves
        // meanwhile (or sends out of turn), the session ends now, so a later
        // click can't link a device that's gone.
        let answer = tokio::select! {
            answer = tokio::time::timeout(CONFIRM_WAIT, from_loop.recv()) => answer,
            _ = frame::read_frame(&mut recv) => {
                return Err(("gone", "the other device stopped waiting; start again"));
            }
        };
        match answer {
            Ok(Some(Some(answer))) => {
                frame::write_frame(&mut send, &answer)
                    .await
                    .map_err(|_| quiet)?;
            }
            Ok(Some(None) | None) => {
                let _ = tokio::time::timeout(STEP, send.shutdown()).await;
                return Ok(());
            }
            Err(_) => return Err(("timeout", "nobody confirmed the new device in time")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N's wait for the identity must outlast E's wait for you to confirm,
    /// plus a step for it to arrive.
    #[test]
    fn the_new_device_waits_out_a_slow_confirm() {
        assert!(NEW_READ_WAIT >= CONFIRM_WAIT + STEP, "N gives up first");
    }

    /// While E waits for you, N leaving ends the session at once, so a
    /// later click can't add a device that's gone.
    #[tokio::test]
    async fn the_existing_device_notices_the_new_one_leaving() {
        let (ours, theirs) = tokio::io::duplex(1024);
        let (recv, send) = tokio::io::split(ours);
        let (back, _answers) = tokio::sync::mpsc::unbounded_channel();
        let report = Report { session: 1, back };
        // Kept open, but never answers: you haven't clicked.
        let (_to_peer, from_loop) = unbounded_channel();
        let peer = async move {
            let (_, mut write) = tokio::io::split(theirs);
            frame::write_frame(&mut write, b"device").await.unwrap();
            // N gives up.
        };
        let (ended, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(pipe(&report, send, recv, from_loop, STEP), peer)
        })
        .await
        .expect("still waiting for a click after N left");
        assert!(ended.is_err(), "N leaving is a failure");
    }
}
