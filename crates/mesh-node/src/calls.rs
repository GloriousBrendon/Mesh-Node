//! Calls (SPEC-calls): DM calls (C7) and voice channels (C8). One call at a
//! time per device. Control messages go one per stream on the `call`
//! service; the voice itself goes as datagrams (`media.rs`).
//!
//! `meshCall` tells Mesh-Voice where the call stands: `state` is `calling`,
//! `ringing`, `live` or `ended` (with an `outcome`), and who's in it and
//! speaking, by ID. `meshVoice` gives who's in each voice channel. Neither
//! the log nor the seed sees an ID or a call.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use mesh_dm::event::Body;
use mesh_identity::MeshId;
use mesh_transport::MeshAddr;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Back, Fail, Helper, dm, emit, parse_id};

/// The `call` service's tag (C2).
pub const CALL: &str = "call";
/// How long a call rings before it's missed (C7).
const RING_TIMEOUT: Duration = Duration::from_secs(45);
/// How long an invite waits for its answer frame.
const INVITE_WAIT: Duration = Duration::from_secs(10);
/// How often a call marks its peers used, so their connections stay (C3).
const KEEP_EVERY: Duration = Duration::from_secs(5);
/// A peer with no connection for this long has left the call.
const LOST_AFTER: Duration = Duration::from_secs(15);
/// The prefix of a call's line in the DM (Q3).
const LINE: &str = "📞";

/// A control message (C2), one per stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallMsg {
    Invite {
        call: [u8; 8],
    },
    Answer {
        call: [u8; 8],
    },
    Decline {
        call: [u8; 8],
    },
    Hangup {
        call: [u8; 8],
    },
    /// Answered on another device: stop ringing.
    Taken {
        call: [u8; 8],
    },
}

impl CallMsg {
    fn call(&self) -> [u8; 8] {
        match self {
            CallMsg::Invite { call }
            | CallMsg::Answer { call }
            | CallMsg::Decline { call }
            | CallMsg::Hangup { call }
            | CallMsg::Taken { call } => *call,
        }
    }
}

/// How an invite to one device went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invited {
    Rings,
    /// It reset the stream: an engine without calls (C11).
    Old,
    Nobody,
}

#[derive(Debug)]
enum Stage {
    /// We called; these devices ring.
    Calling,
    /// We're being called from this device.
    Ringing {
        from: [u8; 32],
    },
    Live {
        since: Instant,
    },
}

pub struct Call {
    id: [u8; 8],
    /// The friend in a DM call.
    with: MeshId,
    stage: Stage,
    caller: bool,
    started: Instant,
    /// Calling: the devices that ring. Live: the device we talk with.
    devices: HashSet<[u8; 32]>,
    /// When each peer device last had an open connection.
    seen: HashMap<[u8; 32], Instant>,
    #[cfg(feature = "audio")]
    media: Option<crate::media::Media>,
}

/// Calls' state on the helper.
#[derive(Default)]
pub struct Calls {
    pub current: Option<Call>,
    pub muted: bool,
    pub deafened: bool,
    /// Who's speaking in the current call, by device.
    speaking: Vec<[u8; 32]>,
    last_keep: Option<Instant>,
    #[cfg(feature = "audio")]
    pub io: crate::media::Io,
}

fn hex8(id: &[u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sends `msg` to each of `addrs`, one stream each; the answer frame of an
/// invite says it rings.
async fn send_to(node: &mesh_transport::Node, addr: &MeshAddr, msg: &CallMsg) -> Invited {
    let Ok(frame) = postcard::to_stdvec(msg) else {
        return Invited::Nobody;
    };
    let exchange = async {
        let (_, mut send, mut recv) = node.open(addr, CALL).await.ok()?;
        mesh_transport::frame::write_frame(&mut send, &frame)
            .await
            .ok()?;
        let _ = send.finish();
        Some(mesh_transport::frame::read_frame(&mut recv).await)
    };
    match tokio::time::timeout(INVITE_WAIT, exchange).await {
        Ok(Some(Ok(Some(_)))) => Invited::Rings,
        // Opened, then reset or closed without an answer: an old engine.
        Ok(Some(Err(_) | Ok(None))) => Invited::Old,
        _ => Invited::Nobody,
    }
}

impl Helper {
    /// The `call` commands (C4).
    pub(super) fn call_command(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} is missing argument {}", i + 1)))
        };
        match func {
            "callStart" => {
                let with = parse_id(arg(0)?)?;
                let friend =
                    self.unlocked()?.account().kind(&with) == Some(mesh_identity::Kind::Friend);
                if !friend {
                    return Err(Fail(
                        "not-a-friend",
                        "you can call only your friends".into(),
                    ));
                }
                self.call_start(with)?;
            }
            "callAnswer" => self.call_answer()?,
            "callDecline" | "callHangup" => self.call_hangup(),
            "callMute" => {
                self.calls.muted = arg(0)? == "true";
                #[cfg(feature = "audio")]
                if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
                    m.set_muted(self.calls.muted);
                }
                self.emit_call(None);
            }
            "callDeafen" => {
                self.calls.deafened = arg(0)? == "true";
                #[cfg(feature = "audio")]
                if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
                    m.set_deafened(self.calls.deafened);
                }
                self.emit_call(None);
            }
            // Microphone and speakers by name, "" for the default: the next
            // call uses them.
            "callDevices" => {
                #[cfg(feature = "audio")]
                {
                    let named = |s: &str| (!s.is_empty()).then(|| s.to_owned());
                    self.calls.io.input = named(arg(0)?);
                    self.calls.io.output = named(arg(1)?);
                }
            }
            _ => return Err(Fail("unknown-fn", format!("unknown command {func}"))),
        }
        Ok(())
    }

    fn call_start(&mut self, with: MeshId) -> Result<(), Fail> {
        if !cfg!(feature = "audio") {
            return Err(Fail(
                "unavailable",
                "this Mesh was built without calls".into(),
            ));
        }
        if self.net.is_none() {
            return Err(Fail("unavailable", "not connected".into()));
        }
        // One call at a time: a new one hangs up the old.
        self.call_hangup();
        let nonce = mesh_dm::space::nonce().ok_or_else(|| Fail("io", "no randomness".into()))?;
        let id: [u8; 8] = nonce[..8].try_into().expect("8");
        self.calls.current = Some(Call {
            id,
            with,
            stage: Stage::Calling,
            caller: true,
            started: Instant::now(),
            devices: HashSet::new(),
            seen: HashMap::new(),
            #[cfg(feature = "audio")]
            media: None,
        });
        self.emit_call(None);
        // Their connected devices ring; with none, one dial first.
        let Some(net) = &self.net else { return Ok(()) };
        let (node, back) = (net.node.clone(), self.back.clone());
        let mut addrs = node.connected(&with);
        if addrs.is_empty() {
            self.dial_back(&with, false);
        }
        tokio::spawn(async move {
            if addrs.is_empty() {
                for _ in 0..20 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    addrs = node.connected(&with);
                    if !addrs.is_empty() {
                        break;
                    }
                }
            }
            let mut rang = Vec::new();
            for addr in addrs {
                let how = send_to(&node, &addr, &CallMsg::Invite { call: id }).await;
                rang.push((*addr.device.as_bytes(), how));
            }
            let _ = back.send(Back::CallInvited(id, rang));
        });
        Ok(())
    }

    /// How the invites went: ringing, or the call ends.
    pub(super) fn call_invited(&mut self, id: [u8; 8], rang: Vec<([u8; 32], Invited)>) {
        let Some(call) = self.calls.current.as_mut().filter(|c| c.id == id) else {
            return;
        };
        if !matches!(call.stage, Stage::Calling) {
            return;
        }
        call.devices = (rang.iter())
            .filter(|(_, h)| *h == Invited::Rings)
            .map(|(d, _)| *d)
            .collect();
        if call.devices.is_empty() {
            let old = rang.iter().any(|(_, h)| *h == Invited::Old);
            self.call_end(if old { "update" } else { "unreachable" }, !old);
        }
    }

    fn call_answer(&mut self) -> Result<(), Fail> {
        let Some(call) = self.calls.current.as_mut() else {
            return Err(Fail("not-found", "nothing is ringing".into()));
        };
        let Stage::Ringing { from } = call.stage else {
            return Err(Fail("not-found", "nothing is ringing".into()));
        };
        call.stage = Stage::Live {
            since: Instant::now(),
        };
        call.devices = HashSet::from([from]);
        let (id, with) = (call.id, call.with);
        self.call_send(&[(with, from)], CallMsg::Answer { call: id });
        self.call_media()?;
        self.emit_call(None);
        Ok(())
    }

    /// `call_hangup`, for locking and quitting.
    pub(super) fn call_hangup_now(&mut self) {
        self.call_hangup();
    }

    /// Hangs up, cancels or declines, whichever the call is at.
    fn call_hangup(&mut self) {
        let Some(call) = &self.calls.current else {
            return;
        };
        let (id, with) = (call.id, call.with);
        let to: Vec<(MeshId, [u8; 32])> = match call.stage {
            Stage::Ringing { from } => vec![(with, from)],
            _ => call.devices.iter().map(|d| (with, *d)).collect(),
        };
        let (msg, outcome) = match call.stage {
            Stage::Ringing { .. } => (CallMsg::Decline { call: id }, "declined"),
            Stage::Calling => (CallMsg::Hangup { call: id }, "missed"),
            Stage::Live { .. } => (CallMsg::Hangup { call: id }, "ended"),
        };
        self.call_send(&to, msg);
        self.call_end(outcome, true);
    }

    /// The call is over: the line in the DM if we called (Q3), and `ended`.
    fn call_end(&mut self, outcome: &str, line: bool) {
        let Some(call) = self.calls.current.take() else {
            return;
        };
        self.calls.speaking.clear();
        if line && call.caller {
            let text = match (&call.stage, outcome) {
                (Stage::Live { since }, _) => {
                    let secs = since.elapsed().as_secs();
                    format!("{LINE} Call, {}:{:02}", secs / 60, secs % 60)
                }
                (_, "declined") => format!("{LINE} Call declined"),
                _ => format!("{LINE} Missed call"),
            };
            let body = Body::Text {
                text,
                reply_to: None,
                attachments: Vec::new(),
            };
            if let Err(Fail(_, e)) = self.dm_send_body(&dm::direct_chat(&call.with), body) {
                eprintln!("mesh-node: couldn't write the call's line: {e}");
            }
        }
        emit(
            "meshCall",
            json!({ "state": "ended", "id": hex8(&call.id), "with": call.with.to_string(), "outcome": outcome }),
        );
    }

    /// Starts the audio for the live call.
    fn call_media(&mut self) -> Result<(), Fail> {
        #[cfg(feature = "audio")]
        {
            let (Some(net), Some(store)) = (&self.net, &self.store) else {
                return Err(Fail("unavailable", "not connected".into()));
            };
            let Some(call) = self.calls.current.as_mut() else {
                return Ok(());
            };
            let back = self.back.clone();
            let me = store.device_key().public().to_bytes();
            let media = crate::media::Media::start(
                net.node.clone(),
                call.id,
                me,
                &self.calls.io,
                move |who| {
                    let _ = back.send(Back::Speaking(who));
                },
            )
            .map_err(|e| Fail("unavailable", format!("couldn't start the audio: {e}")))?;
            media.set_peers(call.devices.iter().copied());
            media.set_muted(self.calls.muted);
            media.set_deafened(self.calls.deafened);
            call.media = Some(media);
        }
        Ok(())
    }

    /// Sends `msg` to each device, in the background.
    fn call_send(&self, to: &[(MeshId, [u8; 32])], msg: CallMsg) {
        let Some(net) = &self.net else { return };
        for (_, device) in to {
            let Some(addr) = MeshAddr::from_device(device) else {
                continue;
            };
            let (node, msg) = (net.node.clone(), msg.clone());
            tokio::spawn(async move {
                send_to(&node, &addr, &msg).await;
            });
        }
    }

    /// A control message from another device.
    pub(super) fn call_heard(&mut self, id: MeshId, device: [u8; 32], msg: CallMsg) {
        let me = self.store.as_ref().map(|s| s.id());
        let current = self.calls.current.as_ref().filter(|c| c.id == msg.call());
        match (msg, current.map(|c| &c.stage)) {
            (CallMsg::Invite { call }, None) => {
                let friend = (self.store.as_ref())
                    .is_some_and(|s| s.account().kind(&id) == Some(mesh_identity::Kind::Friend));
                // Busy, or not a friend: declined.
                if self.calls.current.is_some() || !friend || !cfg!(feature = "audio") {
                    self.call_send(&[(id, device)], CallMsg::Decline { call });
                    return;
                }
                self.calls.current = Some(Call {
                    id: call,
                    with: id,
                    stage: Stage::Ringing { from: device },
                    caller: false,
                    started: Instant::now(),
                    devices: HashSet::new(),
                    seen: HashMap::new(),
                    #[cfg(feature = "audio")]
                    media: None,
                });
                self.emit_call(None);
            }
            (CallMsg::Answer { call }, Some(Stage::Calling)) => {
                let Some(c) = self.calls.current.as_mut() else {
                    return;
                };
                if c.with != id || !c.devices.contains(&device) {
                    return;
                }
                // The others stop ringing.
                let others: Vec<(MeshId, [u8; 32])> = (c.devices.iter())
                    .filter(|d| **d != device)
                    .map(|d| (id, *d))
                    .collect();
                c.stage = Stage::Live {
                    since: Instant::now(),
                };
                c.devices = HashSet::from([device]);
                self.call_send(&others, CallMsg::Taken { call });
                if let Err(Fail(_, e)) = self.call_media() {
                    eprintln!("mesh-node: {e}");
                }
                self.emit_call(None);
            }
            // A second device answering a call that's live: it's over there.
            (CallMsg::Answer { call }, Some(Stage::Live { .. })) => {
                self.call_send(&[(id, device)], CallMsg::Taken { call });
            }
            (CallMsg::Decline { call }, Some(Stage::Calling)) => {
                let Some(c) = self.calls.current.as_ref() else {
                    return;
                };
                if c.with != id {
                    return;
                }
                let others: Vec<(MeshId, [u8; 32])> = (c.devices.iter())
                    .filter(|d| **d != device)
                    .map(|d| (id, *d))
                    .collect();
                self.call_send(&others, CallMsg::Taken { call });
                self.call_end("declined", true);
            }
            (CallMsg::Hangup { .. }, Some(stage)) => {
                let from_them = current.is_some_and(|c| c.with == id || Some(id) == me);
                let ok = match stage {
                    Stage::Ringing { from } => *from == device,
                    _ => from_them,
                };
                if ok {
                    let outcome = if matches!(stage, Stage::Ringing { .. }) {
                        "missed"
                    } else {
                        "ended"
                    };
                    self.call_end(outcome, true);
                }
            }
            (CallMsg::Taken { .. }, Some(Stage::Ringing { from })) if *from == device => {
                self.call_end("elsewhere", false);
            }
            _ => {}
        }
    }

    /// Every second: ring timeouts, keeping the call's connections up (C3),
    /// and a peer gone.
    pub(super) fn call_tick(&mut self) {
        let now = Instant::now();
        let Some(call) = &self.calls.current else {
            return;
        };
        match call.stage {
            Stage::Calling if call.started.elapsed() > RING_TIMEOUT => return self.call_hangup(),
            // The caller's hangup may never come.
            Stage::Ringing { .. }
                if call.started.elapsed() > RING_TIMEOUT + Duration::from_secs(5) =>
            {
                return self.call_end("missed", false);
            }
            _ => {}
        }
        let Stage::Live { .. } = call.stage else {
            return;
        };
        let with = call.with;
        if self
            .calls
            .last_keep
            .is_none_or(|t| now.duration_since(t) >= KEEP_EVERY)
        {
            self.calls.last_keep = Some(now);
            self.wire.used(&with, now);
        }
        let connected: HashSet<[u8; 32]> = (self.net.as_ref())
            .map(|n| {
                n.node
                    .connected(&with)
                    .iter()
                    .map(|a| *a.device.as_bytes())
                    .collect()
            })
            .unwrap_or_default();
        let Some(call) = self.calls.current.as_mut() else {
            return;
        };
        for d in &call.devices {
            if connected.contains(d) {
                call.seen.insert(*d, now);
            }
        }
        let started = call.started;
        let lost = (call.devices.iter())
            .all(|d| now.duration_since(*call.seen.get(d).unwrap_or(&started)) > LOST_AFTER);
        if lost {
            self.call_end("lost", true);
        }
    }

    /// Who's speaking changed (device keys).
    pub(super) fn call_speaking(&mut self, who: Vec<[u8; 32]>) {
        self.calls.speaking = who;
        self.emit_call(None);
    }

    /// `meshCall` for the current call (or `ended` with `outcome`).
    pub(super) fn emit_call(&self, outcome: Option<&str>) {
        let Some(call) = &self.calls.current else {
            return;
        };
        let state = match call.stage {
            Stage::Calling => "calling",
            Stage::Ringing { .. } => "ringing",
            Stage::Live { .. } => "live",
        };
        let me = self
            .store
            .as_ref()
            .map(|s| (s.id(), s.device_key().public().to_bytes()));
        let speaking: Vec<String> = (self.calls.speaking.iter())
            .map(|d| match me {
                Some((id, mine)) if *d == mine => id.to_string(),
                _ => call.with.to_string(),
            })
            .collect();
        emit(
            "meshCall",
            json!({
                "state": state,
                "id": hex8(&call.id),
                "with": call.with.to_string(),
                "caller": call.caller,
                "muted": self.calls.muted,
                "deafened": self.calls.deafened,
                "speaking": speaking,
                "outcome": outcome,
            }),
        );
    }
}

/// Reads a control message from a `call` stream and answers it, so the
/// sender can tell it arrived (an invite rings).
pub async fn serve(
    mut stream: mesh_transport::ServiceStream,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
    wait: Duration,
) {
    let read = mesh_transport::frame::read_frame(&mut stream.recv);
    if let Ok(Ok(Some(frame))) = tokio::time::timeout(wait, read).await
        && frame.len() <= 64
        && let Ok(msg) = postcard::from_bytes::<CallMsg>(&frame)
    {
        let (id, device) = (stream.peer.id, *stream.peer.device.as_bytes());
        let _ = back.send(Back::Call(Box::new((id, device, msg))));
        let _ = mesh_transport::frame::write_frame(&mut stream.send, &[1]).await;
        let _ = stream.send.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message stays small and reads back the same.
    #[test]
    fn messages_round_trip() {
        for msg in [
            CallMsg::Invite { call: [1; 8] },
            CallMsg::Answer { call: [2; 8] },
            CallMsg::Decline { call: [3; 8] },
            CallMsg::Hangup { call: [4; 8] },
            CallMsg::Taken { call: [5; 8] },
        ] {
            let bytes = postcard::to_stdvec(&msg).unwrap();
            assert!(bytes.len() <= 64);
            assert_eq!(postcard::from_bytes::<CallMsg>(&bytes).unwrap(), msg);
        }
    }
}
