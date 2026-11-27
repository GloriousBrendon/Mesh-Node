//! Calls (SPEC-calls): DM calls (C7) and voice channels (C8). One call at a
//! time per device. Control messages go one per stream on the `call`
//! service; the voice itself goes as datagrams (`media.rs`).
//!
//! `meshCall` tells Mesh-Voice where the call stands: `state` is `calling`,
//! `ringing`, `live` or `ended` (with an `outcome`), and who's in it and
//! speaking, by ID. `meshVoice` gives who's in each voice channel. Neither
//! the log nor the seed sees an ID or a call.

use std::collections::{HashMap, HashSet};
#[cfg(feature = "audio")]
use std::sync::Arc;
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
/// People in a voice channel at most (C1).
pub const CALL_MAX: usize = 10;
/// How often a participant says it's in its voice channel (C8).
const VOICE_STATE_EVERY: Duration = Duration::from_secs(30);
/// A participant not heard from for this long has gone.
const VOICE_STALE: Duration = Duration::from_secs(75);

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
    /// A participant's voice channel: it joined (or left) `channel` (C8),
    /// and who else it knows is in it, by ID, so a newcomer can reach people
    /// it isn't connected to.
    Voice {
        space: [u8; 16],
        channel: [u8; 16],
        joined: bool,
        people: Vec<[u8; 32]>,
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
            CallMsg::Voice { channel, .. } => voice_call(channel),
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
    /// In a voice channel; `devices` are the others in it.
    Voice {
        space: [u8; 16],
        channel: [u8; 16],
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

/// Who's in a voice channel, by device: whose it is, and when last heard.
/// Each one's own list of who's in, too: the joiner's count for "full".
type Inside = HashMap<[u8; 32], (MeshId, Instant, Vec<[u8; 32]>)>;

/// Calls' state on the helper.
#[derive(Default)]
pub struct Calls {
    pub current: Option<Call>,
    pub muted: bool,
    pub deafened: bool,
    /// Push-to-talk's mode (`media::PTT_*`); off is the voice gate.
    ptt: u8,
    /// Input volume in percent, once the app set one; `None` is 100.
    gain: Option<u32>,
    /// The switches and sensitivity (SPEC-audio A3).
    #[cfg(feature = "audio")]
    audio: crate::media::Audio,
    /// Each person's volume, in percent, by ID (SPEC-audio A6).
    volumes: HashMap<[u8; 32], u32>,
    /// The plugin chain (SPEC-voice-quality): its version and plugins.
    #[cfg(feature = "audio")]
    fx: (u64, Arc<serde_json::Value>),
    /// The mic test while it runs (SPEC-audio A5).
    #[cfg(feature = "audio")]
    test: Option<crate::media::Media>,
    /// Who's speaking in the current call, by device.
    speaking: Vec<[u8; 32]>,
    last_keep: Option<Instant>,
    last_voice_state: Option<Instant>,
    /// Someone joined or left our voice channel since we last said who's in.
    voice_changed: bool,
    /// Who's in each voice channel we've heard of, by device: whose it is,
    /// and when it last said so (C8). Not us.
    voice: HashMap<([u8; 16], [u8; 16]), Inside>,
    #[cfg(feature = "audio")]
    pub io: crate::media::Io,
}

/// A voice channel's call ID: its own ID's first bytes (channel IDs are
/// already unique, from the Space's).
fn voice_call(channel: &[u8; 16]) -> [u8; 8] {
    channel[..8].try_into().expect("8")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex8(id: &[u8; 8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sends `msg` to each of `addrs`, one stream each; the answer frame of an
/// invite says it rings.
async fn send_to(node: &crate::nodes::Nodes, addr: &MeshAddr, msg: &CallMsg) -> Invited {
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
            "voiceJoin" => {
                let space = super::spaces::parse16(arg(0)?, "Space")?;
                let channel = super::spaces::parse16(arg(1)?, "channel")?;
                self.voice_join(space, channel)?;
            }
            "voiceLeave" => self.call_hangup(),
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
            // Push-to-talk (C10): `off`, `up` (on, the key released) or `down`.
            // Input volume, 0 to 200 percent (SPEC-audio A3), now and for
            // the calls after.
            // The switches and sensitivity, as JSON: any of `echo`, `noise`,
            // `gain` (true/false) and `threshold` (a dBFS number, or null for
            // Automatic); what's left out stays as it was.
            "callAudio" => {
                let v: serde_json::Value = serde_json::from_str(arg(0)?)
                    .map_err(|_| Fail("bad-args", "callAudio takes a JSON object".into()))?;
                #[cfg(feature = "audio")]
                {
                    let a = &mut self.calls.audio;
                    let flag = |k: &str, was: bool| v[k].as_bool().unwrap_or(was);
                    (a.echo, a.noise, a.gain) = (
                        flag("echo", a.echo),
                        flag("noise", a.noise),
                        flag("gain", a.gain),
                    );
                    if let Some(t) = v.get("threshold") {
                        a.threshold = t.as_f64().map(|db| db.clamp(-90.0, 0.0) as f32);
                    }
                    if let Some(o) = v["output"].as_u64() {
                        a.output = (o as u32).min(200);
                    }
                    // `low`, `standard`, `high` or `studio` (SPEC-voice-quality).
                    if let Some(q) = v["quality"].as_str() {
                        a.quality = crate::media::Quality::parse(q).ok_or_else(|| {
                            Fail("bad-args", "quality: low, standard, high or studio".into())
                        })?;
                    }
                    let audio = *a;
                    if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
                        m.set_audio(audio);
                    }
                }
                let _ = v;
            }
            // A person's own plugins (SPEC-voice-quality): `fxChain` sets the
            // chain (`[{path, id, on}]`, in order), `fxRestart` starts it
            // again after a bypass; both reach the call and the mic test now.
            "fxChain" | "fxRestart" => {
                #[cfg(feature = "audio")]
                {
                    let (version, plugins) = &mut self.calls.fx;
                    *version += 1;
                    if func == "fxChain" {
                        let mut v: serde_json::Value = serde_json::from_str(arg(0)?)
                            .ok()
                            .filter(serde_json::Value::is_array)
                            .ok_or_else(|| Fail("bad-args", "fxChain takes a JSON array".into()))?;
                        // Each plugin's state file (Task 5), in our data.
                        let dir = self
                            .path
                            .parent()
                            .unwrap_or(std::path::Path::new("."))
                            .join("fx");
                        for p in v.as_array_mut().into_iter().flatten() {
                            let key = format!(
                                "{}\0{}",
                                p["path"].as_str().unwrap_or(""),
                                p["id"].as_str().unwrap_or("")
                            );
                            let name = format!("{}.state", blake3::hash(key.as_bytes()).to_hex());
                            p["state"] = dir.join(name).to_string_lossy().into_owned().into();
                        }
                        *plugins = Arc::new(v);
                    }
                    let (version, plugins) = (*version, plugins.clone());
                    if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
                        m.set_fx(version, plugins.clone());
                    }
                    if let Some(t) = &self.calls.test {
                        t.set_fx(version, plugins);
                    }
                }
                #[cfg(not(feature = "audio"))]
                return Err(Fail(
                    "unavailable",
                    "this Mesh was built without calls".into(),
                ));
            }
            // A plugin's editor, parameters and state (Task 5), by its place
            // in the chain: `fxEdit <i>`, `fxEditClose <i>`, `fxParams <i>`,
            // `fxParam <i> <param id> <value>`, `fxSave`. They go to the
            // plugins running in the call or the mic test; answers come as
            // `meshFx {"answer": …}`.
            "fxEdit" | "fxEditClose" | "fxParams" | "fxParam" | "fxSave" => {
                #[cfg(feature = "audio")]
                {
                    let plugin = || -> Result<u64, Fail> {
                        arg(0)?.parse().map_err(|_| {
                            Fail("bad-args", "which plugin (its place in the chain)".into())
                        })
                    };
                    let command = match func {
                        "fxEdit" => serde_json::json!({ "cmd": "edit", "plugin": plugin()? }),
                        "fxEditClose" => {
                            serde_json::json!({ "cmd": "editClose", "plugin": plugin()? })
                        }
                        "fxParams" => serde_json::json!({ "cmd": "params", "plugin": plugin()? }),
                        "fxParam" => {
                            let param: u64 = arg(1)?
                                .parse()
                                .map_err(|_| Fail("bad-args", "a parameter id".into()))?;
                            let value: f64 = arg(2)?
                                .parse()
                                .map_err(|_| Fail("bad-args", "a value".into()))?;
                            serde_json::json!({ "cmd": "param", "plugin": plugin()?, "param": param, "value": value })
                        }
                        _ => serde_json::json!({ "cmd": "save" }),
                    };
                    let media = (self.calls.current.as_ref().and_then(|c| c.media.as_ref()))
                        .or(self.calls.test.as_ref())
                        .ok_or_else(|| {
                            Fail("unavailable", "start the mic test or a call first".into())
                        })?;
                    media.fx_control(command);
                }
                #[cfg(not(feature = "audio"))]
                return Err(Fail(
                    "unavailable",
                    "this Mesh was built without calls".into(),
                ));
            }
            // The mic test (A5): `on` or `off`, and with `on`, `hear` to
            // play it back. A call stops it.
            "audioTest" => {
                #[cfg(feature = "audio")]
                {
                    self.calls.test = None;
                    if arg(0)? == "on" {
                        let hear = args.get(1).is_some_and(|a| a == "hear");
                        let test =
                            crate::media::Media::test(&self.calls.io, hear, emit_level, emit_fx)
                                .map_err(|e| {
                                    Fail("unavailable", format!("couldn't open the mic: {e}"))
                                })?;
                        test.set_gain(self.calls.gain.unwrap_or(100));
                        test.set_audio(self.calls.audio);
                        test.set_fx(self.calls.fx.0, self.calls.fx.1.clone());
                        self.calls.test = Some(test);
                    }
                }
                #[cfg(not(feature = "audio"))]
                return Err(Fail(
                    "unavailable",
                    "this Mesh was built without calls".into(),
                ));
            }
            // One person's volume for us, 0 to 200 percent (A6), kept for
            // this run; Aflos sends what it keeps at each call's start.
            "callVolume" => {
                let id = parse_id(arg(0)?)?;
                let percent: u32 = (arg(1)?.parse())
                    .map_err(|_| Fail("bad-args", "a percentage, 0 to 200".into()))?;
                self.calls.volumes.insert(id.to_bytes(), percent.min(200));
                self.push_volumes();
            }
            "callGain" => {
                let percent: u32 = (arg(0)?.parse())
                    .map_err(|_| Fail("bad-args", "a percentage, 0 to 200".into()))?;
                self.calls.gain = Some(percent.min(200));
                #[cfg(feature = "audio")]
                if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
                    m.set_gain(percent);
                }
            }
            "callPtt" => {
                self.calls.ptt = match arg(0)? {
                    "off" => 0,
                    "up" => 1,
                    "down" => 2,
                    _ => return Err(Fail("bad-args", "off, up or down".into())),
                };
                #[cfg(feature = "audio")]
                if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
                    m.set_ptt(self.calls.ptt);
                }
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
        if let Stage::Voice { space, channel } = call.stage {
            self.voice_announce(space, channel, false);
            self.call_end("left", false);
            return self.emit_voice(space, channel);
        }
        let to: Vec<(MeshId, [u8; 32])> = match call.stage {
            Stage::Ringing { from } => vec![(with, from)],
            _ => call.devices.iter().map(|d| (with, *d)).collect(),
        };
        let (msg, outcome) = match call.stage {
            Stage::Ringing { .. } => (CallMsg::Decline { call: id }, "declined"),
            Stage::Calling => (CallMsg::Hangup { call: id }, "missed"),
            Stage::Live { .. } | Stage::Voice { .. } => (CallMsg::Hangup { call: id }, "ended"),
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
            // One user of the mic at a time: a call ends the mic test.
            self.calls.test = None;
            let (Some(net), Some(store)) = (&self.net, &self.store) else {
                return Err(Fail("unavailable", "not connected".into()));
            };
            let nodes = self.call_nodes(net);
            let Some(call) = self.calls.current.as_mut() else {
                return Ok(());
            };
            let back = self.back.clone();
            let me = store.device_key().public().to_bytes();
            let media = crate::media::Media::start(
                nodes,
                call.id,
                me,
                &self.calls.io,
                move |who| {
                    let _ = back.send(Back::Speaking(who));
                },
                emit_level,
                emit_fx,
            )
            .map_err(|e| Fail("unavailable", format!("couldn't start the audio: {e}")))?;
            media.set_peers(call.devices.iter().copied());
            media.set_volumes(self.device_volumes());
            let Some(call) = self.calls.current.as_mut() else {
                return Ok(());
            };
            media.set_muted(self.calls.muted);
            media.set_deafened(self.calls.deafened);
            media.set_ptt(self.calls.ptt);
            media.set_gain(self.calls.gain.unwrap_or(100));
            media.set_audio(self.calls.audio);
            media.set_fx(self.calls.fx.0, self.calls.fx.1.clone());
            call.media = Some(media);
        }
        Ok(())
    }

    /// The nodes the live call runs on: a voice channel is Space traffic,
    /// relayed (connection-privacy P14); a DM call may go direct.
    fn call_nodes(&self, net: &super::Net) -> crate::nodes::Nodes {
        match self.calls.current.as_ref().map(|c| &c.stage) {
            // A voice channel follows its Space's setting (P7, P14).
            Some(Stage::Voice { space, .. }) => self.space_nodes([space]),
            _ => net.node.clone(),
        }
    }

    /// Sends `msg` to each device, in the background.
    fn call_send(&self, to: &[(MeshId, [u8; 32])], msg: CallMsg) {
        let Some(net) = &self.net else { return };
        for (_, device) in to {
            let Some(addr) = MeshAddr::from_device(device) else {
                continue;
            };
            let (node, msg) = (self.call_nodes(net), msg.clone());
            tokio::spawn(async move {
                send_to(&node, &addr, &msg).await;
            });
        }
    }

    /// A control message from another device.
    pub(super) fn call_heard(&mut self, id: MeshId, device: [u8; 32], msg: CallMsg) {
        if let CallMsg::Voice {
            space,
            channel,
            joined,
            people,
        } = msg
        {
            return self.voice_heard(id, device, (space, channel), joined, people);
        }
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
        self.voice_tick(now);
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
            if self
                .net
                .as_ref()
                .is_some_and(|n| n.node.connected(&with).is_empty())
            {
                self.dial_back(&with, false);
            }
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
            Stage::Live { .. } | Stage::Voice { .. } => "live",
        };
        let me = self
            .store
            .as_ref()
            .map(|s| (s.id(), s.device_key().public().to_bytes()));
        let voice = match call.stage {
            Stage::Voice { space, channel } => Some((space, channel)),
            _ => None,
        };
        let in_channel = voice.and_then(|k| self.calls.voice.get(&k));
        let speaking: Vec<String> = (self.calls.speaking.iter())
            .filter_map(|d| match me {
                Some((id, mine)) if *d == mine => Some(id.to_string()),
                _ if voice.is_some() => in_channel?.get(d).map(|(id, ..)| id.to_string()),
                _ => Some(call.with.to_string()),
            })
            .collect();
        let mut payload = json!({
            "state": state,
            "id": hex8(&call.id),
            "with": call.with.to_string(),
            "caller": call.caller,
            "muted": self.calls.muted,
            "deafened": self.calls.deafened,
            "speaking": speaking,
            "outcome": outcome,
        });
        if let Some((space, channel)) = voice {
            payload["space"] = json!(hex(&space));
            payload["channel"] = json!(hex(&channel));
            payload["people"] = json!(self.voice_people(space, channel));
        }
        emit("meshCall", payload);
    }
}

impl Helper {
    /// Joins a voice channel (C8): as a member, while it has room.
    fn voice_join(&mut self, space: [u8; 16], channel: [u8; 16]) -> Result<(), Fail> {
        if !cfg!(feature = "audio") {
            return Err(Fail(
                "unavailable",
                "this Mesh was built without calls".into(),
            ));
        }
        let me = self.unlocked()?.id();
        let v = (self.space_version(&space))
            .ok_or_else(|| Fail("not-found", "no such Space".into()))?;
        if !v.state.members.contains_key(&me.to_bytes()) || v.state.ended {
            return Err(Fail("not-allowed", "you're not in that Space".into()));
        }
        if !v.state.channels.get(&channel).is_some_and(|c| c.voice) {
            return Err(Fail("not-found", "no such voice channel".into()));
        }
        let others = self
            .calls
            .voice
            .get(&(space, channel))
            .cloned()
            .unwrap_or_default();
        // Everyone anyone in it named: we may have heard from only one.
        let named: HashSet<[u8; 32]> = (others.values())
            .flat_map(|(id, _, listed)| listed.iter().copied().chain([id.to_bytes()]))
            .filter(|p| *p != me.to_bytes())
            .collect();
        if named.len() >= CALL_MAX {
            return Err(Fail("full", "that voice channel is full".into()));
        }
        // One call at a time: joining hangs up the old one.
        self.call_hangup();
        self.calls.current = Some(Call {
            id: voice_call(&channel),
            with: me,
            stage: Stage::Voice { space, channel },
            caller: false,
            started: Instant::now(),
            devices: others.keys().copied().collect(),
            seen: HashMap::new(),
            #[cfg(feature = "audio")]
            media: None,
        });
        self.call_media()?;
        self.calls.last_voice_state = Some(Instant::now());
        self.voice_announce(space, channel, true);
        self.emit_call(None);
        self.emit_voice(space, channel);
        Ok(())
    }

    /// Tells the Space's members we joined or left: their connected devices,
    /// and the participants, dialled if need be (C8).
    fn voice_announce(&self, space: [u8; 16], channel: [u8; 16], joined: bool) {
        let Some(store) = &self.store else {
            return;
        };
        let me = store.id();
        let Some(v) = self.space_version(&space) else {
            return;
        };
        let inside: HashSet<MeshId> = (self.calls.voice.get(&(space, channel)))
            .map(|m| m.values().map(|(id, ..)| *id).collect())
            .unwrap_or_default();
        let members: Vec<(MeshId, bool)> = (v.state.members.keys())
            .filter_map(|p| MeshId::from_bytes(p).ok())
            .filter(|id| *id != me)
            .map(|id| (id, inside.contains(&id)))
            .collect();
        let msg = self.voice_msg(space, channel, joined);
        self.voice_send(members, msg);
    }

    /// Our voice state, with who we know is in the channel.
    fn voice_msg(&self, space: [u8; 16], channel: [u8; 16], joined: bool) -> CallMsg {
        let mut people: Vec<[u8; 32]> = (self.calls.voice.get(&(space, channel)))
            .map(|m| m.values().map(|(id, ..)| id.to_bytes()).collect())
            .unwrap_or_default();
        people.sort();
        people.dedup();
        CallMsg::Voice {
            space,
            channel,
            joined,
            people,
        }
    }

    /// Sends `msg` to each person's connected devices; those marked are
    /// dialled first if need be.
    fn voice_send(&self, to: Vec<(MeshId, bool)>, msg: CallMsg) {
        let Some(net) = &self.net else { return };
        for (id, _) in to
            .iter()
            .filter(|(id, dial)| *dial && net.node.connected(id).is_empty())
        {
            self.dial_back(id, false);
        }
        // Each on its own: one slow dial mustn't hold up the rest.
        for (id, dial) in to {
            let (node, msg) = (net.node.relayed(), msg.clone());
            tokio::spawn(async move {
                let mut addrs = node.connected(&id);
                // One we're dialling: give the dial a moment.
                for _ in 0..20 {
                    if !addrs.is_empty() || !dial {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    addrs = node.connected(&id);
                }
                for addr in addrs {
                    send_to(&node, &addr, &msg).await;
                }
            });
        }
    }

    /// A participant joined or left a voice channel.
    fn voice_heard(
        &mut self,
        id: MeshId,
        device: [u8; 32],
        (space, channel): ([u8; 16], [u8; 16]),
        joined: bool,
        people: Vec<[u8; 32]>,
    ) {
        let Some(v) = self.space_version(&space) else {
            return;
        };
        let member = v.state.members.contains_key(&id.to_bytes());
        if joined && !(member && v.state.channels.get(&channel).is_some_and(|c| c.voice)) {
            return;
        }
        let inside = self.calls.voice.entry((space, channel)).or_default();
        let (new, gone) = if joined {
            (
                inside
                    .insert(device, (id, Instant::now(), people.clone()))
                    .is_none(),
                false,
            )
        } else {
            (false, inside.remove(&device).is_some())
        };
        let ours = (self.calls.current.as_ref())
            .is_some_and(|c| matches!(c.stage, Stage::Voice { space: s, channel: ch } if s == space && ch == channel));
        if ours {
            self.calls.voice_changed |= new || gone;
            self.voice_peers(space, channel);
            // A newcomer learns we're here, and who else is, at once; so
            // does anyone whose state doesn't list us (a reply that was lost).
            let me = self.store.as_ref().map(|s| s.id().to_bytes());
            let knows_us = me.is_some_and(|me| people.contains(&me));
            if joined && (new || !knows_us) {
                let msg = self.voice_msg(space, channel, true);
                self.call_send(&[(id, device)], msg);
            }
            // Those they know of and we don't: we tell them we're here.
            let known: HashSet<[u8; 32]> = (self.calls.voice.get(&(space, channel)))
                .map(|m| m.values().map(|(p, ..)| p.to_bytes()).collect())
                .unwrap_or_default();
            let unknown: Vec<(MeshId, bool)> = (people.iter())
                .filter(|p| {
                    Some(**p) != me && !known.contains(*p) && v.state.members.contains_key(*p)
                })
                .filter_map(|p| MeshId::from_bytes(p).ok())
                .map(|p| (p, true))
                .collect();
            if !unknown.is_empty() {
                let msg = self.voice_msg(space, channel, true);
                self.voice_send(unknown, msg);
            }
        }
        self.emit_voice(space, channel);
    }

    /// The current voice call's peers, from who's in its channel.
    fn voice_peers(&mut self, space: [u8; 16], channel: [u8; 16]) {
        let devices: HashSet<[u8; 32]> = (self.calls.voice.get(&(space, channel)))
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        if let Some(call) = self.calls.current.as_mut() {
            #[cfg(feature = "audio")]
            if let Some(m) = &call.media {
                m.set_peers(devices.iter().copied());
            }
            call.devices = devices;
        }
        self.push_volumes();
    }

    /// Each of the current call's devices at its person's volume, where
    /// that isn't 100.
    fn device_volumes(&self) -> HashMap<[u8; 32], u32> {
        let Some(call) = &self.calls.current else {
            return HashMap::new();
        };
        let owner = |device: &[u8; 32]| match call.stage {
            Stage::Voice { space, channel } => (self.calls.voice.get(&(space, channel)))
                .and_then(|m| m.get(device))
                .map(|(id, ..)| *id),
            _ => Some(call.with),
        };
        (call.devices.iter())
            .filter_map(|d| Some((*d, *self.calls.volumes.get(&owner(d)?.to_bytes())?)))
            .collect()
    }

    /// Tells the current call's media the volumes (A6).
    fn push_volumes(&self) {
        #[cfg(feature = "audio")]
        if let Some(m) = self.calls.current.as_ref().and_then(|c| c.media.as_ref()) {
            m.set_volumes(self.device_volumes());
        }
    }

    /// Every second: stale and removed participants go; in a voice channel,
    /// its connections stay up and we say we're here every 30 s.
    fn voice_tick(&mut self, now: Instant) {
        let mut changed = Vec::new();
        let keys: Vec<([u8; 16], [u8; 16])> = self.calls.voice.keys().copied().collect();
        for (space, channel) in keys {
            let members = self.space_version(&space).map(|v| v.state.members);
            let Some(people) = self.calls.voice.get_mut(&(space, channel)) else {
                continue;
            };
            let before = people.len();
            people.retain(|_, (id, at, _)| {
                now.duration_since(*at) < VOICE_STALE
                    && members
                        .as_ref()
                        .is_some_and(|m| m.contains_key(&id.to_bytes()))
            });
            if people.len() != before {
                changed.push((space, channel));
            }
        }
        for (space, channel) in changed {
            self.voice_peers(space, channel);
            self.emit_voice(space, channel);
        }
        let Some(Stage::Voice { space, channel }) = self.calls.current.as_ref().map(|c| &c.stage)
        else {
            return;
        };
        let (space, channel) = (*space, *channel);
        // Kicked, banned, or the channel's gone: out.
        let me = self.store.as_ref().map(|s| s.id().to_bytes());
        let still = self.space_version(&space).is_some_and(|v| {
            me.is_some_and(|me| v.state.members.contains_key(&me))
                && !v.state.ended
                && v.state.channels.get(&channel).is_some_and(|c| c.voice)
        });
        if !still {
            self.call_end("removed", false);
            return self.emit_voice(space, channel);
        }
        if self
            .calls
            .last_keep
            .is_none_or(|t| now.duration_since(t) >= KEEP_EVERY)
        {
            self.calls.last_keep = Some(now);
            let ids: HashSet<MeshId> = (self.calls.voice.get(&(space, channel)))
                .map(|m| m.values().map(|(id, ..)| *id).collect())
                .unwrap_or_default();
            for id in &ids {
                self.wire.used(id, now);
                // A participant we lost the connection to: dialled again,
                // or their voice and states never come back.
                if self
                    .net
                    .as_ref()
                    .is_some_and(|n| n.node.connected(id).is_empty())
                {
                    self.dial_back(id, false);
                }
            }
            // Anyone the others say is in, whom we haven't heard from: we
            // tell them we're here (dialling if need be) until their reply
            // comes, so two members who aren't friends always find each
            // other, whatever was lost.
            let me = self.store.as_ref().map(|s| s.id().to_bytes());
            let v = self.space_version(&space);
            let missing: Vec<(MeshId, bool)> = (self.calls.voice.get(&(space, channel)))
                .into_iter()
                .flat_map(|m| m.values().flat_map(|(_, _, listed)| listed.iter().copied()))
                .collect::<HashSet<[u8; 32]>>()
                .into_iter()
                .filter(|p| {
                    Some(*p) != me && v.as_ref().is_some_and(|v| v.state.members.contains_key(p))
                })
                .filter_map(|p| MeshId::from_bytes(&p).ok())
                .filter(|p| !ids.contains(p))
                .map(|p| (p, true))
                .collect();
            if !missing.is_empty() {
                let msg = self.voice_msg(space, channel, true);
                self.voice_send(missing, msg);
            }
        }
        // Every 30 s, and within 5 s of someone joining or leaving, so
        // members outside see it (and a joiner counts right for "full").
        let since = self.calls.last_voice_state.map(|t| now.duration_since(t));
        let due = since.is_none_or(|d| d >= VOICE_STATE_EVERY)
            || (self.calls.voice_changed && since.is_none_or(|d| d >= KEEP_EVERY));
        if due {
            (self.calls.last_voice_state, self.calls.voice_changed) = (Some(now), false);
            self.voice_announce(space, channel, true);
        }
    }

    /// Who's in a voice channel, by ID: those we've heard, and us if we're in.
    fn voice_people(&self, space: [u8; 16], channel: [u8; 16]) -> Vec<String> {
        let mut people: Vec<String> = (self.calls.voice.get(&(space, channel)))
            .map(|m| m.values().map(|(id, ..)| id.to_string()).collect())
            .unwrap_or_default();
        let ours = (self.calls.current.as_ref())
            .is_some_and(|c| matches!(c.stage, Stage::Voice { space: s, channel: ch } if s == space && ch == channel));
        if let (true, Some(store)) = (ours, &self.store) {
            people.push(store.id().to_string());
        }
        people.sort();
        people.dedup();
        people
    }

    /// `meshVoice`: who's in one voice channel now.
    fn emit_voice(&self, space: [u8; 16], channel: [u8; 16]) {
        emit(
            "meshVoice",
            json!({ "space": hex(&space), "channel": hex(&channel), "people": self.voice_people(space, channel) }),
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
        && frame.len() <= 512
        && let Ok(msg) = postcard::from_bytes::<CallMsg>(&frame)
    {
        let (id, device) = (stream.peer.id, *stream.peer.device.as_bytes());
        let _ = back.send(Back::Call(Box::new((id, device, msg))));
        let _ = mesh_transport::frame::write_frame(&mut stream.send, &[1]).await;
        let _ = stream.send.finish();
    }
}

/// `meshAudioLevel`: the mic's level after the chain (dBFS) and whether
/// it goes out, about 15 times a second in a call or the mic test.
#[cfg(feature = "audio")]
fn emit_level(level: f32, open: bool) {
    let level = (f64::from(level) * 10.0).round() / 10.0;
    emit("meshAudioLevel", json!({ "level": level, "open": open }));
}

/// `meshFx`: how a person's plugins are doing (`starting`, `on` with their
/// `latency` in samples, `off`, `failed` or `bypassed` with an `error`).
#[cfg(feature = "audio")]
fn emit_fx(state: serde_json::Value) {
    emit("meshFx", state);
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
