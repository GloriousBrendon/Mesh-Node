//! Top 8 consent (SPEC-profile PR11): a friend shows up in our Top 8 only
//! after they said yes to our ask, and goes the moment they withdraw. A
//! child of `helper`.
//!
//! On the `top8` service one side opens a stream and sends one message
//! (`Msg`, postcard); the other answers one byte, 1 once it has taken it.
//! Like `profile` it rides the device connection, end-to-end encrypted and
//! authenticated by device key, between friends only. Messages wait in an
//! outbox, saved, until one of the friend's devices has taken them.
//!
//! Kept on disk, sealed with the data key (`profile/top8`): who we asked,
//! who asked us, who said yes (with the name they gave), who we said yes
//! to, and which friends our manifest shows, in its order. Our manifest
//! carries only the shown friends' names and avatars, never their IDs.
//
// ponytail: the lists live on the device that made them; own-device sync
// (social D11) is for when people use Top 8 from two devices.

use super::*;
use mesh_dm::profile::{MAX_TOP8, MAX_TOP8_NAME, Manifest, Shown, Slot};
use mesh_identity::{read_sealed, write_sealed};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The transport service Top 8 messages go on.
pub(super) const SERVICE: &str = "top8";
const WAIT: Duration = Duration::from_secs(20);
const CONTEXT: &str = "mesh/v1/top8";
const FORMAT: u8 = 1;
/// A message is a name at most, with its framing.
const MAX_MSG: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Msg {
    /// "May I show you in my Top 8?"
    Ask,
    /// "You may show me", as `name`. A no is never sent (as social's
    /// silent decline).
    Yes(String),
    /// "Stop showing me."
    Withdraw,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    asked: BTreeSet<[u8; 32]>,
    asks: BTreeSet<[u8; 32]>,
    may_show: BTreeMap<[u8; 32], String>,
    let_show: BTreeMap<[u8; 32], String>,
    shown: Vec<[u8; 32]>,
    outbox: Vec<([u8; 32], Msg)>,
}

/// Sends `msg` to one device: whether it took it.
async fn send(node: crate::nodes::Nodes, addr: MeshAddr, msg: Vec<u8>) -> bool {
    let sent = async {
        let (_, mut send, mut recv) = node.open(&addr, SERVICE).await.ok()?;
        mesh_transport::frame::write_frame(&mut send, &msg)
            .await
            .ok()?;
        let answer = mesh_transport::frame::read_frame(&mut recv).await.ok()??;
        send.finish().ok()?;
        (answer == [1]).then_some(())
    };
    matches!(tokio::time::timeout(WAIT, sent).await, Ok(Some(())))
}

/// Takes one message from a device and answers that it has.
pub(super) async fn serve(
    mut stream: mesh_transport::ServiceStream,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    let id = stream.peer.id;
    let got = async {
        let bytes = mesh_transport::frame::read_frame(&mut stream.recv)
            .await
            .ok()??;
        if bytes.len() > MAX_MSG {
            return None;
        }
        let msg: Msg = postcard::from_bytes(&bytes).ok()?;
        back.send(Back::Top8(Box::new((id, msg)))).ok()?;
        mesh_transport::frame::write_frame(&mut stream.send, &[1])
            .await
            .ok()
    };
    let _ = tokio::time::timeout(WAIT, got).await;
    let _ = stream.send.finish();
}

fn ids(set: impl IntoIterator<Item = [u8; 32]>) -> Vec<String> {
    (set.into_iter())
        .filter_map(|p| MeshId::from_bytes(&p).ok().map(|id| id.to_string()))
        .collect()
}

impl Helper {
    fn top8_path(&self) -> PathBuf {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        dir.join("profile").join("top8")
    }

    fn top8_state(&self) -> State {
        let Some(store) = &self.store else {
            return State::default();
        };
        match read_sealed(&self.top8_path(), store.data_key(), CONTEXT, FORMAT) {
            Ok(Some((_, bytes))) => postcard::from_bytes(&bytes).unwrap_or_default(),
            Ok(None) => State::default(),
            Err(e) => {
                eprintln!("mesh-node: couldn't read the Top 8: {e}");
                State::default()
            }
        }
    }

    fn top8_save(&self, state: &State) -> Result<(), Fail> {
        let store = (self.store.as_ref()).ok_or_else(|| Fail("locked", "locked".to_owned()))?;
        let bytes = postcard::to_stdvec(state).expect("to memory");
        let path = self.top8_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        write_sealed(&path, store.data_key(), CONTEXT, FORMAT, &bytes)
            .map_err(|e| Fail("io", format!("couldn't save the Top 8: {e}")))
    }

    /// `meshTop8`: every list, and what just happened (`event`, `id`).
    fn emit_top8(&self, state: &State, event: Value) {
        let may_show: Vec<Value> = (state.may_show.iter())
            .filter_map(|(p, name)| {
                let id = MeshId::from_bytes(p).ok()?;
                Some(json!({ "id": id.to_string(), "name": name }))
            })
            .collect();
        emit(
            "meshTop8",
            json!({
                "event": event,
                "asked": ids(state.asked.iter().copied()),
                "asks": ids(state.asks.iter().copied()),
                "mayShow": may_show,
                "letShow": ids(state.let_show.keys().copied()),
                "shown": ids(state.shown.iter().copied()),
            }),
        );
    }

    /// `top8Ask(id)`, `top8Answer(id, yes, [name])`, `top8Withdraw(id)`,
    /// `top8Set(ids…)`, `top8List()`.
    pub(super) fn top8_command(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} is missing argument {}", i + 1)))
        };
        let store = (self.store.as_ref()).ok_or_else(|| Fail("locked", "locked".to_owned()))?;
        let friend = |id: &MeshId| -> Result<[u8; 32], Fail> {
            if store.account().kind(id) == Some(Kind::Friend) {
                Ok(id.to_bytes())
            } else {
                Err(Fail("not-a-friend", format!("{id} isn't your friend")))
            }
        };
        let not_found = || Fail("not-found", "nothing waiting from them".to_owned());
        let mut state = self.top8_state();
        let mut republish = false;
        let event = match func {
            "top8Ask" => {
                let id = friend(&parse_id(arg(0)?)?)?;
                if !state.may_show.contains_key(&id) && state.asked.insert(id) {
                    state.outbox.push((id, Msg::Ask));
                }
                json!({ "fn": func, "id": arg(0)? })
            }
            "top8Answer" => {
                let id = parse_id(arg(0)?)?.to_bytes();
                let yes = match arg(1)? {
                    "true" => true,
                    "false" => false,
                    _ => return Err(Fail("bad-args", "true or false".to_owned())),
                };
                let name = match args.get(2).map(|n| n.trim()) {
                    Some(n) if !n.is_empty() => n.to_owned(),
                    _ => store.username().to_owned(),
                };
                if name.len() > MAX_TOP8_NAME {
                    return Err(Fail("too-long", "that name is too long".to_owned()));
                }
                if !state.asks.remove(&id) {
                    return Err(not_found());
                }
                if yes {
                    state.let_show.insert(id, name.clone());
                    state.outbox.push((id, Msg::Yes(name)));
                }
                json!({ "fn": func, "id": arg(0)? })
            }
            "top8Withdraw" => {
                let id = parse_id(arg(0)?)?.to_bytes();
                if state.let_show.remove(&id).is_none() {
                    return Err(Fail("not-found", "you aren't letting them".to_owned()));
                }
                state
                    .outbox
                    .retain(|(to, m)| !(*to == id && matches!(m, Msg::Yes(_))));
                state.outbox.push((id, Msg::Withdraw));
                json!({ "fn": func, "id": arg(0)? })
            }
            "top8Set" => {
                let chosen = (args.iter())
                    .map(|a| parse_id(a).map(|id| id.to_bytes()))
                    .collect::<Result<Vec<_>, _>>()?;
                if chosen.len() > MAX_TOP8 {
                    return Err(Fail("too-long", "a Top 8 shows 8 friends".to_owned()));
                }
                let unique: BTreeSet<_> = chosen.iter().collect();
                if unique.len() != chosen.len() {
                    return Err(Fail("bad-args", "someone is in it twice".to_owned()));
                }
                if chosen.iter().any(|id| !state.may_show.contains_key(id)) {
                    return Err(Fail(
                        "not-allowed",
                        "only friends who said yes can be shown".to_owned(),
                    ));
                }
                republish = state.shown != chosen;
                state.shown = chosen;
                json!({ "fn": func })
            }
            "top8List" => json!({ "fn": func }),
            _ => return Err(Fail("unknown-fn", format!("unknown command {func}"))),
        };
        self.top8_save(&state)?;
        if republish {
            self.top8_republish();
        }
        self.emit_top8(&state, event);
        if let Some(to) = (args.first()).and_then(|a| parse_id(a).ok()) {
            self.top8_deliver(&to);
        }
        Ok(())
    }

    /// A friend's message came.
    pub(super) fn top8_heard(&mut self, from: MeshId, msg: Msg) {
        let Some(store) = &self.store else { return };
        if store.account().kind(&from) != Some(Kind::Friend) {
            return;
        }
        let id = from.to_bytes();
        let mut state = self.top8_state();
        let event = match msg {
            Msg::Ask => {
                if let Some(name) = state.let_show.get(&id) {
                    // They lost our yes: say it again.
                    let again = Msg::Yes(name.clone());
                    state.outbox.push((id, again));
                } else {
                    state.asks.insert(id);
                }
                "ask"
            }
            Msg::Yes(name) => {
                if name.len() > MAX_TOP8_NAME
                    || !(state.asked.remove(&id) || state.may_show.contains_key(&id))
                {
                    return;
                }
                state.may_show.insert(id, name);
                "yes"
            }
            Msg::Withdraw => {
                state.asked.remove(&id);
                state.may_show.remove(&id);
                state.shown.retain(|s| *s != id);
                "withdrawn"
            }
        };
        if self.top8_save(&state).is_err() {
            return;
        }
        if event == "withdrawn" {
            self.top8_republish();
        }
        self.emit_top8(&state, json!({ "event": event, "id": from.to_string() }));
        self.top8_deliver(&from);
    }

    /// Sends what waits for `id` to each of their connected devices; the
    /// first to take a message clears it.
    pub(super) fn top8_deliver(&self, id: &MeshId) {
        let Some(net) = &self.net else { return };
        let to = id.to_bytes();
        let waiting: Vec<Msg> = (self.top8_state().outbox.into_iter())
            .filter(|(t, _)| *t == to)
            .map(|(_, m)| m)
            .collect();
        if waiting.is_empty() {
            return;
        }
        let addrs = net.node.connected(id);
        let (node, back, id) = (net.node.clone(), self.back.clone(), *id);
        tokio::spawn(async move {
            for msg in waiting {
                let bytes = postcard::to_stdvec(&msg).expect("to memory");
                for addr in &addrs {
                    if send(node.clone(), addr.clone(), bytes.clone()).await {
                        let _ = back.send(Back::Top8Sent(Box::new((id, msg))));
                        break;
                    }
                }
            }
        });
    }

    /// A friend's device took `msg`.
    pub(super) fn top8_sent(&mut self, (to, msg): (MeshId, Msg)) {
        let mut state = self.top8_state();
        let to = to.to_bytes();
        if let Some(i) = (state.outbox.iter()).position(|(t, m)| *t == to && *m == msg) {
            state.outbox.remove(i);
            let _ = self.top8_save(&state);
        }
    }

    /// The shown friends as our manifest carries them: the name each gave
    /// and their own profile's avatar.
    pub(super) fn top8_for_profile(&self) -> Vec<Shown> {
        let state = self.top8_state();
        let friends = self.friend_profiles();
        (state.shown.iter())
            .filter_map(|id| {
                let name = state.may_show.get(id)?.clone();
                let avatar = (friends.get(id)).and_then(|m| m.assets(Slot::Avatar).next().cloned());
                Some(Shown { name, avatar })
            })
            .collect()
    }

    /// Signs our profile again with the Top 8 as it is now, if we have one
    /// and it changed.
    fn top8_republish(&self) {
        let (Some(store), Some(old)) = (&self.store, self.own_profile()) else {
            return;
        };
        let top8 = self.top8_for_profile();
        if top8 == old.top8 {
            return;
        }
        let device = store.device_key().public();
        let Some(cert) = (store.devices().devices().iter())
            .find(|c| *c.device() == device)
            .cloned()
        else {
            return;
        };
        let signed = Manifest::signed(
            old.version + 1,
            old.toml.clone(),
            old.assets.clone(),
            top8,
            store.device_key(),
            &cert,
        );
        let Ok(manifest) = signed else {
            return eprintln!("mesh-node: couldn't sign the profile's new Top 8");
        };
        if self.save_own_profile(&manifest).is_err() {
            return;
        }
        self.drop_profile_files(&old, &manifest);
        emit(
            "meshProfile",
            json!({ "fn": "top8", "id": store.id().to_string(), "version": manifest.version }),
        );
        self.offer_profile_all();
    }

    /// `id`'s profile is complete again: if we show them, show what it
    /// has now.
    pub(super) fn top8_refresh(&self, id: &MeshId) {
        let state = self.top8_state();
        if state.shown.contains(&id.to_bytes()) {
            self.top8_republish();
        }
    }

    /// Drops anyone who's no longer a friend from every list.
    pub(super) fn top8_prune(&self) {
        let Some(store) = &self.store else { return };
        let mut state = self.top8_state();
        let friend = |p: &[u8; 32]| {
            MeshId::from_bytes(p).is_ok_and(|id| store.account().kind(&id) == Some(Kind::Friend))
        };
        let before = postcard::to_stdvec(&state).expect("to memory");
        state.asked.retain(|p| friend(p));
        state.asks.retain(|p| friend(p));
        state.may_show.retain(|p, _| friend(p));
        state.let_show.retain(|p, _| friend(p));
        state.shown.retain(|p| friend(p));
        state.outbox.retain(|(p, _)| friend(p));
        if postcard::to_stdvec(&state).expect("to memory") != before
            && self.top8_save(&state).is_ok()
        {
            self.top8_republish();
        }
    }
}
