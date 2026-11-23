//! The helper's side of `dm` (SPEC-dm). Events wait in the sealed history,
//! not as envelopes. When a device is connected, or a fresh session arrives
//! from it, the helper reads what that device hasn't acknowledged, encrypts
//! it for that device alone and sends it on the `e2ee` service with the
//! "answer" flag. The reader stores the events and answers each frame `ok`
//! or `failed`; the counters move past what's `ok` (D5).
//!
//! A friend's device gets each event with the group it's in, if any: group
//! DMs go over the 1:1 sessions (e2ee D6), and History checks membership
//! (D7). Our own devices get everything, forwarded with its chat, author and
//! first arrival (D8). A child of `helper`, so it works on the same `Helper`.

use super::*;
use mesh_dm::Sender as DmSender;
use mesh_dm::Where;
use mesh_dm::chat::Taken;
use mesh_dm::event::{Body, Change, Event, EventId, GroupChange, MAX_MEMBERS};
use mesh_dm::history::History;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// The frame flag asking the reader to answer each frame once it's stored.
pub(super) const ANSWER: u8 = 2;
/// The answer for a frame that was opened and stored, or refused for good.
pub(super) const OK: u8 = 0;
/// The answer for a frame that couldn't be stored: send it again.
pub(super) const FAILED: u8 = 1;
/// The answer for a frame Olm couldn't open. Live senders take it as
/// `failed`; mail lists it apart (mailbox M16).
pub(super) const CANT_OPEN: u8 = 2;
/// Shown text in a notification, at most (as WhatsApp's).
const NOTIFY_CHARS: usize = 100;
/// After a `failed` answer, the first try again; later ones go on refresh.
const RETRY_SOON: Duration = Duration::from_secs(5);
/// Messages in one page of `dmOpen`.
pub(super) const PAGE: usize = 50;

/// The transport service typing goes on (D10): one frame per signal, empty
/// for a 1:1 chat or a group's ID, never stored or queued.
pub(super) const TYPING: &str = "typing";
/// A device's typing signals closer together than this are dropped.
const TYPING_GAP: Duration = Duration::from_secs(2);

/// Where a 1:1 chat with `peer` is kept on our devices.
/// A chat event to take: its frame, its group if it's in one, the event.
pub(super) type Taking = (usize, Option<[u8; 16]>, Event);

pub(super) fn direct_chat(peer: &MeshId) -> Where {
    Where::Direct(peer.to_bytes())
}

/// A chat as Mesh-Voice names it: a friend's ID, or a group's 32 hex.
pub(super) fn chat_text(at: &Where) -> String {
    match at {
        Where::Direct(p) => MeshId::from_bytes(p)
            .map(|p| p.to_string())
            .unwrap_or_default(),
        Where::Group(id) => e2ee::hex(id),
    }
}

fn person_text(p: &[u8; 32]) -> String {
    MeshId::from_bytes(p)
        .map(|p| p.to_string())
        .unwrap_or_default()
}

/// One line of a page, as `meshDmMessages` and `meshSpaceMessages` give it.
pub(super) fn shown_json(m: &mesh_dm::history::Shown, sent: bool) -> Value {
    let reactions: Vec<Value> = (m.reactions.iter())
        .map(|(emoji, who)| {
            let who: Vec<String> = who.iter().map(person_text).collect();
            json!({ "emoji": emoji, "who": who })
        })
        .collect();
    let attachments: Vec<Value> = (m.attachments.iter())
        .map(|a| {
            json!({
                "name": a.name,
                "mime": a.mime,
                "size": a.size,
                // ponytail: hex doubles a 16 KB preview; base64 if pages grow heavy.
                "preview": a.preview.as_ref().map(|p| e2ee::hex(p)),
            })
        })
        .collect();
    json!({
        "id": e2ee::hex(&m.id),
        "from": person_text(&m.author),
        "text": m.text,
        "edited": m.edited,
        "replyTo": m.reply_to.map(|r| e2ee::hex(&r)),
        "attachments": attachments,
        "reactions": reactions,
        "late": m.late,
        "time": m.time,
        "sent": sent,
    })
}

/// Writes the frames, finishes, and reads the reader's answers: one byte
/// per frame, `true` for `ok`. `None` if it didn't answer in time.
pub(super) async fn exchange(
    mut send: impl AsyncWrite + Unpin,
    mut recv: impl AsyncRead + Unpin,
    frames: &[Vec<u8>],
) -> Option<Vec<bool>> {
    let sent = async {
        for frame in frames {
            mesh_transport::frame::write_frame(&mut send, frame)
                .await
                .ok()?;
        }
        send.shutdown().await.ok()?;
        mesh_transport::frame::read_frame(&mut recv).await.ok()?
    };
    let answers = tokio::time::timeout(e2ee::SEND_TIMEOUT, sent)
        .await
        .ok()??;
    (answers.len() == frames.len()).then(|| answers.iter().map(|&a| a == OK).collect())
}

/// The reader's side: one frame of answers, then the end of the stream.
pub(super) async fn answer(mut send: impl AsyncWrite + Unpin, answers: &[u8]) {
    let _ = mesh_transport::frame::write_frame(&mut send, answers).await;
    let _ = send.shutdown().await;
}

/// A friend's body, or the answer it gets if it doesn't read: `failed` for
/// a newer version (the sender keeps it until we update), `ok` for garbage,
/// which is dropped and counted (D14).
pub(super) fn read_friend(body: &[u8]) -> Result<(Option<[u8; 16]>, Event), u8> {
    mesh_dm::history::from_friend(body).map_err(unread_answer)
}

/// History from another of our devices, or the answer if it doesn't read.
pub(super) fn read_forward(body: &[u8]) -> Result<(Where, DmSender, u64, Event), u8> {
    mesh_dm::history::unforward(body).map_err(unread_answer)
}

fn unread_answer(e: mesh_dm::history::Unread) -> u8 {
    match e {
        mesh_dm::history::Unread::Newer => FAILED,
        mesh_dm::history::Unread::Garbage => OK,
    }
}

fn dm_fail(e: impl std::fmt::Display) -> Fail {
    Fail(
        "unavailable",
        format!("the chat history isn't working: {e}"),
    )
}

fn not_found() -> Fail {
    Fail("not-found", "no such message or chat".to_owned())
}

fn parse_event_id(text: &str) -> Result<EventId, Fail> {
    e2ee::parse_conversation(text)
        .ok_or_else(|| Fail("bad-args", "that isn't a message ID".to_owned()))
}

impl Helper {
    /// Opens this device's history, as networking starts.
    pub(super) fn open_dm(&mut self) {
        // Opened copies from the last run go (dm *Never*).
        self.clear_opened(|_| true);
        let Some(store) = &self.store else { return };
        let data = self.path.parent().unwrap_or(Path::new("."));
        let me = DmSender {
            person: store.id().to_bytes(),
            device: store.device_key().public().to_bytes(),
        };
        self.dm = History::open(&data.join("dm"), store.data_key(), me)
            .inspect_err(|e| eprintln!("mesh-node: the chat history didn't open: {e}"))
            .ok();
        // Group changes are signed with our ID key, so any member can pass
        // them on (D7).
        let root = mesh_identity::RootKey::from_secret_bytes(*store.root_key().secret_bytes());
        if let Some(history) = &mut self.dm {
            history.set_signer(Box::new(move |bytes| {
                root.sign_bytes(mesh_dm::event::GROUP_SIGNATURE, bytes)
            }));
        }
    }

    /// Sends each of `id`'s connected devices what it hasn't acknowledged.
    pub(super) fn dm_deliver(&mut self, id: &MeshId) {
        let Some(net) = &self.net else { return };
        for addr in net.node.connected(id) {
            self.dm_deliver_to(id, addr);
        }
    }

    /// The people a chat's events go to, besides our own devices: the
    /// friend of a 1:1, the members of a group's version we hold.
    pub(super) fn dm_recipients(&self, at: &Where) -> Vec<MeshId> {
        let me = self.store.as_ref().map(Keystore::id);
        let people = match at {
            Where::Direct(p) => vec![*p],
            Where::Group(_) => self
                .dm
                .as_ref()
                .and_then(|h| h.members(at))
                .unwrap_or_default(),
        };
        (people.iter())
            .filter_map(|p| MeshId::from_bytes(p).ok())
            .filter(|p| Some(*p) != me)
            .collect()
    }

    /// One device's next batch, if none is in flight to it.
    pub(super) fn dm_deliver_to(&mut self, id: &MeshId, addr: MeshAddr) {
        let device = *addr.device.as_bytes();
        // Mail is collected first at unlock (mailbox *Opening mail* 1).
        if self.dm_flight.contains(&device) || self.net.is_none() || self.mail.collecting {
            return;
        }
        let Some((numbers, envelopes)) = self.dm_batch(id, device, |_| false) else {
            return;
        };
        let Some(net) = &self.net else { return };
        self.dm_flight.insert(device);
        let (node, back, id) = (net.node.clone(), self.back.clone(), *id);
        tokio::spawn(async move {
            let frames: Vec<Vec<u8>> = envelopes
                .iter()
                .map(|e| [&[ANSWER][..], e].concat())
                .collect();
            let answers = match node.open(&addr, e2ee::SERVICE).await {
                Ok((_, send, recv)) => exchange(send, recv, &frames).await,
                Err(_) => None,
            };
            let _ = back.send(Back::DmAnswered(Box::new((id, addr, numbers, answers))));
        });
    }

    /// What `device` of `id`'s hasn't acknowledged, but for what `skip`
    /// names, encrypted for it: the events' numbers and envelopes.
    pub(super) fn dm_batch(
        &mut self,
        id: &MeshId,
        device: [u8; 32],
        skip: impl Fn(&mesh_dm::history::ToSend) -> bool,
    ) -> Option<(Vec<u64>, Vec<Vec<u8>>)> {
        let own = self.store.as_ref().is_some_and(|s| s.id() == *id);
        let (Some(history), Some(e2ee)) = (&mut self.dm, &mut self.e2ee) else {
            return None;
        };
        history.add_device(device, id.to_bytes());
        let mut out = match history.outgoing(&device, unix_now() * 1000) {
            Ok(out) => out,
            Err(e) => {
                eprintln!("mesh-node: couldn't read the chat history: {e}");
                return None;
            }
        };
        out.retain(|t| !skip(t));
        out.truncate(e2ee::MAX_FRAMES);
        if out.is_empty() {
            return None;
        }
        // Our own devices get each event with its chat and author (D8); a
        // friend's, with its group if it's in one (e2ee D6).
        let bodies: Vec<Vec<u8>> = if own {
            out.iter().map(mesh_dm::history::forward).collect()
        } else {
            out.iter()
                .map(|t| mesh_dm::history::to_friend(&t.at, &t.event))
                .collect()
        };
        let sealed = e2ee.encrypt_device_batch(id, &device, NoteKind::Message, &bodies);
        let envelopes = match sealed {
            Ok(envelopes) => envelopes,
            Err(e) => {
                eprintln!("mesh-node: couldn't encrypt for a device: {e}");
                return None;
            }
        };
        Some((out.iter().map(|t| t.number).collect(), envelopes))
    }

    /// A device answered a batch (or didn't): move its counter, and send
    /// the next batch if it took this one.
    pub(super) fn dm_answered(
        &mut self,
        id: MeshId,
        addr: MeshAddr,
        numbers: Vec<u64>,
        answers: Option<Vec<bool>>,
    ) {
        let device = *addr.device.as_bytes();
        self.dm_flight.remove(&device);
        let Some(history) = &mut self.dm else { return };
        let Some(answers) = answers else { return };
        for (number, ok) in numbers.iter().zip(&answers) {
            history.acked(&device, *number, *ok);
        }
        if let Err(e) = history.save_counters() {
            eprintln!("mesh-node: couldn't save the delivery counters: {e}");
        }
        // "Sent" may have changed on the open chat.
        if let Some(open) = self.dm_open
            && answers.iter().any(|ok| *ok)
        {
            let _ = self.emit_page(&open, None);
        }
        if answers.iter().all(|ok| *ok) {
            self.dm_retry.remove(&device);
            self.dm_deliver_to(&id, addr);
        } else if self.dm_retry.insert(device, (id, addr)).is_none() {
            // Not taken yet (an add that hasn't arrived there, D7): again
            // soon, then on each refresh.
            let back = self.back.clone();
            tokio::spawn(async move {
                tokio::time::sleep(RETRY_SOON).await;
                let _ = back.send(Back::DmRetry(device));
            });
        }
    }

    /// The refresh: every device that answered `failed` gets another try.
    pub(super) fn dm_retry_all(&mut self) {
        let waiting: Vec<_> = self.dm_retry.values().cloned().collect();
        for (id, addr) in waiting {
            self.dm_deliver_to(&id, addr);
        }
    }

    /// Takes in the dm events of one stream from `id`'s device, each with
    /// its group if it's in one: stored with one sync per chat, and each
    /// frame's answer.
    pub(super) fn dm_take(
        &mut self,
        id: &MeshId,
        device: &[u8; 32],
        events: Vec<Taking>,
        answers: &mut [u8],
    ) {
        let from = DmSender {
            person: id.to_bytes(),
            device: *device,
        };
        let mut runs: Vec<(Where, Vec<usize>, Vec<Event>)> = Vec::new();
        for (i, group, event) in events {
            let at = group.map_or(direct_chat(id), Where::Group);
            match runs.last_mut() {
                Some(run) if run.0 == at => {
                    run.1.push(i);
                    run.2.push(event);
                }
                _ => runs.push((at, vec![i], vec![event])),
            }
        }
        for (at, frames, events) in runs {
            if self.dm.is_none() {
                for i in frames {
                    answers[i] = FAILED;
                }
                continue;
            }
            // A file's message shows by its name when it has no text.
            let texts: Vec<Option<String>> = (events.iter())
                .map(|e| match &e.body {
                    Body::Text {
                        text, attachments, ..
                    } if text.is_empty() => attachments.first().map(|a| a.name.clone()),
                    Body::Text { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .collect();
            // A delete drops the files it takes with it (D13).
            let dropped = self.files_of_deleted(&events);
            let history = self.dm.as_mut().expect("checked above");
            match history.receive(&at, from, events, unix_now() * 1000) {
                Ok(taken) => {
                    // Not known as a member yet: the sender keeps it (D7).
                    for (t, i) in taken.iter().zip(&frames) {
                        if *t == Taken::Refused(mesh_dm::chat::Refusal::NotYetMember) {
                            answers[*i] = FAILED;
                        }
                    }
                    let refused = taken
                        .iter()
                        .filter(|t| matches!(t, Taken::Refused(_)))
                        .count();
                    if refused > 0 {
                        eprintln!("mesh-node: {refused} chat events refused");
                    }
                    let new = (taken.iter().zip(texts))
                        .filter(|(t, _)| **t == Taken::Shown)
                        .filter_map(|(_, text)| text)
                        .collect();
                    for (hash, t) in dropped.iter().zip(&taken) {
                        if let (Some(file), Taken::Shown) = (hash, t) {
                            self.drop_file(file);
                        }
                    }
                    self.dm_changed(&at, id, new);
                }
                Err(e) => {
                    eprintln!("mesh-node: couldn't store chat events: {e}");
                    for i in frames {
                        answers[i] = FAILED;
                    }
                }
            }
        }
    }

    /// A chat named by Mesh-Voice: a friend's ID (they must be a friend), or
    /// a group's hex ID (it must be listed).
    pub(super) fn dm_chat(&mut self, text: &str) -> Result<Where, Fail> {
        if let Some(id) = e2ee::parse_conversation(text) {
            let at = Where::Group(id);
            let history = self.dm.as_ref().ok_or_else(|| dm_fail("not open"))?;
            if !history.chats().contains(&at) {
                return Err(not_found());
            }
            return Ok(at);
        }
        let peer = parse_id(text)?;
        self.friend(&peer)?;
        Ok(direct_chat(&peer))
    }

    fn friend(&mut self, peer: &MeshId) -> Result<(), Fail> {
        if self.unlocked()?.account().kind(peer) != Some(Kind::Friend) {
            return Err(Fail(
                "not-a-friend",
                format!("{peer} isn't a friend; you can only message friends"),
            ));
        }
        Ok(())
    }

    /// `meshDmMessages` for one chat: its newest page, or the page before
    /// `before`.
    pub(super) fn emit_page(&mut self, at: &Where, before: Option<EventId>) -> Result<(), Fail> {
        let me = self.unlocked()?.id().to_bytes();
        let history = self.dm.as_mut().ok_or_else(|| dm_fail("not open"))?;
        let (page, more) = history
            .page(at, before, PAGE, unix_now() * 1000)
            .map_err(dm_fail)?;
        let events: Vec<Value> = (page.iter())
            .map(|m| shown_json(m, m.author == me && history.is_sent(&m.id)))
            .collect();
        emit(
            "meshDmMessages",
            json!({ "id": chat_text(at), "events": events, "more": more }),
        );
        Ok(())
    }

    /// `meshDmChats`: every chat, newest activity first.
    pub(super) fn emit_chats(&mut self) -> Result<(), Fail> {
        let now = unix_now() * 1000;
        let names: HashMap<[u8; 32], String> = {
            let store = self.unlocked()?;
            (store.account().entries().iter())
                .map(|e| {
                    let name = if e.nick.is_empty() {
                        e.name.clone()
                    } else {
                        e.nick.clone()
                    };
                    (e.id().to_bytes(), name)
                })
                .collect()
        };
        let history = self.dm.as_mut().ok_or_else(|| dm_fail("not open"))?;
        let mut chats = Vec::new();
        // ponytail: loads every chat's newest segment for the list; keep last activity and unread in each index if lists grow long.
        for at in history.chats() {
            let (kind, name, members) = match at {
                Where::Direct(p) => (
                    "direct",
                    names.get(&p).cloned().unwrap_or_default(),
                    vec![p],
                ),
                Where::Group(_) => {
                    let Some(version) = history.group(&at, now).map_err(dm_fail)? else {
                        continue;
                    };
                    ("group", version.name, version.members.into_iter().collect())
                }
            };
            let chat = history.chat(&at, now).map_err(dm_fail)?;
            let last = chat
                .messages()
                .last()
                .and_then(|m| chat.display_time(&m.id))
                .unwrap_or(0);
            let members: Vec<String> = members.iter().map(person_text).collect();
            chats.push(json!({
                "id": chat_text(&at),
                "kind": kind,
                "name": name,
                "members": members,
                "last": last,
                "unread": chat.unread(),
                "mentions": 0,
            }));
        }
        chats.sort_by_key(|c| std::cmp::Reverse(c["last"].as_u64()));
        emit("meshDmChats", json!({ "chats": chats }));
        Ok(())
    }

    /// Stores one of our events and sends it to the chat's people and our
    /// own devices. For a group, we must be in the version we hold, and it
    /// goes to that version's members (D7).
    fn dm_store_and_send(&mut self, at: &Where, body: Body) -> Result<(), Fail> {
        let me = self.unlocked()?.id().to_bytes();
        let history = self.dm.as_mut().ok_or_else(|| dm_fail("not open"))?;
        let creation = matches!(body, Body::Group(GroupChange { after: None, .. }));
        if matches!(at, Where::Group(_))
            && !creation
            && !history.members(at).is_some_and(|m| m.contains(&me))
        {
            return Err(Fail("not-member", "you're not in this group".to_owned()));
        }
        match history.send(at, body, unix_now() * 1000) {
            Ok(_) => {}
            Err(mesh_dm::history::HistoryError::Event(e)) => {
                let kind = match e {
                    mesh_dm::event::EventError::TooLong(_) => "too-long",
                    mesh_dm::event::EventError::TooMany(_) => "too-many",
                    _ => "bad-args",
                };
                return Err(Fail(kind, e.to_string()));
            }
            Err(e) => return Err(dm_fail(e)),
        }
        for person in self.dm_recipients(at) {
            self.dm_deliver(&person);
            self.mail_out(&person);
        }
        if let Some(me) = self.store.as_ref().map(Keystore::id) {
            self.dm_deliver(&me);
            self.mail_out(&me);
        }
        Ok(())
    }

    /// Stores and sends one of our events, then answers with the chat's page.
    pub(super) fn dm_send_body(&mut self, at: &Where, body: Body) -> Result<(), Fail> {
        self.dm_store_and_send(at, body)?;
        self.emit_page(at, None)
    }

    /// The chat an event is in; with `own`, refused unless it's ours.
    fn dm_event(&mut self, id: &str, own: bool) -> Result<(Where, EventId), Fail> {
        let event = parse_event_id(id)?;
        let me = self.unlocked()?.id().to_bytes();
        let history = self.dm.as_ref().ok_or_else(|| dm_fail("not open"))?;
        let at = history.where_of(&event).ok_or_else(not_found)?;
        if own && history.author_of(&event) != Some(me) {
            return Err(Fail(
                "not-author",
                "only the author can change a message".to_owned(),
            ));
        }
        Ok((at, event))
    }

    /// A group change of ours, following the version we hold.
    fn dm_group_change(&mut self, group: &str, change: Change) -> Result<(), Fail> {
        let at = self.dm_chat(group)?;
        let history = self.dm.as_mut().ok_or_else(|| dm_fail("not open"))?;
        let version = history
            .group(&at, unix_now() * 1000)
            .map_err(dm_fail)?
            .ok_or_else(not_found)?;
        if let Change::Remove(_) = change
            && self.store.as_ref().map(|s| s.id().to_bytes()) != Some(version.creator)
        {
            return Err(Fail(
                "not-creator",
                "only the group's creator removes people".to_owned(),
            ));
        }
        // A removal also goes to the person removed (they're not a member
        // after it, so the members alone wouldn't send it to them).
        let removed = match &change {
            Change::Remove(p) => MeshId::from_bytes(p).ok(),
            _ => None,
        };
        let body = Body::Group(GroupChange {
            after: Some(version.head),
            change,
            signed: None,
        });
        self.dm_store_and_send(&at, body)?;
        if let Some(removed) = removed {
            self.dm_deliver(&removed);
        }
        self.emit_chats()
    }

    /// The dm commands (SPEC-dm *Client side*).
    pub(super) fn dm_command(&mut self, func: &str, args: &[String]) -> Result<(), Fail> {
        let arg = |i: usize| {
            args.get(i)
                .map(String::as_str)
                .ok_or_else(|| Fail("bad-args", format!("{func} is missing argument {}", i + 1)))
        };
        let optional_id = |i: usize| -> Result<Option<EventId>, Fail> {
            args.get(i)
                .filter(|a| !a.is_empty())
                .map(|a| parse_event_id(a))
                .transpose()
        };
        match func {
            "dmList" => self.emit_chats(),
            "dmOpen" => {
                let at = self.dm_chat(arg(0)?)?;
                self.dm_open = Some(at);
                self.emit_page(&at, optional_id(1)?)
            }
            "dmSend" => {
                let at = self.dm_chat(arg(0)?)?;
                // Sending in a chat means it's open on screen.
                self.dm_open = Some(at);
                let body = Body::Text {
                    text: arg(1)?.to_owned(),
                    reply_to: optional_id(2)?,
                    attachments: Vec::new(),
                };
                self.dm_send_body(&at, body)
            }
            "dmEdit" => {
                let (at, target) = self.dm_event(arg(0)?, true)?;
                let text = arg(1)?.to_owned();
                self.dm_send_body(&at, Body::Edit { target, text })
            }
            "dmDelete" => {
                let everyone = arg(1)? == "true";
                let (at, target) = self.dm_event(arg(0)?, everyone)?;
                let body = Body::Delete { target, everyone };
                let dropped = self.files_of_deleted(std::slice::from_ref(&Event {
                    version: mesh_dm::event::VERSION,
                    id: [0; 16],
                    time: 0,
                    seq: 0,
                    n: 0,
                    body: body.clone(),
                }));
                self.dm_send_body(&at, body)?;
                for file in dropped.into_iter().flatten() {
                    self.drop_file(&file);
                }
                Ok(())
            }
            "dmSendFile" | "dmFetch" => self.files_command(func, args),
            "dmReact" => {
                let (at, target) = self.dm_event(arg(0)?, false)?;
                let body = Body::React {
                    target,
                    emoji: arg(1)?.to_owned(),
                    on: arg(2)? == "true",
                };
                self.dm_send_body(&at, body)
            }
            "dmRead" => {
                let at = self.dm_chat(arg(0)?)?;
                let up_to = parse_event_id(arg(1)?)?;
                self.dm_store_and_send(&at, Body::Read { up_to })?;
                self.emit_chats()
            }
            "dmTyping" => {
                let at = self.dm_chat(arg(0)?)?;
                self.send_typing(&at);
                Ok(())
            }
            "dmGroupCreate" => {
                let mut members = Vec::new();
                for id in arg(0)?.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let peer = parse_id(id)?;
                    self.friend(&peer)?;
                    if !members.contains(&peer.to_bytes()) {
                        members.push(peer.to_bytes());
                    }
                }
                if members.is_empty() || members.len() >= MAX_MEMBERS {
                    return Err(Fail(
                        "too-many",
                        format!("a group has 2 to {MAX_MEMBERS} people"),
                    ));
                }
                let me = self.unlocked()?.id().to_bytes();
                let (nonce, id) = mesh_dm::new_group(&me).ok_or_else(|| {
                    Fail(
                        "random",
                        "couldn't get randomness from the system".to_owned(),
                    )
                })?;
                let at = Where::Group(id);
                let change = Change::Create {
                    name: arg(1)?.to_owned(),
                    members,
                    nonce,
                };
                let body = Body::Group(GroupChange {
                    after: None,
                    change,
                    signed: None,
                });
                self.dm_store_and_send(&at, body)?;
                self.emit_chats()
            }
            "dmGroupAdd" => {
                let peer = parse_id(arg(1)?)?;
                self.friend(&peer)?;
                self.dm_group_change(arg(0)?, Change::Add(peer.to_bytes()))
            }
            "dmGroupRemove" => {
                let peer = parse_id(arg(1)?)?;
                self.dm_group_change(arg(0)?, Change::Remove(peer.to_bytes()))
            }
            "dmGroupLeave" => self.dm_group_change(arg(0)?, Change::Leave),
            "dmGroupRename" => self.dm_group_change(arg(0)?, Change::Rename(arg(1)?.to_owned())),
            _ => Err(Fail("unknown-fn", format!("unknown command {func}"))),
        }
    }

    /// After events came in from `from`: the open chat's page again, or a
    /// note for each new message, and the list.
    pub(super) fn dm_changed(&mut self, at: &Where, from: &MeshId, new: Vec<String>) {
        if self.dm_open == Some(*at) {
            let _ = self.emit_page(at, None);
        } else {
            for text in new {
                let text: String = text.chars().take(NOTIFY_CHARS).collect();
                emit(
                    "meshDmNotify",
                    json!({ "id": chat_text(at), "from": from.to_string(), "text": text }),
                );
            }
        }
        let _ = self.emit_chats();
    }
}

impl Helper {
    /// "Typing" to the chat's people's connected devices, on the live
    /// connection only (D10).
    fn send_typing(&mut self, at: &Where) {
        let Some(net) = &self.net else { return };
        let frame = match at {
            Where::Direct(_) => Vec::new(),
            Where::Group(id) => id.to_vec(),
        };
        for person in self.dm_recipients(at) {
            for addr in net.node.connected(&person) {
                let (node, frame) = (net.node.clone(), frame.clone());
                tokio::spawn(async move {
                    if let Ok((_, mut send, _)) = node.open(&addr, TYPING).await {
                        let _ = mesh_transport::frame::write_frame(&mut send, &frame).await;
                        let _ = send.finish();
                    }
                });
            }
        }
    }

    /// A typing signal from `id`'s device: `meshDmTyping` if it's from a
    /// friend in that 1:1 chat or a member of that group.
    pub(super) fn typing_heard(&mut self, id: MeshId, device: [u8; 32], frame: Vec<u8>) {
        let now = std::time::Instant::now();
        if self
            .typing_last
            .get(&device)
            .is_some_and(|at| now.duration_since(*at) < TYPING_GAP)
        {
            return;
        }
        if let Ok(both) = <[u8; 32]>::try_from(&frame[..]) {
            return self.space_typing_heard(id, device, both, now);
        }
        let at = match <[u8; 16]>::try_from(&frame[..]) {
            Ok(group) => Where::Group(group),
            Err(_) if frame.is_empty() => direct_chat(&id),
            Err(_) => return,
        };
        let allowed = match at {
            Where::Direct(_) => self
                .store
                .as_ref()
                .is_some_and(|s| s.account().kind(&id) == Some(Kind::Friend)),
            Where::Group(_) => (self.dm.as_ref())
                .and_then(|h| h.members(&at))
                .is_some_and(|m| m.contains(&id.to_bytes())),
        };
        if !allowed {
            return;
        }
        self.typing_last.insert(device, now);
        emit(
            "meshDmTyping",
            json!({ "id": chat_text(&at), "who": [id.to_string()] }),
        );
    }
}

/// One chat and author's events in a synced stream: the frames they came
/// in, and each with its first arrival.
type Run = (Where, DmSender, Vec<usize>, Vec<(u64, Event)>);

impl Helper {
    /// History another of our devices passed on: stored as it was there,
    /// each run of one chat and author as one batch.
    pub(super) fn dm_take_synced(
        &mut self,
        via: &[u8; 32],
        synced: Vec<(usize, (Where, DmSender, u64, Event))>,
        answers: &mut [u8],
    ) {
        let Some(history) = &mut self.dm else {
            for (i, _) in synced {
                answers[i] = FAILED;
            }
            return;
        };
        let now = unix_now() * 1000;
        let mut runs: Vec<Run> = Vec::new();
        for (i, (at, author, received, event)) in synced {
            match runs.last_mut() {
                Some(run) if run.0 == at && run.1 == author => {
                    run.2.push(i);
                    run.3.push((received, event));
                }
                _ => runs.push((at, author, vec![i], vec![(received, event)])),
            }
        }
        let mut chats = Vec::new();
        for (at, author, frames, events) in runs {
            match history.receive_synced(&at, author, *via, events, now) {
                Ok(taken) => {
                    for (t, i) in taken.iter().zip(&frames) {
                        if *t == Taken::Refused(mesh_dm::chat::Refusal::NotYetMember) {
                            answers[*i] = FAILED;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("mesh-node: couldn't store synced history: {e}");
                    for i in frames {
                        answers[i] = FAILED;
                    }
                }
            }
            if !chats.contains(&at) {
                chats.push(at);
            }
        }
        // Our own devices' history isn't news: no notes, just what's open
        // and the list (a chat made there shows here).
        if let Some(open) = self.dm_open
            && chats.contains(&open)
        {
            let _ = self.emit_page(&open, None);
        }
        if !chats.is_empty() {
            let _ = self.emit_chats();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_dm::event::{Body, VERSION};

    /// The ack logic over a stream: answers line up with frames, a short or
    /// missing answer is no answer.
    #[tokio::test]
    async fn frames_and_answers() {
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let (recv, send) = tokio::io::split(ours);
        let frames = vec![vec![ANSWER, 1], vec![ANSWER, 2], vec![ANSWER, 3]];
        let reader = async move {
            let (mut r, w) = tokio::io::split(theirs);
            let got = e2ee::read(&mut r).await;
            assert_eq!(got.len(), 3);
            assert!(got.iter().all(|(flags, _)| flags & ANSWER != 0));
            answer(w, &[OK, FAILED, OK]).await;
        };
        let (answers, ()) = tokio::join!(exchange(send, recv, &frames), reader);
        assert_eq!(answers, Some(vec![true, false, true]));

        // Two answers for three frames: not trusted.
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let (recv, send) = tokio::io::split(ours);
        let reader = async move {
            let (mut r, w) = tokio::io::split(theirs);
            e2ee::read(&mut r).await;
            answer(w, &[OK, OK]).await;
        };
        let (answers, ()) = tokio::join!(exchange(send, recv, &frames), reader);
        assert_eq!(answers, None);
    }

    /// A body from a newer version is answered `failed`, so the sender
    /// keeps it until we update; garbage is answered ok and dropped.
    #[test]
    fn a_newer_event_waits_on_the_sender() {
        let event = mesh_dm::event::Event {
            version: VERSION,
            id: [1; 16],
            time: 1,
            seq: 1,
            n: 1,
            body: Body::Read { up_to: [2; 16] },
        };
        let body = mesh_dm::history::to_friend(&Where::Direct([3; 32]), &event);
        assert!(read_friend(&body).is_ok());
        let mut newer = body.clone();
        newer[0] = mesh_dm::history::FRIEND_VERSION + 1;
        assert_eq!(read_friend(&newer).err(), Some(FAILED));
        assert_eq!(read_friend(b"junk").err(), Some(OK));
        let _ = VERSION;
    }

    #[test]
    fn each_peer_has_its_own_chat() {
        let (a, b) = (
            RootKey::generate().unwrap().id(),
            RootKey::generate().unwrap().id(),
        );
        assert_ne!(direct_chat(&a).key(), direct_chat(&b).key());
        assert_eq!(direct_chat(&a).key(), direct_chat(&a).key());
    }

    /// PLAN-dm Task 9b, criterion 4: one device takes in 10,000 events from
    /// another, on disk, through e2ee, the frames and the acks. The network
    /// itself isn't in it: 10,000 small frames are about 3 MB, well under a
    /// second on a LAN.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "a measurement: cargo test --release -p mesh-node intake -- --ignored --nocapture"]
    async fn intake_of_ten_thousand_events() {
        use mesh_e2ee::E2ee;
        use mesh_identity::{DeviceCert, DeviceKey, DeviceList};
        const EVENTS: usize = 10_000;
        const KEY: [u8; 32] = [5; 32];
        let now = unix_now();
        let person = |name: &str| {
            let root = RootKey::generate().unwrap();
            let device = DeviceKey::generate().unwrap();
            let cert = DeviceCert::issue(&root, &device.public(), name, now).unwrap();
            let devices = DeviceList::first(&root, cert).unwrap();
            // On the real disk, not /tmp, which may be RAM: syncs must cost.
            let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
            let dir = target.join(format!("mesh-intake-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let e2ee = E2ee::open(&dir, &KEY, &root, &device, &devices, now).unwrap();
            let me = DmSender {
                person: root.id().to_bytes(),
                device: device.public().to_bytes(),
            };
            let history = History::open(&dir.join("dm"), &KEY, me).unwrap();
            (root, device, devices, e2ee, history, dir)
        };
        let (a_root, a_device, a_devices, mut a_e2ee, mut a_history, a_dir) = person("alice");
        let (b_root, b_device, b_devices, mut b_e2ee, mut b_history, b_dir) = person("bob");
        let (alice, bob) = (a_root.id(), b_root.id());
        let field = b_e2ee.record_field(&alice, now).unwrap();
        a_e2ee
            .learn(&bob, &b_devices, &b_device.public(), &field)
            .unwrap();
        let field = a_e2ee.record_field(&bob, now).unwrap();
        b_e2ee
            .learn(&alice, &a_devices, &a_device.public(), &field)
            .unwrap();

        let chat = direct_chat(&bob);
        let ms = now * 1000;
        let text = |i: usize| Body::Text {
            text: format!("message {i}: about the length of a short chat line"),
            reply_to: None,
            attachments: vec![],
        };
        let started = std::time::Instant::now();
        for i in 0..EVENTS {
            a_history.send(&chat, text(i), ms).unwrap();
        }
        let stored = started.elapsed();

        let device = b_device.public().to_bytes();
        // Criterion 4 is a new device of our own taking in history, which
        // has no limit; a friend's device gets the newest 2,000 (D5). Own-
        // device encryption comes with Task 10, so the counters treat this
        // device as ours while the envelopes use the pair's session: the
        // same opening and storing, event for event.
        a_history.add_device(device, alice.to_bytes());
        let started = std::time::Instant::now();
        let mut intake = std::time::Duration::ZERO;
        let mut taken = 0;
        loop {
            let mut out = a_history.outgoing(&device, ms).unwrap();
            out.truncate(e2ee::MAX_FRAMES);
            if out.is_empty() {
                break;
            }
            let bodies: Vec<Vec<u8>> = out.iter().map(|t| t.event.to_bytes().unwrap()).collect();
            let sealed = a_e2ee
                .encrypt_device_batch(&bob, &device, NoteKind::Message, &bodies)
                .unwrap();
            let frames: Vec<Vec<u8>> = sealed.iter().map(|e| [&[ANSWER][..], e].concat()).collect();
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            let (recv, send) = tokio::io::split(ours);
            let reader = async {
                let (mut r, w) = tokio::io::split(theirs);
                let got = e2ee::read(&mut r).await;
                let begun = std::time::Instant::now();
                let envelopes: Vec<Vec<u8>> = got.into_iter().map(|(_, e)| e).collect();
                let opened = b_e2ee.decrypt_batch(&envelopes, now).unwrap();
                let events: Vec<Event> = opened
                    .into_iter()
                    .map(|r| Event::from_bytes(&r.unwrap().opened[0].body).unwrap())
                    .collect();
                let from = DmSender {
                    person: alice.to_bytes(),
                    device: a_device.public().to_bytes(),
                };
                let kept = b_history
                    .receive(&direct_chat(&alice), from, events, ms)
                    .unwrap();
                taken += kept.iter().filter(|t| **t == Taken::Shown).count();
                intake += begun.elapsed();
                answer(w, &vec![OK; envelopes.len()]).await;
            };
            let (answers, ()) = tokio::join!(exchange(send, recv, &frames), reader);
            for (t, ok) in out.iter().zip(answers.unwrap()) {
                a_history.acked(&device, t.number, ok);
            }
            a_history.save_counters().unwrap();
        }
        let total = started.elapsed();
        assert_eq!(taken, EVENTS);
        println!(
            "intake of {EVENTS} events: {:.2} s in all (sender's reads, encryption, frames, acks), \
             {:.2} s of it the reader opening and storing; storing them on the sender took {:.2} s",
            total.as_secs_f64(),
            intake.as_secs_f64(),
            stored.as_secs_f64()
        );
        assert!(total.as_secs() < 30, "criterion 4: under 30 s");
        let _ = (VERSION, a_dir.clone(), b_dir.clone());
        for dir in [a_dir, b_dir] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
