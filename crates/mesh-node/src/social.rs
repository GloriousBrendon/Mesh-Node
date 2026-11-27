//! The helper's side of `social` (SPEC-social revision 3): learning which
//! of our codes are gone, the `added` proof that a friendship is mutual, presence to and from friends (D12, D13),
//! and account sync between our own devices (D11). A child of `helper`, so
//! it works on the same `Helper`.

use super::*;

/// How often friend requests left with our codes are collected (D7).
pub(super) const COLLECT_EVERY: Duration = Duration::from_secs(300);

/// What a friend's device shows: on the wire, one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Presence {
    Offline = 0,
    Idle = 1,
    Online = 2,
    Dnd = 3,
}

impl Presence {
    pub(super) fn from_byte(byte: u8) -> Option<Self> {
        [Self::Offline, Self::Idle, Self::Online, Self::Dnd]
            .into_iter()
            .find(|p| *p as u8 == byte)
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Idle => "idle",
            Self::Online => "online",
            Self::Dnd => "dnd",
        }
    }
}

/// One code's requests, from every seed that answered.
pub(super) struct Collected {
    pub(super) code: FriendCode,
    /// A seed says the code is still live.
    pub(super) live: bool,
    /// A seed knows the code and says it's gone.
    pub(super) gone: bool,
}

/// "I have you as outgoing or friend" (social R3-3): one frame, `1`.
pub(super) const ADDED: &str = "added";

/// Takes one `added` frame and answers that it came.
pub(super) async fn serve_added(
    mut stream: mesh_transport::ServiceStream,
    back: tokio::sync::mpsc::UnboundedSender<Back>,
) {
    let id = stream.peer.id;
    let got = async {
        let frame = mesh_transport::frame::read_frame(&mut stream.recv)
            .await
            .ok()??;
        (frame == [1]).then(|| back.send(Back::Added(id)).ok())??;
        mesh_transport::frame::write_frame(&mut stream.send, &[1])
            .await
            .ok()
    };
    let _ = tokio::time::timeout(SYNC_TIMEOUT, got).await;
    let _ = stream.send.finish();
}

/// The account-state service between our own devices (D11).
pub(super) const SYNC: &str = "sync";

/// What a device shows its friends (D12).
pub(super) const PRESENCE: &str = "presence";

/// Presence is sent again this often, even unchanged.
pub(super) const HEARTBEAT: Duration = Duration::from_secs(60);

/// A friend's device silent this long counts as offline.
pub(super) const PRESENCE_SILENCE: Duration = Duration::from_secs(150);

/// How long a device has to send its state.
pub(super) const SYNC_TIMEOUT: Duration = Duration::from_secs(20);

/// Sends our account state to another of our devices, in the background.
pub(super) fn push_account(node: crate::nodes::Nodes, addr: MeshAddr, account: Vec<u8>) {
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

impl Helper {
    /// Collects the friend requests left with our codes, in the background.
    pub(super) fn collect(&self) {
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
                .map(|(code, _)| Collected {
                    code: *code,
                    live: false,
                    gone: false,
                })
                .collect();
            for addr in seeds.iter() {
                let Ok(answers) = seed::ask_many(&anon, addr, seed::KNOCK_GET, &requests).await
                else {
                    continue;
                };
                for (got, answer) in found.iter_mut().zip(answers) {
                    if let Some(knocks::Get::Found { live, .. }) = knocks::Get::from_bytes(&answer)
                    {
                        got.live |= live;
                        got.gone |= !live;
                    }
                }
            }
            let _ = back.send(Back::Collected(found));
        });
    }

    /// Drops our codes the seeds say are gone.
    pub(super) fn collected(&mut self, found: Vec<Collected>) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let mut dropped = false;
        // Requests left by 0.5.x clients are never read (social R3-4); a
        // collect only learns which codes are gone.
        for got in found {
            if got.gone && !got.live {
                dropped = true;
                if let Err(e) = store.drop_code(&got.code) {
                    eprintln!("mesh-node: couldn't drop a used code: {e}");
                }
            }
        }
        if dropped {
            self.emit_codes(None);
        }
    }

    /// Tells each connected device of `id` that we've added them, if we
    /// have (social R3-3).
    pub(super) fn send_added(&self, id: &MeshId) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        if !matches!(
            store.account().kind(id),
            Some(Kind::Outgoing | Kind::Friend)
        ) {
            return;
        }
        for addr in net.node.connected(id) {
            let node = net.node.clone();
            tokio::spawn(async move {
                let sent = async {
                    let (_, mut send, mut recv) = node.open(&addr, ADDED).await.ok()?;
                    mesh_transport::frame::write_frame(&mut send, &[1])
                        .await
                        .ok()?;
                    let _ = mesh_transport::frame::read_frame(&mut recv).await;
                    send.finish().ok()
                };
                let _ = tokio::time::timeout(SYNC_TIMEOUT, sent).await;
            });
        }
    }

    /// `id` says they've added us: if we'd added them, friends now, and we
    /// say so back. From anyone else it's dropped and nothing shows.
    pub(super) fn added_heard(&mut self, id: MeshId) {
        if self.connected(&id) {
            self.changed(None);
            self.present_to(&id);
            self.send_added(&id);
        }
    }

    /// A friend's best device (D13): DND beats online, which beats idle.
    pub(super) fn presence_of(&self, id: &MeshId) -> Presence {
        self.presence
            .get(&id.to_bytes())
            .and_then(|devices| devices.values().max().copied())
            .unwrap_or(Presence::Offline)
    }

    /// What friends see of this device: invisible shows as offline, but we
    /// stay reachable (D13).
    pub(super) fn update_shown(&self) {
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
    pub(super) fn present_to(&self, id: &MeshId) {
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
            // Each presence stream starts with our direct key, so a friend
            // who restarted (and forgot it) learns it again (P3).
            let direct = self.direct_frame();
            tokio::spawn(async move {
                if let Some(frame) = direct {
                    send_direct(&node, &addr, &frame).await;
                }
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

    /// What friends and own devices are told on `direct`: our direct key's
    /// cert and the direct node's relay. `None` while there's no direct node
    /// (Hide my IP) or it has no relay yet.
    pub(super) fn direct_frame(&self) -> Option<Vec<u8>> {
        let cert = self.direct_cert.as_ref()?;
        let relay = self.net.as_ref()?.node.direct()?.addr().relay?;
        Some([cert.to_bytes(), relay.to_string().into_bytes()].concat())
    }

    /// Tells each of `id`'s connected devices our direct key, if `id` is us
    /// or a friend (P3).
    pub(super) fn tell_direct(&self, id: &MeshId) {
        let (Some(store), Some(net), Some(frame)) = (&self.store, &self.net, self.direct_frame())
        else {
            return;
        };
        if *id != store.id() && store.account().kind(id) != Some(Kind::Friend) {
            return;
        }
        for addr in net.node.connected(id) {
            let (node, frame) = (net.node.clone(), frame.clone());
            tokio::spawn(async move { send_direct(&node, &addr, &frame).await });
        }
    }

    /// A device told us its direct key: kept if it's ours or a friend's.
    pub(super) fn direct_heard(&self, id: &MeshId, cert: &DirectCert, relay: &str) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let own = *id == store.id();
        if own || store.account().kind(id) == Some(Kind::Friend) {
            net.node.learn(id, cert, relay, own);
        }
    }

    /// A friend's device said what it shows, or went quiet (`None`).
    pub(super) fn presence_heard(
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

    /// Another of our devices sent its account state: take in what's newer,
    /// and send ours back if it's missing something.
    pub(super) fn synced(&mut self, theirs: &Account, from: &MeshAddr) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let merged = match store.merge_account(theirs) {
            Ok(merged) => merged,
            Err(e) => return eprintln!("mesh-node: couldn't save a synced change: {e}"),
        };
        let ours = store.account().clone();
        if merged {
            self.contacts_changed(None);
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
    pub(super) fn sync_own(&self) {
        let (Some(store), Some(net)) = (&self.store, &self.net) else {
            return;
        };
        let Some(own) = Target::own(store) else {
            return;
        };
        // One sync at a time: a slow one isn't stacked on at each refresh.
        if self.dialling.claim(vec![store.id()]).is_empty() {
            return;
        }
        let this = *store.device_key().public().as_bytes();
        let account = store.account().to_bytes();
        let (node, anon, seeds) = (net.node.clone(), net.anon.clone(), self.seeds.clone());
        let (gets, dialling, me) = (net.gets.for_("own"), self.dialling.clone(), store.id());
        tokio::spawn(async move {
            let found = loop {
                let found =
                    routing::own_devices(&anon, &gets, &seeds, &own, &this, unix_now()).await;
                if !dialling.done(&me) {
                    break found;
                }
            };
            for addr in found {
                push_account(node.clone(), addr, account.clone());
            }
        });
    }

    /// Someone we know connected: an `outgoing` contact becomes a friend (D8).
    /// True if that changed anything.
    pub(super) fn connected(&mut self, id: &MeshId) -> bool {
        let Some(store) = self.store.as_mut() else {
            return false;
        };
        match store.connected(id) {
            Ok(changed) => {
                // A new friend: the direct node lets them in from now (P3).
                if changed {
                    self.allow_contacts();
                }
                changed
            }
            Err(e) => {
                eprintln!("mesh-node: couldn't save a new friend: {e}");
                false
            }
        }
    }

    /// `meshSocial`: friends, requests both ways, blocks and our status.
    /// `answers` names the command it answers; `None` when something changed
    /// by itself (a request came, someone connected).
    pub(super) fn emit_social(&self, answers: Option<&str>) {
        let Some(store) = &self.store else { return };
        let (mut friends, mut outgoing, mut blocked) = (Vec::new(), Vec::new(), Vec::new());
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
                // Never shown (social R3-2): an old device's sync may bring one.
                Kind::Incoming => {}
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
                "incoming": [],
                "outgoing": outgoing,
                "blocked": blocked,
                "status": store.account().status().as_str(),
            }),
        );
    }
}

/// Sends one `direct` frame to `addr`, in the background's own time.
async fn send_direct(node: &crate::nodes::Nodes, addr: &MeshAddr, frame: &[u8]) {
    if let Ok((_, mut send, _recv)) = node.open(addr, crate::nodes::DIRECT).await
        && mesh_transport::frame::write_frame(&mut send, frame)
            .await
            .is_ok()
    {
        let _ = send.finish();
    }
}
