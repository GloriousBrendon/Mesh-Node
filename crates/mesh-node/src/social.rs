//! The helper's side of `social` (SPEC-social): collecting the friend
//! requests left with our codes, presence to and from friends (D12, D13),
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
    pub(super) lookup_id: [u8; 16],
    /// A seed says the code is still live.
    pub(super) live: bool,
    /// A seed knows the code and says it's gone.
    pub(super) gone: bool,
    pub(super) knocks: Vec<Vec<u8>>,
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
pub(super) fn push_account(node: Arc<Node>, addr: MeshAddr, account: Vec<u8>) {
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
    pub(super) fn request(
        &mut self,
        id: MeshId,
        lookup_id: [u8; 16],
        note: &str,
    ) -> Result<(), Fail> {
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

    /// Takes in the requests left with our codes, and drops codes that are
    /// gone once their requests are in.
    pub(super) fn collected(&mut self, found: Vec<Collected>) {
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
            self.contacts_changed(None);
            self.dial_contacts();
            self.changed(None);
        }
        if dropped {
            self.emit_codes(None);
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
    pub(super) fn connected(&mut self, id: &MeshId) -> bool {
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

    /// `meshSocial`: friends, requests both ways, blocks and our status.
    /// `answers` names the command it answers; `None` when something changed
    /// by itself (a request came, someone connected).
    pub(super) fn emit_social(&self, answers: Option<&str>) {
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
}
