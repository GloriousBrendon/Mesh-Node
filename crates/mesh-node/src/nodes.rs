//! A device's two endpoints (SPEC-connection-privacy P3): the relay node on
//! the device key, which everyone may know and which never goes direct, and
//! the direct node on the direct key, which only friends and own devices are
//! told (over a connection with them, the `direct` service) and only they
//! may connect to. Both report peers by device key, so callers name a device
//! the same way whichever node carries it.
//!
//! `open` and `ping` to a device go over the direct node when it already has
//! a connection to that device; otherwise over the relay node, while the
//! direct node dials the device's direct key (if known) in the background,
//! for next time. So a direct key that's stale or not up yet (a friend who
//! just restarted) never slows a message down. `relayed()` is the same pair for Space
//! traffic (P14): direct only with our own devices, relayed with everyone
//! else, friends included. The direct node is swapped on rotation (P4), for
//! every holder at once.

use mesh_identity::{DirectCert, MeshId};
use mesh_transport::{
    MeshAddr, Node, Peer, Pong, PublicKey, RecvStream, SendStream, Status, TransportError,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// The service a device tells a friend its direct key on: one frame, the
/// `DirectCert` then the direct node's relay URL. Sent again on rotation.
pub const DIRECT: &str = "direct";

/// One friend's or own device's direct address.
#[derive(Clone)]
struct Known {
    addr: MeshAddr,
    id: MeshId,
    own: bool,
}

#[derive(Clone)]
pub struct Nodes {
    pub relay: Arc<Node>,
    /// `None` with Hide my IP on (P6).
    direct: Arc<RwLock<Option<Arc<Node>>>>,
    /// By device key.
    directs: Arc<Mutex<HashMap<[u8; 32], Known>>>,
    /// `relayed()`: the direct node is for our own devices only.
    own_only: bool,
    /// Devices a background direct dial is under way to.
    dialling: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
}

impl Nodes {
    pub fn new(relay: Arc<Node>, direct: Option<Arc<Node>>) -> Self {
        Self {
            relay,
            direct: Arc::new(RwLock::new(direct)),
            directs: Arc::default(),
            own_only: false,
            dialling: Arc::default(),
        }
    }

    /// The same nodes for Space traffic (P14): relayed, except with our own
    /// devices.
    pub fn relayed(&self) -> Self {
        Self {
            own_only: true,
            ..self.clone()
        }
    }

    pub fn direct(&self) -> Option<Arc<Node>> {
        read(&self.direct).clone()
    }

    /// Puts in a new direct node (rotation, P4), returning the old one.
    pub fn swap_direct(&self, new: Option<Arc<Node>>) -> Option<Arc<Node>> {
        let mut direct = (self.direct.write()).unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::replace(&mut direct, new)
    }

    /// Remembers `id`'s device's direct address, from a `direct` frame that
    /// `cert`'s device sent; `own` if `id` is us. The caller checks it's us
    /// or a friend.
    pub fn learn(&self, id: &MeshId, cert: &DirectCert, relay: &str, own: bool) -> bool {
        let Some(addr) = MeshAddr::from_parts(cert.direct().as_bytes(), relay) else {
            return false;
        };
        let known = Known { addr, id: *id, own };
        lock(&self.directs).insert(*cert.device().as_bytes(), known);
        true
    }

    /// Forgets the direct addresses of everyone `keep` says no to (no longer
    /// a friend: removed or blocked).
    pub fn forget_all_but(&self, keep: impl Fn(&MeshId) -> bool) {
        lock(&self.directs).retain(|_, k| keep(&k.id));
    }

    /// The direct node if it has a connection to `addr`'s device that may
    /// be used here. With none, a background dial to its direct key, once.
    fn pick(&self, addr: &MeshAddr) -> Option<Arc<Node>> {
        let direct = self.direct()?;
        let known = lock(&self.directs).get(addr.device.as_bytes()).cloned();
        if self.own_only && !known.as_ref().is_some_and(|k| k.own) {
            return None;
        }
        if direct.has(&addr.device) {
            return Some(direct);
        }
        let device = *addr.device.as_bytes();
        if let Some(known) = known
            && lock(&self.dialling).insert(device)
        {
            let dialling = self.dialling.clone();
            tokio::spawn(async move {
                let _ = direct.dial(&known.addr).await;
                lock(&dialling).remove(&device);
            });
        }
        None
    }

    pub async fn open(
        &self,
        addr: &MeshAddr,
        service: &str,
    ) -> Result<(Peer, SendStream, RecvStream), TransportError> {
        if let Some(direct) = self.pick(addr)
            && let Ok(opened) = direct.open(addr, service).await
        {
            return Ok(opened);
        }
        self.relay.open(addr, service).await
    }

    pub async fn ping(&self, addr: &MeshAddr) -> Result<Pong, TransportError> {
        if let Some(direct) = self.pick(addr)
            && let Ok(pong) = direct.ping(addr).await
        {
            return Ok(pong);
        }
        self.relay.ping(addr).await
    }

    pub fn send_datagram(&self, device: &PublicKey, data: Vec<u8>) -> bool {
        match MeshAddr::from_device(device.as_bytes()).and_then(|a| self.pick(&a)) {
            Some(direct) => direct.send_datagram(device, data),
            None => self.relay.send_datagram(device, data),
        }
    }

    /// The next datagram from either node.
    pub async fn next_datagram(&self) -> Option<(Peer, Vec<u8>)> {
        match self.direct() {
            Some(direct) => tokio::select! {
                got = self.relay.next_datagram() => got,
                got = direct.next_datagram() => got,
            },
            None => self.relay.next_datagram().await,
        }
    }

    /// `id`'s devices with an open connection on either node, by device key.
    pub fn connected(&self, id: &MeshId) -> Vec<MeshAddr> {
        let mut all = self.relay.connected(id);
        for addr in self.direct().iter().flat_map(|d| d.connected(id)) {
            if !all.iter().any(|a| a.device == addr.device) {
                all.push(addr);
            }
        }
        all
    }

    pub fn close_idle(&self, id: &MeshId) {
        self.each(|n| n.close_idle(id));
    }

    pub fn disconnect(&self, id: &MeshId) {
        self.each(|n| n.disconnect(id));
    }

    pub fn prune(&self) {
        self.each(Node::prune);
    }

    pub fn open_connections(&self) -> usize {
        self.relay.open_connections() + self.direct().map_or(0, |d| d.open_connections())
    }

    /// The relay node's state, `direct` if either has a direct path, and the
    /// devices connected on both.
    pub fn status(&self) -> Status {
        let mut status = self.relay.status();
        if let Some(direct) = self.direct() {
            let theirs = direct.status();
            status.direct |= theirs.direct;
            status.connections += theirs.connections;
            for (id, path) in theirs.paths {
                match status.paths.binary_search_by_key(&id, |(i, _)| *i) {
                    Ok(at) if path == mesh_transport::Path::Direct => status.paths[at].1 = path,
                    Ok(_) => {}
                    Err(at) => status.paths.insert(at, (id, path)),
                }
            }
        }
        status
    }

    /// The relay node's address: what address records carry (no IPs).
    pub fn addr(&self) -> MeshAddr {
        self.relay.addr()
    }

    pub async fn close(&self) {
        if let Some(direct) = self.swap_direct(None) {
            direct.close().await;
        }
        self.relay.close().await;
    }

    fn each(&self, f: impl Fn(&Node)) {
        f(&self.relay);
        if let Some(direct) = self.direct() {
            f(&direct);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}
