//! A device's two endpoints (SPEC-connection-privacy P3): the relay node on
//! the device key, which everyone may know and which never goes direct, and
//! the direct node on the direct key, which only friends and own devices are
//! told (over a connection with them, the `direct` service) and only they
//! may connect to. Both report peers by device key, so callers name a device
//! the same way whichever node carries it.
//!
//! `open` and `ping` to a device go over the direct node when it already has
//! a connection to that device, or knows its direct key; otherwise, and if
//! that fails, over the relay node. `relayed()` is the same pair for Space
//! traffic (P14): direct only with our own devices, relayed with everyone
//! else, friends included.

use mesh_identity::{DirectCert, MeshId};
use mesh_transport::{
    MeshAddr, Node, Peer, Pong, PublicKey, RecvStream, SendStream, Status, TransportError,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The service a device tells a friend its direct key on: one frame, the
/// `DirectCert` then the direct node's relay URL. Sent again on rotation.
pub const DIRECT: &str = "direct";

/// Friends' and own devices' direct addresses, by device key, and whether
/// the device is one of ours.
type Directs = Arc<Mutex<HashMap<[u8; 32], (MeshAddr, bool)>>>;

#[derive(Clone)]
pub struct Nodes {
    pub relay: Arc<Node>,
    /// `None` with Hide my IP on (P6).
    pub direct: Option<Arc<Node>>,
    directs: Directs,
    /// `relayed()`: the direct node is for our own devices only.
    own_only: bool,
}

impl Nodes {
    pub fn new(relay: Arc<Node>, direct: Option<Arc<Node>>) -> Self {
        Self {
            relay,
            direct,
            directs: Directs::default(),
            own_only: false,
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

    /// Remembers a friend's or own (`own`) device's direct address, from a
    /// `direct` frame `cert`'s device sent. The caller checks whose it is.
    pub fn learn(&self, cert: &DirectCert, relay: &str, own: bool) -> bool {
        let Some(addr) = MeshAddr::from_parts(cert.direct().as_bytes(), relay) else {
            return false;
        };
        lock(&self.directs).insert(*cert.device().as_bytes(), (addr, own));
        true
    }

    /// Forgets every direct address of `devices` (unfriended or blocked).
    pub fn forget(&self, devices: impl IntoIterator<Item = [u8; 32]>) {
        let mut directs = lock(&self.directs);
        for device in devices {
            directs.remove(&device);
        }
    }

    /// The direct node and the address to use on it for `addr`'s device.
    fn pick(&self, addr: &MeshAddr) -> Option<(&Node, MeshAddr)> {
        self.direct_for(&addr.device)
            .map(|(d, known)| (d, known.unwrap_or_else(|| addr.clone())))
    }

    /// The direct node if `device` may use it here, and its direct address
    /// when there's no open connection to reuse.
    fn direct_for(&self, device: &PublicKey) -> Option<(&Node, Option<MeshAddr>)> {
        let direct = self.direct.as_deref()?;
        let known = lock(&self.directs).get(device.as_bytes()).cloned();
        if self.own_only && !known.as_ref().is_some_and(|(_, own)| *own) {
            return None;
        }
        if direct.has(device) {
            return Some((direct, None));
        }
        known.map(|(addr, _)| (direct, Some(addr)))
    }

    pub async fn open(
        &self,
        addr: &MeshAddr,
        service: &str,
    ) -> Result<(Peer, SendStream, RecvStream), TransportError> {
        if let Some((direct, at)) = self.pick(addr)
            && let Ok(opened) = direct.open(&at, service).await
        {
            return Ok(opened);
        }
        self.relay.open(addr, service).await
    }

    pub async fn ping(&self, addr: &MeshAddr) -> Result<Pong, TransportError> {
        if let Some((direct, at)) = self.pick(addr)
            && let Ok(pong) = direct.ping(&at).await
        {
            return Ok(pong);
        }
        self.relay.ping(addr).await
    }

    pub fn send_datagram(&self, device: &PublicKey, data: Vec<u8>) -> bool {
        let direct = self
            .direct_for(device)
            .filter(|(d, _)| d.has(device))
            .map(|(d, _)| d);
        match direct {
            Some(direct) => direct.send_datagram(device, data),
            None => self.relay.send_datagram(device, data),
        }
    }

    /// The next datagram from either node.
    pub async fn next_datagram(&self) -> Option<(Peer, Vec<u8>)> {
        match &self.direct {
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
        for addr in self.direct.iter().flat_map(|d| d.connected(id)) {
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
        self.relay.open_connections() + self.direct.as_ref().map_or(0, |d| d.open_connections())
    }

    /// The relay node's state, `direct` if either has a direct path, and the
    /// devices connected on both.
    pub fn status(&self) -> Status {
        let mut status = self.relay.status();
        if let Some(direct) = &self.direct {
            let theirs = direct.status();
            status.direct |= theirs.direct;
            status.connections += theirs.connections;
        }
        status
    }

    /// The relay node's address: what address records carry (no IPs).
    pub fn addr(&self) -> MeshAddr {
        self.relay.addr()
    }

    pub async fn close(&self) {
        if let Some(direct) = &self.direct {
            direct.close().await;
        }
        self.relay.close().await;
    }

    fn each(&self, f: impl Fn(&Node)) {
        f(&self.relay);
        if let Some(direct) = &self.direct {
            f(direct);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
