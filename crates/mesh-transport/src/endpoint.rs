//! The device's iroh endpoint (SPEC-transport "Endpoint"): built with the
//! `Minimal` preset so nothing about this device is published (D2), keyed by
//! the device key, and accepting only connections that pass the handshake.

use crate::handshake::{self, ALPN, HandshakeError};
use crate::{MeshAddr, Peer, Relays, TransportError};
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, RelayMap, RelayMode};
use mesh_identity::{DeviceCert, DeviceKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a dial (connecting plus the handshake) may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a peer that connected has to finish its hello.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// This device on the Mesh network, while the identity is unlocked (D7).
pub struct Node {
    endpoint: Endpoint,
    /// Our certificate, as sent in every hello.
    cert: Arc<[u8]>,
    /// Authenticated connections, by device.
    conns: Arc<Mutex<HashMap<iroh::PublicKey, (Peer, Connection)>>>,
    /// Peers that connected to us, as they pass the handshake.
    accepted: tokio::sync::Mutex<mpsc::UnboundedReceiver<Peer>>,
}

impl Node {
    /// Starts the endpoint for this device. `cert` must be this device's own
    /// certificate.
    pub async fn start(
        device: &DeviceKey,
        cert: &DeviceCert,
        relays: Relays,
    ) -> Result<Self, TransportError> {
        if cert.device() != &device.public() {
            return Err(TransportError::CertNotOurs);
        }
        let relay_mode = match relays {
            Relays::Default => RelayMode::Default,
            Relays::Custom(urls) => RelayMode::Custom(RelayMap::from_iter(urls)),
            Relays::Disabled => RelayMode::Disabled,
        };
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(crate::secret_key(device))
            .relay_mode(relay_mode)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        let cert: Arc<[u8]> = cert.to_bytes().into();
        let conns = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(accept_loop(
            endpoint.clone(),
            cert.clone(),
            conns.clone(),
            tx,
        ));
        Ok(Self {
            endpoint,
            cert,
            conns,
            accepted: tokio::sync::Mutex::new(rx),
        })
    }

    /// Where this device can be reached: its key, its home relay (once it has
    /// one) and its direct addresses.
    pub fn addr(&self) -> MeshAddr {
        let addr = self.endpoint.addr();
        MeshAddr {
            device: self.endpoint.id(),
            relay: addr.relay_urls().next().cloned(),
            direct: addr.ip_addrs().copied().collect(),
        }
    }

    /// The local sockets the endpoint listens on.
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Connects to a device and runs the handshake, or reuses the connection
    /// already open to it.
    pub async fn dial(&self, addr: &MeshAddr) -> Result<Peer, TransportError> {
        if let Some(peer) = self.open(&addr.device) {
            return Ok(peer);
        }
        let attempt = async {
            let conn = self
                .endpoint
                .connect(addr.endpoint_addr(), ALPN)
                .await
                .map_err(|e| TransportError::Unreachable(e.to_string()))?;
            match handshake::dial(&conn, &self.cert).await {
                Ok(peer) => Ok((peer, conn)),
                Err(e) => {
                    e.close(&conn);
                    Err(TransportError::Handshake(e))
                }
            }
        };
        let (peer, conn) = tokio::time::timeout(DIAL_TIMEOUT, attempt)
            .await
            .map_err(|_| TransportError::Timeout)??;
        lock(&self.conns).insert(addr.device, (peer.clone(), conn));
        Ok(peer)
    }

    /// The next peer that connected to us and passed the handshake; `None`
    /// once the node is closed.
    pub async fn next_peer(&self) -> Option<Peer> {
        self.accepted.lock().await.recv().await
    }

    /// Closes every connection, then the endpoint.
    pub async fn close(&self) {
        lock(&self.conns).clear();
        self.endpoint.close().await;
    }

    /// The open, authenticated connection to a device, if there is one.
    fn open(&self, device: &iroh::PublicKey) -> Option<Peer> {
        let mut conns = lock(&self.conns);
        match conns.get(device) {
            Some((peer, conn)) if conn.close_reason().is_none() => Some(peer.clone()),
            Some(_) => {
                conns.remove(device);
                None
            }
            None => None,
        }
    }
}

/// The map is only held for quick inserts and lookups, never across an await;
/// a panic elsewhere while holding it doesn't leave it inconsistent.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Accepts connections and runs the handshake on each, without letting one
/// slow peer hold up the others.
async fn accept_loop(
    endpoint: Endpoint,
    cert: Arc<[u8]>,
    conns: Arc<Mutex<HashMap<iroh::PublicKey, (Peer, Connection)>>>,
    accepted: mpsc::UnboundedSender<Peer>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let (cert, conns, accepted) = (cert.clone(), conns.clone(), accepted.clone());
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake::accept(&conn, &cert))
                .await
                .unwrap_or(Err(HandshakeError::Timeout));
            match result {
                Ok(peer) => {
                    lock(&conns).insert(peer.device, (peer.clone(), conn));
                    let _ = accepted.send(peer);
                }
                Err(e) => e.close(&conn),
            }
        });
    }
}
