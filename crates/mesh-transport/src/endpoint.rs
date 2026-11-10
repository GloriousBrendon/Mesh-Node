//! The device's iroh endpoint (SPEC-transport "Endpoint"): built with the
//! `Minimal` preset so nothing about this device is published (D2), keyed by
//! the device key, and accepting only connections that pass the handshake.

use crate::frame;
use crate::handshake::{self, ALPN, HandshakeError};
use crate::{
    Config, Limits, MeshAddr, Path, Peer, Pong, Relays, ServiceStream, Status, TransportError,
};
use iroh::endpoint::{Connection, QuicTransportConfig, RecvStream, SendStream, presets};
use iroh::{Endpoint, RelayMap, RelayMode};
use mesh_identity::{DeviceCert, DeviceKey, MeshId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long reaching a device may take before it counts as unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long either side has to finish the hello once connected.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a ping may take once connected.
const PING_TIMEOUT: Duration = Duration::from_secs(10);
/// Close code for connections ended by locking (after the handshake codes).
const LOCKED: u32 = 5;
/// Newly accepted peers waiting to be read with `next_peer`; past this,
/// the notice is dropped (the connection itself stays).
const ACCEPTED_QUEUE: usize = 64;
/// Service streams waiting for `next_stream`; past this, new ones are reset.
const STREAM_QUEUE: usize = 64;
/// Stream reset codes: an unknown service, and a busy one.
const UNKNOWN_SERVICE: u32 = 1;
const BUSY: u32 = 2;

/// This device on the Mesh network, while the identity is unlocked (D7).
pub struct Node {
    endpoint: Endpoint,
    shared: Arc<Shared>,
    accepted: tokio::sync::Mutex<mpsc::Receiver<Peer>>,
    streams: tokio::sync::Mutex<mpsc::Receiver<ServiceStream>>,
}

/// What the node's tasks share.
struct Shared {
    /// Our certificate, as sent in every hello.
    cert: Vec<u8>,
    /// Authenticated connections, by device.
    /// Every live connection, by device and connection: two devices that
    /// dial each other at once have two, and `disconnect` must close both.
    conns: Mutex<HashMap<(iroh::PublicKey, usize), (Peer, Connection)>>,
    /// Incoming connections still in their handshake.
    pending: AtomicUsize,
    limits: Limits,
    accepted: mpsc::Sender<Peer>,
    services: Vec<String>,
    streams: mpsc::Sender<ServiceStream>,
    allow: crate::Allow,
}

impl Node {
    /// Starts the endpoint for this device. `cert` must be this device's own
    /// certificate.
    pub async fn start(
        device: &DeviceKey,
        cert: &DeviceCert,
        config: Config,
    ) -> Result<Self, TransportError> {
        if cert.device() != &device.public() {
            return Err(TransportError::CertNotOurs);
        }
        let relay_mode = match config.relays {
            Relays::Default => RelayMode::Default,
            Relays::Custom(urls) => RelayMode::Custom(RelayMap::from_iter(urls)),
            Relays::Disabled => RelayMode::Disabled,
        };
        let quic = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(config.limits.streams.into())
            .max_concurrent_uni_streams(0u32.into())
            .build();
        let builder = Endpoint::builder(presets::Minimal)
            .secret_key(crate::secret_key(device))
            .relay_mode(relay_mode)
            .transport_config(quic)
            .alpns(vec![ALPN.to_vec()]);
        #[cfg(feature = "test-utils")]
        let builder = config.test.apply(builder);
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        let (tx, rx) = mpsc::channel(ACCEPTED_QUEUE);
        let (streams_tx, streams_rx) = mpsc::channel(STREAM_QUEUE);
        let shared = Arc::new(Shared {
            cert: cert.to_bytes(),
            conns: Mutex::new(HashMap::new()),
            pending: AtomicUsize::new(0),
            limits: config.limits,
            accepted: tx,
            services: config.services,
            streams: streams_tx,
            allow: config.allow,
        });
        tokio::spawn(accept_loop(endpoint.clone(), shared.clone()));
        Ok(Self {
            endpoint,
            shared,
            accepted: tokio::sync::Mutex::new(rx),
            streams: tokio::sync::Mutex::new(streams_rx),
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

    /// Waits until a home relay is connected, for up to `wait`; false if it
    /// isn't by then (or relays are disabled).
    pub async fn online(&self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.endpoint.online())
            .await
            .is_ok()
    }

    /// What the UI shows. Never includes IP addresses (spec "Endpoint").
    pub fn status(&self) -> Status {
        let relay = self.endpoint.addr().relay_urls().next().cloned();
        let conns = lock(&self.shared.conns);
        let open: Vec<_> = conns
            .values()
            .filter(|(_, c)| c.close_reason().is_none())
            .collect();
        let devices: std::collections::HashSet<_> = open.iter().map(|(p, _)| p.device).collect();
        Status {
            online: relay.is_some(),
            relay,
            direct: open.iter().any(|(_, c)| path(c) == Path::Direct),
            connections: devices.len(),
        }
    }

    /// Connects to a device and runs the handshake, or reuses the connection
    /// already open to it. Connections are made when asked; there's no retry
    /// loop here, so callers that retry by themselves pace their retries.
    pub async fn dial(&self, addr: &MeshAddr) -> Result<Peer, TransportError> {
        Ok(self.connection(addr).await?.0)
    }

    /// Pings a device: who answered, the round-trip time, and whether the
    /// connection is direct or through a relay.
    pub async fn ping(&self, addr: &MeshAddr) -> Result<Pong, TransportError> {
        let (peer, conn) = self.connection(addr).await?;
        let nonce = rand_nonce();
        let started = Instant::now();
        let exchange = async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| TransportError::Unreachable(e.to_string()))?;
            frame::write_tag(&mut send, "ping").await.map_err(dropped)?;
            frame::write_frame(&mut send, &nonce)
                .await
                .map_err(dropped)?;
            send.finish()
                .map_err(|e| TransportError::Unreachable(e.to_string()))?;
            match frame::read_frame(&mut recv).await.map_err(dropped)? {
                Some(echo) if echo == nonce => Ok(()),
                _ => Err(TransportError::Unreachable(
                    "the device didn't answer the ping".into(),
                )),
            }
        };
        tokio::time::timeout(PING_TIMEOUT, exchange)
            .await
            .map_err(|_| TransportError::Timeout)??;
        Ok(Pong {
            peer,
            rtt: started.elapsed(),
            path: path(&conn),
        })
    }

    /// Opens a stream to a device for `service`, connecting first if needed;
    /// the tag is already written.
    pub async fn open(
        &self,
        addr: &MeshAddr,
        service: &str,
    ) -> Result<(Peer, SendStream, RecvStream), TransportError> {
        let (peer, conn) = self.connection(addr).await?;
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;
        frame::write_tag(&mut send, service)
            .await
            .map_err(dropped)?;
        Ok((peer, send, recv))
    }

    /// The next stream another device opened for one of `Config::services`.
    pub async fn next_stream(&self) -> Option<ServiceStream> {
        self.streams.lock().await.recv().await
    }

    /// The next peer that connected to us and passed the handshake; `None`
    /// once the node is closed.
    pub async fn next_peer(&self) -> Option<Peer> {
        self.accepted.lock().await.recv().await
    }

    /// `id`'s devices we have an open connection with.
    pub fn connected(&self, id: &MeshId) -> Vec<MeshAddr> {
        let mut devices: Vec<_> = lock(&self.shared.conns)
            .values()
            .filter(|(peer, conn)| peer.id == *id && conn.close_reason().is_none())
            .map(|(peer, _)| peer.device)
            .collect();
        devices.sort_by_key(|d| *d.as_bytes());
        devices.dedup();
        devices
            .into_iter()
            .map(|device| MeshAddr {
                device,
                relay: None,
                direct: Vec::new(),
            })
            .collect()
    }

    /// Closes every connection with `id`'s devices (they were removed).
    pub fn disconnect(&self, id: &MeshId) {
        lock(&self.shared.conns).retain(|_, (peer, conn)| {
            if peer.id == *id {
                conn.close(HandshakeError::NotAllowed.code().into(), b"not-allowed");
            }
            peer.id != *id
        });
    }

    /// Closes every connection `allow` no longer lets in: call it after the
    /// allowed set changes (a contact or a device removed).
    pub fn prune(&self) {
        let allow = &self.shared.allow;
        lock(&self.shared.conns).retain(|_, (peer, conn)| {
            let keep = allow.allows(&peer.id, &peer.device);
            if !keep {
                conn.close(HandshakeError::NotAllowed.code().into(), b"not-allowed");
            }
            keep
        });
    }

    /// Closes every connection, saying it's locked, then the endpoint.
    pub async fn close(&self) {
        for (_, (_, conn)) in lock(&self.shared.conns).drain() {
            conn.close(LOCKED.into(), b"locked");
        }
        self.endpoint.close().await;
    }

    /// The open connection to a device, or a new one through the handshake.
    async fn connection(&self, addr: &MeshAddr) -> Result<(Peer, Connection), TransportError> {
        if let Some(open) = self.shared.open(&addr.device) {
            return Ok(open);
        }
        let conn = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.endpoint.connect(addr.endpoint_addr(), ALPN),
        )
        .await
        .map_err(|_| TransportError::Unreachable("no answer".into()))?
        .map_err(|e| TransportError::Unreachable(e.to_string()))?;
        let peer = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake::dial(&conn, &self.shared.cert),
        )
        .await
        {
            Ok(Ok(peer)) => peer,
            Ok(Err(e)) => {
                e.close(&conn);
                return Err(e.into());
            }
            Err(_) => {
                HandshakeError::Timeout.close(&conn);
                return Err(TransportError::Timeout);
            }
        };
        self.shared.add(peer.clone(), conn.clone())?;
        Ok((peer, conn))
    }
}

impl Shared {
    fn open(&self, device: &iroh::PublicKey) -> Option<(Peer, Connection)> {
        let mut conns = lock(&self.conns);
        conns.retain(|_, (_, conn)| conn.close_reason().is_none());
        conns
            .iter()
            .find(|((d, _), _)| d == device)
            .map(|(_, (peer, conn))| (peer.clone(), conn.clone()))
    }

    /// Keeps an authenticated connection and starts answering its streams.
    /// The peer is checked against `allow` again under the lock that
    /// `disconnect` takes: a handshake that was under way when its peer was
    /// removed must not leave a connection behind.
    fn add(self: &Arc<Self>, peer: Peer, conn: Connection) -> Result<(), HandshakeError> {
        let mut conns = lock(&self.conns);
        if !self.allow.allows(&peer.id, &peer.device) {
            HandshakeError::NotAllowed.close(&conn);
            return Err(HandshakeError::NotAllowed);
        }
        conns.insert(
            (peer.device, conn.stable_id()),
            (peer.clone(), conn.clone()),
        );
        drop(conns);
        tokio::spawn(serve(self.clone(), peer, conn));
        Ok(())
    }

    fn full(&self) -> bool {
        lock(&self.conns).len() >= self.limits.connections
            || self.pending.load(Ordering::Relaxed) >= self.limits.handshakes
    }
}

/// The map is only held for quick inserts and lookups, never across an await;
/// a panic elsewhere while holding it doesn't leave it inconsistent.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Accepts connections and runs the handshake on each, refusing new ones
/// while the limits are reached (D9).
async fn accept_loop(endpoint: Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        if shared.full() {
            incoming.refuse();
            continue;
        }
        shared.pending.fetch_add(1, Ordering::Relaxed);
        let shared = shared.clone();
        tokio::spawn(async move {
            let accepted = async {
                let conn = incoming.await.ok()?;
                let result = tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    handshake::accept(&conn, &shared.cert, &shared.allow),
                )
                .await
                .unwrap_or(Err(HandshakeError::Timeout));
                match result {
                    Ok(peer) => Some((peer, conn)),
                    Err(e) => {
                        e.close(&conn);
                        None
                    }
                }
            };
            let accepted = accepted.await;
            shared.pending.fetch_sub(1, Ordering::Relaxed);
            if let Some((peer, conn)) = accepted
                && shared.add(peer.clone(), conn).is_ok()
            {
                let _ = shared.accepted.try_send(peer);
            }
        });
    }
}

/// Answers a connection's streams until it closes, then forgets it.
async fn serve(shared: Arc<Shared>, peer: Peer, conn: Connection) {
    let device = peer.device;
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let (shared, peer, direct_ip) = (shared.clone(), peer.clone(), direct_ip(&conn));
        tokio::spawn(async move {
            match frame::read_tag(&mut recv).await.as_deref() {
                Ok(tag) if shared.services.iter().any(|s| s == tag) => {
                    let stream = ServiceStream {
                        peer,
                        service: tag.to_owned(),
                        send,
                        recv,
                        direct_ip,
                    };
                    if let Err(mpsc::error::TrySendError::Full(mut stream)) =
                        shared.streams.try_send(stream)
                    {
                        let _ = stream.send.reset(BUSY.into());
                    }
                }
                Ok("ping") => {
                    if let Ok(Some(nonce)) = frame::read_frame(&mut recv).await
                        && nonce.len() == 8
                        && frame::write_frame(&mut send, &nonce).await.is_ok()
                    {
                        let _ = send.finish();
                    }
                }
                // Unknown services end the stream, not the connection.
                _ => {
                    let _ = send.reset(UNKNOWN_SERVICE.into());
                }
            }
        });
    }
    lock(&shared.conns).remove(&(device, conn.stable_id()));
}

/// Whether the connection's current path is direct or through a relay.
fn path(conn: &Connection) -> Path {
    let paths = conn.paths();
    let relayed = paths
        .iter()
        .find(|p| p.is_selected())
        .is_none_or(|p| p.is_relay());
    if relayed { Path::Relay } else { Path::Direct }
}

/// The other side's IP if the connection's current path is direct.
fn direct_ip(conn: &Connection) -> Option<std::net::IpAddr> {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .and_then(|p| match p.remote_addr() {
            iroh::TransportAddr::Ip(addr) => Some(addr.ip()),
            _ => None,
        })
}

fn dropped(e: frame::FrameError) -> TransportError {
    TransportError::Unreachable(e.to_string())
}

fn rand_nonce() -> [u8; 8] {
    // Only has to differ between pings, not be secret.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos as u64).to_be_bytes()
}
