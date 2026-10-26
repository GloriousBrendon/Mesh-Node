//! Seed mode (SPEC-seed): an always-on node with its own key that holds
//! friend codes. `mesh-node seed --data <dir>`. Logs counts only (D10).
//!
//! Each request is one stream: the service tag, one request frame, one
//! answer frame whose first byte is the answer (`codes::Hold`/`codes::Get`).

use crate::codes::{self, Caller, Get, Store};
use mesh_identity::{DeviceCert, DeviceKey, RootKey};
use mesh_transport::{Config, MeshAddr, Node, Relays, ServiceStream, frame};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const HOLD: &str = "code-hold";
pub const GET: &str = "code-get";
pub const REVOKE: &str = "code-revoke";

const KEY_FILE: &str = "seed.key";
const STORE_FILE: &str = "codes.bin";
/// How long a caller has to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a changed store is written out.
const SAVE_EVERY: Duration = Duration::from_secs(5);
/// How often expired records go, and the counts are logged.
const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// What the hourly log line reports.
#[derive(Default)]
struct Counts {
    holds: AtomicU64,
    lookups: AtomicU64,
    found: AtomicU64,
    slowed: AtomicU64,
    revokes: AtomicU64,
}

pub async fn run(dir: &Path, relays: Relays) -> Result<(), String> {
    let (root, device) = key(&dir.join(KEY_FILE))?;
    let cert = DeviceCert::issue(&root, &device.public(), "seed", unix_now())
        .map_err(|e| format!("can't make the seed's certificate: {e}"))?;
    let store = Store::load(&dir.join(STORE_FILE)).map_err(|e| e.to_string())?;
    eprintln!("mesh-node seed: holding {} codes", store.len());
    let store = Arc::new(Mutex::new(store));
    let config = Config {
        relays,
        services: [HOLD, GET, REVOKE].map(String::from).to_vec(),
        ..Config::default()
    };
    let node = Arc::new(
        Node::start(&device, &cert, config)
            .await
            .map_err(|e| e.to_string())?,
    );
    let counts = Arc::new(Counts::default());

    tokio::spawn(announce(node.clone()));
    tokio::spawn(serve(node.clone(), store.clone(), counts.clone()));
    tokio::spawn(save_often(store.clone()));
    tokio::spawn(sweep_hourly(store.clone(), counts));

    shutdown().await;
    eprintln!("mesh-node seed: stopping");
    node.close().await;
    save(&store);
    Ok(())
}

/// The seed's key: made on first start (owner-only file), loaded after.
/// `root secret [32] | device secret [32]`.
fn key(path: &Path) -> Result<(RootKey, DeviceKey), String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (root, device) = (RootKey::generate(), DeviceKey::generate());
            let (root, device) = root
                .and_then(|r| Ok((r, device?)))
                .map_err(|e| format!("no randomness: {e}"))?;
            let mut bytes = root.secret_bytes().to_vec();
            bytes.extend_from_slice(device.secret_bytes().as_ref());
            write_private(path, &bytes)
                .map_err(|e| format!("can't write {}: {e}", path.display()))?;
            eprintln!("mesh-node seed: made a new seed key");
            bytes
        }
        Err(e) => return Err(format!("can't read {}: {e}", path.display())),
    };
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| format!("{} is damaged", path.display()))?;
    let (root, device) = bytes.split_at(32);
    Ok((
        RootKey::from_secret_bytes(root.try_into().expect("32 bytes")),
        DeviceKey::from_secret_bytes(device.try_into().expect("32 bytes")),
    ))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(bytes)
}

/// Logs the seed's ticket once it has a home relay: it goes in the clients'
/// built-in list. It names the seed's key and relay, nobody else's.
async fn announce(node: Arc<Node>) {
    while !node.online(Duration::from_secs(30)).await {
        eprintln!("mesh-node seed: no relay reachable yet");
    }
    match node.addr().ticket() {
        Ok(ticket) => eprintln!("mesh-node seed: ticket {ticket}"),
        Err(e) => eprintln!("mesh-node seed: no ticket: {e}"),
    }
}

async fn serve(node: Arc<Node>, store: Arc<Mutex<Store>>, counts: Arc<Counts>) {
    while let Some(stream) = node.next_stream().await {
        tokio::spawn(answer(stream, store.clone(), counts.clone()));
    }
}

async fn answer(mut stream: ServiceStream, store: Arc<Mutex<Store>>, counts: Arc<Counts>) {
    let request =
        match tokio::time::timeout(REQUEST_TIMEOUT, frame::read_frame(&mut stream.recv)).await {
            Ok(Ok(Some(request))) => request,
            _ => {
                let _ = stream.send.reset(0u32.into());
                return;
            }
        };
    let caller = Caller {
        device: *stream.peer.device.as_bytes(),
        network: stream.direct_ip.map(codes::network),
    };
    let now = unix_now();
    let reply = {
        let mut store = lock(&store);
        match stream.service.as_str() {
            HOLD => {
                let hold = store.hold(&caller, &request, now);
                if hold == codes::Hold::Ok {
                    counts.holds.fetch_add(1, Ordering::Relaxed);
                }
                vec![hold.byte()]
            }
            GET => {
                counts.lookups.fetch_add(1, Ordering::Relaxed);
                let get = match <[u8; 16]>::try_from(request.as_slice()) {
                    Ok(id) => store.get(&caller, &id, now),
                    Err(_) => Get::None,
                };
                match &get {
                    Get::Found(_) => counts.found.fetch_add(1, Ordering::Relaxed),
                    Get::SlowDown => counts.slowed.fetch_add(1, Ordering::Relaxed),
                    Get::None => 0,
                };
                get.to_bytes()
            }
            _ => {
                counts.revokes.fetch_add(1, Ordering::Relaxed);
                store.revoke(&request);
                vec![codes::Hold::Ok.byte()]
            }
        }
    };
    if frame::write_frame(&mut stream.send, &reply).await.is_ok() {
        let _ = stream.send.finish();
        // Let the answer go before the stream is dropped.
        let _ = stream.send.stopped().await;
    }
}

async fn save_often(store: Arc<Mutex<Store>>) {
    loop {
        tokio::time::sleep(SAVE_EVERY).await;
        save(&store);
    }
}

fn save(store: &Mutex<Store>) {
    let mut store = lock(store);
    if store.dirty
        && let Err(e) = store.save()
    {
        eprintln!("mesh-node seed: couldn't save the codes: {e}");
    }
}

async fn sweep_hourly(store: Arc<Mutex<Store>>, counts: Arc<Counts>) {
    loop {
        tokio::time::sleep(SWEEP_EVERY).await;
        let held = {
            let mut store = lock(&store);
            store.sweep(unix_now());
            store.len()
        };
        let take = |n: &AtomicU64| n.swap(0, Ordering::Relaxed);
        eprintln!(
            "mesh-node seed: last hour {} holds, {} lookups ({} found, {} slowed), {} revokes; {held} held",
            take(&counts.holds),
            take(&counts.lookups),
            take(&counts.found),
            take(&counts.slowed),
            take(&counts.revokes),
        );
    }
}

/// How long a client waits for a seed's answer, connecting included.
const ASK_TIMEOUT: Duration = Duration::from_secs(20);

/// The client side: one request to a seed, one answer.
pub async fn ask(
    node: &Node,
    seed: &MeshAddr,
    service: &str,
    request: &[u8],
) -> Result<Vec<u8>, ()> {
    let exchange = async {
        let (_, mut send, mut recv) = node.open(seed, service).await.map_err(drop)?;
        frame::write_frame(&mut send, request).await.map_err(drop)?;
        send.finish().map_err(drop)?;
        frame::read_frame(&mut recv).await.ok().flatten().ok_or(())
    };
    tokio::time::timeout(ASK_TIMEOUT, exchange)
        .await
        .map_err(drop)?
}

/// SIGTERM (Docker, systemd) or Ctrl-C.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The store is only held for quick, non-async work.
fn lock(store: &Mutex<Store>) -> std::sync::MutexGuard<'_, Store> {
    store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
