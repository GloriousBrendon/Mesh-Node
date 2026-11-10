//! Seed mode (SPEC-seed): an always-on node with its own key that holds
//! friend codes. `mesh-node seed --data <dir>`. Logs counts only (D10).
//!
//! Each request is one stream: the service tag, one request frame, one
//! answer frame whose first byte is the answer (`codes::Hold`/`codes::Get`).
//! The address services (SPEC-routing D5) and the friend-request services
//! (SPEC-social D1, D3) are batched: frames until the caller finishes, each
//! answered in turn (`addrs::Put`/`addrs::Get`, `knocks::Put`/`knocks::Get`).

use crate::codes::{self, Caller, Get, Store};
use crate::saved::Snapshot;
use crate::{addrs, knocks};
use mesh_identity::{DeviceCert, DeviceKey, RootKey, unix_now};
use mesh_transport::{Config, Limits, MeshAddr, Node, Relays, ServiceStream, frame};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const HOLD: &str = "code-hold";
pub const GET: &str = "code-get";
pub const REVOKE: &str = "code-revoke";
pub const ADDR_PUT: &str = "addr-put";
pub const ADDR_GET: &str = "addr-get";
pub const KNOCK_PUT: &str = "knock-put";
pub const KNOCK_GET: &str = "knock-get";

const KEY_FILE: &str = "seed.key";
const STORE_FILE: &str = "codes.bin";
const ADDR_FILE: &str = "addrs.bin";
const KNOCK_FILE: &str = "knocks.bin";
/// Address records come back within 30 minutes, so losing a few minutes of
/// them costs nothing (SPEC-routing).
const SAVE_ADDRS_EVERY: Duration = Duration::from_secs(300);
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
    puts: AtomicU64,
    gets: AtomicU64,
    knock_puts: AtomicU64,
    knock_gets: AtomicU64,
}

#[derive(Clone)]
struct Stores {
    codes: Arc<Mutex<Store>>,
    addrs: Arc<Mutex<addrs::Store>>,
    knocks: Arc<Mutex<knocks::Store>>,
}

/// Clients connect only to ask something, then go quiet: close a connection
/// idle this long, so people unlocked all day don't hold one each (audit
/// finding 7). They dial again on their next request.
const IDLE: Duration = Duration::from_secs(30);
/// Open connections at once: with `IDLE`, people asking within 30 s of each
/// other, not people online. Each costs tens of KiB.
const CONNECTIONS: usize = 2048;
/// Handshakes under way at once.
const HANDSHAKES: usize = 128;

pub async fn run(dir: &Path, relays: Relays) -> Result<(), String> {
    let (root, device) = key(&dir.join(KEY_FILE))?;
    let cert = DeviceCert::issue(&root, &device.public(), "seed", unix_now())
        .map_err(|e| format!("can't make the seed's certificate: {e}"))?;
    let store = Store::load(&dir.join(STORE_FILE)).map_err(|e| e.to_string())?;
    let addrs = load_addrs(&dir.join(ADDR_FILE))?;
    let knocks = knocks::Store::load(&dir.join(KNOCK_FILE)).map_err(|e| e.to_string())?;
    eprintln!(
        "mesh-node seed: holding {} codes, {} address records, {} friend requests",
        store.len(),
        addrs.len(),
        knocks.len()
    );
    let stores = Stores {
        codes: Arc::new(Mutex::new(store)),
        addrs: Arc::new(Mutex::new(addrs)),
        knocks: Arc::new(Mutex::new(knocks)),
    };
    let config = Config {
        relays,
        services: [HOLD, GET, REVOKE, ADDR_PUT, ADDR_GET, KNOCK_PUT, KNOCK_GET]
            .map(String::from)
            .to_vec(),
        limits: Limits {
            connections: CONNECTIONS,
            handshakes: HANDSHAKES,
            idle: Some(IDLE),
            ..Limits::default()
        },
        ..Config::default()
    };
    let node = Arc::new(
        Node::start(&device, &cert, config)
            .await
            .map_err(|e| e.to_string())?,
    );
    let counts = Arc::new(Counts::default());

    tokio::spawn(announce(node.clone()));
    tokio::spawn(serve(node.clone(), stores.clone(), counts.clone()));
    tokio::spawn(save_often(stores.codes.clone(), SAVE_EVERY));
    tokio::spawn(save_often(stores.addrs.clone(), SAVE_ADDRS_EVERY));
    tokio::spawn(save_often(stores.knocks.clone(), SAVE_ADDRS_EVERY));
    tokio::spawn(sweep_hourly(stores.clone(), counts));

    shutdown().await;
    eprintln!("mesh-node seed: stopping");
    node.close().await;
    save(&stores.codes);
    save(&stores.addrs);
    save(&stores.knocks);
    Ok(())
}

/// Address records are put again within 30 minutes (routing D4), so a
/// damaged file (a power cut) is moved aside and the store starts empty,
/// rather than stopping the seed for good. The other stores still refuse.
fn load_addrs(path: &Path) -> Result<addrs::Store, String> {
    match addrs::Store::load(path) {
        Err(crate::saved::StoreError::Corrupt(..)) => {
            eprintln!("mesh-node seed: the address records were damaged; starting empty");
            let mut aside = path.as_os_str().to_owned();
            aside.push(".damaged");
            std::fs::rename(path, &aside)
                .map_err(|e| format!("can't move {} aside: {e}", path.display()))?;
            addrs::Store::load(path).map_err(|e| e.to_string())
        }
        loaded => loaded.map_err(|e| e.to_string()),
    }
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
            mesh_identity::write_atomically(path, &bytes)
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

async fn serve(node: Arc<Node>, stores: Stores, counts: Arc<Counts>) {
    while let Some(stream) = node.next_stream().await {
        let (stores, counts) = (stores.clone(), counts.clone());
        let count = |n: &AtomicU64| {
            n.fetch_add(1, Ordering::Relaxed);
        };
        match stream.service.as_str() {
            ADDR_PUT => tokio::spawn(answer_batch(stream, move |caller, request, now| {
                count(&counts.puts);
                vec![lock(&stores.addrs).put(caller, request, now).byte()]
            })),
            ADDR_GET => tokio::spawn(answer_batch(stream, move |caller, request, now| {
                count(&counts.gets);
                match <[u8; 16]>::try_from(request) {
                    Ok(lookup) => lock(&stores.addrs).get(caller, &lookup, now).to_bytes(),
                    Err(_) => vec![addrs::Put::Bad.byte()],
                }
            })),
            KNOCK_PUT => tokio::spawn(answer_batch(stream, move |caller, request, now| {
                count(&counts.knock_puts);
                let mut codes = lock(&stores.codes);
                let put = lock(&stores.knocks).put(caller, request, &mut codes, now);
                vec![put.byte()]
            })),
            KNOCK_GET => tokio::spawn(answer_batch(stream, move |caller, request, now| {
                count(&counts.knock_gets);
                let codes = lock(&stores.codes);
                lock(&stores.knocks)
                    .get(caller, request, &codes, now)
                    .to_bytes()
            })),
            _ => tokio::spawn(answer(stream, stores.codes.clone(), counts.clone())),
        };
    }
}

/// Batched requests: each frame answered by `handle` as it comes, until the
/// caller finishes.
async fn answer_batch(mut stream: ServiceStream, handle: impl Fn(&Caller, &[u8], u64) -> Vec<u8>) {
    let caller = Caller {
        device: *stream.peer.device.as_bytes(),
        network: stream.direct_ip.map(codes::network),
    };
    loop {
        let request = match tokio::time::timeout(
            REQUEST_TIMEOUT,
            frame::read_frame(&mut stream.recv),
        )
        .await
        {
            Ok(Ok(Some(request))) => request,
            Ok(Ok(None)) => break,
            _ => {
                let _ = stream.send.reset(0u32.into());
                return;
            }
        };
        let reply = handle(&caller, &request, unix_now());
        if frame::write_frame(&mut stream.send, &reply).await.is_err() {
            return;
        }
    }
    let _ = stream.send.finish();
    let _ = stream.send.stopped().await;
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

/// The stores, as saving sees them.
trait Saved: Send + 'static {
    fn dirty(&mut self) -> &mut bool;
    fn snapshot(&mut self) -> Snapshot;
}

impl Saved for Store {
    fn dirty(&mut self) -> &mut bool {
        &mut self.dirty
    }
    fn snapshot(&mut self) -> Snapshot {
        Store::snapshot(self)
    }
}

impl Saved for addrs::Store {
    fn dirty(&mut self) -> &mut bool {
        &mut self.dirty
    }
    fn snapshot(&mut self) -> Snapshot {
        addrs::Store::snapshot(self)
    }
}

impl Saved for knocks::Store {
    fn dirty(&mut self) -> &mut bool {
        &mut self.dirty
    }
    fn snapshot(&mut self) -> Snapshot {
        knocks::Store::snapshot(self)
    }
}

async fn save_often<S: Saved>(store: Arc<Mutex<S>>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        let store = store.clone();
        // The write and its syncs block: off the runtime's threads.
        let _ = tokio::task::spawn_blocking(move || save(&store)).await;
    }
}

/// One write at a time, in the order the snapshots were taken.
static WRITING: Mutex<()> = Mutex::new(());

/// Takes the store's bytes under its lock, then writes them without it, so
/// requests don't wait for the disk (audit finding 8).
fn save<S: Saved>(store: &Mutex<S>) {
    let _one = lock(&WRITING);
    let snapshot = {
        let mut store = lock(store);
        if !*store.dirty() {
            return;
        }
        store.snapshot()
    };
    if let Err(e) = snapshot.write() {
        eprintln!("mesh-node seed: {e}");
        *lock(store).dirty() = true;
    }
}

async fn sweep_hourly(stores: Stores, counts: Arc<Counts>) {
    loop {
        tokio::time::sleep(SWEEP_EVERY).await;
        let now = unix_now();
        let held = {
            let mut store = lock(&stores.codes);
            store.sweep(now);
            store.len()
        };
        let records = {
            let mut store = lock(&stores.addrs);
            store.sweep(now);
            store.len()
        };
        let requests = {
            let mut store = lock(&stores.knocks);
            store.sweep(now);
            store.len()
        };
        let take = |n: &AtomicU64| n.swap(0, Ordering::Relaxed);
        eprintln!(
            "mesh-node seed: last hour {} holds, {} lookups ({} found, {} slowed), {} revokes, {} address puts, {} address gets, {} request puts, {} request gets; {held} held, {records} address records, {requests} requests",
            take(&counts.holds),
            take(&counts.lookups),
            take(&counts.found),
            take(&counts.slowed),
            take(&counts.revokes),
            take(&counts.puts),
            take(&counts.gets),
            take(&counts.knock_puts),
            take(&counts.knock_gets),
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

/// The client side of a batched service: every request, then every answer,
/// in order. Sending and reading run together so a big batch can't stall on
/// flow control.
pub async fn ask_many(
    node: &Node,
    seed: &MeshAddr,
    service: &str,
    requests: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, ()> {
    let exchange = async {
        let (_, mut send, mut recv) = node.open(seed, service).await.map_err(drop)?;
        let sending = async {
            for request in requests {
                frame::write_frame(&mut send, request).await.map_err(drop)?;
            }
            send.finish().map_err(drop)
        };
        let reading = async {
            let mut answers = Vec::with_capacity(requests.len());
            while answers.len() < requests.len() {
                answers.push(
                    frame::read_frame(&mut recv)
                        .await
                        .ok()
                        .flatten()
                        .ok_or(())?,
                );
            }
            Ok::<_, ()>(answers)
        };
        let (sent, answers) = tokio::join!(sending, reading);
        sent?;
        answers
    };
    tokio::time::timeout(ASK_TIMEOUT, exchange)
        .await
        .map_err(drop)?
}

/// SIGTERM (Docker, systemd), Ctrl-C, or Ctrl-Break on Windows.
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
    #[cfg(windows)]
    if let Ok(mut brk) = tokio::signal::windows::ctrl_break() {
        tokio::select! {
            _ = brk.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The store is only held for quick, non-async work.
fn lock<S>(store: &Mutex<S>) -> std::sync::MutexGuard<'_, S> {
    store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
