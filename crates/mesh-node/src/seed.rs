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
use crate::{addrs, knocks, mailstore};
use mesh_identity::{DeviceCert, DeviceKey, RootKey, unix_now};
use mesh_transport::{Config, Limits, MeshAddr, Node, Relays, ServiceStream, frame};
use std::collections::HashMap;
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
/// The mail services (SPEC-mailbox), only with `--mail`.
pub const MAIL_CLAIM: &str = "mail-claim";
pub const MAIL_PUT: &str = "mail-put";
pub const MAIL_GET: &str = "mail-get";
pub const MAIL_TAKE: &str = "mail-take";

const KEY_FILE: &str = "seed.key";
const STORE_FILE: &str = "codes.bin";
const ADDR_FILE: &str = "addrs.bin";
const KNOCK_FILE: &str = "knocks.bin";
/// The mail store's logs (mailstore).
const MAIL_DIR: &str = "mail";
/// Address records come back within 30 minutes, so losing a few minutes of
/// them costs nothing (SPEC-routing).
const SAVE_ADDRS_EVERY: Duration = Duration::from_secs(300);
/// How long a caller has to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a changed store is written out.
const SAVE_EVERY: Duration = Duration::from_secs(5);
/// How often expired records go, and the counts are logged.
/// How often the stores are swept and the counts logged.
pub const REPORT_EVERY: Duration = Duration::from_secs(3600);
/// How long a client tries a seed's direct address alone before it adds the
/// relay (D8c): enough for a handshake on a slow line (two round trips of
/// about 700 ms on satellite), short enough that a network that blocks UDP
/// costs only this once.
const DIRECT_FIRST: Duration = Duration::from_secs(2);

/// How a seed is run (`mesh-node seed` flags).
pub struct Options {
    /// A fixed UDP port (D8c).
    pub port: Option<u16>,
    /// The address callers reach that port at, for the ticket.
    pub public: Option<std::net::SocketAddr>,
    pub report: Duration,
    /// The mail services are on (`--mail`; off by default).
    pub mail: bool,
}

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
    mail_claims: AtomicU64,
    mail_puts: AtomicU64,
    mail_gets: AtomicU64,
    mail_takes: AtomicU64,
    callers: Mutex<Callers>,
}

/// Callers told apart in one hour's count, at most (memory).
const MAX_COUNTED_CALLERS: usize = 100_000;
const ARRIVED_RELAYED: u8 = 1;
const ARRIVED_DIRECT: u8 = 2;

/// How this hour's callers arrived: by throwaway key, in memory only, and
/// only counts are ever logged (D10).
#[derive(Default)]
struct Callers {
    seen: HashMap<[u8; 32], u8>,
    /// Requests from callers past `MAX_COUNTED_CALLERS`, not told apart.
    beyond: u64,
}

/// One hour's callers: direct only, relayed only, both, and requests beyond
/// the count.
#[derive(Debug, PartialEq, Eq)]
struct Arrivals {
    direct: usize,
    relayed: usize,
    both: usize,
    beyond: u64,
}

impl Callers {
    fn saw(&mut self, device: [u8; 32], direct: bool) {
        let how = if direct {
            ARRIVED_DIRECT
        } else {
            ARRIVED_RELAYED
        };
        let full = self.seen.len() >= MAX_COUNTED_CALLERS;
        match self.seen.get_mut(&device) {
            Some(seen) => *seen |= how,
            None if full => self.beyond += 1,
            None => {
                self.seen.insert(device, how);
            }
        }
    }

    /// This hour's counts; the next hour starts empty.
    fn take(&mut self) -> Arrivals {
        let count = |how| self.seen.values().filter(|&&s| s == how).count();
        let arrivals = Arrivals {
            direct: count(ARRIVED_DIRECT),
            relayed: count(ARRIVED_RELAYED),
            both: count(ARRIVED_DIRECT | ARRIVED_RELAYED),
            beyond: self.beyond,
        };
        *self = Self::default();
        arrivals
    }
}

#[derive(Clone)]
struct Stores {
    codes: Arc<Mutex<Store>>,
    addrs: Arc<Mutex<addrs::Store>>,
    knocks: Arc<Mutex<knocks::Store>>,
    /// `None` without `--mail`.
    mail: Option<Arc<Mutex<mailstore::Store>>>,
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

pub async fn run(dir: &Path, relays: Relays, options: Options) -> Result<(), String> {
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
        mail: if options.mail {
            let mail = mailstore::Store::open(&dir.join(MAIL_DIR), unix_now())
                .map_err(|e| format!("the mail store didn't open: {e}"))?;
            eprintln!("mesh-node seed: holding {} envelopes of mail", mail.len());
            Some(Arc::new(Mutex::new(mail)))
        } else {
            None
        },
    };
    let mut services = vec![HOLD, GET, REVOKE, ADDR_PUT, ADDR_GET, KNOCK_PUT, KNOCK_GET];
    if options.mail {
        services.extend([MAIL_CLAIM, MAIL_PUT, MAIL_GET, MAIL_TAKE]);
    }
    let config = Config {
        relays,
        services: services.into_iter().map(String::from).collect(),
        limits: Limits {
            connections: CONNECTIONS,
            handshakes: HANDSHAKES,
            idle: Some(IDLE),
            ..Limits::default()
        },
        port: options.port,
        ..Config::default()
    };
    let node = Arc::new(
        Node::start(&device, &cert, config)
            .await
            .map_err(|e| e.to_string())?,
    );
    let counts = Arc::new(Counts::default());

    tokio::spawn(announce(node.clone(), options.public));
    tokio::spawn(serve(node.clone(), stores.clone(), counts.clone()));
    tokio::spawn(save_often(stores.codes.clone(), SAVE_EVERY));
    tokio::spawn(save_often(stores.addrs.clone(), SAVE_ADDRS_EVERY));
    tokio::spawn(save_often(stores.knocks.clone(), SAVE_ADDRS_EVERY));
    tokio::spawn(sweep_hourly(stores.clone(), counts, options.report));

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
/// built-in list. It names the seed's key, relay and `--public` address,
/// nothing else: never the machine's own LAN addresses.
async fn announce(node: Arc<Node>, public: Option<std::net::SocketAddr>) {
    while !node.online(Duration::from_secs(30)).await {
        eprintln!("mesh-node seed: no relay reachable yet");
    }
    let addr = MeshAddr {
        direct: public.into_iter().collect(),
        ..node.addr()
    };
    match addr.ticket_with_direct() {
        Ok(ticket) => eprintln!("mesh-node seed: ticket {ticket}"),
        Err(e) => eprintln!("mesh-node seed: no ticket: {e}"),
    }
}

async fn serve(node: Arc<Node>, stores: Stores, counts: Arc<Counts>) {
    while let Some(stream) = node.next_stream().await {
        let device = *stream.peer.device.as_bytes();
        lock(&counts.callers).saw(device, stream.direct_ip.is_some());
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
            MAIL_CLAIM | MAIL_PUT | MAIL_GET | MAIL_TAKE if stores.mail.is_some() => {
                let mail = stores.mail.clone().expect("checked");
                let service = stream.service.clone();
                tokio::spawn(answer_batch(stream, move |_, request, now| {
                    let mut mail = lock(&mail);
                    match service.as_str() {
                        MAIL_CLAIM => {
                            count(&counts.mail_claims);
                            vec![mail.claim(request, now) as u8]
                        }
                        MAIL_PUT => {
                            count(&counts.mail_puts);
                            vec![mail.put(request, now) as u8]
                        }
                        MAIL_GET => {
                            count(&counts.mail_gets);
                            mail.get(request, now)
                        }
                        _ => {
                            count(&counts.mail_takes);
                            vec![mail.take(request, now) as u8]
                        }
                    }
                }))
            }
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

async fn sweep_hourly(stores: Stores, counts: Arc<Counts>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
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
        let Arrivals {
            direct,
            relayed,
            both,
            beyond,
        } = lock(&counts.callers).take();
        eprintln!(
            "mesh-node seed: last hour {} holds, {} lookups ({} found, {} slowed), {} revokes, {} address puts, {} address gets, {} request puts, {} request gets; {held} held, {records} address records, {requests} requests; callers {direct} direct, {relayed} relayed, {both} both ways, {beyond} requests from callers not told apart",
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
        if let Some(mail) = &stores.mail {
            let held = {
                let mut mail = lock(mail);
                mail.sweep(now);
                mail.len()
            };
            eprintln!(
                "mesh-node seed: last hour mail {} claims, {} puts, {} collects, {} takes; {held} envelopes held",
                take(&counts.mail_claims),
                take(&counts.mail_puts),
                take(&counts.mail_gets),
                take(&counts.mail_takes),
            );
        }
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
        let (_, mut send, mut recv) = node
            .open_direct_first(seed, service, DIRECT_FIRST)
            .await
            .map_err(drop)?;
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
        let (_, mut send, mut recv) = node
            .open_direct_first(seed, service, DIRECT_FIRST)
            .await
            .map_err(drop)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callers_are_counted_by_how_they_arrived() {
        let mut callers = Callers::default();
        callers.saw([1; 32], true);
        callers.saw([1; 32], true);
        callers.saw([2; 32], false);
        // Relayed first, then direct once a path was found.
        callers.saw([3; 32], false);
        callers.saw([3; 32], true);
        let hour = Arrivals {
            direct: 1,
            relayed: 1,
            both: 1,
            beyond: 0,
        };
        assert_eq!(callers.take(), hour);
        let empty = Arrivals {
            direct: 0,
            relayed: 0,
            both: 0,
            beyond: 0,
        };
        assert_eq!(callers.take(), empty, "a new hour");

        for i in 0..MAX_COUNTED_CALLERS as u32 + 2 {
            let mut device = [0; 32];
            device[..4].copy_from_slice(&i.to_be_bytes());
            callers.saw(device, false);
        }
        callers.saw([0; 32], true);
        let full = callers.take();
        assert_eq!(
            (full.relayed, full.both, full.beyond),
            (MAX_COUNTED_CALLERS - 1, 1, 2)
        );
    }
}
