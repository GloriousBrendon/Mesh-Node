//! mailbox (SPEC-mailbox): mail for someone who's away, held by a seed with
//! the mail services on, collected when they come back. The acceptance
//! tests, by number.

use mesh_identity::{DeviceCert, DeviceKey, Keystore, MeshId, RootKey, mail_collect_tag};
use mesh_transport::{Config, MeshAddr, Node, Relays, frame};
use serde_json::Value;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
/// Short records, so refreshes come every 2 s.
const TTL: &str = "8";
/// Test 1: "one" shows within this long of the reader's helper coming online.
const SHOWS_WITHIN: Duration = Duration::from_secs(5);
/// With clocks 30 s apart, records of a minute.
const SKEWED_TTL: &str = "60";

fn helper(
    dir: &std::path::Path,
    relay: &Relay,
    seed: &str,
    name: &str,
    more: &[&str],
) -> (Helper, String) {
    let ttl = if more.contains(&"--record-ttl") {
        &[][..]
    } else {
        &["--record-ttl", TTL][..]
    };
    let args = [&["--seed", seed][..], ttl, more].concat();
    let mut h = Helper::start_with(dir, relay, &args);
    assert_eq!(h.event().0, "meshIdentity");
    let id = h.expect("idCreate", &[name, PASSWORD], "meshIdentity")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(h.event().0, "meshCodes");
    h.net_state("online");
    (h, id)
}

fn has(social: &Value, list: &str, id: &str) -> bool {
    social[list]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == id)
}

/// The next `binding` event that `done` accepts; other events are skipped.
fn until(h: &mut Helper, binding: &str, done: impl Fn(&Value) -> bool) -> Value {
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "no {binding} came"
        );
        let (got, payload) = h.event();
        if got == binding && done(&payload) {
            return payload;
        }
    }
}

/// Sends a command and waits for its answer, skipping updates that come
/// by themselves meanwhile.
fn ask(h: &mut Helper, func: &str, args: &[&str], binding: &str) -> Value {
    h.send(func, args);
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{func}: no {binding}"
        );
        let (got, payload) = h.event();
        if got == binding || got == "meshError" {
            assert_eq!(got, binding, "{func} answered {payload}");
            return payload;
        }
    }
}

fn texts(messages: &Value) -> Vec<String> {
    let events = messages["events"].as_array().unwrap();
    events
        .iter()
        .map(|e| e["text"].as_str().unwrap().to_owned())
        .collect()
}

/// Opens the chat until its page satisfies `done`.
fn page_until(h: &mut Helper, chat: &str, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = ask(h, "dmOpen", &[chat], "meshDmMessages");
        if done(&page) {
            return page;
        }
        assert!(
            Instant::now() < deadline,
            "the page never came right: {page}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn locks(h: &mut Helper) {
    ask(h, "idLock", &[], "meshIdentity");
}

fn unlocks(h: &mut Helper, name: &str) {
    h.send("idUnlock", &[name, PASSWORD]);
    until(h, "meshIdentity", |i| i["state"] == "unlocked");
}

/// Events mailed, by the helper's own count lines.
fn mailed(stderr: &str) -> u64 {
    stderr
        .lines()
        .filter_map(|l| l.strip_prefix("mesh-node: mailed "))
        .filter_map(|l| l.split(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Test 1. Bob locks; Alice sends "one" and locks. Bob unlocks while Alice
/// is still locked: "one" shows within 5 s of his helper coming online,
/// once. When Alice unlocks, it's "sent" by Bob's receipt and isn't mailed
/// again.
#[test]
fn test_1_one_to_one() {
    one_to_one("mail1", "0");
}

/// Test 1 with both helpers' clocks 30 s ahead of the seed's: their claims
/// still stand.
#[test]
fn test_1_clocks_ahead() {
    one_to_one("mail1-ahead", "30");
}

/// And 30 s behind.
#[test]
fn test_1_clocks_behind() {
    one_to_one("mail1-behind", "-30");
}

/// Test 1 through a relay-only seed, as the home seed runs (SPEC-seed D8c
/// as changed).
#[test]
fn test_1_through_a_relay_only_seed() {
    one_to_one_with("mail1-relay-only", "0", &["--mail", "--relay-only"]);
}

/// Claims the seed refused, by the helper's own count lines.
fn refused(stderr: &str) -> u64 {
    stderr
        .lines()
        .filter_map(|l| l.strip_prefix("mesh-node: "))
        .filter_map(|l| l.strip_suffix(" mail claims refused"))
        .filter_map(|n| n.parse::<u64>().ok())
        .sum()
}

fn one_to_one(name: &str, clock: &str) {
    one_to_one_with(name, clock, &["--mail"]);
}

fn one_to_one_with(name: &str, clock: &str, seed_args: &[&str]) {
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, seed_args);
    let ticket = seed.ticket();
    // Records long enough to outlast the clocks' gap (routing D4's are 2 h).
    let skewed = ["--clock-offset", clock, "--record-ttl", SKEWED_TTL];
    let clock = if clock == "0" { &[][..] } else { &skewed[..] };
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice", clock);
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob", clock);
    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    alice.social_until(|s| has(s, "friends", &id_b));
    bob.social_until(|s| has(s, "friends", &id_a));
    // They've written once, live, so a session is open (PLAN-mailbox Task
    // 1; without one it takes the mail record, test 17).
    ask(&mut alice, "dmSend", &[&id_b, "hi"], "meshDmMessages");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "hi");
    page_until(&mut alice, &id_b, |p| p["events"][0]["sent"] == true);

    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "one"], "meshDmMessages");
    locks(&mut alice);

    bob.send("idUnlock", &["bob", PASSWORD]);
    let (mut online, mut shown) = (None, None);
    let started = Instant::now();
    while online.is_none() || shown.is_none() {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "\"one\" never came"
        );
        let (binding, payload) = bob.line();
        let now = Instant::now();
        match binding.as_str() {
            "meshNet" if payload["state"] == "online" => {
                online.get_or_insert(now);
            }
            "meshDmNotify" if payload["text"] == "one" => {
                assert!(shown.is_none(), "\"one\" was told twice");
                shown = Some(now);
            }
            _ => {}
        }
    }
    let took = shown.unwrap().saturating_duration_since(online.unwrap());
    eprintln!(
        "test 1: \"one\" showed {took:?} after Bob's helper came online, {:?} after he unlocked",
        shown.unwrap() - started
    );
    assert!(took <= SHOWS_WITHIN, "\"one\" took {took:?}");

    unlocks(&mut alice, "alice");
    let sent = page_until(&mut alice, &id_b, |p| p["events"][1]["sent"] == true);
    assert_eq!(texts(&sent), ["hi", "one"]);
    // Alice and Bob are online together now; nothing goes twice.
    std::thread::sleep(Duration::from_secs(3));
    let seen = page_until(&mut bob, &id_a, |_| true);
    assert_eq!(texts(&seen), ["hi", "one"]);

    let alice_log = alice.quit();
    let bob_log = bob.quit();
    assert_eq!(
        mailed(&alice_log),
        1,
        "Alice mailed \"one\" once, and only it"
    );
    assert_eq!(
        refused(&alice_log) + refused(&bob_log),
        0,
        "no claim was refused"
    );
    let seed_log = seed.stop().concat();
    for secret in ["one", "hi"] {
        let quoted = format!("\"{secret}\"");
        for log in [&alice_log, &bob_log, &seed_log] {
            assert!(!log.contains(&quoted), "a log holds {quoted}");
        }
    }
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A bare Mesh device on the relay, to ask a seed things directly.
async fn client(relay: &Relay) -> Node {
    let (root, key) = (RootKey::generate().unwrap(), DeviceKey::generate().unwrap());
    let cert = DeviceCert::issue(&root, &key.public(), "client", 1).unwrap();
    let config = Config {
        relays: Relays::Custom(vec![relay.url.parse().unwrap()]),
        ..Config::default()
    };
    let node = Node::start(&key, &cert, config).await.unwrap();
    assert!(node.online(Duration::from_secs(10)).await);
    node
}

/// One batched request, one answer.
async fn ask_seed(node: &Node, seed: &MeshAddr, service: &str, request: &[u8]) -> Vec<u8> {
    let (_, mut send, mut recv) = node.open(seed, service).await.expect("open");
    frame::write_frame(&mut send, request).await.unwrap();
    send.finish().unwrap();
    frame::read_frame(&mut recv)
        .await
        .unwrap()
        .expect("an answer")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const OK: u8 = 0;
const NO_BOX: u8 = 2;
const TAKEN: u8 = 3;
const FULL: u8 = 4;
const SLOW_DOWN: u8 = 5;
const CLOSED: u8 = 6;

/// Many requests on one batched stream, every answer back in order.
async fn ask_seed_many(
    node: &Node,
    seed: &MeshAddr,
    service: &str,
    requests: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let (_, mut send, mut recv) = node.open(seed, service).await.expect("open");
    let sending = async {
        for request in requests {
            frame::write_frame(&mut send, request).await.unwrap();
        }
        send.finish().unwrap();
    };
    let reading = async {
        let mut answers = Vec::new();
        while answers.len() < requests.len() {
            answers.push(
                frame::read_frame(&mut recv)
                    .await
                    .unwrap()
                    .expect("an answer"),
            );
        }
        answers
    };
    tokio::join!(sending, reading).1
}

/// A claim of `at` for a day, with `token` (empty for an open seed).
fn claim_with(token: &[u8], at: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let expiry = (now() + 86_400).to_be_bytes();
    [
        &[token.len() as u8][..],
        token,
        at,
        &mail_collect_tag(secret),
        &expiry,
    ]
    .concat()
}

/// Test 6, the rest (PLAN-mailbox Task 4): a friend can't put past a box's
/// quota; a closed seed refuses a claim or put without its token; a key
/// over its hour's limits gets `slow-down`.
#[test]
fn test_6_junk_quotas_tokens_and_rates() {
    const TOKEN: &[u8] = b"friends-of-the-operator";
    let dirs = ["open", "closed"].map(|n| temp_dir(&format!("mail6b-{n}")));
    let relay = Relay::start();
    let mut open = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let open_addr = MeshAddr::from_ticket(&open.ticket()).unwrap();
    let token = std::str::from_utf8(TOKEN).unwrap();
    let mut closed = Seed::start_with(&dirs[1], &relay, &["--mail", "--mail-token", token]);
    let closed_addr = MeshAddr::from_ticket(&closed.ticket()).unwrap();
    relay.runtime.block_on(async {
        let node = client(&relay).await;
        let at = [[4u8; 16].as_slice(), &[1u8; 8]].concat();
        let claim = claim_with(&[], &at, &[7; 32]);
        assert_eq!(
            ask_seed(&node, &open_addr, "mail-claim", &claim).await,
            [OK]
        );
        // A box takes 4 MiB: 60 KiB envelopes fill it before the 70th.
        let big: Vec<Vec<u8>> = (0..70)
            .map(|_| [vec![0], at.clone(), vec![5; 60 * 1024]].concat())
            .collect();
        let answers = ask_seed_many(&node, &open_addr, "mail-put", &big).await;
        let full = answers.iter().filter(|a| **a == [FULL]).count();
        assert!(
            full > 0 && answers[0] == [OK],
            "the box never filled: {answers:?}"
        );
        // One key's 601st put in an hour is slowed.
        let other = [[4u8; 16].as_slice(), &[2u8; 8]].concat();
        assert_eq!(
            ask_seed(
                &node,
                &open_addr,
                "mail-claim",
                &claim_with(&[], &other, &[7; 32])
            )
            .await,
            [OK]
        );
        let small: Vec<Vec<u8>> = (0..600)
            .map(|_| [vec![0], other.clone(), vec![5; 10]].concat())
            .collect();
        let answers = ask_seed_many(&node, &open_addr, "mail-put", &small).await;
        assert_eq!(
            answers.last().unwrap(),
            &[SLOW_DOWN],
            "70 + 530 puts, then slowed"
        );
        // The closed seed: nothing without its token.
        assert_eq!(
            ask_seed(&node, &closed_addr, "mail-claim", &claim).await,
            [CLOSED]
        );
        let with = claim_with(TOKEN, &at, &[7; 32]);
        assert_eq!(
            ask_seed(&node, &closed_addr, "mail-claim", &with).await,
            [OK]
        );
        let put = [vec![0], at.clone(), vec![5; 10]].concat();
        assert_eq!(
            ask_seed(&node, &closed_addr, "mail-put", &put).await,
            [CLOSED]
        );
        let put = [&[TOKEN.len() as u8][..], TOKEN, &at, &[5; 10]].concat();
        assert_eq!(ask_seed(&node, &closed_addr, "mail-put", &put).await, [OK]);
        // Nor mail records: they count in --mail-max.
        let record = [
            &[6u8; 16][..],
            &[1; 8],
            &(now() + 60).to_be_bytes(),
            &[9; 80],
        ]
        .concat();
        let stranger = [&[0u8][..], &record].concat();
        assert_eq!(
            ask_seed(&node, &closed_addr, "mrec-put", &stranger).await,
            [CLOSED]
        );
        let friend = [&[TOKEN.len() as u8][..], TOKEN, &record].concat();
        assert_eq!(
            ask_seed(&node, &closed_addr, "mrec-put", &friend).await,
            [OK]
        );
        node.close().await;
    });
    let logs = [open.stop(), closed.stop()].concat().concat();
    assert!(!logs.contains(token), "the token reached a log");
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

const DAY: u64 = 86_400;
/// Long enough for a new contact's records to be put and read.
const SETTLE: Duration = Duration::from_secs(3);

/// Starts a helper again on its data with the clock `days` on, unlocked.
fn again(dir: &std::path::Path, relay: &Relay, seeds: &[&str], name: &str, days: u64) -> Helper {
    again_with(dir, relay, seeds, name, days, &[])
}

fn again_with(
    dir: &std::path::Path,
    relay: &Relay,
    seeds: &[&str],
    name: &str,
    days: u64,
    more: &[&str],
) -> Helper {
    again_at(dir, relay, seeds, name, days * DAY, TTL, more)
}

/// `again_with`, the clock `offset` seconds on, with records of `ttl`.
fn again_at(
    dir: &std::path::Path,
    relay: &Relay,
    seeds: &[&str],
    name: &str,
    offset: u64,
    ttl: &str,
    more: &[&str],
) -> Helper {
    let offset = offset.to_string();
    let mut args: Vec<&str> = seeds.iter().flat_map(|s| ["--seed", s]).collect();
    args.extend(["--record-ttl", ttl, "--clock-offset", &offset]);
    args.extend(more);
    let mut h = Helper::start_with(dir, relay, &args);
    let (binding, first) = h.event();
    assert_eq!(binding, "meshIdentity");
    if first["state"] != "unlocked" {
        unlocks(&mut h, name);
    }
    h
}

/// The seed again on its data with the clock `days` on; its ticket doesn't
/// change.
fn seed_at(dir: &std::path::Path, relay: &Relay, ticket: &str, days: u64) -> Seed {
    let offset = (days * DAY).to_string();
    let mut seed = Seed::start_with(dir, relay, &["--mail", "--clock-offset", &offset]);
    assert_eq!(seed.ticket(), ticket);
    seed
}

/// Two people and their seeds: Bob's only seed holds mail; Alice lists a
/// seed without mail first, so she mails Bob at the holder his mail record
/// names, not at her own first seed.
struct Pair {
    relay: Relay,
    dirs: [std::path::PathBuf; 4],
    seed: Option<Seed>,
    plain: Option<Seed>,
    /// The second seed holds mail too.
    plain_mail: bool,
    ticket: String,
    plain_ticket: String,
}

impl Pair {
    fn alice_seeds(&self) -> [&str; 2] {
        [&self.plain_ticket, &self.ticket]
    }

    /// The mail seed again, `days` on.
    fn seed_at(&mut self, days: u64) {
        self.stop_seed();
        self.seed = Some(seed_at(&self.dirs[0], &self.relay, &self.ticket, days));
    }

    fn stop_seed(&mut self) -> String {
        self.seed
            .take()
            .map(|s| s.stop().join("\n"))
            .unwrap_or_default()
    }

    /// The mail seed again with `args` beside `--mail`; its log so far.
    fn seed_with(&mut self, args: &[&str]) -> String {
        let log = self.stop_seed();
        let args = [&["--mail"][..], args].concat();
        let mut seed = Seed::start_with(&self.dirs[0], &self.relay, &args);
        assert_eq!(seed.ticket(), self.ticket);
        self.seed = Some(seed);
        log
    }

    /// The mail seed again, full: the claims it holds stand, and nothing
    /// new fits (test 4).
    fn seed_full(&mut self) -> String {
        self.seed_with(&["--mail-max", "1"])
    }

    fn stop_plain(&mut self) -> String {
        self.plain
            .take()
            .map(|s| s.stop().join("\n"))
            .unwrap_or_default()
    }

    /// The second seed again, on its data.
    fn plain_back(&mut self) {
        let args: &[&str] = if self.plain_mail { &["--mail"] } else { &[] };
        let mut plain = Seed::start_with(&self.dirs[3], &self.relay, args);
        assert_eq!(plain.ticket(), self.plain_ticket);
        self.plain = Some(plain);
    }

    /// Ends the test: no claim was refused, and no log holds `secrets`.
    fn done(mut self, mut logs: Vec<String>, secrets: &[&str]) {
        logs.push(self.stop_seed());
        logs.push(self.stop_plain());
        for log in &logs {
            assert_eq!(refused(log), 0, "no claim was refused");
            for secret in secrets {
                assert!(
                    !log.contains(&format!("\"{secret}\"")),
                    "a log holds {secret}"
                );
            }
        }
        drop(self.relay.runtime);
        for dir in self.dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Alice and Bob made friends, and (with `write`) wrote once live; then a
/// pause so each has read the other's mail record. Their helpers and IDs.
fn friends(name: &str, write: bool) -> (Pair, Helper, String, Helper, String) {
    friends_with(name, write, true)
}

/// `friends`; with `plain_first`, Alice's first seed is one without mail.
/// Without, it's the mail seed, so mail for Alice (receipts) reaches her.
// ponytail: a helper's own holder is its first seed until PLAN-mailbox Task
// 12, so with the plain seed first nothing can be mailed to Alice.
fn friends_with(
    name: &str,
    write: bool,
    plain_first: bool,
) -> (Pair, Helper, String, Helper, String) {
    friends_on(name, write, plain_first, false)
}

/// `friends_with`; with `plain_mail`, the second seed holds mail too.
fn friends_on(
    name: &str,
    write: bool,
    plain_first: bool,
    plain_mail: bool,
) -> (Pair, Helper, String, Helper, String) {
    let dirs = ["seed", "alice", "bob", "plain"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let ticket = seed.ticket();
    let mut plain = if plain_mail {
        Seed::start_with(&dirs[3], &relay, &["--mail"])
    } else {
        Seed::start(&dirs[3], &relay)
    };
    let plain_ticket = plain.ticket();
    let (first, then) = if plain_first {
        (&plain_ticket, &ticket)
    } else {
        (&ticket, &plain_ticket)
    };
    let (mut alice, id_a) = helper(&dirs[1], &relay, first, "alice", &["--seed", then]);
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob", &[]);
    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    alice.social_until(|s| has(s, "friends", &id_b));
    bob.social_until(|s| has(s, "friends", &id_a));
    if write {
        ask(&mut alice, "dmSend", &[&id_b, "hi"], "meshDmMessages");
        until(&mut bob, "meshDmNotify", |n| n["text"] == "hi");
        page_until(&mut alice, &id_b, |p| p["events"][0]["sent"] == true);
    }
    std::thread::sleep(SETTLE);
    let pair = Pair {
        relay,
        dirs,
        seed: Some(seed),
        plain: Some(plain),
        plain_mail,
        ticket,
        plain_ticket,
    };
    (pair, alice, id_a, bob, id_b)
}

/// Tests 9 and 10. Bob locks; Alice sends "ten" and locks. With `late`,
/// Alice comes back on that day, Bob's record long gone, and sends "late"
/// from her memory of his holders and their session. Bob comes back on
/// day `away` and gets what was sent.
fn away(name: &str, away: u64, late: Option<u64>) {
    let (mut p, mut alice, _, mut bob, id_b) = friends(name, true);
    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "ten"], "meshDmMessages");
    locks(&mut alice);
    let mut logs = vec![alice.quit(), bob.quit()];
    if let Some(day) = late {
        p.seed_at(day);
        let mut alice = again(&p.dirs[1], &p.relay, &p.alice_seeds(), "alice", day);
        ask(&mut alice, "dmSend", &[&id_b, "late"], "meshDmMessages");
        locks(&mut alice);
        logs.push(alice.quit());
    }
    p.seed_at(away);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", away);
    until(&mut bob, "meshDmNotify", |n| n["text"] == "ten");
    if late.is_some() {
        until(&mut bob, "meshDmNotify", |n| n["text"] == "late");
    }
    logs.push(bob.quit());
    p.done(logs, &["ten", "late"]);
}

/// Test 9. Away 10 days: Bob's mail record has lapsed from the seed.
#[test]
fn test_9_away_10_days() {
    away("mail9", 10, None);
}

/// Test 10. Away 25 days, and Alice sends "late" on day 20.
#[test]
fn test_10_away_25_days() {
    away("mail10", 25, Some(20));
}

/// Test 17. Alice and Bob have never written. On day 0 both are unlocked
/// long enough for Alice to read Bob's mail record, then both lock. On day
/// 20 Alice sends "first", mailed on a session she starts from the
/// remembered fallback key; on day 25 Bob gets it.
#[test]
fn test_17_first_mail_from_a_record_read_ahead() {
    let (mut p, mut alice, _, mut bob, id_b) = friends("mail17", false);
    locks(&mut bob);
    locks(&mut alice);
    let mut logs = vec![alice.quit(), bob.quit()];
    p.seed_at(20);
    let mut alice = again(&p.dirs[1], &p.relay, &p.alice_seeds(), "alice", 20);
    ask(&mut alice, "dmSend", &[&id_b, "first"], "meshDmMessages");
    locks(&mut alice);
    let late = alice.quit();
    assert_eq!(mailed(&late), 1, "mailed on day 20");
    logs.push(late);
    p.seed_at(25);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 25);
    until(&mut bob, "meshDmNotify", |n| n["text"] == "first");
    logs.push(bob.quit());
    p.done(logs, &["first"]);
}

/// Test 5. Alice mails Bob "three" and locks; the seed's mail is wiped. Bob
/// unlocks, finds his claims gone, claims again, and his record says the
/// seed is good only since now. Alice unlocks, reads that, and mails
/// "three" again at once. Bob gets it once.
#[test]
fn test_5_wiped_holder() {
    let (mut p, mut alice, id_a, mut bob, id_b) = friends("mail5", true);
    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "three"], "meshDmMessages");
    locks(&mut alice);
    p.stop_seed();
    std::fs::remove_dir_all(p.dirs[0].join("mail")).unwrap();
    p.seed_at(0);
    // Bob comes and goes: his claims are new, and so is his record. Alice
    // stays locked meanwhile, so nothing reaches him live.
    unlocks(&mut bob, "bob");
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "three");
    std::thread::sleep(Duration::from_secs(2));
    let seen = page_until(&mut bob, &id_a, |_| true);
    assert_eq!(texts(&seen), ["hi", "three"], "once");
    let alice_log = alice.quit();
    assert_eq!(mailed(&alice_log), 2, "mailed, and again after the wipe");
    p.done(vec![alice_log, bob.quit()], &["three"]);
}

/// Test 5 with a crash where Alice reads Bob's moved `since`: after the
/// marks are saved, before the remembered records (M15, Task 12b). After
/// the restart she reads the record as new again and mails "three".
#[test]
fn a_crash_between_the_saves_still_mails_again() {
    let (mut p, mut alice, _, mut bob, id_b) = friends_with("mail-crash", true, false);
    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "three"], "meshDmMessages");
    locks(&mut alice);
    let mut logs = vec![alice.quit()];
    p.stop_seed();
    std::fs::remove_dir_all(p.dirs[0].join("mail")).unwrap();
    p.seed_at(0);
    unlocks(&mut bob, "bob");
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    let seeds = [p.ticket.as_str(), p.plain_ticket.as_str()];
    let crash = ["--crash-at", "records"];
    let alice = again_with(&p.dirs[1], &p.relay, &seeds, "alice", 0, &crash);
    let crashed = alice.crashed();
    assert!(crashed.contains("crashing between the saves"), "{crashed}");
    logs.push(crashed);
    let mut alice = again_with(&p.dirs[1], &p.relay, &seeds, "alice", 0, &[]);
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "three");
    logs.extend([alice.quit(), bob.quit()]);
    let mailed: u64 = logs.iter().map(|l| mailed(l)).sum();
    assert_eq!(mailed, 2, "mailed, and again after the restart");
    p.done(logs, &["three"]);
}

/// Test 2. Alice, Bob and Carol (Dave here) in a group. Bob and Carol lock.
/// Alice sends "g1" and locks. Bob unlocks, Alice and Carol still off: he
/// gets "g1". Bob locks; Carol unlocks: she gets "g1".
#[test]
fn test_2_a_group() {
    let (t, mut alice, mut bob, mut carol) = three("mail2", true);
    locks(&mut bob);
    locks(&mut carol);
    ask(&mut alice, "dmSend", &[&t.g, "g1"], "meshDmMessages");
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "g1");
    locks(&mut bob);
    unlocks(&mut carol, "dave");
    until(&mut carol, "meshDmNotify", |n| n["text"] == "g1");
    let logs = [alice.quit(), bob.quit(), carol.quit()];
    assert_eq!(mailed(&logs[0]), 2, "once for each member");
    assert!(logs.iter().all(|l| !l.contains("g1")), "no text in a log");
    t.done(logs.to_vec());
}

/// Test 3. Alice's laptop has been unlocked once since it was linked, then
/// locked. Her desk sends Bob "two" and locks. The laptop unlocks while the
/// desk is still off: it shows "two" in the chat with Bob.
#[test]
fn test_3_your_own_second_device() {
    let (p, mut desk, id_a, mut bob, id_b) = friends_with("mail3", true, false);
    let laptop_dir = temp_dir("mail3-laptop");
    let args = ["--seed", p.ticket.as_str(), "--record-ttl", TTL];
    let mut laptop = Helper::start_with(&laptop_dir, &p.relay, &args);
    assert_eq!(laptop.event().0, "meshIdentity");
    let code = ask(&mut desk, "linkStart", &[], "meshLink")["code"]
        .as_str()
        .unwrap()
        .to_owned();
    laptop.send("linkJoin", &[&code, "laptop"]);
    until(&mut desk, "meshLinkConfirm", |_| true);
    desk.send("linkConfirm", &["true"]);
    until(&mut laptop, "meshLinkReceived", |_| true);
    laptop.send("linkFinish", &["alice", PASSWORD]);
    until(&mut laptop, "meshIdentity", |i| i["state"] == "unlocked");
    std::thread::sleep(SETTLE);
    locks(&mut laptop);
    // Bob writes to Alice while the laptop is away. The desk mustn't mail
    // it on (own devices get by mail only what was written here); Bob
    // hasn't read Alice's records since the link, so he can't yet.
    ask(&mut bob, "dmSend", &[&id_a, "from bob"], "meshDmMessages");
    page_until(&mut desk, &id_b, |p| {
        texts(p).contains(&"from bob".to_owned())
    });
    // Bob is away too: the laptop can only have "two" by mail.
    locks(&mut bob);
    ask(&mut desk, "dmSend", &[&id_b, "two"], "meshDmMessages");
    locks(&mut desk);
    unlocks(&mut laptop, "alice");
    let page = page_until(&mut laptop, &id_b, |p| texts(p).contains(&"two".to_owned()));
    assert!(
        !texts(&page).contains(&"from bob".to_owned()),
        "the desk mailed on Bob's message"
    );
    let logs = vec![desk.quit(), laptop.quit(), bob.quit()];
    let _ = std::fs::remove_dir_all(laptop_dir);
    p.done(logs, &["two"]);
}

/// Test 18. Bob stays unlocked over a week's edge (the clock a little
/// before it), his live connection to Alice cut. Alice mails "edge" just
/// before the edge; Bob's next refresh comes after it, and he gets "edge"
/// from last week's box.
#[test]
fn test_18_a_refresh_over_a_weeks_edge() {
    const WEEK: u64 = 7 * DAY;
    // Bob refreshes every 50 s (a quarter of his records' life): his first
    // after the unlock comes after the edge.
    const BOB_TTL: &str = "200";
    let (mut p, alice, _, bob, id_b) = friends("mail18", true);
    let mut logs = vec![alice.quit(), bob.quit()];
    let edge = (now() / WEEK + 1) * WEEK;
    let offset = edge - 40 - now();
    logs.push(p.stop_seed());
    let seed_offset = offset.to_string();
    let args = ["--mail", "--clock-offset", &seed_offset];
    p.seed = Some(Seed::start_with(&p.dirs[0], &p.relay, &args));
    let seeds = [p.ticket.as_str()];
    let cut = ["--cut", "live"];
    let mut bob = again_at(&p.dirs[2], &p.relay, &seeds, "bob", offset, BOB_TTL, &cut);
    // His unlock's collect is done before Alice puts.
    std::thread::sleep(SETTLE);
    let mut alice = again_at(&p.dirs[1], &p.relay, &seeds, "alice", offset, TTL, &[]);
    std::thread::sleep(SETTLE);
    ask(&mut alice, "dmSend", &[&id_b, "edge"], "meshDmMessages");
    assert!(now() + offset < edge, "sent before the edge");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "edge");
    assert!(now() + offset >= edge, "collected after it");
    logs.extend([alice.quit(), bob.quit()]);
    p.done(logs, &["edge"]);
}

/// A device left unlocked over a wipe finds it at its next refresh, which
/// collects before it renews: it claims again and moves `since` (M12), and
/// puts its record at once, not at the daily round. Alice, reading it at
/// her next unlock, mails "w" again; Bob gets it.
#[test]
fn a_wipe_while_unlocked_moves_since() {
    // Bob refreshes every 50 s, so "w" waits on the seed until the wipe.
    const BOB_TTL: &str = "200";
    let (mut p, mut alice, _, bob, id_b) = friends("mail-wipe", true);
    let mut logs = vec![bob.quit()];
    let seeds = [p.ticket.as_str()];
    let cut = ["--cut", "live"];
    let mut bob = again_at(&p.dirs[2], &p.relay, &seeds, "bob", 0, BOB_TTL, &cut);
    std::thread::sleep(SETTLE);
    ask(&mut alice, "dmSend", &[&id_b, "w"], "meshDmMessages");
    std::thread::sleep(SETTLE);
    logs.push(p.stop_seed());
    std::fs::remove_dir_all(p.dirs[0].join("mail")).unwrap();
    p.seed_at(0);
    // Bob's next refresh finds the wipe; his claims and record follow.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_secs(1));
    }
    locks(&mut alice);
    unlocks(&mut alice, "alice");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "w");
    let alice_log = alice.quit();
    assert_eq!(mailed(&alice_log), 2, "mailed, and again after the wipe");
    let bob_log = bob.quit();
    assert!(bob_log.contains("holders lost our claims; claiming again"));
    logs.extend([alice_log, bob_log]);
    p.done(logs, &["w"]);
}

/// Test 8. A 1:1 message and a group's go by mail; then the seed's mail
/// files and every helper's stderr hold no ID, device key, conversation ID
/// or message text, as text or as bytes (M17, M19).
#[test]
fn test_8_nothing_readable_on_the_holder() {
    const ONE: &str = "a private word for Bob";
    const GROUP: &str = "a private word for the trip";
    let (t, mut alice, mut bob, mut dave) = three("mail8", true);
    let mut keys: Vec<String> = Vec::new();
    for (h, name) in [
        (&mut alice, "alice"),
        (&mut bob, "bob"),
        (&mut dave, "dave"),
    ] {
        locks(h);
        h.send("idUnlock", &[name, PASSWORD]);
        let me = until(h, "meshIdentity", |i| i["state"] == "unlocked");
        let devices = me["devices"].as_array().unwrap();
        keys.extend(
            devices
                .iter()
                .map(|d| d["key"].as_str().unwrap().to_owned()),
        );
    }
    locks(&mut bob);
    locks(&mut dave);
    ask(&mut alice, "dmSend", &[&t.ids[1], ONE], "meshDmMessages");
    ask(&mut alice, "dmSend", &[&t.g, GROUP], "meshDmMessages");
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    page_until(&mut bob, &t.ids[0], |p| texts(p).contains(&ONE.to_owned()));
    page_until(&mut bob, &t.g, |p| texts(p).contains(&GROUP.to_owned()));
    locks(&mut bob);
    unlocks(&mut dave, "dave");
    page_until(&mut dave, &t.g, |p| texts(p).contains(&GROUP.to_owned()));
    let stderr = [alice, bob, dave].map(Helper::quit).concat();
    let log = t.seed.stop().join("\n");
    let mut stored = Vec::new();
    for entry in std::fs::read_dir(t.dirs[0].join("mail")).unwrap() {
        stored.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    assert!(!stored.is_empty(), "the seed held mail");
    let unhex = |h: &str| -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    // Hex of the right lengths, so the byte greps compare real bytes.
    assert!(
        t.g.len() == 32 && keys.iter().all(|k| k.len() == 64),
        "{} {keys:?}",
        t.g
    );
    let raw = |b: &[u8]| stored.windows(b.len()).any(|w| w == b);
    let readable = |what: &str| log.contains(what) || stderr.contains(what);
    for id in &t.ids {
        let bytes = MeshId::parse(id).unwrap().to_bytes();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!readable(id) && !readable(&hex), "an ID in a log");
        assert!(!raw(&bytes), "an ID in the seed's mail files");
    }
    for key in &keys {
        assert!(!readable(key), "a device key in a log");
        assert!(!raw(&unhex(key)), "a device key in the seed's mail files");
    }
    assert!(!readable(&t.g), "a conversation ID in a log");
    assert!(
        !raw(&unhex(&t.g)),
        "a conversation ID in the seed's mail files"
    );
    for text in [ONE, GROUP] {
        assert!(!readable(text), "message text in a log");
        assert!(
            !raw(text.as_bytes()),
            "message text in the seed's mail files"
        );
    }
    drop(t.relay.runtime);
    for dir in t.dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// A holder that answers every claim `closed` (a closed seed, no token)
/// never gets a `since`: it isn't taken for wiped at each refresh, and the
/// claims don't all go again every time.
#[test]
fn a_holder_that_refuses_every_claim_gets_no_since() {
    let (p, alice, _, bob, _) = friends("mail-closed", true);
    let mut logs = vec![alice.quit(), bob.quit()];
    let closed_dir = temp_dir("mail-closed-shut");
    let args = ["--mail", "--mail-token", "let-me-in-please-0"];
    let mut closed = Seed::start_with(&closed_dir, &p.relay, &args);
    // Its ticket without the token: every claim is refused.
    let ticket = closed.ticket();
    let ticket = ticket.split("&mail=").next().unwrap().to_owned();
    let seeds = [p.ticket.as_str()];
    let holder = ["--holder", ticket.as_str()];
    let mut bob = again_at(&p.dirs[2], &p.relay, &seeds, "bob", 0, TTL, &holder);
    // Refreshes every 2 s: several of them.
    std::thread::sleep(Duration::from_secs(10));
    locks(&mut bob);
    let bob_log = bob.quit();
    assert!(refused(&bob_log) > 0, "the claims were refused");
    assert!(
        !bob_log.contains("holders lost our claims"),
        "taken for wiped: {bob_log}"
    );
    closed.stop();
    let _ = std::fs::remove_dir_all(closed_dir);
    // Bob's refusals are the point here, so his log isn't checked for them.
    logs.push(String::new());
    p.done(logs, &[]);
}

/// PLAN-mailbox Task 16, measurement 1: Bob with 1,000 contacts (Alice and
/// 999 made here, with no network) unlocks against a seed holding his
/// 6,144 claims and one envelope: the time from his helper coming online to
/// the envelope shown, on loopback. Compare test 1's line, the same at one
/// contact.
#[test]
#[ignore = "a measurement: cargo test --release -p mesh-node --test mailbox unlock_at_1000 -- --ignored --nocapture"]
fn unlock_at_1000_contacts() {
    // MESH_CONTACTS runs it at another size (PLAN-mailbox Task 16 follow-up).
    let contacts: usize = std::env::var("MESH_CONTACTS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1000);
    let (mut p, mut alice, _, bob, id_b) = friends("mail-k", true);
    let mut logs = vec![bob.quit()];
    let path = p.dirs[2].join("identity.mks");
    let mut store = Keystore::unlock(&path, "bob", PASSWORD).unwrap();
    for i in 1..contacts {
        let id = RootKey::generate().unwrap().id();
        store.add_contact(id, &format!("c{i}")).unwrap();
    }
    assert_eq!(store.contacts().len(), contacts);
    drop(store);
    // The seed reports every 5 s from here.
    logs.push(p.seed_with(&["--report-every", "5"]));
    // The first unlock claims every slot (six weeks of boxes). MESH_TTL sets
    // Bob's records' life, so his refresh (a quarter of it): 8 s by default.
    let ttl = std::env::var("MESH_TTL").unwrap_or_else(|_| TTL.to_owned());
    let mut bob = again_at(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0, &ttl, &[]);
    std::thread::sleep(Duration::from_secs(20));
    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "one"], "meshDmMessages");
    locks(&mut alice);
    // Bob's CPU time while he unlocks: busy or idle.
    let pid = bob.pid();
    let ticks = move || -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let after = stat.rsplit(')').next().unwrap_or("");
        let f: Vec<&str> = after.split_whitespace().collect();
        f.get(11).and_then(|u| u.parse::<u64>().ok()).unwrap_or(0)
            + f.get(12).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
    };
    let sampler = std::thread::spawn(move || {
        let mut last = ticks();
        let mut seen = Vec::new();
        for _ in 0..12 {
            std::thread::sleep(Duration::from_secs(5));
            let now = ticks();
            seen.push(now.saturating_sub(last));
            last = now;
        }
        seen
    });
    bob.send("idUnlock", &["bob", PASSWORD]);
    let started = Instant::now();
    let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (mut online, mut shown) = (None, None);
        while online.is_none() || shown.is_none() {
            let (binding, payload) = bob.line();
            let now = Instant::now();
            match binding.as_str() {
                "meshNet" if payload["state"] == "online" => {
                    online.get_or_insert(now);
                }
                "meshDmNotify" if payload["text"] == "one" => shown = Some(now),
                _ => {}
            }
        }
        (shown.unwrap() - started, online.unwrap() - started)
    }));
    let cpu = sampler.join().unwrap();
    let seed_log = p.stop_seed();
    let mail_lines: Vec<&str> = (seed_log.lines())
        .filter(|l| l.contains("last hour mail") && !l.contains(" 0 collects"))
        .collect();
    let bob_log = bob.quit();
    eprintln!("measure 1 at {contacts} contacts: Bob's CPU ticks (1/100 s) every 5 s {cpu:?}");
    eprintln!("measure 1: seed {mail_lines:#?}");
    eprintln!("measure 1: Bob's log {bob_log}");
    match waited {
        // From the unlock: "one" can show before the helper says it's
        // online (its relay comes later than the seed's answer).
        Ok((shown, online)) => eprintln!(
            "measure 1: \"one\" showed {shown:?} after Bob unlocked; online came {online:?} after"
        ),
        Err(_) => panic!("\"one\" never showed at {contacts} contacts"),
    }
    logs.extend([alice.quit(), bob_log, seed_log]);
    p.done(logs, &["one"]);
}

/// An unlock while the seed can't be reached: the collect gets no answer.
/// Alice's mail is three weeks old, so a refresh's two weeks wouldn't find
/// it; Bob's refresh is 10 minutes off anyway. When the seed is back, his
/// next full publish starts a collect, which asks that holder for all six
/// weeks, and Bob gets "old" without unlocking again.
#[test]
fn an_unanswered_unlock_collect_goes_again_in_full() {
    // Records of 40 minutes: a refresh every 10.
    const BOB_TTL: &str = "2400";
    let (mut p, mut alice, _, mut bob, id_b) = friends("mail-owed", true);
    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "old"], "meshDmMessages");
    locks(&mut alice);
    let mut logs = vec![alice.quit(), bob.quit()];
    logs.push(p.stop_seed());
    let seeds = [p.ticket.as_str()];
    let mut bob = again_at(&p.dirs[2], &p.relay, &seeds, "bob", 21 * DAY, BOB_TTL, &[]);
    std::thread::sleep(Duration::from_secs(5));
    p.seed_at(21);
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(150),
            "\"old\" never came"
        );
        let (binding, payload) = bob.event();
        if binding == "meshDmNotify" && payload["text"] == "old" {
            break;
        }
    }
    logs.push(bob.quit());
    p.done(logs, &["old"]);
}

/// `x` and `y` become friends.
fn befriend(x: &mut Helper, id_x: &str, y: &mut Helper, id_y: &str) {
    x.expect("friendAdd", &[id_y, ""], "meshSocial");
    y.expect("friendAdd", &[id_x, ""], "meshSocial");
    x.social_until(|s| has(s, "friends", id_y));
    y.social_until(|s| has(s, "friends", id_x));
}

/// The group chat `g` has `n` members.
fn members(g: &str, n: usize) -> impl Fn(&Value) -> bool {
    let g = g.to_owned();
    move |c: &Value| {
        (c["chats"].as_array().unwrap().iter())
            .any(|c| c["id"] == g.as_str() && c["members"].as_array().unwrap().len() == n)
    }
}

/// Alice, Bob and Dave, all friends, on one mail seed; a group `g` of Alice
/// and Bob (with `dave_too`, Dave as well), made by Alice.
struct Three {
    relay: Relay,
    dirs: [std::path::PathBuf; 4],
    seed: Seed,
    ticket: String,
    ids: [String; 3],
    g: String,
}

fn three(name: &str, dave_too: bool) -> (Three, Helper, Helper, Helper) {
    let dirs = ["seed", "alice", "bob", "dave"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice", &[]);
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob", &[]);
    let (mut dave, id_d) = helper(&dirs[3], &relay, &ticket, "dave", &[]);
    befriend(&mut alice, &id_a, &mut bob, &id_b);
    befriend(&mut alice, &id_a, &mut dave, &id_d);
    befriend(&mut bob, &id_b, &mut dave, &id_d);
    let made = ask(&mut alice, "dmGroupCreate", &[&id_b, "trip"], "meshDmChats");
    let g = (made["chats"].as_array().unwrap().iter())
        .find(|c| c["kind"] == "group")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    if dave_too {
        ask(&mut alice, "dmGroupAdd", &[&g, &id_d], "meshDmChats");
        until(&mut dave, "meshDmChats", members(&g, 3));
        until(&mut bob, "meshDmChats", members(&g, 3));
    } else {
        until(&mut bob, "meshDmChats", members(&g, 2));
    }
    std::thread::sleep(SETTLE);
    let t = Three {
        relay,
        dirs,
        seed,
        ticket,
        ids: [id_a, id_b, id_d],
        g,
    };
    (t, alice, bob, dave)
}

impl Three {
    /// The seed again, `day` on.
    fn seed_at(&mut self, day: u64) {
        let old = std::mem::replace(
            &mut self.seed,
            seed_at(&self.dirs[0], &self.relay, &self.ticket, day),
        );
        drop(old);
    }

    fn done(self, mut logs: Vec<String>) {
        logs.push(self.seed.stop().concat());
        assert!(
            logs.iter()
                .all(|l| !l.contains("\"d") && !l.contains("hi from Dave"))
        );
        drop(self.relay.runtime);
        for dir in self.dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Test 12. A group of Alice and Bob; Bob is away. Alice adds Dave, cut
/// off from the seed, and her add is mailed before Bob unlocks, so Bob
/// collects it and Dave's message in one collect, Dave's put first:
/// he shows Dave's message straight away and refuses nothing.
#[test]
fn test_12_an_add_and_a_message_in_one_collect() {
    let (t, alice, mut bob, mut dave) = three("mail12", false);
    locks(&mut bob);
    let mut logs = vec![alice.quit()];
    let mut alice = again_with(
        &t.dirs[1],
        &t.relay,
        &[&t.ticket],
        "alice",
        0,
        &["--cut", "seed"],
    );
    ask(&mut alice, "dmGroupAdd", &[&t.g, &t.ids[2]], "meshDmChats");
    until(&mut dave, "meshDmChats", members(&t.g, 3));
    ask(
        &mut dave,
        "dmSend",
        &[&t.g, "hi from Dave"],
        "meshDmMessages",
    );
    locks(&mut dave);
    alice.send("cutOff", &[]);
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    page_until(&mut bob, &t.g, |p| {
        texts(p).contains(&"hi from Dave".to_owned())
    });
    let bob_log = bob.quit();
    assert!(!bob_log.contains("chat events refused"), "nothing refused");
    logs.extend([alice.quit(), bob_log, dave.quit()]);
    t.done(logs);
}

/// Test 13. Alice mails Bob 60 messages; then the two meet live (Bob cut
/// off from the seed, so he doesn't collect) and Alice sends them again on
/// the live session; Bob collects the mail afterwards. Every message shows
/// once; what he can't open any more is dropped quietly, starts no session
/// repair and leaves no error.
#[test]
fn test_13_out_of_order() {
    let (p, mut alice, id_a, mut bob, id_b) = friends_with("mail13", true, false);
    locks(&mut bob);
    let sent: Vec<String> = (1..=60).map(|i| format!("m{i}")).collect();
    for text in &sent {
        ask(&mut alice, "dmSend", &[&id_b, text], "meshDmMessages");
    }
    let mut logs = vec![bob.quit()];
    let mut bob = again_with(
        &p.dirs[2],
        &p.relay,
        &[&p.ticket],
        "bob",
        0,
        &["--cut", "seed"],
    );
    // A page is the newest 50.
    let newest: Vec<String> = sent[10..].to_vec();
    page_until(&mut bob, &id_a, |page| texts(page) == newest);
    page_until(&mut alice, &id_b, |p| {
        p["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["sent"] == true)
    });
    locks(&mut alice);
    bob.send("cutOff", &[]);
    locks(&mut bob);
    unlocks(&mut bob, "bob");
    std::thread::sleep(SETTLE);
    let page = page_until(&mut bob, &id_a, |_| true);
    assert_eq!(texts(&page), newest, "every message once, in order");
    let bob_log = bob.quit();
    assert!(
        !bob_log.contains("couldn't open an envelope"),
        "no error for mail"
    );
    assert!(bob_log.contains("couldn't be opened"), "counted");
    // Alice collects his receipt: every one it lists has an `ok`.
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    let alice_log = alice.quit();
    assert!(
        alice_log.contains("couldn't be opened"),
        "the receipt listed them"
    );
    assert!(
        !alice_log.contains("fresh mail session"),
        "no fresh session"
    );
    logs.extend([alice_log, bob_log]);
    p.done(logs, &["m1", "m60"]);
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// Alice and Bob write live; then Bob quits, and his e2ee state is put
/// back as it was before they wrote: he holds Alice's keys but no session.
fn lose_session(p: &Pair, alice: &mut Helper, id_a: &str, bob: Helper, id_b: &str) -> Vec<String> {
    let e2ee = p.dirs[2].join("e2ee");
    let before = p.dirs[2].join("e2ee-before");
    let mut logs = vec![bob.quit()];
    copy_dir(&e2ee, &before);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    ask(alice, "dmSend", &[id_b, "hi"], "meshDmMessages");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "hi");
    ask(&mut bob, "dmSend", &[id_a, "hey"], "meshDmMessages");
    page_until(alice, id_b, |p| texts(p).contains(&"hey".to_owned()));
    locks(&mut bob);
    logs.push(bob.quit());
    restore(&before, &e2ee);
    logs
}

fn restore(from: &std::path::Path, to: &std::path::Path) {
    std::fs::remove_dir_all(to).unwrap();
    copy_dir(from, to);
}

/// Test 14. Bob's stored session with Alice is lost: his e2ee state is put
/// back as it was before they wrote, so he holds her keys but no session.
/// Alice, away, mails him "four" and locks; Bob can't open it, drops it,
/// and his receipt lists it as couldn't-open. Bob locks. Alice unlocks,
/// collects the receipt and mails "four" again at once on a fresh session.
/// Bob unlocks and gets it. The two are never online together.
#[test]
fn test_14_a_broken_session_heals_by_mail() {
    let (p, mut alice, id_a, bob, id_b) = friends_with("mail14", false, false);
    let mut logs = lose_session(&p, &mut alice, &id_a, bob, &id_b);
    ask(&mut alice, "dmSend", &[&id_b, "four"], "meshDmMessages");
    locks(&mut alice);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    std::thread::sleep(SETTLE);
    let page = page_until(&mut bob, &id_a, |_| true);
    assert!(!texts(&page).contains(&"four".to_owned()), "it can't open");
    locks(&mut bob);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    page_until(&mut bob, &id_a, |p| texts(p).contains(&"four".to_owned()));
    let alice_log = alice.quit();
    assert!(
        alice_log.contains("a fresh mail session for 1 events"),
        "four, again, on a fresh session"
    );
    logs.extend([alice_log, bob.quit()]);
    p.done(logs, &["four"]);
}

fn shows(page: &Value, wanted: &[&str]) -> bool {
    let got = texts(page);
    wanted.iter().all(|w| got.iter().any(|g| g == w))
}

/// Two couldn't-opens collected together: the first starts a fresh
/// session, and the second, with no new one allowed within the hour, goes
/// again on it (M16 as changed 2026-11-12). Alice's holder is her own mail
/// seed, down while she sends "five", so she collects both receipts at once.
#[test]
fn two_couldnt_opens_within_the_hour_both_go_again() {
    let (mut p, mut alice, id_a, bob, id_b) = friends_on("mail14b", false, true, true);
    let mut logs = lose_session(&p, &mut alice, &id_a, bob, &id_b);
    ask(&mut alice, "dmSend", &[&id_b, "four"], "meshDmMessages");
    locks(&mut alice);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    logs.push(p.stop_plain());
    unlocks(&mut alice, "alice");
    ask(&mut alice, "dmSend", &[&id_b, "five"], "meshDmMessages");
    locks(&mut alice);
    p.plain_back();
    unlocks(&mut bob, "bob");
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    page_until(&mut bob, &id_a, |p| shows(p, &["four", "five"]));
    let alice_log = alice.quit();
    assert!(alice_log.contains("a fresh mail session for 1 events"));
    assert!(alice_log.contains("1 mailed events go again on the newest session"));
    logs.extend([alice_log, bob.quit()]);
    p.done(logs, &["four", "five"]);
}

/// A couldn't-open when the fallback key has started a fresh session
/// already: no second one from it, so the event goes again on the newest
/// session, at once and then with `failed`'s backoff (M16 as changed
/// 2026-11-12). Bob opens it once his record names a newer fallback key.
#[test]
fn a_couldnt_open_with_a_stale_fallback_key_goes_again() {
    let (p, mut alice, id_a, bob, id_b) = friends_with("mail14c", false, false);
    let mut logs = lose_session(&p, &mut alice, &id_a, bob, &id_b);
    // As test 14: "four" heals on a fresh session from Bob's fallback key.
    ask(&mut alice, "dmSend", &[&id_b, "four"], "meshDmMessages");
    locks(&mut alice);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    logs.push(bob.quit());
    // Bob as he is before he opens the fresh session.
    let (e2ee, mid) = (p.dirs[2].join("e2ee"), p.dirs[2].join("e2ee-mid"));
    copy_dir(&e2ee, &mid);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    page_until(&mut bob, &id_a, |p| shows(p, &["four"]));
    // They meet: Bob's reply on it means Alice's next mail needs his session.
    unlocks(&mut alice, "alice");
    ask(&mut bob, "dmSend", &[&id_a, "ok"], "meshDmMessages");
    page_until(&mut alice, &id_b, |p| shows(p, &["ok"]));
    locks(&mut bob);
    locks(&mut alice);
    logs.extend([bob.quit(), alice.quit()]);
    restore(&mid, &e2ee);
    // A restart, so no hour has to pass: only the fallback key says no.
    let seeds = [p.ticket.as_str(), p.plain_ticket.as_str()];
    let mut alice = again(&p.dirs[1], &p.relay, &seeds, "alice", 0);
    ask(&mut alice, "dmSend", &[&id_b, "five"], "meshDmMessages");
    locks(&mut alice);
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    let alice_log = alice.quit();
    assert!(
        !alice_log.contains("a fresh mail session"),
        "not from that key"
    );
    assert!(alice_log.contains("1 mailed events go again on the newest session"));
    assert_eq!(mailed(&alice_log), 2, "five, and five again");
    logs.extend([alice_log, bob.quit()]);
    p.done(logs, &["four", "five", "ok"]);
}

/// A round the seed didn't answer is tried again at the next refresh, not
/// a day later (PLAN-mailbox Task 10b, fix 3). The seed's mail is wiped
/// and Alice forgets Bob's record. Bob unlocks while the seed is down, so
/// his claims and record don't arrive; it comes back while he's unlocked.
/// Bob locks; Alice reads his record, mails him "x", and he gets it.
#[test]
fn a_round_the_seed_missed_goes_again() {
    let (mut p, alice, _, bob, id_b) = friends("mail-missed", true);
    let mut logs = vec![alice.quit(), bob.quit()];
    p.stop_seed();
    std::fs::remove_dir_all(p.dirs[0].join("mail")).unwrap();
    std::fs::remove_dir_all(p.dirs[1].join("mail")).unwrap();
    let mut bob = again(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0);
    // Past `HOLDER_WAIT`, so the unlock's collect gives up.
    std::thread::sleep(Duration::from_secs(12));
    p.seed_at(0);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    let mut alice = again(&p.dirs[1], &p.relay, &p.alice_seeds(), "alice", 0);
    std::thread::sleep(SETTLE);
    ask(&mut alice, "dmSend", &[&id_b, "x"], "meshDmMessages");
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "x");
    logs.extend([alice.quit(), bob.quit()]);
    p.done(logs, &["x"]);
}

/// Test 15. Alice mails Bob 20 messages and locks; she unlocks again before
/// Bob is back, and then restarts: nothing is mailed again (M15).
#[test]
fn test_15_no_re_mail_on_unlock() {
    let (p, mut alice, _, mut bob, id_b) = friends("mail15", true);
    locks(&mut bob);
    for i in 1..=20 {
        ask(
            &mut alice,
            "dmSend",
            &[&id_b, &format!("t{i}")],
            "meshDmMessages",
        );
    }
    locks(&mut alice);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    let first = alice.quit();
    assert_eq!(mailed(&first), 20, "mailed once");
    let mut alice = again(&p.dirs[1], &p.relay, &p.alice_seeds(), "alice", 0);
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    let restarted = alice.quit();
    assert_eq!(mailed(&restarted), 0, "nothing again after a restart");
    p.done(vec![first, restarted, bob.quit()], &["t1", "t20"]);
}

/// Test 4. Bob's holder is full: Alice's message waits on her devices
/// (`full`), and reaches Bob when they're next online together.
#[test]
fn test_4_full_holder() {
    let (mut p, mut alice, id_a, mut bob, id_b) = friends("mail4", true);
    locks(&mut bob);
    let mut logs = vec![p.seed_full()];
    ask(&mut alice, "dmSend", &[&id_b, "full"], "meshDmMessages");
    locks(&mut alice);
    // Bob comes back while Alice is away: nothing was held for him.
    unlocks(&mut bob, "bob");
    std::thread::sleep(SETTLE);
    let page = page_until(&mut bob, &id_a, |_| true);
    assert!(!texts(&page).contains(&"full".to_owned()), "nothing held");
    unlocks(&mut alice, "alice");
    // Bob has the chat open, so it comes as a page, not a note.
    page_until(&mut bob, &id_a, |p| texts(p).contains(&"full".to_owned()));
    let alice_log = alice.quit();
    assert!(alice_log.contains("mailed events weren't taken"), "full");
    logs.extend([alice_log, bob.quit()]);
    p.done(logs, &["full"]);
}

/// Bob lists two holders, the first full: Alice's mail goes to the
/// second, and Bob collects it there (M10).
#[test]
fn the_next_holder_takes_what_the_first_wont() {
    let (mut p, mut alice, _, bob, id_b) = friends_on("mail-next", true, true, true);
    let mut logs = vec![bob.quit()];
    let holders = ["--holder", &p.ticket, "--holder", &p.plain_ticket];
    let mut bob = again_with(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0, &holders);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    // Alice reads Bob's record, which lists both.
    locks(&mut alice);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    logs.push(p.seed_full());
    ask(&mut alice, "dmSend", &[&id_b, "second"], "meshDmMessages");
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "second");
    let alice_log = alice.quit();
    assert_eq!(mailed(&alice_log), 1);
    assert!(
        !alice_log.contains("weren't taken"),
        "the second holder took it"
    );
    logs.extend([alice_log, bob.quit()]);
    p.done(logs, &["second"]);
}

/// A seed's reported counts: the sum of `what` ("claims", "collects") over
/// its report lines.
fn seed_count(log: &str, what: &str) -> u64 {
    (log.lines())
        .filter_map(|l| l.strip_prefix("mesh-node seed: last hour mail "))
        .flat_map(|l| l.split([',', ';']))
        .filter_map(|part| {
            let mut words = part.split_whitespace();
            let n = words.next()?.parse::<u64>().ok()?;
            (words.next()? == what).then_some(n)
        })
        .sum()
}

/// Test 19. Bob lists seeds S1 and S2. Alice mails Bob "five" (to S1) and
/// locks. Bob unlocks with only S2 listed, his live connection to Alice
/// cut: he still collects "five" from S1, where his claims stand. Alice
/// unlocks and reads Bob's record without S1. Bob shows "five" once, makes
/// no new claims at S1, and stops collecting there once his claims run out.
#[test]
fn test_19_a_holder_dropped_from_a_record() {
    let (mut p, alice, id_a, bob, id_b) = friends_on("mail19", true, true, true);
    let mut logs = vec![bob.quit(), alice.quit()];
    // Alice keeps her mail at S2 only, so S1's claims are Bob's alone.
    let seeds = [p.plain_ticket.as_str(), p.ticket.as_str()];
    let s2 = ["--holder", p.plain_ticket.as_str()];
    let mut alice = again_with(&p.dirs[1], &p.relay, &seeds, "alice", 0, &s2);
    let both = ["--holder", &p.ticket, "--holder", &p.plain_ticket];
    let mut bob = again_with(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0, &both);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    logs.push(bob.quit());
    locks(&mut alice);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    ask(&mut alice, "dmSend", &[&id_b, "five"], "meshDmMessages");
    locks(&mut alice);
    // S1 reports every second from here.
    logs.push(p.seed_with(&["--report-every", "1"]));
    let s2 = ["--holder", &p.plain_ticket, "--cut", "live"];
    let mut bob = again_with(&p.dirs[2], &p.relay, &[&p.ticket], "bob", 0, &s2);
    until(&mut bob, "meshDmNotify", |n| n["text"] == "five");
    std::thread::sleep(SETTLE);
    unlocks(&mut alice, "alice");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    let page = page_until(&mut bob, &id_a, |_| true);
    let fives = texts(&page).iter().filter(|t| *t == "five").count();
    assert_eq!(fives, 1, "once");
    locks(&mut bob);
    logs.extend([alice.quit(), bob.quit()]);
    let s1 = p.stop_seed();
    assert_eq!(seed_count(&s1, "claims"), 0, "no new claims at S1");
    assert!(seed_count(&s1, "collects") > 0, "collected there");
    logs.push(s1);
    // A day past his claims there: S1 isn't asked any more.
    let day = 36;
    let offset = (day * DAY).to_string();
    let args = ["--mail", "--report-every", "1", "--clock-offset", &offset];
    p.seed = Some(Seed::start_with(&p.dirs[0], &p.relay, &args));
    // S2 on the same day, or it refuses Bob's claims as too far ahead.
    logs.push(p.stop_plain());
    let plain_args = ["--mail", "--clock-offset", &offset];
    p.plain = Some(Seed::start_with(&p.dirs[3], &p.relay, &plain_args));
    let mut s2 = vec!["--holder", p.plain_ticket.as_str()];
    s2.extend(["--cut", "live"]);
    let mut bob = again_with(&p.dirs[2], &p.relay, &[&p.ticket], "bob", day, &s2);
    std::thread::sleep(SETTLE);
    locks(&mut bob);
    logs.push(bob.quit());
    let s1 = p.stop_seed();
    assert_eq!(seed_count(&s1, "collects"), 0, "not collected there");
    logs.push(s1);
    p.done(logs, &["five"]);
}

/// Test 20. Alice and Bob have met. (a) The seed is down; (b) it's up
/// without the mail services. Alice is unlocked; Bob comes back, and
/// Alice's message, sent as his helper comes online, shows on him within
/// 2 s of that.
#[test]
fn test_20_an_unreachable_holder_holds_nothing_up() {
    for plain in [false, true] {
        let name = if plain { "mail20b" } else { "mail20a" };
        let (mut p, mut alice, _, bob, id_b) = friends(name, true);
        let mut logs = vec![bob.quit()];
        logs.push(p.stop_seed());
        if plain {
            let mut seed = Seed::start(&p.dirs[0], &p.relay);
            assert_eq!(seed.ticket(), p.ticket);
            p.seed = Some(seed);
        }
        let args = ["--seed", p.ticket.as_str(), "--record-ttl", TTL];
        let mut bob = Helper::start_with(&p.dirs[2], &p.relay, &args);
        let (binding, first) = bob.event();
        assert_eq!(binding, "meshIdentity");
        if first["state"] != "unlocked" {
            unlocks(&mut bob, "bob");
        }
        bob.net_state("online");
        let online = Instant::now();
        ask(&mut alice, "dmSend", &[&id_b, "quick"], "meshDmMessages");
        until(&mut bob, "meshDmNotify", |n| n["text"] == "quick");
        let took = online.elapsed();
        assert!(took < Duration::from_secs(2), "{name}: {took:?}");
        logs.extend([alice.quit(), bob.quit()]);
        p.done(logs, &["quick"]);
    }
}

/// Test 16. A group of Alice, Bob and Dave, made by Alice. Bob locks. Over
/// five days Dave sends "d1" to "d5", mailed to Bob, and locks; Alice sees
/// each. Alice removes Dave and locks. Bob collects all six in one
/// collect: "d1" to "d5" show, then the removal; nothing is refused.
#[test]
fn test_16_a_removal_and_earlier_messages_in_one_collect() {
    let (mut t, alice, mut bob, dave) = three("mail16", true);
    locks(&mut bob);
    let mut logs = vec![alice.quit(), dave.quit(), bob.quit()];
    for day in 0..5u64 {
        t.seed_at(day);
        let mut alice = again(&t.dirs[1], &t.relay, &[&t.ticket], "alice", day);
        let mut dave = again(&t.dirs[3], &t.relay, &[&t.ticket], "dave", day);
        let text = format!("d{}", day + 1);
        ask(&mut dave, "dmSend", &[&t.g, &text], "meshDmMessages");
        page_until(&mut alice, &t.g, |p| texts(p).contains(&text));
        locks(&mut dave);
        logs.extend([dave.quit(), alice.quit()]);
    }
    t.seed_at(5);
    let mut alice = again(&t.dirs[1], &t.relay, &[&t.ticket], "alice", 5);
    ask(
        &mut alice,
        "dmGroupRemove",
        &[&t.g, &t.ids[2]],
        "meshDmChats",
    );
    locks(&mut alice);
    logs.push(alice.quit());
    let mut bob = again(&t.dirs[2], &t.relay, &[&t.ticket], "bob", 5);
    until(&mut bob, "meshDmChats", members(&t.g, 2));
    let page = page_until(&mut bob, &t.g, |p| texts(p).len() >= 5);
    assert_eq!(texts(&page), ["d1", "d2", "d3", "d4", "d5"]);
    let bob_log = bob.quit();
    assert!(!bob_log.contains("chat events refused"), "nothing refused");
    logs.push(bob_log);
    t.done(logs);
}

/// Records that outlast the test, so no refresh comes.
const NO_REFRESH: &str = "3600";

/// A new contact is claimed for at once (PLAN-mailbox Tasks 6 and 7): Bob
/// adds Alice and locks, Alice mails him, and he gets it, with no refresh
/// between.
#[test]
fn a_new_contact_is_claimed_at_once() {
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("mail-new-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let ticket = seed.ticket();
    let once = ["--record-ttl", NO_REFRESH];
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice", &once);
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob", &once);
    alice.expect("friendAdd", &[&id_b, ""], "meshSocial");
    bob.expect("friendAdd", &[&id_a, ""], "meshSocial");
    alice.social_until(|s| has(s, "friends", &id_b));
    bob.social_until(|s| has(s, "friends", &id_a));
    // Alice has Bob's keys from his address record once they've met.
    std::thread::sleep(Duration::from_secs(2));
    locks(&mut bob);
    ask(&mut alice, "dmSend", &[&id_b, "new"], "meshDmMessages");
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmNotify", |n| n["text"] == "new");
    let alice_log = alice.quit();
    assert_eq!(mailed(&alice_log), 1);
    bob.quit();
    seed.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Test 6, first part (PLAN-mailbox Task 2): nothing is held for a slot
/// nobody claimed, and only the claimer's collect secret collects.
#[test]
fn test_6_junk_unclaimed_and_secrets() {
    let dir = temp_dir("mail6-seed");
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dir, &relay, &["--mail"]);
    let addr = MeshAddr::from_ticket(&seed.ticket()).unwrap();
    relay.runtime.block_on(async {
        let node = client(&relay).await;
        let at = [[1u8; 16].as_slice(), &[2u8; 8]].concat();
        let secret = [7u8; 32];
        let put = [vec![0], at.clone(), vec![9; 100]].concat();
        // A stranger's put into a slot nobody claimed: no-box.
        assert_eq!(ask_seed(&node, &addr, "mail-put", &put).await, [NO_BOX]);
        let claim = |tag: [u8; 32]| {
            [
                vec![0],
                at.clone(),
                tag.to_vec(),
                (now() + 86_400).to_be_bytes().to_vec(),
            ]
            .concat()
        };
        let tag = mail_collect_tag(&secret);
        assert_eq!(
            ask_seed(&node, &addr, "mail-claim", &claim(tag)).await,
            [OK]
        );
        // Someone else's tag can't take over a standing claim; a renewal can.
        let other = mail_collect_tag(&[8; 32]);
        assert_eq!(
            ask_seed(&node, &addr, "mail-claim", &claim(other)).await,
            [TAKEN]
        );
        assert_eq!(
            ask_seed(&node, &addr, "mail-claim", &claim(tag)).await,
            [OK]
        );
        assert_eq!(ask_seed(&node, &addr, "mail-put", &put).await, [OK]);
        // The wrong secret collects nothing and deletes nothing.
        let get = |s: [u8; 32]| [at.clone(), s.to_vec()].concat();
        assert_eq!(
            ask_seed(&node, &addr, "mail-get", &get([8; 32])).await,
            [NO_BOX]
        );
        // mail-take = slot | secret | the highest number the get gave.
        let take = |s: [u8; 32], upto: &[u8]| [get(s), upto.to_vec()].concat();
        assert_eq!(
            ask_seed(&node, &addr, "mail-take", &take([8; 32], &[0xff; 8])).await,
            [NO_BOX]
        );
        let got = ask_seed(&node, &addr, "mail-get", &get(secret)).await;
        assert_eq!(got[..2], [0, 1], "one envelope");
        assert_eq!(
            ask_seed(&node, &addr, "mail-take", &take(secret, &got[2..10])).await,
            [OK]
        );
        let got = ask_seed(&node, &addr, "mail-get", &get(secret)).await;
        assert_eq!(got, [0; 10], "taken");
        node.close().await;
    });
    seed.stop();
    drop(relay.runtime);
    let _ = std::fs::remove_dir_all(dir);
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Test 7. Mail older than `MAIL_LIFE` (30 days) and claims not renewed
/// for `CLAIM_LIFE` (35 days) are gone from the seed's files.
#[test]
fn test_7_expiry() {
    const DAY: u64 = 86_400;
    let dir = temp_dir("mail7-seed");
    let relay = Relay::start();
    let (short, long) = (
        [[3u8; 16].as_slice(), &[1u8; 8]].concat(),
        [[3u8; 16].as_slice(), &[2u8; 8]].concat(),
    );
    let letter = b"a letter that must not outlive its month".to_vec();
    let mut seed = Seed::start_with(&dir, &relay, &["--mail"]);
    let addr = MeshAddr::from_ticket(&seed.ticket()).unwrap();
    relay.runtime.block_on(async {
        let node = client(&relay).await;
        let tag = mail_collect_tag(&[7; 32]);
        for (at, life) in [(&short, DAY), (&long, 35 * DAY)] {
            let claim = [
                vec![0],
                at.clone(),
                tag.to_vec(),
                (now() + life).to_be_bytes().to_vec(),
            ]
            .concat();
            assert_eq!(ask_seed(&node, &addr, "mail-claim", &claim).await, [OK]);
        }
        let put = [vec![0], long.clone(), letter.clone()].concat();
        assert_eq!(ask_seed(&node, &addr, "mail-put", &put).await, [OK]);
        node.close().await;
    });
    seed.stop();
    let files =
        || ["claims", "envelopes"].map(|f| std::fs::read(dir.join("mail").join(f)).unwrap());
    let [claims, envelopes] = files();
    assert!(contains(&envelopes, &letter) && contains(&claims, &short));

    // 31 days on: the letter is gone, and the short claim; the long stands.
    let offset = (31 * DAY).to_string();
    let mut seed = Seed::start_with(&dir, &relay, &["--mail", "--clock-offset", &offset]);
    seed.ticket();
    seed.stop();
    let [claims, envelopes] = files();
    assert!(
        !contains(&envelopes, &letter),
        "the letter outlived its month"
    );
    assert!(!contains(&claims, &short), "the lapsed claim stayed");
    assert!(contains(&claims, &long));

    // 36 days on, the long claim has lapsed too.
    let offset = (36 * DAY).to_string();
    let mut seed = Seed::start_with(&dir, &relay, &["--mail", "--clock-offset", &offset]);
    seed.ticket();
    seed.stop();
    let [claims, _] = files();
    assert!(!contains(&claims, &long), "a claim outlived CLAIM_LIFE");
    drop(relay.runtime);
    let _ = std::fs::remove_dir_all(dir);
}

/// Mail records on the seed (PLAN-mailbox Task 5; routing D3, D5, D6 as
/// changed): one 7 days ahead is taken and one past that and the seed's
/// hour of room for clocks refused, and
/// `mrec-get` finds it; a seed without `--mail` has no such services.
#[test]
fn mail_records_on_the_seed() {
    const WEEK: u64 = 7 * 86_400;
    let dirs = ["mail", "plain"].map(|n| temp_dir(&format!("mrec-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let addr = MeshAddr::from_ticket(&seed.ticket()).unwrap();
    let mut plain = Seed::start(&dirs[1], &relay);
    let plain_addr = MeshAddr::from_ticket(&plain.ticket()).unwrap();
    let record = |expiry: u64| [&[6u8; 16][..], &[1; 8], &expiry.to_be_bytes(), &[9; 80]].concat();
    // An open seed's token: none (mrec-put = token | record).
    let put = |record: &[u8]| [&[0u8][..], record].concat();
    relay.runtime.block_on(async {
        let node = client(&relay).await;
        let week = record(now() + WEEK - 5);
        assert_eq!(ask_seed(&node, &addr, "mrec-put", &put(&week)).await, [0]);
        let past = record(now() + WEEK + 3600 + 60);
        assert_eq!(
            ask_seed(&node, &addr, "mrec-put", &put(&past)).await,
            [5],
            "bad"
        );
        let got = ask_seed(&node, &addr, "mrec-get", &[6; 16]).await;
        assert_eq!(got, [&[0u8, 0, week.len() as u8][..], &week].concat());
        // Without --mail the service isn't there: the stream is refused.
        let refused = async {
            let (_, mut send, mut recv) = node.open(&plain_addr, "mrec-put").await.ok()?;
            frame::write_frame(&mut send, &week).await.ok()?;
            send.finish().ok()?;
            frame::read_frame(&mut recv).await.ok()?
        };
        assert_eq!(refused.await, None);
        node.close().await;
    });
    seed.stop();
    plain.stop();
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}
