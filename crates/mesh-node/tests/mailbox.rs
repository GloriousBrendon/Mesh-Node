//! mailbox (SPEC-mailbox): mail for someone who's away, held by a seed with
//! the mail services on, collected when they come back. The acceptance
//! tests, by number.

use mesh_identity::{DeviceCert, DeviceKey, RootKey, mail_collect_tag};
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
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
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
    let offset = (days * DAY).to_string();
    let mut args: Vec<&str> = seeds.iter().flat_map(|s| ["--seed", s]).collect();
    args.extend(["--record-ttl", TTL, "--clock-offset", &offset]);
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
    plain: Seed,
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
            .map(|s| s.stop().concat())
            .unwrap_or_default()
    }

    /// Ends the test: no claim was refused, and no log holds `secrets`.
    fn done(mut self, mut logs: Vec<String>, secrets: &[&str]) {
        logs.push(self.stop_seed());
        logs.push(self.plain.stop().concat());
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
    let dirs = ["seed", "alice", "bob", "plain"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let ticket = seed.ticket();
    let mut plain = Seed::start(&dirs[3], &relay);
    let plain_ticket = plain.ticket();
    let (mut alice, id_a) = helper(
        &dirs[1],
        &relay,
        &plain_ticket,
        "alice",
        &["--seed", &ticket],
    );
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
        plain,
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

/// Test 11. A group of Alice and Bob; Bob is away. Alice adds Dave with her
/// seed connection cut, so her add can't be mailed to Bob yet; Dave gets it
/// live, sends "hi from Dave" (mailed to Bob) and locks. Bob collects
/// Dave's message with no add and answers `failed` by receipt. Alice's
/// connection comes back and her add is mailed; Bob collects it. Dave
/// collects the `failed` and mails his message again at once; Bob shows
/// it. (Bob comes and goes between steps, so nothing reaches him live.)
///
/// Can't happen as written: dm sends every event of a shared chat to each
/// member's devices but its author's, so Dave's mail carries Alice's add
/// before his message, and Bob takes both. Waiting on a decision (the
/// Task 10 report).
#[test]
#[ignore = "Dave relays Alice's add (dm D5), so Bob never lacks it"]
fn test_11_failed_by_mail() {
    let dirs = ["seed", "alice", "bob", "dave"].map(|n| temp_dir(&format!("mail11-{n}")));
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
    until(&mut bob, "meshDmChats", members(&g, 2));
    std::thread::sleep(SETTLE);
    locks(&mut bob);

    // Alice, cut off from the seed, adds Dave; he writes, mailed to Bob.
    let mut logs = vec![alice.quit()];
    let mut alice = again_with(&dirs[1], &relay, &[&ticket], "alice", 0, &["--cut", "seed"]);
    ask(&mut alice, "dmGroupAdd", &[&g, &id_d], "meshDmChats");
    until(&mut dave, "meshDmChats", members(&g, 3));
    ask(&mut dave, "dmSend", &[&g, "hi from Dave"], "meshDmMessages");
    locks(&mut dave);
    locks(&mut alice);

    // Bob gets Dave's message before the add: refused, `failed` by receipt.
    unlocks(&mut bob, "bob");
    std::thread::sleep(SETTLE);
    let page = ask(&mut bob, "dmOpen", &[&g], "meshDmMessages");
    assert!(!texts(&page).contains(&"hi from Dave".to_owned()));
    locks(&mut bob);

    // Alice's connection comes back; her add is mailed, and Bob takes it.
    unlocks(&mut alice, "alice");
    ask(&mut alice, "cutOff", &[], "meshNet");
    std::thread::sleep(SETTLE);
    locks(&mut alice);
    unlocks(&mut bob, "bob");
    until(&mut bob, "meshDmChats", members(&g, 3));
    std::thread::sleep(SETTLE);
    locks(&mut bob);

    // Dave collects the `failed` and mails his message again at once.
    unlocks(&mut dave, "dave");
    std::thread::sleep(SETTLE);
    locks(&mut dave);
    unlocks(&mut bob, "bob");
    page_until(&mut bob, &g, |p| {
        texts(p).contains(&"hi from Dave".to_owned())
    });

    let dave_log = dave.quit();
    assert_eq!(mailed(&dave_log), 2, "mailed, then again on the `failed`");
    logs.extend([alice.quit(), bob.quit(), dave_log, seed.stop().concat()]);
    assert!(logs.iter().all(|l| !l.contains("hi from Dave")));
    drop(relay.runtime);
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
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
