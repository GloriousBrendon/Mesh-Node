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

fn helper(dir: &std::path::Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
    let mut h = Helper::start_with(dir, relay, &["--seed", seed, "--record-ttl", TTL]);
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
    let dirs = ["seed", "alice", "bob"].map(|n| temp_dir(&format!("mail1-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, &["--mail"]);
    let ticket = seed.ticket();
    let (mut alice, id_a) = helper(&dirs[1], &relay, &ticket, "alice");
    let (mut bob, id_b) = helper(&dirs[2], &relay, &ticket, "bob");
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
        node.close().await;
    });
    let logs = [open.stop(), closed.stop()].concat().concat();
    assert!(!logs.contains(token), "the token reached a log");
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
        let take = |s: [u8; 32]| [get(s), 1u32.to_be_bytes().to_vec()].concat();
        assert_eq!(
            ask_seed(&node, &addr, "mail-take", &take([8; 32])).await,
            [NO_BOX]
        );
        let got = ask_seed(&node, &addr, "mail-get", &get(secret)).await;
        assert_eq!(got[..2], [0, 1], "one envelope");
        assert_eq!(
            ask_seed(&node, &addr, "mail-take", &take(secret)).await,
            [OK]
        );
        let got = ask_seed(&node, &addr, "mail-get", &get(secret)).await;
        assert_eq!(got, [0, 0], "taken");
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
/// changed): one 7 days ahead is taken and one a minute more refused, and
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
    relay.runtime.block_on(async {
        let node = client(&relay).await;
        let week = record(now() + WEEK - 5);
        assert_eq!(ask_seed(&node, &addr, "mrec-put", &week).await, [0]);
        let past = record(now() + WEEK + 60);
        assert_eq!(ask_seed(&node, &addr, "mrec-put", &past).await, [5], "bad");
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
