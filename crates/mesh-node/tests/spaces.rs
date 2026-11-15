//! Spaces (SPEC-spaces), through the helper's commands: people who aren't
//! all friends talk in a Space's channels; they stay strangers otherwise;
//! roles hold; a member who comes back catches up live (the hello).

use serde_json::Value;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, fail, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
/// Short records, so refreshes come every 2 s.
const TTL: &str = "8";

fn helper(dir: &std::path::Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
    let args = ["--seed", seed, "--record-ttl", TTL, "--peer-idle", "3"];
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
// It reads every line itself, `meshNet` included, so the 60 s limit holds
// even while the network keeps reporting.
fn until(h: &mut Helper, binding: &str, done: impl Fn(&Value) -> bool) -> Value {
    let started = Instant::now();
    loop {
        if started.elapsed() > Duration::from_secs(60) {
            fail(&format!("no {binding} came"));
        }
        let (got, payload) = h.line();
        if got == binding && done(&payload) {
            return payload;
        }
    }
}

/// Sends a command and waits for its answer (or its error).
fn ask(h: &mut Helper, func: &str, args: &[&str], binding: &str) -> Value {
    h.send(func, args);
    let started = Instant::now();
    loop {
        if started.elapsed() > Duration::from_secs(60) {
            fail(&format!("{func}: no {binding}"));
        }
        let (got, payload) = h.event();
        if got == binding || got == "meshError" {
            assert_eq!(got, binding, "{func} answered {payload}");
            return payload;
        }
    }
}

fn befriend(a: &mut Helper, id_a: &str, b: &mut Helper, id_b: &str) {
    ask(a, "friendAdd", &[id_b, ""], "meshSocial");
    ask(b, "friendAdd", &[id_a, ""], "meshSocial");
    until(a, "meshSocial", |s| has(s, "friends", id_b));
    until(b, "meshSocial", |s| has(s, "friends", id_a));
}

/// The Space in a `meshSpaces` payload, by name.
fn space<'a>(spaces: &'a Value, name: &str) -> &'a Value {
    spaces["spaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no Space {name} in {spaces}"))
}

fn channel(space: &Value, name: &str) -> String {
    let channels = space["channels"].as_array().unwrap();
    let c = channels.iter().find(|c| c["name"] == name).unwrap();
    c["id"].as_str().unwrap().to_owned()
}

fn members(space: &Value) -> Vec<String> {
    let members = space["members"].as_array().unwrap();
    let mut ids: Vec<String> = members
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

/// O makes "club" with #general and adds B and C, who are O's friends but
/// not each other's. Each of them ends up holding the Space.
struct Club {
    o: Helper,
    b: Helper,
    c: Helper,
    id_o: String,
    id_b: String,
    id_c: String,
    space: String,
    general: String,
    ticket: String,
    seed: Seed,
    _relay: Relay,
}

fn club(name: &str) -> Club {
    club_with(name, &[])
}

/// `club`, with a seed started with `seed_args`.
fn club_with(name: &str, seed_args: &[&str]) -> Club {
    let dirs = ["seed", "o", "b", "c"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, seed_args);
    let ticket = seed.ticket();
    let (mut o, id_o) = helper(&dirs[1], &relay, &ticket, "owen");
    let (mut b, id_b) = helper(&dirs[2], &relay, &ticket, "bea");
    let (mut c, id_c) = helper(&dirs[3], &relay, &ticket, "cal");
    befriend(&mut o, &id_o, &mut b, &id_b);
    befriend(&mut o, &id_o, &mut c, &id_c);

    let made = ask(&mut o, "spaceCreate", &["club"], "meshSpaces");
    let s = space(&made, "club")["id"].as_str().unwrap().to_owned();
    let made = ask(
        &mut o,
        "spaceChannel",
        &[&s, "general", "everyone"],
        "meshSpaces",
    );
    let general = channel(space(&made, "club"), "general");
    // Only friends can be added.
    let stranger = mesh_identity::RootKey::generate().unwrap().id().to_string();
    let err = ask(&mut o, "spaceAdd", &[&s, &stranger], "meshError");
    assert_eq!(err["kind"], "not-a-friend", "{err}");
    ask(&mut o, "spaceAdd", &[&s, &id_b], "meshSpaces");
    ask(&mut o, "spaceAdd", &[&s, &id_c], "meshSpaces");
    let mut all = vec![id_o.clone(), id_b.clone(), id_c.clone()];
    all.sort();
    for h in [&mut b, &mut c] {
        let held = until(h, "meshSpaces", |v| {
            v["spaces"].as_array().unwrap().iter().any(|s| {
                s["name"] == "club"
                    && members(s) == all
                    && s["channels"].as_array().unwrap().len() == 1
            })
        });
        assert_eq!(channel(space(&held, "club"), "general"), general);
    }
    Club {
        o,
        b,
        c,
        id_o,
        id_b,
        id_c,
        space: s,
        general,
        ticket,
        seed,
        _relay: relay,
    }
}

/// Test 1: strangers in one Space talk live, and stay strangers.
#[test]
fn strangers_in_one_space() {
    let mut k = club("spaces-strangers");
    let (s, g) = (k.space.clone(), k.general.clone());

    let started = Instant::now();
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "hi from bea"],
        "meshSpaceMessages",
    );
    let told = until(&mut k.c, "meshSpaceNotify", |n| n["text"] == "hi from bea");
    assert_eq!(
        (
            told["space"].as_str(),
            told["channel"].as_str(),
            told["from"].as_str()
        ),
        (Some(&*s), Some(&*g), Some(&*k.id_b))
    );
    let first = started.elapsed();
    let started = Instant::now();
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "hi from cal"],
        "meshSpaceMessages",
    );
    until(&mut k.b, "meshSpaceNotify", |n| n["text"] == "hi from cal");
    let back = started.elapsed();
    eprintln!("test 1: the first line {first:?} (with its dial), the reply {back:?}");
    assert!(back < Duration::from_secs(1), "the reply took {back:?}");
    let open = ask(&mut k.o, "spaceOpen", &[&s, &g], "meshSpaceMessages");
    let texts: Vec<&str> = (open["events"].as_array().unwrap().iter())
        .map(|e| e["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, ["hi from bea", "hi from cal"]);

    // Still strangers: a DM between them is refused, since they aren't
    // friends (and so get no presence either, social D12).
    let err = ask(&mut k.b, "dmSend", &[&k.id_c, "psst"], "meshError");
    assert_eq!(err["kind"], "not-a-friend", "{err}");

    // C leaves: B drops C as a peer, so C's devices no longer get through
    // B's handshake (the allow-list is the contacts plus the peers).
    ask(&mut k.c, "spaceLeave", &[&s], "meshSpaces");
    until(&mut k.b, "meshSpaces", |v| {
        let held = v["spaces"].as_array().unwrap();
        held.iter()
            .any(|sp| sp["id"] == s.as_str() && !members(sp).contains(&k.id_c))
    });
    let err = ask(&mut k.b, "netPingId", &[&k.id_c], "meshError");
    assert_eq!(err["kind"], "not-a-contact", "{err}");
    let _ = (k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 6, the part a member's own helper refuses: a member can't make a
/// channel or post where only admins post. (Every other member's device
/// refusing a forged one is Task 10's, with `spaceForge`.)
#[test]
fn roles_hold_locally() {
    let mut k = club("spaces-roles");
    let s = k.space.clone();
    let err = ask(
        &mut k.b,
        "spaceChannel",
        &[&s, "mine", "everyone"],
        "meshError",
    );
    assert_eq!(err["kind"], "not-allowed", "{err}");
    let made = ask(
        &mut k.o,
        "spaceChannel",
        &[&s, "news", "admins"],
        "meshSpaces",
    );
    let news = channel(space(&made, "club"), "news");
    until(&mut k.b, "meshSpaces", |v| {
        v["spaces"][0]["channels"].as_array().unwrap().len() == 2
    });
    let err = ask(&mut k.b, "spaceSend", &[&s, &news, "official"], "meshError");
    assert_eq!(err["kind"], "not-allowed", "{err}");
    // Made an admin, B may.
    ask(&mut k.o, "spaceRole", &[&s, &k.id_b, "admin"], "meshSpaces");
    until(&mut k.b, "meshSpaces", |v| {
        let ms = v["spaces"][0]["members"].as_array().unwrap();
        ms.iter()
            .any(|m| m["id"] == k.id_b.as_str() && m["role"] == "admin")
    });
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &news, "official"],
        "meshSpaceMessages",
    );
    until(&mut k.c, "meshSpaceNotify", |n| n["text"] == "official");
    let _ = (k.o.quit(), k.b.quit(), k.c.quit(), &k.id_o);
}

/// Test 12: C comes back while O and B are talking, and sees B's next line
/// in under 5 s without posting anything (the hello, S14). B, not O, speaks:
/// O is C's friend and dialled at unlock anyway.
#[test]
fn a_returning_member_catches_up_live() {
    let mut k = club("spaces-return");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(&mut k.c, "idLock", &[], "meshIdentity");
    // C's address records lapse (8 s here), so a dial to C now fails.
    std::thread::sleep(Duration::from_secs(10));
    ask(
        &mut k.o,
        "spaceSend",
        &[&s, &g, "while you were out"],
        "meshSpaceMessages",
    );
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "indeed"],
        "meshSpaceMessages",
    );
    // B's dial to C gives up (10 s), and B's retry on C starts.
    std::thread::sleep(Duration::from_secs(12));
    k.c.send("idUnlock", &["cal", PASSWORD]);
    until(&mut k.c, "meshIdentity", |i| i["state"] == "unlocked");
    // Give the hello a moment once online, then O speaks.
    std::thread::sleep(Duration::from_secs(2));
    let started = Instant::now();
    // B is only C's peer, and found C away while C was out: B's retry on C
    // is running, so only C's hello lets B's next line through live.
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "welcome back"],
        "meshSpaceMessages",
    );
    until(&mut k.c, "meshSpaceNotify", |n| n["text"] == "welcome back");
    let took = started.elapsed();
    eprintln!("test 12: the next line reached the returning member in {took:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
    let _ = (k.o.quit(), k.b.quit(), k.c.quit(), &k.id_b, &k.id_c);
}

/// A seed's reported mail counts: the sum of `what` ("puts") over its
/// report lines.
fn seed_count(log: &[String], what: &str) -> u64 {
    (log.iter())
        .filter_map(|l| l.strip_prefix("mesh-node seed: last hour mail "))
        .flat_map(|l| l.split([',', ';']))
        .filter_map(|part| {
            let mut words = part.split_whitespace();
            let n = words.next()?.parse::<u64>().ok()?;
            (words.next()? == what).then_some(n)
        })
        .sum()
}

/// Test 2: C is away; B posts three lines and locks; with nobody else
/// online, C gets all three by mail, in order. B's three lines cost one put
/// per away device, not one per line (S9).
#[test]
fn away_and_back_by_batched_mail() {
    let mut k = club_with("spaces-mail", &["--mail", "--report-every", "1"]);
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(&mut k.c, "idLock", &[], "meshIdentity");
    ask(&mut k.o, "idLock", &[], "meshIdentity");
    for line in ["one", "two", "three"] {
        ask(&mut k.b, "spaceSend", &[&s, &g, line], "meshSpaceMessages");
    }
    ask(&mut k.b, "idLock", &[], "meshIdentity");
    k.c.send("idUnlock", &["cal", PASSWORD]);
    for line in ["one", "two", "three"] {
        until(&mut k.c, "meshSpaceNotify", |n| n["text"] == line);
    }
    let open = ask(&mut k.c, "spaceOpen", &[&s, &g], "meshSpaceMessages");
    let texts: Vec<&str> = (open["events"].as_array().unwrap().iter())
        .map(|e| e["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, ["one", "two", "three"]);
    std::thread::sleep(Duration::from_secs(2));
    let b_log = k.b.quit();
    let _ = (k.o.quit(), k.c.quit(), &k.id_o, &k.id_b, &k.id_c);
    let log = k.seed.stop();
    let puts = seed_count(&log, "puts");
    // B's three lines went as one envelope per away device (C and O), not
    // one per line: two puts where one per line would be six.
    let batches: Vec<&str> = (b_log.lines())
        .filter(|l| l.contains("Space batches"))
        .collect();
    eprintln!(
        "test 2: B {batches:?}; {puts} mail puts at the seed in all (receipts, and C passing the changes on, included)"
    );
    assert_eq!(batches, ["mesh-node: mailed 2 Space batches"], "{b_log}");
}

/// Everyone's helper: a new person on the club's relay and seed.
fn newcomer(k: &mut Club, name: &str) -> (Helper, String) {
    let dir = temp_dir(&format!("spaces-{name}-{}", k.space));
    helper(&dir, &k._relay, &k.ticket, name)
}

fn channel_texts(h: &mut Helper, s: &str, g: &str) -> Vec<String> {
    // The page asked for, not another channel's page pushed meanwhile.
    h.send("spaceOpen", &[s, g]);
    let open = until(h, "meshSpaceMessages", |m| m["channel"] == g);
    (open["events"].as_array().unwrap().iter())
        .map(|e| e["text"].as_str().unwrap().to_owned())
        .collect()
}

/// Waits until `h` holds the club with `want` messages in #general.
fn history_until(h: &mut Helper, s: &str, g: &str, want: &[&str]) -> Vec<String> {
    until(h, "meshSpaces", |v| {
        v["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|sp| sp["id"] == s)
    });
    let started = Instant::now();
    loop {
        let texts = channel_texts(h, s, g);
        if want.iter().all(|w| texts.iter().any(|t| t == w)) {
            return texts;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "history so far: {texts:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Waits until a channel `h` already holds shows all of `want`.
fn texts_until(h: &mut Helper, s: &str, g: &str, want: &[&str]) -> Vec<String> {
    let started = Instant::now();
    loop {
        let texts = channel_texts(h, s, g);
        if want.iter().all(|w| texts.iter().any(|t| t == w)) {
            return texts;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "so far: {texts:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Test 3: D, a friend of B's and nobody else's, is added by B and sees
/// what was said before D joined.
#[test]
fn a_friend_of_one_member_joins_and_sees_the_past() {
    let mut k = club("spaces-join");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "before you came"],
        "meshSpaceMessages",
    );
    // C answers after seeing B's line, so it sorts after it (dm D2: `seq`
    // counts on from what's held; lines sent unseen are concurrent).
    until(&mut k.c, "meshSpaceNotify", |n| {
        n["text"] == "before you came"
    });
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "long ago"],
        "meshSpaceMessages",
    );
    until(&mut k.b, "meshSpaceNotify", |n| n["text"] == "long ago");
    let (mut d, id_d) = newcomer(&mut k, "dee");
    befriend(&mut k.b, &k.id_b, &mut d, &id_d);
    ask(&mut k.b, "spaceAdd", &[&s, &id_d], "meshSpaces");
    let texts = history_until(&mut d, &s, &g, &["before you came", "long ago"]);
    assert_eq!(texts, ["before you came", "long ago"]);
    let _ = (d.quit(), k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 4, its departure half (the removed device is `mesh-dm`'s unit
/// test): C posts and leaves; E, added later, still sees C's line as C's.
#[test]
fn history_outlives_a_departure() {
    let mut k = club("spaces-gone");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "cal was here"],
        "meshSpaceMessages",
    );
    until(&mut k.o, "meshSpaceNotify", |n| n["text"] == "cal was here");
    ask(&mut k.c, "spaceLeave", &[&s], "meshSpaces");
    until(&mut k.o, "meshSpaces", |v| {
        !members(&v["spaces"][0]).contains(&k.id_c)
    });
    let (mut e, id_e) = newcomer(&mut k, "eve");
    befriend(&mut k.o, &k.id_o, &mut e, &id_e);
    ask(&mut k.o, "spaceAdd", &[&s, &id_e], "meshSpaces");
    history_until(&mut e, &s, &g, &["cal was here"]);
    let open = ask(&mut e, "spaceOpen", &[&s, &g], "meshSpaceMessages");
    assert_eq!(open["events"][0]["from"], k.id_c.as_str());
    let _ = (e.quit(), k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 5: C serves D an altered line and a line C forged into #news,
/// where only admins post. D refuses both, keeps the rest, and gets the
/// real line from another member.
#[test]
fn history_cant_be_forged() {
    let mut k = club("spaces-forge");
    let (s, g) = (k.space.clone(), k.general.clone());
    let made = ask(
        &mut k.o,
        "spaceChannel",
        &[&s, "news", "admins"],
        "meshSpaces",
    );
    let news = channel(space(&made, "club"), "news");
    ask(
        &mut k.o,
        "spaceSend",
        &[&s, &news, "real news"],
        "meshSpaceMessages",
    );
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "the true line"],
        "meshSpaceMessages",
    );
    // C holds both (in whichever order they came).
    history_until(&mut k.c, &s, &g, &["the true line"]);
    let started = Instant::now();
    while !channel_texts(&mut k.c, &s, &news).contains(&"real news".to_owned()) {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "C never got the news"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // C turns dishonest: alters others' lines and forges one into #news.
    ask(&mut k.c, "spaceForge", &["alter"], "meshForge");
    ask(
        &mut k.c,
        "spaceForge",
        &["inject", &s, &news, "fake news"],
        "meshForge",
    );
    let (mut d, id_d) = newcomer(&mut k, "dan");
    befriend(&mut k.c, &k.id_c, &mut d, &id_d);
    ask(&mut k.c, "spaceAdd", &[&s, &id_d], "meshSpaces");
    let texts = history_until(&mut d, &s, &g, &["the true line"]);
    assert!(!texts.iter().any(|t| t.contains("altered")), "{texts:?}");
    let news_texts = texts_until(&mut d, &s, &news, &["real news"]);
    assert!(
        news_texts.contains(&"real news".to_owned()),
        "{news_texts:?}"
    );
    assert!(
        !news_texts.contains(&"fake news".to_owned()),
        "{news_texts:?}"
    );
    // D asked C first (C added D, so C was connected) and refused C's
    // forgeries before asking another member.
    let d_log = d.quit();
    assert!(d_log.contains("history events refused"), "{d_log}");
    let _ = (k.o.quit(), k.b.quit(), k.c.quit());
}
