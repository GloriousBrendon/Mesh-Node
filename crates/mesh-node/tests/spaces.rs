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
    helper_ttl(dir, relay, seed, name, Some(TTL))
}

/// `helper`, with its records' life: `None` is the real one, and so the
/// real refresh (every 30 minutes).
fn helper_ttl(
    dir: &std::path::Path,
    relay: &Relay,
    seed: &str,
    name: &str,
    ttl: Option<&str>,
) -> (Helper, String) {
    helper_args(dir, relay, seed, name, ttl, &[])
}

/// `helper_ttl`, started with `extra` arguments too.
fn helper_args(
    dir: &std::path::Path,
    relay: &Relay,
    seed: &str,
    name: &str,
    ttl: Option<&str>,
    extra: &[&str],
) -> (Helper, String) {
    let mut args = vec!["--seed", seed, "--peer-idle", "3"];
    if let Some(ttl) = ttl {
        args.extend(["--record-ttl", ttl]);
    }
    args.extend(extra);
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
fn until(h: &mut Helper, binding: &str, done: impl FnMut(&Value) -> bool) -> Value {
    until_for(h, binding, Duration::from_secs(60), done)
}

/// `until`, waiting at most `limit`.
fn until_for(
    h: &mut Helper,
    binding: &str,
    limit: Duration,
    mut done: impl FnMut(&Value) -> bool,
) -> Value {
    let started = Instant::now();
    loop {
        if started.elapsed() > limit {
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
    // A list with no Space yet: no members.
    let members = space["members"].as_array().into_iter().flatten();
    let mut ids: Vec<String> = members
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
    club_ttl(name, seed_args, Some(TTL))
}

/// `club_with`, everyone's records lasting `ttl` (`None`: the real life).
fn club_ttl(name: &str, seed_args: &[&str], ttl: Option<&str>) -> Club {
    let dirs = ["seed", "o", "b", "c"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start_with(&dirs[0], &relay, seed_args);
    let ticket = seed.ticket();
    let (mut o, id_o) = helper_ttl(&dirs[1], &relay, &ticket, "owen", ttl);
    let (mut b, id_b) = helper_ttl(&dirs[2], &relay, &ticket, "bea", ttl);
    let (mut c, id_c) = helper_ttl(&dirs[3], &relay, &ticket, "cal", ttl);
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
    // Spec test 1's "under 1 s" is a figure for an idle machine: Task 11
    // records it. Here, both lines came live.
    eprintln!("test 1: the first line {first:?} (with its dial), the reply {back:?}");
    // O, a member too, holds both, in order (C's may still be on its way).
    let texts = texts_until(&mut k.o, &s, &g, &["hi from bea", "hi from cal"]);
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

/// The address gets a seed's report lines say it refused.
fn gets_slowed(log: &[String]) -> u64 {
    (log.iter())
        .filter_map(|l| {
            l.split(" address gets (")
                .nth(1)?
                .split(' ')
                .next()?
                .parse::<u64>()
                .ok()
        })
        .sum()
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
/// online, C gets all three by mail, in order. Each mail round costs one
/// put per away device, not one per line (S9).
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
    // Each mail round (a refresh, the lock's flush) puts one envelope per
    // away device (C and O), whatever it carries (S9): never one per line.
    // A refresh between two sends splits the lines over two rounds.
    let rounds: Vec<usize> = (b_log.lines())
        .filter_map(|l| {
            l.strip_prefix("mesh-node: mailed ")?
                .strip_suffix(" Space batches")
        })
        .map(|n| n.parse().unwrap())
        .collect();
    eprintln!(
        "test 2: B's rounds {rounds:?}; {puts} mail puts at the seed in all (receipts, and C passing the changes on, included)"
    );
    assert!(!rounds.is_empty(), "{b_log}");
    assert!(rounds.iter().all(|&n| n <= 2), "{rounds:?}");
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
/// real lines from another member once one is online.
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
    // O and B are away, so C is the only member D can ask.
    ask(&mut k.o, "idLock", &[], "meshIdentity");
    ask(&mut k.b, "idLock", &[], "meshIdentity");
    let (mut d, id_d) = newcomer(&mut k, "dan");
    befriend(&mut k.c, &k.id_c, &mut d, &id_d);
    ask(&mut k.c, "spaceAdd", &[&s, &id_d], "meshSpaces");
    let started = Instant::now();
    while !d.stderr_so_far().contains("history events refused") {
        if started.elapsed() > Duration::from_secs(60) {
            fail("D never refused C's history");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    // O comes back: D asks O, and gets the real lines.
    k.o.send("idUnlock", &["owen", PASSWORD]);
    until(&mut k.o, "meshIdentity", |i| i["state"] == "unlocked");
    let texts = history_until(&mut d, &s, &g, &["the true line"]);
    assert!(!texts.iter().any(|t| t.contains("altered")), "{texts:?}");
    let news_texts = texts_until(&mut d, &s, &news, &["real news"]);
    assert!(
        !news_texts.contains(&"fake news".to_owned()),
        "{news_texts:?}"
    );
    let _ = d.quit();
    let _ = (k.o.quit(), k.b.quit(), k.c.quit());
}

/// Own-device sync (dm D8, SPEC-spaces D8 unchanged): B links a laptop. The
/// laptop gets the club with what was said, works out the same peers, hears
/// C live, and what it posts reaches B's desk and C.
#[test]
fn a_linked_device_gets_the_spaces() {
    let mut k = club("spaces-own");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "before the laptop"],
        "meshSpaceMessages",
    );
    until(&mut k.b, "meshSpaceNotify", |n| {
        n["text"] == "before the laptop"
    });

    let dir = temp_dir(&format!("spaces-own-laptop-{s}"));
    let args = ["--seed", &k.ticket, "--record-ttl", TTL, "--peer-idle", "3"];
    let mut laptop = Helper::start_with(&dir, &k._relay, &args);
    assert_eq!(laptop.event().0, "meshIdentity");
    let shown = ask(&mut k.b, "linkStart", &[], "meshLink");
    let code = shown["code"].as_str().unwrap().to_owned();
    laptop.send("linkJoin", &[&code, "laptop"]);
    until(&mut k.b, "meshLinkConfirm", |_| true);
    ask(&mut k.b, "linkConfirm", &["true"], "meshLinkDone");
    until(&mut laptop, "meshLinkReceived", |_| true);
    ask(
        &mut laptop,
        "linkFinish",
        &["bea", PASSWORD],
        "meshIdentity",
    );

    // The club and its past, from B's desk.
    let texts = history_until(&mut laptop, &s, &g, &["before the laptop"]);
    assert_eq!(texts, ["before the laptop"]);
    // C, a stranger to B, is the laptop's peer too: C's next line comes live.
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "hello laptop"],
        "meshSpaceMessages",
    );
    until(&mut laptop, "meshSpaceNotify", |n| {
        n["text"] == "hello laptop"
    });
    // What the laptop says reaches C, and B's desk shows it as B's.
    ask(
        &mut laptop,
        "spaceSend",
        &[&s, &g, "from the laptop"],
        "meshSpaceMessages",
    );
    let told = until(&mut k.c, "meshSpaceNotify", |n| {
        n["text"] == "from the laptop"
    });
    assert_eq!(told["from"], k.id_b.as_str());
    let desk = texts_until(&mut k.b, &s, &g, &["from the laptop"]);
    assert!(desk.contains(&"hello laptop".to_owned()), "{desk:?}");
    let _ = (laptop.quit(), k.o.quit(), k.b.quit(), k.c.quit(), &k.id_o);
}

/// A line written after someone was added is news to them however it comes:
/// B's line while D was locked, only in history when D unlocks. Clocks
/// differ, so up to `JOIN_CLOCK_TOLERANCE` (2 minutes) of skew is allowed:
/// F's clock is a minute behind O's (who added D), and F's line after the
/// add is told. E's clock is five minutes behind, so E's line before the add
/// is well before it, and isn't.
#[test]
fn a_line_after_the_add_is_told_even_from_history() {
    let mut k = club("spaces-told");
    let (s, g) = (k.space.clone(), k.general.clone());
    let mut skewed = |name: &str, offset: &str| {
        let dir = temp_dir(&format!("spaces-told-{name}-{}", k.space));
        let (mut h, id) = helper_args(
            &dir,
            &k._relay,
            &k.ticket,
            name,
            // Records long enough to outlast the clocks' gap.
            None,
            &["--clock-offset", offset],
        );
        befriend(&mut k.o, &k.id_o, &mut h, &id);
        ask(&mut k.o, "spaceAdd", &[&s, &id], "meshSpaces");
        until(&mut h, "meshSpaces", |v| {
            members(&v["spaces"][0]).contains(&id)
        });
        h
    };
    let (mut e, mut f) = (skewed("eve", "-300"), skewed("fay", "-60"));
    ask(
        &mut e,
        "spaceSend",
        &[&s, &g, "old news"],
        "meshSpaceMessages",
    );
    until(&mut k.o, "meshSpaceNotify", |n| n["text"] == "old news");
    let (mut d, id_d) = newcomer(&mut k, "dot");
    befriend(&mut k.o, &k.id_o, &mut d, &id_d);
    ask(&mut d, "idLock", &[], "meshIdentity");
    ask(&mut k.o, "spaceAdd", &[&s, &id_d], "meshSpaces");
    for h in [&mut k.b, &mut f] {
        until(h, "meshSpaces", |v| {
            members(&v["spaces"][0]).contains(&id_d)
        });
    }
    for (h, text) in [(&mut k.b, "while you joined"), (&mut f, "a minute slow")] {
        ask(h, "spaceSend", &[&s, &g, text], "meshSpaceMessages");
        until(&mut k.o, "meshSpaceNotify", |n| n["text"] == text);
    }
    for h in [&mut k.b, &mut k.c, &mut e, &mut f] {
        ask(h, "idLock", &[], "meshIdentity");
    }
    d.send("idUnlock", &["dot", PASSWORD]);
    let mut told = Vec::new();
    until(&mut d, "meshSpaceNotify", |n| {
        told.push(n["text"].as_str().unwrap().to_owned());
        ["while you joined", "a minute slow"]
            .iter()
            .all(|t| told.iter().any(|x| x == t))
    });
    assert!(!told.contains(&"old news".to_owned()), "{told:?}");
    let _ = (
        d.quit(),
        e.quit(),
        f.quit(),
        k.o.quit(),
        k.b.quit(),
        k.c.quit(),
    );
}

/// The club's `name` channel as `h` sees it in a `meshSpaces`, if any.
fn channel_named(v: &Value, name: &str) -> bool {
    (v["spaces"][0]["channels"].as_array().into_iter().flatten()).any(|c| c["name"] == name)
}

fn changes_held(v: &Value) -> u64 {
    v["spaces"][0]["changes"].as_u64().unwrap_or(0)
}

/// `id`'s role in the club, if they're in it (a list with no Space yet: no).
fn role_of(v: &Value, id: &str) -> Option<String> {
    let ms = v["spaces"][0]["members"].as_array()?;
    (ms.iter().find(|m| m["id"] == id)).map(|m| m["role"].as_str().unwrap().to_owned())
}

/// Waits until every helper's `meshSpaces` passes `done`.
fn all_until(hs: &mut [&mut Helper], done: impl Fn(&Value) -> bool) {
    for h in hs.iter_mut() {
        h.send("spaceList", &[]);
        until(h, "meshSpaces", &done);
    }
}

/// Test 6, every device's part: a member's forged channel, forged post in
/// an admins-only channel and an admin's forged kick of another admin
/// are refused by every other member; an admin's delete of C's line is
/// gone everywhere.
#[test]
fn roles_hold_on_every_device() {
    let mut k = club("spaces-roles-all");
    let (s, g) = (k.space.clone(), k.general.clone());
    let made = ask(
        &mut k.o,
        "spaceChannel",
        &[&s, "news", "admins"],
        "meshSpaces",
    );
    let news = channel(space(&made, "club"), "news");
    all_until(&mut [&mut k.b, &mut k.c], |v| channel_named(v, "news"));
    let held_before: Vec<u64> = [&mut k.o, &mut k.b]
        .into_iter()
        .map(|h| {
            h.send("spaceList", &[]);
            changes_held(&until(h, "meshSpaces", |_| true))
        })
        .collect();
    // C, a member, with a client that skips its own checks.
    ask(&mut k.c, "spaceForge", &["unchecked"], "meshForge");
    ask(
        &mut k.c,
        "spaceChannel",
        &[&s, "mine", "everyone"],
        "meshSpaces",
    );
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &news, "forged news"],
        "meshSpaceMessages",
    );
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "after the forgeries"],
        "meshSpaceMessages",
    );
    // Each reaches O and B after the forgeries: held, and refused.
    for (h, before) in [&mut k.o, &mut k.b].into_iter().zip(held_before) {
        until(h, "meshSpaceNotify", |n| n["text"] == "after the forgeries");
        h.send("spaceList", &[]);
        let v = until(h, "meshSpaces", |_| true);
        assert_eq!(changes_held(&v), before + 1, "the forged channel came");
        assert!(!channel_named(&v, "mine"), "{v}");
        assert!(!channel_texts(h, &s, &news).contains(&"forged news".to_owned()));
    }
    // O deletes C's line: gone on B and C too.
    let open = ask(&mut k.o, "spaceOpen", &[&s, &g], "meshSpaceMessages");
    let line = (open["events"].as_array().unwrap().iter())
        .find(|e| e["text"] == "after the forgeries")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ask(
        &mut k.o,
        "spaceDelete",
        &[&s, &g, &line],
        "meshSpaceMessages",
    );
    for h in [&mut k.b, &mut k.c] {
        let started = Instant::now();
        while channel_texts(h, &s, &g).contains(&"after the forgeries".to_owned()) {
            if started.elapsed() > Duration::from_secs(60) {
                fail("the admin's delete never reached them");
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    // B and C admins; B's forged kick of C, an admin, counts nowhere.
    ask(&mut k.o, "spaceRole", &[&s, &k.id_b, "admin"], "meshSpaces");
    ask(&mut k.o, "spaceRole", &[&s, &k.id_c, "admin"], "meshSpaces");
    let (id_b, id_c) = (k.id_b.clone(), k.id_c.clone());
    let admins = |v: &Value| {
        role_of(v, &id_b).as_deref() == Some("admin")
            && role_of(v, &id_c).as_deref() == Some("admin")
    };
    all_until(&mut [&mut k.b, &mut k.c], admins);
    k.o.send("spaceList", &[]);
    let o_before = changes_held(&until(&mut k.o, "meshSpaces", |_| true));
    ask(&mut k.b, "spaceForge", &["unchecked"], "meshForge");
    ask(&mut k.b, "spaceKick", &[&s, &id_c], "meshSpaces");
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "after the kick"],
        "meshSpaceMessages",
    );
    for h in [&mut k.o, &mut k.c] {
        until(h, "meshSpaceNotify", |n| n["text"] == "after the kick");
        h.send("spaceList", &[]);
        let v = until(h, "meshSpaces", |_| true);
        assert_eq!(role_of(&v, &id_c).as_deref(), Some("admin"), "{v}");
    }
    k.o.send("spaceList", &[]);
    let v = until(&mut k.o, "meshSpaces", |_| true);
    assert_eq!(changes_held(&v), o_before + 1, "the forged kick came");
    let _ = (k.o.quit(), k.b.quit(), k.c.quit());
}

/// The club with D, O's friend, added as a member, and B and C made admins.
fn club_with_admins(name: &str) -> (Club, Helper, String) {
    let mut k = club(name);
    let s = k.space.clone();
    let (mut d, id_d) = newcomer(&mut k, &format!("{name}-dee"));
    befriend(&mut k.o, &k.id_o, &mut d, &id_d);
    ask(&mut k.o, "spaceAdd", &[&s, &id_d], "meshSpaces");
    ask(&mut k.o, "spaceRole", &[&s, &k.id_b, "admin"], "meshSpaces");
    ask(&mut k.o, "spaceRole", &[&s, &k.id_c, "admin"], "meshSpaces");
    let (id_b, id_c, dd) = (k.id_b.clone(), k.id_c.clone(), id_d.clone());
    let ready = move |v: &Value| {
        role_of(v, &id_b).as_deref() == Some("admin")
            && role_of(v, &id_c).as_deref() == Some("admin")
            && role_of(v, &dd).is_some()
    };
    all_until(&mut [&mut k.b, &mut k.c, &mut d], ready);
    (k, d, id_d)
}

/// Test 7.1: O removes admin C. C, apart, forks from before the removal with
/// a low event ID and `seq`, kicks B and renames #general. Every device
/// follows O's branch: C is out, B is in, and the name stands.
#[test]
fn an_ex_admin_cant_win() {
    let mut k = club("spaces-exadmin");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(&mut k.o, "spaceRole", &[&s, &k.id_c, "admin"], "meshSpaces");
    let id_c = k.id_c.clone();
    all_until(&mut [&mut k.b, &mut k.c], |v| {
        role_of(v, &id_c).as_deref() == Some("admin")
    });
    ask(&mut k.o, "spaceKick", &[&s, &k.id_c], "meshSpaces");
    all_until(&mut [&mut k.b, &mut k.c], |v| role_of(v, &id_c).is_none());
    k.o.send("spaceList", &[]);
    let before = changes_held(&until(&mut k.o, "meshSpaces", |_| true));
    ask(
        &mut k.c,
        "spaceForge",
        &["fork", &s, "1", "low"],
        "meshForge",
    );
    ask(&mut k.c, "spaceKick", &[&s, &k.id_b], "meshSpaces");
    ask(&mut k.c, "spaceRename", &[&s, "hijacked", &g], "meshSpaces");
    // Both forged changes reach O and B, and lose.
    let (id_b, id_o) = (k.id_b.clone(), k.id_o.clone());
    let settled = |v: &Value| {
        changes_held(v) >= before + 2
            && role_of(v, &id_b).is_some()
            && role_of(v, &id_c).is_none()
            && channel_named(v, "general")
            && role_of(v, &id_o).as_deref() == Some("owner")
    };
    all_until(&mut [&mut k.o, &mut k.b], settled);
    let _ = (k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 7.2: two admins apart. B kicks D while C, on a branch from the same
/// version, renames #general. Every device ends with both changes: the
/// losing branch's author redoes its change on the winner.
#[test]
fn two_admins_apart_both_changes_stand() {
    let (mut k, d, id_d) = club_with_admins("spaces-apart");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(&mut k.b, "spaceKick", &[&s, &id_d], "meshSpaces");
    let dd = id_d.clone();
    all_until(&mut [&mut k.c], |v| role_of(v, &dd).is_none());
    ask(
        &mut k.c,
        "spaceForge",
        &["fork", &s, "1", "same"],
        "meshForge",
    );
    ask(&mut k.c, "spaceRename", &[&s, "chat", &g], "meshSpaces");
    let dd = id_d.clone();
    let both = |v: &Value| role_of(v, &dd).is_none() && channel_named(v, "chat");
    all_until(&mut [&mut k.o, &mut k.b, &mut k.c], both);
    let _ = (d.quit(), k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 7.3: C forks from before B's ban of D, low, so C's branch wins and
/// drops the ban. B's device sees it dropped and bans D again: every device
/// ends with D banned, and an add of D is refused.
#[test]
fn a_late_fork_undoes_and_the_author_redoes() {
    let (mut k, d, id_d) = club_with_admins("spaces-late");
    let (s, g) = (k.space.clone(), k.general.clone());
    ask(&mut k.b, "spaceBan", &[&s, &id_d], "meshSpaces");
    let dd = id_d.clone();
    all_until(&mut [&mut k.c], |v| role_of(v, &dd).is_none());
    k.o.send("spaceList", &[]);
    let before = changes_held(&until(&mut k.o, "meshSpaces", |_| true));
    ask(
        &mut k.c,
        "spaceForge",
        &["fork", &s, "1", "low"],
        "meshForge",
    );
    ask(&mut k.c, "spaceRename", &[&s, "late", &g], "meshSpaces");
    // The fork, and B's redo of the ban after it: two more changes.
    let dd = id_d.clone();
    let banned_again = |v: &Value| {
        changes_held(v) >= before + 2 && role_of(v, &dd).is_none() && channel_named(v, "late")
    };
    all_until(&mut [&mut k.o, &mut k.b, &mut k.c], banned_again);
    let err = ask(&mut k.o, "spaceAdd", &[&s, &id_d], "meshError");
    assert_eq!(err["kind"], "not-allowed", "{err}");
    let _ = (d.quit(), k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 8: O kicks C, and C can be added again. O bans C: an add of C is
/// refused, C can't post, and C's devices no longer get through B's
/// handshake; O, C's friend, still lets C in.
#[test]
fn kick_and_ban() {
    let mut k = club("spaces-ban");
    let (s, g) = (k.space.clone(), k.general.clone());
    let id_c = k.id_c.clone();
    ask(&mut k.o, "spaceKick", &[&s, &id_c], "meshSpaces");
    all_until(&mut [&mut k.b], |v| role_of(v, &id_c).is_none());
    ask(&mut k.o, "spaceAdd", &[&s, &id_c], "meshSpaces");
    all_until(&mut [&mut k.b, &mut k.c], |v| role_of(v, &id_c).is_some());
    ask(&mut k.o, "spaceBan", &[&s, &id_c], "meshSpaces");
    all_until(&mut [&mut k.b, &mut k.c], |v| role_of(v, &id_c).is_none());
    let err = ask(&mut k.o, "spaceAdd", &[&s, &id_c], "meshError");
    assert_eq!(err["kind"], "not-allowed", "{err}");
    // C hears of the ban in its own time (a list from before it can still
    // be waiting): once it has, its sends are refused.
    let started = Instant::now();
    let err = loop {
        k.c.send("spaceSend", &[&s, &g, "still here?"]);
        let (got, answer) = loop {
            let (got, answer) = k.c.event();
            if got == "meshError" || got == "meshSpaceMessages" {
                break (got, answer);
            }
        };
        if got == "meshError" {
            break answer;
        }
        assert!(started.elapsed() < Duration::from_secs(60), "C still posts");
        std::thread::sleep(Duration::from_millis(500));
    };
    assert!(
        ["not-allowed", "not-found"].contains(&err["kind"].as_str().unwrap()),
        "{err}"
    );
    let err = ask(&mut k.b, "netPingId", &[&id_c], "meshError");
    assert_eq!(err["kind"], "not-a-contact", "{err}");
    ask(&mut k.o, "netPingId", &[&id_c], "meshPing");
    let _ = (k.o.quit(), k.b.quit(), k.c.quit());
}

/// Test 11: the seed's files and log, and every helper's stderr, hold no
/// Space ID, channel ID or name, member ID or message text.
#[test]
fn nothing_identifying_is_logged() {
    let name = "spaces-quiet";
    let mut k = club_with(name, &["--mail", "--report-every", "1"]);
    let (s, g) = (k.space.clone(), k.general.clone());
    let made = ask(
        &mut k.o,
        "spaceChannel",
        &[&s, "hidden-room", "everyone"],
        "meshSpaces",
    );
    let hidden = channel(space(&made, "club"), "hidden-room");
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "a secret line"],
        "meshSpaceMessages",
    );
    until(&mut k.c, "meshSpaceNotify", |n| {
        n["text"] == "a secret line"
    });
    // C away: what B says next goes by mail, through the seed.
    ask(&mut k.c, "idLock", &[], "meshIdentity");
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "a mailed secret"],
        "meshSpaceMessages",
    );
    ask(&mut k.b, "idLock", &[], "meshIdentity");
    let stderr = [k.o, k.b, k.c].map(Helper::quit).concat();
    let log = k.seed.stop().join("\n");
    let seed_dir =
        std::env::temp_dir().join(format!("mesh-node-{name}-seed-{}", std::process::id()));
    let files = read_all(&seed_dir);
    for secret in [
        s.as_str(),
        g.as_str(),
        hidden.as_str(),
        "hidden-room",
        "a secret line",
        "a mailed secret",
        &k.id_o,
        &k.id_b,
        &k.id_c,
    ] {
        assert!(!stderr.contains(secret), "a helper logged {secret:?}");
        assert!(!log.contains(secret), "the seed logged {secret:?}");
        assert!(!files.contains(secret), "the seed's files hold {secret:?}");
    }
}

/// Every file under `dir`, as text (lossy), one after another.
fn read_all(dir: &std::path::Path) -> String {
    let mut out = String::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out += &read_all(&path);
        } else if let Ok(bytes) = std::fs::read(&path) {
            out += &String::from_utf8_lossy(&bytes);
        }
    }
    out
}

/// PLAN-spaces Task 11 (your review, 2026-11-15): a join with the real
/// refresh (every 30 minutes). From O's add of D, how long until D and
/// each old member see a line from the other.
#[test]
#[ignore]
fn measure_a_join_with_the_real_refresh() {
    let mut k = club_ttl("spaces-join-real", &[], None);
    let (s, g) = (k.space.clone(), k.general.clone());
    let dir = temp_dir(&format!("spaces-join-real-dee-{s}"));
    let (mut d, id_d) = helper_ttl(&dir, &k._relay, &k.ticket, "dee", None);
    befriend(&mut k.o, &k.id_o, &mut d, &id_d);
    let long = Duration::from_secs(40 * 60);
    let added = Instant::now();
    ask(&mut k.o, "spaceAdd", &[&s, &id_d], "meshSpaces");
    until_for(&mut d, "meshSpaces", long, |v| {
        v["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|sp| sp["id"] == s)
    });
    let holds = added.elapsed();
    ask(
        &mut d,
        "spaceSend",
        &[&s, &g, "from dee"],
        "meshSpaceMessages",
    );
    until_for(&mut k.b, "meshSpaceNotify", long, |n| {
        n["text"] == "from dee"
    });
    let to_b = added.elapsed();
    until_for(&mut k.c, "meshSpaceNotify", long, |n| {
        n["text"] == "from dee"
    });
    let to_c = added.elapsed();
    ask(
        &mut k.b,
        "spaceSend",
        &[&s, &g, "from bea"],
        "meshSpaceMessages",
    );
    until_for(&mut d, "meshSpaceNotify", long, |n| n["text"] == "from bea");
    let from_b = added.elapsed();
    ask(
        &mut k.c,
        "spaceSend",
        &[&s, &g, "from cal"],
        "meshSpaceMessages",
    );
    until_for(&mut d, "meshSpaceNotify", long, |n| n["text"] == "from cal");
    let from_c = added.elapsed();
    eprintln!(
        "join, real refresh, from the add: D holds the Space {holds:?}; D's line at B {to_b:?}, at C {to_c:?}; B's line at D {from_b:?}; C's line at D {from_c:?}"
    );
    let _ = (d.quit(), k.o.quit(), k.b.quit(), k.c.quit());
}

/// A seed's reported address counts: the sum of `what` ("lookups",
/// "address puts") over its report lines.
fn seed_address(lines: &[String], what: &str) -> u64 {
    (lines.iter())
        .filter_map(|l| l.strip_prefix("mesh-node seed: last hour "))
        .filter(|l| !l.starts_with("mail "))
        .flat_map(|l| l.split([',', ';', '(']))
        .filter_map(|part| {
            let (n, label) = part.trim().split_once(' ')?;
            (label == what).then(|| n.parse::<u64>().ok()).flatten()
        })
        .sum()
}

/// A process's CPU time in clock ticks, and the bytes it has written
/// through syscalls (sockets included), from /proc.
fn cpu_and_written(pid: u32) -> (u64, u64) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let f: Vec<&str> = stat
        .rsplit(')')
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let tick = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    let io = std::fs::read_to_string(format!("/proc/{pid}/io")).unwrap_or_default();
    let written = (io.lines())
        .find_map(|l| l.strip_prefix("wchar: "))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    (tick(11) + tick(12), written)
}

/// Test 9 (an `--ignored` measurement, recorded in PLAN-spaces): a Space of
/// 50, one device each. A line to all 49; for one line, the sender's CPU,
/// bytes, connections and the seed's puts; unlock with 5 such Spaces; ten
/// minutes with 45 away (one line a minute) and the seed's lookups; and a
/// returning device's hello: its lookups and its time to reach everyone
/// online.
#[test]
#[ignore]
fn measure_fifty_members() {
    const N: usize = 50;
    let relay = Relay::start();
    let seed_dir = temp_dir("spaces-fifty-seed");
    let mut seed = Seed::start_with(&seed_dir, &relay, &["--report-every", "1"]);
    let ticket = seed.ticket();
    let started = Instant::now();
    let mut hs: Vec<(Helper, String)> = (0..N)
        .map(|i| {
            let dir = temp_dir(&format!("spaces-fifty-{i}"));
            // The real refresh: a 30 s one puts all 50 over the seed's
            // per-network put limit, which a real club never shares.
            helper_ttl(&dir, &relay, &ticket, &format!("m{i}"), None)
        })
        .collect();
    let ids: Vec<String> = hs.iter().map(|(_, id)| id.clone()).collect();
    let (o, rest) = hs.split_first_mut().unwrap();
    for (h, id) in rest.iter_mut() {
        befriend(&mut o.0, &ids[0], h, id);
    }
    // Five Spaces of all 50; the first with #general.
    let mut spaces = Vec::new();
    for n in 0..5 {
        let made = ask(
            &mut o.0,
            "spaceCreate",
            &[&format!("fifty{n}")],
            "meshSpaces",
        );
        spaces.push(
            space(&made, &format!("fifty{n}"))["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let made = ask(
        &mut o.0,
        "spaceChannel",
        &[&spaces[0], "general", "everyone"],
        "meshSpaces",
    );
    let g = channel(space(&made, "fifty0"), "general");
    for s in &spaces {
        for id in &ids[1..] {
            ask(&mut o.0, "spaceAdd", &[s, id], "meshSpaces");
        }
    }
    let full = |v: &Value| {
        let held = v["spaces"].as_array().unwrap();
        held.len() == 5
            && held
                .iter()
                .all(|s| s["members"].as_array().unwrap().len() == N)
    };
    for (h, _) in hs.iter_mut().skip(1) {
        h.send("spaceList", &[]);
        until_for(h, "meshSpaces", Duration::from_secs(600), full);
    }
    eprintln!(
        "fifty: set up in {:?}, seed refused {} address gets",
        started.elapsed(),
        gets_slowed(&seed.drain())
    );
    let s = spaces[0].clone();
    let line_to_all = |hs: &mut Vec<(Helper, String)>, from: usize, text: &str| -> Duration {
        let t = Instant::now();
        ask(
            &mut hs[from].0,
            "spaceSend",
            &[&s, &g, text],
            "meshSpaceMessages",
        );
        for (i, (h, _)) in hs.iter_mut().enumerate() {
            if i != from {
                until_for(h, "meshSpaceNotify", Duration::from_secs(300), |n| {
                    n["text"] == text
                });
            }
        }
        t.elapsed()
    };
    // B (m1) has met none of the other 48: the first line dials them.
    let first = line_to_all(&mut hs, 1, "first");
    std::thread::sleep(Duration::from_secs(2));
    seed.drain();
    let pid = hs[1].0.pid();
    let (cpu0, w0) = cpu_and_written(pid);
    let second = line_to_all(&mut hs, 1, "second");
    let (cpu1, w1) = cpu_and_written(pid);
    std::thread::sleep(Duration::from_secs(2));
    let lines = seed.drain();
    let connections = ask(&mut hs[1].0, "netStatus", &[], "meshNet")["connections"].clone();
    eprintln!(
        "fifty: a line to all 49: first {first:?} (with its dials), second {second:?}; for the second, B's CPU {} ticks, {} bytes written, {connections} connections open, seed {} address puts, {} lookups",
        cpu1 - cpu0,
        w1 - w0,
        seed_address(&lines, "address puts"),
        seed_address(&lines, "lookups"),
    );
    // O's unlock with 5 such Spaces.
    ask(&mut hs[0].0, "idLock", &[], "meshIdentity");
    let t = Instant::now();
    hs[0].0.send("idUnlock", &["m0", PASSWORD]);
    until(&mut hs[0].0, "meshIdentity", |i| i["state"] == "unlocked");
    let unlocked = t.elapsed();
    until(&mut hs[0].0, "meshNet", |n| n["state"] == "online");
    let online = t.elapsed();
    hs[0].0.send("spaceList", &[]);
    until(&mut hs[0].0, "meshSpaces", full);
    let listed = t.elapsed();
    eprintln!(
        "fifty: O's unlock with 5 Spaces of 50: unlocked {unlocked:?}, online {online:?}, Spaces listed {listed:?} ({:?} after online)",
        listed - online
    );
    // 45 away (m5 to m49); B says a line a minute for ten minutes.
    for (h, _) in hs.iter_mut().skip(5) {
        ask(h, "idLock", &[], "meshIdentity");
    }
    std::thread::sleep(Duration::from_secs(5));
    seed.drain();
    for minute in 0..10 {
        let text = format!("minute {minute}");
        ask(
            &mut hs[1].0,
            "spaceSend",
            &[&s, &g, &text],
            "meshSpaceMessages",
        );
        std::thread::sleep(Duration::from_secs(60));
    }
    let lines = seed.drain();
    eprintln!(
        "fifty: ten minutes, 45 away, a line a minute from B: seed {} lookups, {} address puts",
        seed_address(&lines, "lookups"),
        seed_address(&lines, "address puts"),
    );
    // m49 comes back: its hello's lookups, and its time to reach the 5 online.
    let t = Instant::now();
    hs[49].0.send("idUnlock", &["m49", PASSWORD]);
    until(&mut hs[49].0, "meshNet", |n| n["state"] == "online");
    ask(
        &mut hs[49].0,
        "spaceSend",
        &[&s, &g, "back"],
        "meshSpaceMessages",
    );
    for (h, _) in hs.iter_mut().take(5) {
        until_for(h, "meshSpaceNotify", Duration::from_secs(300), |n| {
            n["text"] == "back"
        });
    }
    let reached = t.elapsed();
    std::thread::sleep(Duration::from_secs(60));
    let lines = seed.drain();
    eprintln!(
        "fifty: a returning device: its line reached the 5 online {reached:?} after unlock; seed lookups in that minute {}",
        seed_address(&lines, "lookups"),
    );
    for (h, _) in hs {
        let _ = h.quit();
    }
}

/// A test that passes leaves no folders behind; one that fails keeps its
/// own, to look at (each test runs on its own thread).
#[test]
fn a_passing_test_leaves_no_folders() {
    let made = |name: &'static str, fails: bool| {
        std::thread::spawn(move || {
            let dir = temp_dir(name);
            std::fs::create_dir_all(dir.join("inner")).unwrap();
            std::fs::write(dir.join("inner/file"), b"x").unwrap();
            assert!(!fails, "a failing test");
            dir
        })
        .join()
    };
    let passed = made("folders-pass", false).unwrap();
    assert!(!passed.exists(), "{passed:?} is still there");
    assert!(made("folders-fail", true).is_err());
    let failed =
        std::env::temp_dir().join(format!("mesh-node-folders-fail-{}", std::process::id()));
    assert!(failed.exists(), "a failed test's folder is kept");
    std::fs::remove_dir_all(failed).unwrap();
}
