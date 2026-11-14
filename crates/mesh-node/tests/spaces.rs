//! Spaces (SPEC-spaces), through the helper's commands: people who aren't
//! all friends talk in a Space's channels; they stay strangers otherwise;
//! roles hold; a member who comes back catches up live (the hello).

use serde_json::Value;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, temp_dir};

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
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "no {binding} came"
        );
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

fn befriend(a: &mut Helper, id_a: &str, b: &mut Helper, id_b: &str) {
    a.expect("friendAdd", &[id_b, ""], "meshSocial");
    b.expect("friendAdd", &[id_a, ""], "meshSocial");
    a.social_until(|s| has(s, "friends", id_b));
    b.social_until(|s| has(s, "friends", id_a));
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
    _seed: Seed,
    _relay: Relay,
}

fn club(name: &str) -> Club {
    let dirs = ["seed", "o", "b", "c"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
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
        _seed: seed,
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
