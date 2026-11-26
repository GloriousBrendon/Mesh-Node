//! SPEC-connection-privacy, through the helper's commands: friends get a
//! direct path, everyone else (a Space member who isn't a friend) only the
//! relay, whatever they do.

use serde_json::Value;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, fail, temp_dir};

const PASSWORD: &str = "correct horse battery staple";

fn helper(dir: &std::path::Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
    let args = ["--seed", seed, "--peer-idle", "3", "--record-ttl", "8"];
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

/// The next `binding` event `done` accepts, within 60 s; others are skipped.
fn until(h: &mut Helper, binding: &str, mut done: impl FnMut(&Value) -> bool) -> Value {
    let started = Instant::now();
    loop {
        let left = Duration::from_secs(60).saturating_sub(started.elapsed());
        let Some((got, payload)) = h.line_within(left).filter(|_| !left.is_zero()) else {
            fail(&format!("no {binding} came"));
        };
        if got == binding && done(&payload) {
            return payload;
        }
    }
}

/// Sends a command and waits for its answer (or its error).
fn ask(h: &mut Helper, func: &str, args: &[&str], binding: &str) -> Value {
    h.send(func, args);
    until(h, binding, |_| true)
}

fn has(social: &Value, list: &str, id: &str) -> bool {
    (social[list].as_array().unwrap().iter()).any(|e| e["id"] == id)
}

fn befriend(a: &mut Helper, id_a: &str, b: &mut Helper, id_b: &str) {
    ask(a, "friendAdd", &[id_b, ""], "meshSocial");
    ask(b, "friendAdd", &[id_a, ""], "meshSocial");
    until(a, "meshSocial", |s| has(s, "friends", id_b));
    until(b, "meshSocial", |s| has(s, "friends", id_a));
}

/// `from` pings `to` by ID until the path is `want`, for up to 30 s; the
/// last path seen.
fn ping_until(from: &mut Helper, to: &str, want: &str) -> String {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < Duration::from_secs(30) {
        from.send("netPingId", &[to]);
        let got = until(from, "meshPing", |_| true);
        last = got["path"].as_str().unwrap().to_owned();
        if last == want {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    last
}

#[test]
fn friends_go_direct_and_space_strangers_stay_relayed() {
    let dirs = ["seed", "o", "b", "c"].map(|n| temp_dir(&format!("privacy-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut o, id_o) = helper(&dirs[1], &relay, &ticket, "owen");
    let (mut b, id_b) = helper(&dirs[2], &relay, &ticket, "bea");
    let (mut c, id_c) = helper(&dirs[3], &relay, &ticket, "cal");
    befriend(&mut o, &id_o, &mut b, &id_b);
    befriend(&mut o, &id_o, &mut c, &id_c);

    // Friends: the first connection is relayed (that's where the direct key
    // is told), then they go direct.
    assert_eq!(
        ping_until(&mut o, &id_b, "direct"),
        "direct",
        "O and B never went direct"
    );
    assert_eq!(
        ping_until(&mut b, &id_o, "direct"),
        "direct",
        "B and O never went direct"
    );

    // B and C share O's Space but aren't friends.
    let made = ask(&mut o, "spaceCreate", &["club"], "meshSpaces");
    let club = |v: &Value| {
        v["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "club")
            .cloned()
    };
    let s = club(&made).unwrap()["id"].as_str().unwrap().to_owned();
    let made = ask(
        &mut o,
        "spaceChannel",
        &[&s, "general", "everyone"],
        "meshSpaces",
    );
    let general = (club(&made).unwrap()["channels"].as_array().unwrap().iter())
        .find(|c| c["name"] == "general")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ask(&mut o, "spaceAdd", &[&s, &id_b], "meshSpaces");
    ask(&mut o, "spaceAdd", &[&s, &id_c], "meshSpaces");
    for h in [&mut b, &mut c] {
        until(h, "meshSpaces", |v| {
            club(v).is_some_and(|s| s["members"].as_array().is_some_and(|m| m.len() == 3))
        });
    }
    // C hears B in the channel: they're connected, and only by the relay.
    b.send("spaceSend", &[&s, &general, "hi from bea"]);
    until(&mut c, "meshSpaceNotify", |n| n["text"] == "hi from bea");
    assert_eq!(
        ping_until(&mut b, &id_c, "direct"),
        "relay",
        "B reached C direct"
    );
    assert_eq!(
        ping_until(&mut c, &id_b, "direct"),
        "relay",
        "C reached B direct"
    );

    for h in [o, b, c] {
        h.quit();
    }
    seed.stop();
}
