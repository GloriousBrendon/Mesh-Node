//! SPEC-connection-privacy, through the helper's commands: friends get a
//! direct path, everyone else (a Space member who isn't a friend) only the
//! relay, whatever they do.

use serde_json::Value;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, fail, temp_dir};

const PASSWORD: &str = "correct horse battery staple";

fn helper(dir: &std::path::Path, relay: &Relay, seed: &str, name: &str) -> (Helper, String) {
    helper_with(dir, relay, seed, name, &[])
}

/// `helper`, started with `extra` arguments too.
fn helper_with(
    dir: &std::path::Path,
    relay: &Relay,
    seed: &str,
    name: &str,
    extra: &[&str],
) -> (Helper, String) {
    let mut args = vec!["--seed", seed, "--peer-idle", "3", "--record-ttl", "8"];
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

    // P7: the owner turns it on, and every member holds it.
    ask(&mut o, "spaceDirect", &[&s, "true"], "meshSpaces");
    for h in [&mut b, &mut c] {
        until(h, "meshSpaces", |v| {
            club(v).is_some_and(|s| s["directAllowed"] == true)
        });
    }
    // Still only friends go direct: B and C stay relayed.
    assert_eq!(
        ping_until(&mut b, &id_c, "direct"),
        "relay",
        "B reached C direct with P7 on"
    );
    ask(&mut o, "spaceDirect", &[&s, "false"], "meshSpaces");
    until(&mut b, "meshSpaces", |v| {
        club(v).is_some_and(|s| s["directAllowed"] == false)
    });

    for h in [o, b, c] {
        h.quit();
    }
    seed.stop();
}

/// One `netPingId`: the path, or `None` if it was refused or unreachable.
fn ping_once(from: &mut Helper, to: &str) -> Option<String> {
    from.send("netPingId", &[to]);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(40) {
        let (got, payload) = from.event();
        match got.as_str() {
            "meshPing" => return payload["path"].as_str().map(str::to_owned),
            "meshError" if payload["fn"] == "netPingId" => return None,
            _ => {}
        }
    }
    fail("netPingId: no answer");
}

/// The direct key's issue time `h` (in `dir`) keeps, waiting up to 15 s
/// for it to differ from `not`.
fn issued(dir: &std::path::Path, not: &str) -> String {
    let started = Instant::now();
    loop {
        let now = std::fs::read_to_string(dir.join("direct-issued")).unwrap_or_default();
        if now != not || started.elapsed() > Duration::from_secs(15) {
            return now;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Three people: O is friends with B and C, and both are direct with O.
fn three(name: &str) -> (Relay, Seed, [std::path::PathBuf; 4], [(Helper, String); 3]) {
    let dirs = ["seed", "o", "b", "c"].map(|n| temp_dir(&format!("{name}-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut o, id_o) = helper(&dirs[1], &relay, &ticket, "owen");
    let (mut b, id_b) = helper(&dirs[2], &relay, &ticket, "bea");
    let (mut c, id_c) = helper(&dirs[3], &relay, &ticket, "cal");
    befriend(&mut o, &id_o, &mut b, &id_b);
    befriend(&mut o, &id_o, &mut c, &id_c);
    assert_eq!(ping_until(&mut b, &id_o, "direct"), "direct");
    assert_eq!(ping_until(&mut c, &id_o, "direct"), "direct");
    (relay, seed, dirs, [(o, id_o), (b, id_b), (c, id_c)])
}

#[test]
fn unfriending_and_blocking_rotate_the_direct_key() {
    let (_relay, seed, dirs, [(mut o, id_o), (mut b, id_b), (mut c, id_c)]) = three("rotate");
    let first = issued(&dirs[1], "");
    assert!(!first.is_empty(), "no direct-issued beside O's identity");

    // O removes C: a new key, B (still a friend) moves to it, C gets nothing.
    std::thread::sleep(Duration::from_secs(1));
    ask(&mut o, "friendRemove", &[&id_c], "meshSocial");
    let second = issued(&dirs[1], &first);
    assert_ne!(
        second, first,
        "removing a friend didn't rotate the direct key"
    );
    assert_eq!(
        ping_until(&mut b, &id_o, "direct"),
        "direct",
        "B didn't move to the new key"
    );
    assert_ne!(
        ping_once(&mut c, &id_o).as_deref(),
        Some("direct"),
        "C still goes direct"
    );

    // O blocks B: another key, and B never goes direct again.
    std::thread::sleep(Duration::from_secs(1));
    ask(&mut o, "block", &[&id_b], "meshSocial");
    let third = issued(&dirs[1], &second);
    assert_ne!(third, second, "blocking didn't rotate the direct key");
    assert_ne!(
        ping_once(&mut b, &id_o).as_deref(),
        Some("direct"),
        "B still goes direct"
    );

    for h in [o, b, c] {
        h.quit();
    }
    seed.stop();
}

#[test]
fn a_week_old_direct_key_is_replaced_and_friends_follow() {
    let (_relay, seed, dirs, [(mut o, id_o), (mut b, _), (c, _)]) = three("week");
    o.send("idLock", &[]);
    until(&mut o, "meshIdentity", |i| i["state"] == "locked");
    // As if O's key were issued 8 days ago.
    let old = (mesh_identity::unix_now() - 8 * 86_400).to_string();
    std::fs::write(dirs[1].join("direct-issued"), &old).unwrap();
    o.send("idUnlock", &["owen", PASSWORD]);
    until(&mut o, "meshIdentity", |i| i["state"] == "unlocked");
    let new = issued(&dirs[1], &old);
    assert_ne!(new, old, "the week-old key was kept");
    assert_eq!(
        ping_until(&mut b, &id_o, "direct"),
        "direct",
        "B didn't reach O's new key"
    );

    for h in [o, b, c] {
        h.quit();
    }
    seed.stop();
}

/// `h`'s next `meshNet` whose path for `id` is `want`, within 60 s.
fn net_path(h: &mut Helper, id: &str, want: &str) -> Value {
    until(h, "meshNet", |n| n["paths"][id] == want)
}

#[test]
fn hide_my_ip_relays_friends_too() {
    let dirs = ["seed", "o", "b"].map(|n| temp_dir(&format!("hide-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut o, id_o) = helper_with(&dirs[1], &relay, &ticket, "owen", &["--hide-ip"]);
    let (mut b, id_b) = helper(&dirs[2], &relay, &ticket, "bea");
    befriend(&mut o, &id_o, &mut b, &id_b);

    // On from the start: friends are relayed, and O's status says so.
    assert_eq!(
        ping_until(&mut b, &id_o, "direct"),
        "relay",
        "B went direct to a hidden O"
    );
    o.send("netStatus", &[]);
    let net = net_path(&mut o, &id_b, "relay");
    assert_eq!(net["hideIp"], true, "{net}");
    assert_eq!(net["directCount"], 0, "{net}");

    // Off: a direct key, which B is told, and they go direct.
    ask(&mut o, "netPrivacy", &["false"], "meshDone");
    assert_eq!(
        ping_until(&mut b, &id_o, "direct"),
        "direct",
        "B never went direct"
    );
    let net = net_path(&mut o, &id_b, "direct");
    assert_eq!(net["hideIp"], false, "{net}");

    // On again: the direct node closes, and B is relayed again.
    ask(&mut o, "netPrivacy", &["true"], "meshDone");
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        ping_until(&mut b, &id_o, "direct"),
        "relay",
        "B still went direct"
    );
    net_path(&mut o, &id_b, "relay");

    for h in [o, b] {
        h.quit();
    }
    seed.stop();
}

#[test]
fn a_report_reaches_the_owner_only_and_waits_for_them() {
    let dirs = ["seed", "o", "b", "c"].map(|n| temp_dir(&format!("report-{n}")));
    let relay = Relay::start();
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let (mut o, id_o) = helper(&dirs[1], &relay, &ticket, "owen");
    let (mut b, id_b) = helper(&dirs[2], &relay, &ticket, "bea");
    let (mut c, id_c) = helper(&dirs[3], &relay, &ticket, "cal");
    befriend(&mut o, &id_o, &mut b, &id_b);
    befriend(&mut o, &id_o, &mut c, &id_c);
    let made = ask(&mut o, "spaceCreate", &["club"], "meshSpaces");
    let club = |v: &Value| {
        (v["spaces"].as_array().unwrap().iter())
            .find(|s| s["name"] == "club")
            .cloned()
    };
    let s = club(&made).unwrap()["id"].as_str().unwrap().to_owned();
    ask(&mut o, "spaceAdd", &[&s, &id_b], "meshSpaces");
    ask(&mut o, "spaceAdd", &[&s, &id_c], "meshSpaces");
    for h in [&mut b, &mut c] {
        until(h, "meshSpaces", |v| {
            club(v).is_some_and(|s| s["members"].as_array().is_some_and(|m| m.len() == 3))
        });
    }

    // The owner is away; B reports C, with one of C's messages.
    o.send("idLock", &[]);
    until(&mut o, "meshIdentity", |i| i["state"] == "locked");
    ask(
        &mut b,
        "spaceReport",
        &[&s, &id_c, "spam", "buy now"],
        "meshDone",
    );
    let err = ask(&mut b, "spaceReport", &[&s, &id_b, "me"], "meshError");
    assert_eq!(err["kind"], "not-allowed", "{err}");

    // Back: the report comes, from B, about C.
    o.send("idUnlock", &["owen", PASSWORD]);
    let got = until(&mut o, "meshSpaceReports", |r| {
        r["reports"].as_array().is_some_and(|a| !a.is_empty())
    });
    let r = &got["reports"][0];
    assert_eq!(
        (r["from"].as_str(), r["about"].as_str()),
        (Some(&*id_b), Some(&*id_c)),
        "{got}"
    );
    assert_eq!(
        (r["reason"].as_str(), r["quoted"][0].as_str()),
        (Some("spam"), Some("buy now"))
    );

    // Nobody else holds one; the owner dismisses it.
    let none = ask(&mut c, "spaceReports", &[&s], "meshSpaceReports");
    assert_eq!(none["reports"], serde_json::json!([]), "C holds a report");
    let at = r["at"].to_string();
    let left = ask(
        &mut o,
        "spaceReportDismiss",
        &[&s, &id_b, &at],
        "meshSpaceReports",
    );
    assert_eq!(left["reports"], serde_json::json!([]));

    for h in [o, b, c] {
        h.quit();
    }
    seed.stop();
}
