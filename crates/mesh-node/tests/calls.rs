//! Calls (SPEC-calls), through the helper's commands. Each helper's
//! microphone is a tone (`--tone`) and its speakers a file (`--heard`), so a
//! test can tell who heard whom by the pitch.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, Seed, fail, temp_dir};

const PASSWORD: &str = "correct horse battery staple";
const TTL: &str = "8";

struct Person {
    h: Helper,
    id: String,
    heard: PathBuf,
}

fn person(dir: &Path, relay: &Relay, seed: &str, name: &str, tone: &str) -> Person {
    let heard = dir.join("heard.raw");
    let mut h = Helper::start_with(
        dir,
        relay,
        &[
            "--seed",
            seed,
            "--record-ttl",
            TTL,
            "--tone",
            tone,
            "--heard",
            heard.to_str().unwrap(),
        ],
    );
    assert_eq!(h.event().0, "meshIdentity");
    let id = h.expect("idCreate", &[name, PASSWORD], "meshIdentity")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.net_state("online");
    Person { h, id, heard }
}

fn until(h: &mut Helper, binding: &str, done: impl FnMut(&Value) -> bool) -> Value {
    until_for(h, binding, Duration::from_secs(60), done)
}

fn until_for(
    h: &mut Helper,
    binding: &str,
    limit: Duration,
    mut done: impl FnMut(&Value) -> bool,
) -> Value {
    let started = Instant::now();
    loop {
        let left = limit.saturating_sub(started.elapsed());
        let Some((got, payload)) = h.line_within(left).filter(|_| !left.is_zero()) else {
            fail(&format!("no {binding} came"));
        };
        if got == binding && done(&payload) {
            return payload;
        }
    }
}

fn friends(a: &mut Person, b: &mut Person) {
    a.h.send("friendAdd", &[&b.id, ""]);
    b.h.send("friendAdd", &[&a.id, ""]);
    let (ia, ib) = (a.id.clone(), b.id.clone());
    let has = |s: &Value, id: &str| {
        s["friends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == id)
    };
    until(&mut a.h, "meshSocial", |s| has(s, &ib));
    until(&mut b.h, "meshSocial", |s| has(s, &ia));
}

fn call_state(h: &mut Helper, state: &str) -> Value {
    until(h, "meshCall", |c| c["state"] == state)
}

/// How strongly `hz` is in the last second heard (Goertzel), against the
/// frame's overall level: near 1 for a clean tone at that pitch.
fn strength(heard: &Path, hz: f64) -> f64 {
    let bytes = std::fs::read(heard).unwrap_or_default();
    let samples: Vec<f64> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| f64::from(i16::from_le_bytes([b[0], b[1]])))
        .collect();
    let tail = &samples[samples.len().saturating_sub(48_000)..];
    if tail.is_empty() {
        return 0.0;
    }
    let w = 2.0 * std::f64::consts::PI * hz / 48_000.0;
    let (mut s1, mut s2) = (0.0, 0.0);
    for x in tail {
        let s = x + 2.0 * w.cos() * s1 - s2;
        (s2, s1) = (s1, s);
    }
    let power = s1 * s1 + s2 * s2 - 2.0 * w.cos() * s1 * s2;
    let energy: f64 = tail.iter().map(|x| x * x).sum();
    (power / (energy * tail.len() as f64 / 2.0)).sqrt()
}

/// Waits until `heard` holds `hz` clearly, and not `not`.
fn hears(p: &Person, hz: f64, not: f64) {
    let started = Instant::now();
    loop {
        let (yes, no) = (strength(&p.heard, hz), strength(&p.heard, not));
        if yes > 0.5 && no < 0.2 {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{hz} Hz: {yes:.2}, {not} Hz: {no:.2}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The DM's newest line, as `h` has it.
fn last_line(h: &mut Helper, with: &str) -> String {
    h.send("dmOpen", &[with, ""]);
    let page = until(h, "meshDmMessages", |p| p["id"] == with);
    let events = page["events"].as_array().unwrap();
    events
        .last()
        .map(|e| e["text"].as_str().unwrap_or("").to_owned())
        .unwrap_or_default()
}

struct World {
    _relay: Relay,
    _seed: Seed,
    a: Person,
    b: Person,
}

fn world(name: &str) -> World {
    let relay = Relay::start();
    let dirs = ["seed", "a", "b"].map(|n| temp_dir(&format!("{name}-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut a = person(&dirs[1], &relay, &ticket, "ann", "440");
    let mut b = person(&dirs[2], &relay, &ticket, "ben", "660");
    friends(&mut a, &mut b);
    World {
        _relay: relay,
        _seed: seed,
        a,
        b,
    }
}

/// Test 1: A calls B, B answers; each hears the other's tone and not their
/// own; A hangs up, both see it end, and the DM has the call's line.
#[test]
fn a_dm_call() {
    let mut w = world("calls-dm");
    let (ia, ib) = (w.a.id.clone(), w.b.id.clone());
    w.a.h.send("callStart", &[&ib]);
    call_state(&mut w.a.h, "calling");
    let ringing = call_state(&mut w.b.h, "ringing");
    assert_eq!(ringing["with"], ia.as_str(), "{ringing}");
    w.b.h.send("callAnswer", &[]);
    call_state(&mut w.b.h, "live");
    call_state(&mut w.a.h, "live");
    hears(&w.a, 660.0, 440.0);
    hears(&w.b, 440.0, 660.0);
    w.a.h.send("callHangup", &[]);
    for h in [&mut w.a.h, &mut w.b.h] {
        let ended = call_state(h, "ended");
        assert_eq!(ended["outcome"], "ended", "{ended}");
    }
    let started = Instant::now();
    while !last_line(&mut w.b.h, &ia).starts_with("📞 Call, 0:") {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "no call line on B"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = (w.a.h.quit(), w.b.h.quit());
}

/// Test 2: declined, and unreachable with the missed line by mail. Muting
/// stops the voice.
#[test]
fn declined_unreachable_and_muted() {
    let mut w = world("calls-missed");
    let (ia, ib) = (w.a.id.clone(), w.b.id.clone());
    w.a.h.send("callStart", &[&ib]);
    call_state(&mut w.b.h, "ringing");
    w.b.h.send("callDecline", &[]);
    assert_eq!(call_state(&mut w.a.h, "ended")["outcome"], "declined");
    assert_eq!(last_line(&mut w.a.h, &ib), "📞 Call declined");

    // Muted, B hears nothing new from A.
    w.a.h.send("callMute", &["true"]);
    w.a.h.send("callStart", &[&ib]);
    call_state(&mut w.b.h, "ringing");
    w.b.h.send("callAnswer", &[]);
    call_state(&mut w.a.h, "live");
    hears(&w.a, 660.0, 440.0);
    let before = std::fs::metadata(&w.b.heard).map(|m| m.len()).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(2));
    let after = std::fs::metadata(&w.b.heard).map(|m| m.len()).unwrap_or(0);
    assert_eq!(before, after, "nothing played on B while A is muted");
    w.b.h.send("callHangup", &[]);
    call_state(&mut w.a.h, "ended");
    w.a.h.send("callMute", &["false"]);

    w.b.h.send("idLock", &[]);
    until(&mut w.b.h, "meshIdentity", |i| i["state"] == "locked");
    w.a.h.send("callStart", &[&ib]);
    let ended = until_for(&mut w.a.h, "meshCall", Duration::from_secs(60), |c| {
        c["state"] == "ended"
    });
    assert_eq!(ended["outcome"], "unreachable", "{ended}");
    w.b.h.send("idUnlock", &["ben", PASSWORD]);
    until(&mut w.b.h, "meshIdentity", |i| i["state"] == "unlocked");
    let started = Instant::now();
    while last_line(&mut w.b.h, &ia) != "📞 Missed call" {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "no missed line on B"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    let _ = (w.a.h.quit(), w.b.h.quit());
}
