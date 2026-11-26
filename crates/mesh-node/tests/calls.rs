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

/// Waits until `p` clearly hears every one of `yes` and not `no`.
fn hears_all(p: &Person, yes: &[f64], no: f64) {
    let started = Instant::now();
    loop {
        let got: Vec<f64> = yes.iter().map(|hz| strength(&p.heard, *hz)).collect();
        let own = strength(&p.heard, no);
        if got.iter().all(|s| *s > 0.35) && own < 0.2 {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{yes:?}: {got:.2?}, own {no}: {own:.2}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The longest run of silence (in samples) in the last second heard.
fn longest_gap(heard: &Path) -> usize {
    let bytes = std::fs::read(heard).unwrap_or_default();
    let samples: Vec<i16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes(*b))
        .collect();
    let tail = &samples[samples.len().saturating_sub(48_000)..];
    let (mut run, mut longest) = (0, 0);
    for s in tail {
        run = if s.unsigned_abs() < 50 { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    longest
}

fn ask(h: &mut Helper, func: &str, args: &[&str], binding: &str) -> Value {
    h.send(func, args);
    loop {
        let (got, payload) = h.event();
        if got == binding || got == "meshError" {
            assert_eq!(got, binding, "{func} answered {payload}");
            return payload;
        }
    }
}

fn voice(people: &Value) -> Vec<String> {
    let mut v: Vec<String> = (people["people"].as_array().unwrap().iter())
        .map(|p| p.as_str().unwrap().to_owned())
        .collect();
    v.sort();
    v
}

/// Tests 3 and 4 at four members: O makes a voice channel; O, B and C join
/// and each hears the other two (and not themselves); D, outside it, sees
/// the three. B leaves and is dropped; O kicks C, who is out of the channel
/// and can't come back.
#[test]
fn a_voice_channel() {
    let relay = Relay::start();
    let dirs = ["seed", "o", "b", "c", "d"].map(|n| temp_dir(&format!("calls-voice-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut o = person(&dirs[1], &relay, &ticket, "owen", "440");
    let mut b = person(&dirs[2], &relay, &ticket, "ben", "660");
    let mut c = person(&dirs[3], &relay, &ticket, "cal", "880");
    let mut d = person(&dirs[4], &relay, &ticket, "dee", "1100");
    for p in [&mut b, &mut c, &mut d] {
        friends(&mut o, p);
    }
    let made = ask(&mut o.h, "spaceCreate", &["club"], "meshSpaces");
    let s = made["spaces"][0]["id"].as_str().unwrap().to_owned();
    let made = ask(
        &mut o.h,
        "spaceVoiceChannel",
        &[&s, "lounge", ""],
        "meshSpaces",
    );
    let lounge = made["spaces"][0]["channels"][0].clone();
    assert_eq!(lounge["voice"], true, "{lounge}");
    let v = lounge["id"].as_str().unwrap().to_owned();
    for p in [&b, &c, &d] {
        ask(&mut o.h, "spaceAdd", &[&s, &p.id], "meshSpaces");
    }
    for p in [&mut b, &mut c, &mut d] {
        until(&mut p.h, "meshSpaces", |l| {
            l["spaces"][0]["members"]
                .as_array()
                .is_some_and(|m| m.len() == 4)
        });
    }
    // A member can't make one.
    let err = ask(
        &mut b.h,
        "spaceVoiceChannel",
        &[&s, "mine", ""],
        "meshError",
    );
    assert_eq!(err["kind"], "not-allowed", "{err}");

    let mut inside = vec![o.id.clone(), b.id.clone(), c.id.clone()];
    inside.sort();
    for p in [&mut o, &mut b, &mut c] {
        p.h.send("voiceJoin", &[&s, &v]);
        call_state(&mut p.h, "live");
    }
    hears_all(&o, &[660.0, 880.0], 440.0);
    hears_all(&b, &[440.0, 880.0], 660.0);
    hears_all(&c, &[440.0, 660.0], 880.0);
    until(&mut d.h, "meshVoice", |m| voice(m) == inside);

    b.h.send("voiceLeave", &[]);
    assert_eq!(call_state(&mut b.h, "ended")["outcome"], "left");
    let mut two = vec![o.id.clone(), c.id.clone()];
    two.sort();
    for p in [&mut o, &mut c, &mut d] {
        until_for(&mut p.h, "meshVoice", Duration::from_secs(5), |m| {
            voice(m) == two
        });
    }

    ask(&mut o.h, "spaceKick", &[&s, &c.id], "meshSpaces");
    assert_eq!(call_state(&mut c.h, "ended")["outcome"], "removed");
    let alone = vec![o.id.clone()];
    until_for(&mut o.h, "meshVoice", Duration::from_secs(5), |m| {
        voice(m) == alone
    });
    c.h.send("voiceJoin", &[&s, &v]);
    until(&mut c.h, "meshError", |e| e["fn"] == "voiceJoin");
    let _ = (o.h.quit(), b.h.quit(), c.h.quit(), d.h.quit());
}

/// Test 5: with 10% of B's incoming voice dropped, B still hears A's tone
/// with no gap over 60 ms (concealment and FEC fill them).
#[test]
fn a_lossy_path() {
    let relay = Relay::start();
    let dirs = ["seed", "a", "b"].map(|n| temp_dir(&format!("calls-loss-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut a = person(&dirs[1], &relay, &ticket, "ann", "440");
    let heard = dirs[2].join("heard.raw");
    let mut h = Helper::start_with(
        &dirs[2],
        &relay,
        &[
            "--seed",
            &ticket,
            "--record-ttl",
            TTL,
            "--tone",
            "660",
            "--heard",
            heard.to_str().unwrap(),
            "--drop",
            "10",
        ],
    );
    assert_eq!(h.event().0, "meshIdentity");
    let id = h.expect("idCreate", &["ben", PASSWORD], "meshIdentity")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.net_state("online");
    let mut b = Person { h, id, heard };
    friends(&mut a, &mut b);
    a.h.send("callStart", &[&b.id]);
    call_state(&mut b.h, "ringing");
    b.h.send("callAnswer", &[]);
    call_state(&mut a.h, "live");
    hears(&b, 440.0, 660.0);
    std::thread::sleep(Duration::from_secs(2));
    let gap = longest_gap(&b.heard);
    assert!(gap <= 2_880, "a gap of {} ms", gap / 48);
    let _ = (a.h.quit(), b.h.quit());
}

/// Test 1's two devices (C7): B links a laptop; A's call rings both; the
/// laptop answers and the desk stops ringing, answered elsewhere; A and the
/// laptop hear each other.
#[test]
fn both_devices_ring_and_one_answers() {
    let relay = Relay::start();
    let dirs = ["seed", "a", "desk", "laptop"].map(|n| temp_dir(&format!("calls-two-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut a = person(&dirs[1], &relay, &ticket, "ann", "440");
    let mut desk = person(&dirs[2], &relay, &ticket, "ben", "660");
    friends(&mut a, &mut desk);

    let heard = dirs[3].join("heard.raw");
    let mut h = Helper::start_with(
        &dirs[3],
        &relay,
        &[
            "--seed",
            &ticket,
            "--record-ttl",
            TTL,
            "--tone",
            "880",
            "--heard",
            heard.to_str().unwrap(),
        ],
    );
    assert_eq!(h.event().0, "meshIdentity");
    let code = ask(&mut desk.h, "linkStart", &[], "meshLink")["code"]
        .as_str()
        .unwrap()
        .to_owned();
    h.send("linkJoin", &[&code, "Laptop"]);
    until(&mut desk.h, "meshLinkConfirm", |_| true);
    desk.h.send("linkConfirm", &["true"]);
    until(&mut h, "meshLinkReceived", |_| true);
    h.send("linkFinish", &["ben", PASSWORD]);
    until(&mut h, "meshIdentity", |i| i["state"] == "unlocked");
    h.net_state("online");
    let mut laptop = Person {
        h,
        id: desk.id.clone(),
        heard,
    };
    let ia = a.id.clone();
    until(&mut laptop.h, "meshSocial", |s| {
        s["friends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == ia.as_str())
    });

    // The laptop connects to A on its own soon after: call until both ring.
    let started = Instant::now();
    loop {
        a.h.send("callStart", &[&desk.id]);
        call_state(&mut desk.h, "ringing");
        let both = laptop
            .h
            .line_within(Duration::from_secs(5))
            .into_iter()
            .chain(std::iter::from_fn(|| {
                laptop.h.line_within(Duration::from_millis(500))
            }))
            .take(20)
            .any(|(b, c)| b == "meshCall" && c["state"] == "ringing");
        if both {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the laptop never rang"
        );
        a.h.send("callHangup", &[]);
        call_state(&mut desk.h, "ended");
        std::thread::sleep(Duration::from_secs(2));
    }
    laptop.h.send("callAnswer", &[]);
    call_state(&mut laptop.h, "live");
    let ended = until_for(&mut desk.h, "meshCall", Duration::from_secs(5), |c| {
        c["state"] == "ended"
    });
    assert_eq!(ended["outcome"], "elsewhere", "{ended}");
    call_state(&mut a.h, "live");
    hears(&a, 880.0, 660.0);
    hears(&laptop, 440.0, 880.0);
    let _ = (a.h.quit(), desk.h.quit(), laptop.h.quit());
}

/// Test 7: calling an engine from before calls (here `--no-calls`, which
/// refuses the `call` service as one would): "they need to update Mesh",
/// and no call line.
#[test]
fn an_old_engine_needs_an_update() {
    let relay = Relay::start();
    let dirs = ["seed", "a", "b"].map(|n| temp_dir(&format!("calls-old-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut a = person(&dirs[1], &relay, &ticket, "ann", "440");
    let mut h = Helper::start_with(
        &dirs[2],
        &relay,
        &["--seed", &ticket, "--record-ttl", TTL, "--no-calls"],
    );
    assert_eq!(h.event().0, "meshIdentity");
    let id = h.expect("idCreate", &["ben", PASSWORD], "meshIdentity")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.net_state("online");
    let mut b = Person {
        h,
        id,
        heard: dirs[2].join("none"),
    };
    friends(&mut a, &mut b);
    a.h.send("callStart", &[&b.id]);
    let ended = until(&mut a.h, "meshCall", |c| c["state"] == "ended");
    assert_eq!(ended["outcome"], "update", "{ended}");
    assert!(
        !last_line(&mut a.h, &b.id).starts_with("📞"),
        "no call line"
    );
    let _ = (a.h.quit(), b.h.quit());
}

/// Push-to-talk (C10): on with the key up, B hears nothing new from A;
/// held, B hears A; off again, the voice gate sends A's tone as before.
#[test]
fn push_to_talk() {
    let mut w = world("calls-ptt");
    let ib = w.b.id.clone();
    w.a.h.send("callPtt", &["up"]);
    w.a.h.send("callStart", &[&ib]);
    call_state(&mut w.b.h, "ringing");
    w.b.h.send("callAnswer", &[]);
    call_state(&mut w.a.h, "live");
    hears(&w.a, 660.0, 440.0);
    let size = |p: &Person| std::fs::metadata(&p.heard).map(|m| m.len()).unwrap_or(0);
    let before = size(&w.b);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(size(&w.b), before, "nothing from A with the key up");
    w.a.h.send("callPtt", &["down"]);
    hears(&w.b, 440.0, 660.0);
    w.a.h.send("callPtt", &["up"]);
    std::thread::sleep(Duration::from_millis(500));
    let before = size(&w.b);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(size(&w.b), before, "nothing once it's let go");
    w.a.h.send("callPtt", &["off"]);
    let started = Instant::now();
    while size(&w.b) == before {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "voice activity again"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = (w.a.h.quit(), w.b.h.quit());
}

/// CPU seconds a process has used (Linux: /proc/<pid>/stat).
fn cpu_secs(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let after = stat.rsplit(')').next().unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    let ticks = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    (ticks(11) + ticks(12)) / 100.0
}

/// Tests 3 and 9 at full size (`--ignored`): ten members in one voice
/// channel, each hearing the others; the eleventh is told it's full; each
/// helper's CPU over 10 s with all ten sending. Printed for PLAN-calls.
#[test]
#[ignore = "eleven helpers, a minute or two: run by hand"]
fn measure_a_full_voice_channel() {
    let relay = Relay::start();
    let names: Vec<String> = (0..11).map(|i| format!("m{i}")).collect();
    let mut dirs = vec![temp_dir("calls-full-seed")];
    dirs.extend(names.iter().map(|n| temp_dir(&format!("calls-full-{n}"))));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut people: Vec<Person> = (0..11)
        .map(|i| {
            person(
                &dirs[i + 1],
                &relay,
                &ticket,
                &names[i],
                &(300 + 70 * i).to_string(),
            )
        })
        .collect();
    let (owner, rest) = people.split_first_mut().unwrap();
    for p in rest.iter_mut() {
        friends(owner, p);
    }
    let made = ask(&mut owner.h, "spaceCreate", &["big"], "meshSpaces");
    let s = made["spaces"][0]["id"].as_str().unwrap().to_owned();
    let made = ask(
        &mut owner.h,
        "spaceVoiceChannel",
        &[&s, "hall", ""],
        "meshSpaces",
    );
    let v = made["spaces"][0]["channels"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for p in rest.iter() {
        ask(&mut owner.h, "spaceAdd", &[&s, &p.id], "meshSpaces");
    }
    for p in rest.iter_mut() {
        until_for(&mut p.h, "meshSpaces", Duration::from_secs(120), |l| {
            l["spaces"][0]["members"]
                .as_array()
                .is_some_and(|m| m.len() == 11)
        });
    }
    for p in people.iter_mut().take(10) {
        p.h.send("voiceJoin", &[&s, &v]);
        call_state(&mut p.h, "live");
    }
    for p in people.iter_mut().take(10) {
        until_for(&mut p.h, "meshVoice", Duration::from_secs(120), |m| {
            m["channel"] == v.as_str() && m["people"].as_array().is_some_and(|x| x.len() == 10)
        });
    }
    // Each hears every other's tone.
    for (i, p) in people.iter().take(10).enumerate() {
        let others: Vec<f64> = (0..10)
            .filter(|j| *j != i)
            .map(|j| (300 + 70 * j) as f64)
            .collect();
        let started = Instant::now();
        loop {
            let got: Vec<f64> = others.iter().map(|hz| strength(&p.heard, *hz)).collect();
            if got.iter().all(|s| *s > 0.15) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "m{i}: {got:.2?}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    let before: Vec<f64> = people
        .iter()
        .take(10)
        .map(|p| cpu_secs(p.h.pid()))
        .collect();
    std::thread::sleep(Duration::from_secs(10));
    let cpu: Vec<f64> = (people.iter().take(10).zip(&before))
        .map(|(p, b)| (cpu_secs(p.h.pid()) - b) / 10.0 * 100.0)
        .collect();
    let eleventh = &mut people[10];
    eleventh.h.send("voiceJoin", &[&s, &v]);
    let err = until(&mut eleventh.h, "meshError", |e| e["fn"] == "voiceJoin");
    assert_eq!(err["kind"], "full", "{err}");
    eprintln!("full voice channel: CPU per helper over 10 s (%, debug build): {cpu:.1?}");
    for p in people {
        let _ = p.h.quit();
    }
}

/// PLAN-audio Task 4: the mic test, with no call. Levels come about 15 a
/// second and say a loud tone goes out; with `hear` it plays back (late);
/// `off` stops both. (Played back, a steady tone looks like an echo of
/// itself to the canceller, so the levels are counted without `hear`.)
#[test]
fn the_mic_test_reports_levels_and_plays_back() {
    let relay = Relay::start();
    let dirs = ["seed", "a"].map(|n| temp_dir(&format!("calls-mictest-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut a = person(&dirs[1], &relay, &ticket, "ann", "440");
    a.h.send("audioTest", &["on"]);
    let started = Instant::now();
    let (mut levels, mut open) = (0, 0);
    while started.elapsed() < Duration::from_secs(3) {
        if let Some((binding, v)) = a.h.line_within(Duration::from_millis(200))
            && binding == "meshAudioLevel"
        {
            levels += 1;
            open += usize::from(v["open"] == true);
            assert!(v["level"].as_f64().unwrap() < 0.0, "{v}");
        }
    }
    assert!((35..=60).contains(&levels), "{levels} levels in 3 s");
    assert!(open * 10 >= levels * 9, "{open} of {levels} said open");
    assert_eq!(
        std::fs::metadata(&a.heard).map_or(0, |m| m.len()),
        0,
        "played without hear"
    );
    // With hear: played back, half a second late.
    a.h.send("audioTest", &["on", "hear"]);
    std::thread::sleep(Duration::from_secs(2));
    let played = std::fs::metadata(&a.heard).map_or(0, |m| m.len());
    assert!(played > 96_000, "played back {played} bytes");
    // off: no more levels.
    a.h.send("audioTest", &["off"]);
    std::thread::sleep(Duration::from_millis(300));
    while a.h.line_within(Duration::from_millis(50)).is_some() {}
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(1) {
        if let Some((binding, _)) = a.h.line_within(Duration::from_millis(200)) {
            assert_ne!(binding, "meshAudioLevel", "levels after off");
        }
    }
    let _ = a.h.quit();
    seed.stop();
}

/// The loudness of the last half second `p` heard (RMS).
fn recent_rms(p: &Person) -> f64 {
    let bytes = std::fs::read(&p.heard).unwrap_or_default();
    let samples: Vec<f64> = (bytes.as_chunks::<2>().0.iter())
        .map(|b| f64::from(i16::from_le_bytes(*b)))
        .collect();
    let tail = &samples[samples.len().saturating_sub(24_000)..];
    (tail.iter().map(|s| s * s).sum::<f64>() / tail.len().max(1) as f64).sqrt()
}

/// PLAN-audio Task 5: B turns A down to 0% and hears silence from A; back
/// to 100%, A again.
#[test]
fn a_persons_volume_is_ours_to_set() {
    let relay = Relay::start();
    let dirs = ["seed", "a", "b"].map(|n| temp_dir(&format!("calls-volume-{n}")));
    let mut seed = Seed::start(&dirs[0], &relay);
    let ticket = seed.ticket();
    let mut a = person(&dirs[1], &relay, &ticket, "ann", "440");
    let mut b = person(&dirs[2], &relay, &ticket, "ben", "660");
    friends(&mut a, &mut b);
    a.h.send("callStart", &[&b.id]);
    call_state(&mut b.h, "ringing");
    b.h.send("callAnswer", &[]);
    call_state(&mut a.h, "live");
    hears(&b, 440.0, 660.0);
    let loud = recent_rms(&b);
    b.h.send("callVolume", &[&a.id, "0"]);
    std::thread::sleep(Duration::from_millis(1500));
    let quiet = recent_rms(&b);
    assert!(quiet < loud / 20.0, "at 0%: {quiet:.0}, before {loud:.0}");
    b.h.send("callVolume", &[&a.id, "100"]);
    hears(&b, 440.0, 660.0);
    let _ = (a.h.quit(), b.h.quit());
    seed.stop();
}
