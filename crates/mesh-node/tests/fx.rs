//! A person's own plugins (SPEC-voice-quality), through the helper and a
//! real `mesh-fx` with the test plugins (mesh-fx's examples). One test, run
//! in order: the plugins take their settings from the environment, which
//! each helper (and its mesh-fx) gets when it starts.

#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

mod common;
use common::{Helper, Relay, temp_dir};

const PASSWORD: &str = "correct horse battery staple";

/// Builds mesh-fx and the test plugins beside mesh-node, and lays the
/// plugins out as their formats want: a `.clap` file and a `.vst3` bundle.
/// mesh-fx is copied under a name of this test's own, so killing it hits
/// nothing else.
fn built(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let bin = Path::new(env!("CARGO_BIN_EXE_mesh-node")).parent().unwrap().to_owned();
    let ok = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "mesh-fx", "--bin", "mesh-fx"])
        .args(["--example", "test_gain_clap", "--example", "test_gain_vst3"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap();
    assert!(ok.success(), "mesh-fx and the test plugins didn't build");
    let fx = dir.join("mesh-fx-under-test");
    std::fs::copy(bin.join("mesh-fx"), &fx).unwrap();
    let clap = dir.join("test-gain.clap");
    std::fs::copy(bin.join("examples/libtest_gain_clap.so"), &clap).unwrap();
    let vst3 = dir.join("test-gain.vst3");
    let lib = vst3.join("Contents/x86_64-linux");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::copy(bin.join("examples/libtest_gain_vst3.so"), lib.join("test-gain.so")).unwrap();
    (fx, clap, vst3)
}

fn helper(dir: &Path, relay: &Relay, env: &[(&str, &str)]) -> Helper {
    for (k, v) in env {
        // SAFETY: one test in this file, no other threads reading the environment.
        unsafe { std::env::set_var(k, v) };
    }
    let mut h = Helper::start_with(dir, relay, &["--tone", "440"]);
    for (k, _) in env {
        unsafe { std::env::remove_var(k) };
    }
    assert_eq!(h.event().0, "meshIdentity");
    h.expect("idCreate", &["fx", PASSWORD], "meshIdentity");
    h
}

/// The next `meshFx` that `done` accepts.
fn fx_until(h: &mut Helper, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if let Some((b, v)) = h.line_within(Duration::from_millis(200))
            && b == "meshFx"
            && done(&v)
        {
            return v;
        }
    }
    panic!("no meshFx {what}");
}

/// The mic's level after processing, averaged over a second (dBFS).
fn level(h: &mut Helper) -> f64 {
    // What was measured before this asked doesn't count.
    let settle = Instant::now() + Duration::from_millis(400);
    while Instant::now() < settle {
        let _ = h.line_within(Duration::from_millis(50));
    }
    let (started, mut got) = (Instant::now(), Vec::new());
    while started.elapsed() < Duration::from_secs(1) {
        if let Some((b, v)) = h.line_within(Duration::from_millis(100))
            && b == "meshAudioLevel"
        {
            got.push(v["level"].as_f64().unwrap());
        }
    }
    assert!(got.len() > 5, "levels: {got:?}");
    got.iter().sum::<f64>() / got.len() as f64
}

fn near(got: f64, want: f64, what: &str) {
    assert!((got - want).abs() <= 1.0, "{what}: {got:.2} dBFS, wanted {want:.2} ±1");
}

fn chain(h: &mut Helper, plugins: Value) {
    h.send("fxChain", &[&plugins.to_string()]);
}

#[test]
fn plugins_change_the_voice_keep_their_state_and_never_stall_it() {
    let relay = Relay::start();
    let dir = temp_dir("fx-plugins");
    std::fs::create_dir_all(&dir).unwrap();
    let (fx, clap, vst3) = built(&dir);
    let fx_s = fx.to_str().unwrap().to_owned();
    let mut a = helper(&dir.join("a"), &relay, &[("MESH_FX", &fx_s)]);
    a.send("callAudio", &[r#"{"gain": false, "noise": false, "echo": false}"#]);
    a.send("audioTest", &["on"]);
    let dry = level(&mut a);

    // The CLAP gain at 0 dB, then +6 dB by its parameter.
    let clap_one = json!([{ "path": clap, "id": "aflos.test.gain", "on": true }]);
    chain(&mut a, clap_one.clone());
    fx_until(&mut a, "on", |v| v["state"] == "on");
    near(level(&mut a), dry, "through the plugin at 0 dB");
    a.send("fxParams", &["0"]);
    let params = fx_until(&mut a, "params", |v| v["answer"]["cmd"] == "params");
    assert_eq!(params["answer"]["params"][0]["name"], "Gain", "{params}");
    a.send("fxParam", &["0", "1", "6"]);
    fx_until(&mut a, "param set", |v| v["answer"]["cmd"] == "param");
    near(level(&mut a), dry + 6.0, "the gain set to +6 dB");

    // Saved and restarted: still +6 dB, from its state file.
    a.send("fxSave", &[]);
    let saved = fx_until(&mut a, "saved", |v| v["answer"]["cmd"] == "save");
    assert_eq!(saved["answer"]["saved"], 1, "{saved}");
    a.send("fxRestart", &[]);
    fx_until(&mut a, "on again", |v| v["state"] == "on");
    near(level(&mut a), dry + 6.0, "after a restart");

    // A damaged state file is ignored: the plugin starts fresh at 0 dB.
    chain(&mut a, json!([]));
    fx_until(&mut a, "off", |v| v["state"] == "off");
    std::thread::sleep(Duration::from_millis(300));
    let states: Vec<PathBuf> = std::fs::read_dir(dir.join("a/fx"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "state"))
        .collect();
    assert_eq!(states.len(), 1, "{states:?}");
    // Too short for the plugin to read: it refuses it, and mesh-fx goes on.
    std::fs::write(&states[0], b"x").unwrap();
    chain(&mut a, clap_one);
    fx_until(&mut a, "on with a damaged state", |v| v["state"] == "on");
    near(level(&mut a), dry, "a damaged state ignored");

    // The VST3 gain: normalized 0.5 is twice as loud, +6 dB.
    let out = Command::new(&fx).args(["list", vst3.to_str().unwrap()]).output().unwrap();
    let id = String::from_utf8_lossy(&out.stdout).split('\t').next().unwrap().to_owned();
    chain(&mut a, json!([{ "path": vst3, "id": id, "on": true }]));
    fx_until(&mut a, "VST3 on", |v| v["state"] == "on");
    near(level(&mut a), dry, "through the VST3 plugin at 0 dB");
    a.send("fxParam", &["0", "0", "0.5"]);
    fx_until(&mut a, "VST3 param", |v| v["answer"]["cmd"] == "param");
    near(level(&mut a), dry + 6.0, "the VST3 gain at +6 dB");

    // mesh-fx killed mid-stream: bypassed at once, and the voice goes on dry.
    let killed = Instant::now();
    Command::new("pkill").args(["-f", "mesh-fx-under-test serve"]).status().unwrap();
    fx_until(&mut a, "bypassed", |v| v["state"] == "bypassed");
    let took = killed.elapsed();
    assert!(took < Duration::from_millis(500), "bypassed after {took:?}");
    near(level(&mut a), dry, "dry after the crash");
    let _ = a.quit();

    // A plugin that takes 50 ms a block: bypassed as too slow.
    let mut b = helper(&dir.join("b"), &relay, &[("MESH_FX", &fx_s), ("MESH_FX_TEST_SLEEP_MS", "50")]);
    b.send("callAudio", &[r#"{"gain": false, "noise": false, "echo": false}"#]);
    b.send("audioTest", &["on"]);
    chain(&mut b, json!([{ "path": clap, "id": "aflos.test.gain", "on": true }]));
    let bypassed = fx_until(&mut b, "too slow", |v| v["state"] == "bypassed");
    assert!(bypassed["error"].as_str().unwrap().contains("too slow"), "{bypassed}");
    let _ = b.quit();
}
