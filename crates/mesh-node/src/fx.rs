//! mesh-node's end of `mesh-fx` (SPEC-voice-quality F2, F4): a person's own
//! plugins run in that process; frames go there and back over its pipe.
//! A writer and a reader thread own the pipe, so the audio thread never
//! blocks on it: a frame that isn't back in time, or can't even be queued,
//! is `Late`, and the caller sends it dry.

// Without calls (the seed's build) there is no voice chain to run plugins in.
#![cfg_attr(not(feature = "audio"), allow(dead_code))]

use std::io;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

#[path = "../../mesh-fx/src/proto.rs"]
mod proto;

use proto::Msg;

/// Messages queued for the writer at most; a full queue means mesh-fx is
/// stuck, and waiting for room would stall the call.
const QUEUE: usize = 4;

#[derive(Debug, PartialEq)]
pub enum FxError {
    /// Not back within the deadline: send this one dry.
    Late,
    /// mesh-fx has exited or its pipe broke.
    Dead,
}

/// `mesh-fx`: `MESH_FX` if set (tests, development), else beside us.
pub fn mesh_fx_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os("MESH_FX") {
        return p.into();
    }
    let me = std::env::current_exe().unwrap_or_default();
    me.with_file_name(format!("mesh-fx{}", std::env::consts::EXE_SUFFIX))
}

pub struct Fx {
    child: Child,
    to: SyncSender<Msg>,
    from: Receiver<Msg>,
    seq: u32,
    id: u64,
}

impl Fx {
    /// Starts `cmd` (normally `mesh-fx serve`) with its stdin and stdout as
    /// the pipe; stderr is ours.
    pub fn start(mut cmd: Command) -> io::Result<Fx> {
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
        let (mut stdin, mut stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let (to, queued) = mpsc::sync_channel::<Msg>(QUEUE);
        let (got, from) = mpsc::channel();
        std::thread::Builder::new()
            .name("fx-write".into())
            .spawn(move || {
                for msg in queued {
                    if proto::write(&mut stdin, &msg).is_err() {
                        break;
                    }
                }
            })?;
        std::thread::Builder::new()
            .name("fx-read".into())
            .spawn(move || {
                loop {
                    match proto::read(&mut stdout) {
                        Ok(Some(msg)) => {
                            if got.send(msg).is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("mesh-node: mesh-fx sent something unreadable: {e}");
                            break;
                        }
                    }
                }
                // Dropping `got` here is what tells a waiting caller it's dead.
            })?;
        Ok(Fx {
            child,
            to,
            from,
            seq: 0,
            id: 0,
        })
    }

    /// Runs `frame` through mesh-fx, in place, if it's back within `within`.
    pub fn process(&mut self, frame: &mut [i16], within: Duration) -> Result<(), FxError> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.send(Msg::Audio(seq, frame.to_vec()))?;
        self.wait(within, |msg| match msg {
            Msg::Audio(s, pcm) if s == seq && pcm.len() == frame.len() => {
                frame.copy_from_slice(&pcm);
                Some(())
            }
            // An earlier frame that came back late, or a control answer
            // nobody waits for any more.
            _ => None,
        })
    }

    /// Sends `command` (a JSON object) and waits for its answer.
    pub fn control(
        &mut self,
        mut command: serde_json::Value,
        within: Duration,
    ) -> Result<serde_json::Value, FxError> {
        self.id += 1;
        let id = self.id;
        command["id"] = id.into();
        self.send(Msg::Control(command.to_string().into_bytes()))?;
        self.wait(within, |msg| match msg {
            Msg::Control(json) => serde_json::from_slice::<serde_json::Value>(&json)
                .ok()
                .filter(|v| v["id"] == id),
            Msg::Audio(..) => None,
        })
    }

    fn send(&self, msg: Msg) -> Result<(), FxError> {
        self.to.try_send(msg).map_err(|e| match e {
            TrySendError::Full(_) => FxError::Late,
            TrySendError::Disconnected(_) => FxError::Dead,
        })
    }

    /// Waits until `take` accepts a message, skipping the ones it doesn't.
    fn wait<T>(
        &self,
        within: Duration,
        mut take: impl FnMut(Msg) -> Option<T>,
    ) -> Result<T, FxError> {
        let until = Instant::now() + within;
        loop {
            match self
                .from
                .recv_timeout(until.saturating_duration_since(Instant::now()))
            {
                Ok(msg) => {
                    if let Some(t) = take(msg) {
                        return Ok(t);
                    }
                }
                Err(RecvTimeoutError::Timeout) => return Err(FxError::Late),
                Err(RecvTimeoutError::Disconnected) => return Err(FxError::Dead),
            }
        }
    }
}

/// How long a frame may take in mesh-fx before it goes out dry (F4).
const DEADLINE: Duration = Duration::from_millis(20);
/// Late frames in a row before the plugins are bypassed (F4).
const LATE_MAX: u32 = 3;
/// How long loading a chain may take.
const LOAD_LIMIT: Duration = Duration::from_secs(30);

/// Starts mesh-fx with a chain: the running process and its answer.
pub type Starter = Arc<dyn Fn(&Value) -> Result<(Fx, Value), String> + Send + Sync>;

/// The real one: `mesh-fx serve`, then the chain.
pub fn start_mesh_fx(plugins: &Value) -> Result<(Fx, Value), String> {
    let mut cmd = Command::new(mesh_fx_path());
    cmd.arg("serve");
    let mut fx = Fx::start(cmd).map_err(|e| format!("couldn't start mesh-fx: {e}"))?;
    let answer = fx
        .control(json!({ "cmd": "chain", "plugins": plugins }), LOAD_LIMIT)
        .map_err(|e| format!("the plugins didn't load ({e:?})"))?;
    match answer["error"].as_str() {
        Some(e) => Err(e.to_owned()),
        None => Ok((fx, answer)),
    }
}

/// A call's (or the mic test's) plugins (F3, F4): started off the audio
/// thread when the chain changes, each frame through them within the
/// deadline or dry, bypassed after `LATE_MAX` late frames or a crash until
/// the chain is set or restarted again. Tells `report` each change.
pub struct Runner {
    start: Starter,
    applied: u64,
    fx: Option<Fx>,
    starting: Option<Receiver<Result<(Fx, Value), String>>>,
    late: u32,
}

impl Runner {
    pub fn new(start: Starter) -> Self {
        Runner {
            start,
            applied: 0,
            fx: None,
            starting: None,
            late: 0,
        }
    }

    /// `frame` through the chain at `version` (`plugins`, `[{path, id, on}]`).
    pub fn step(
        &mut self,
        frame: &mut [i16],
        version: u64,
        plugins: &Arc<Value>,
        report: &dyn Fn(Value),
    ) {
        if version != self.applied {
            (self.applied, self.fx, self.starting, self.late) = (version, None, None, 0);
            if plugins
                .as_array()
                .is_some_and(|a| a.iter().any(|p| p["on"] != false))
            {
                let (tx, rx) = mpsc::channel();
                let (start, plugins) = (self.start.clone(), plugins.clone());
                std::thread::spawn(move || drop(tx.send(start(&plugins))));
                self.starting = Some(rx);
                report(json!({ "state": "starting" }));
            } else {
                report(json!({ "state": "off" }));
            }
        }
        if let Some(rx) = &self.starting {
            match rx.try_recv() {
                Ok(Ok((fx, answer))) => {
                    (self.fx, self.starting) = (Some(fx), None);
                    report(json!({ "state": "on", "latency": answer["latency"] }));
                    // From the next frame on.
                    return;
                }
                Ok(Err(error)) => {
                    self.starting = None;
                    report(json!({ "state": "failed", "error": error }));
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.starting = None;
                    report(json!({ "state": "failed", "error": "mesh-fx didn't start" }));
                }
            }
        }
        let Some(fx) = self.fx.as_mut() else { return };
        // The wait mustn't hold up the other tasks on this runtime thread.
        let result = match tokio::runtime::Handle::try_current() {
            Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| fx.process(frame, DEADLINE))
            }
            _ => fx.process(frame, DEADLINE),
        };
        let why = match result {
            Ok(()) => {
                self.late = 0;
                return;
            }
            Err(FxError::Late) => {
                self.late += 1;
                if self.late < LATE_MAX {
                    return;
                }
                "too slow: 3 frames late in a row"
            }
            Err(FxError::Dead) => "the plugins stopped (crashed)",
        };
        self.fx = None;
        report(json!({ "state": "bypassed", "error": why }));
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// `cat` stands in for mesh-fx: it sends every message straight back, which
// is what `mesh-fx serve` does until the chain is wired.
#[cfg(all(test, unix))]
mod tests {
    use super::proto::FRAME;
    use super::*;

    fn cat() -> Fx {
        Fx::start(Command::new("cat")).unwrap()
    }

    #[test]
    fn frames_come_back_in_order() {
        let mut fx = cat();
        for k in 0..200 {
            let sent: Vec<i16> = (0..FRAME).map(|i| (i as i16).wrapping_mul(k)).collect();
            let mut frame = sent.clone();
            fx.process(&mut frame, Duration::from_secs(1)).unwrap();
            assert_eq!(frame, sent);
        }
    }

    /// A frame given no time is late; its answer, when it comes, is
    /// skipped rather than taken for the next frame's.
    #[test]
    fn a_late_answer_is_not_the_next_frames() {
        let mut fx = cat();
        let mut first = vec![1i16; FRAME];
        let _ = fx.process(&mut first, Duration::ZERO);
        std::thread::sleep(Duration::from_millis(50));
        let mut second = vec![2i16; FRAME];
        fx.process(&mut second, Duration::from_secs(1)).unwrap();
        assert_eq!(second, vec![2i16; FRAME]);
    }

    #[test]
    fn a_control_answer_is_matched_by_id() {
        let mut fx = cat();
        let v = fx
            .control(serde_json::json!({"cmd": "x"}), Duration::from_secs(1))
            .unwrap();
        assert_eq!(v["cmd"], "x");
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn a_dead_process_is_seen_within_100_ms() {
        let mut fx = cat();
        let mut frame = vec![1i16; FRAME];
        fx.process(&mut frame, Duration::from_secs(1)).unwrap();
        fx.child.kill().unwrap();
        let killed = Instant::now();
        let mut frame = vec![1i16; FRAME];
        let r = fx.process(&mut frame, Duration::from_secs(1));
        assert_eq!(r, Err(FxError::Dead));
        assert!(
            killed.elapsed() < Duration::from_millis(100),
            "{:?}",
            killed.elapsed()
        );
    }

    fn runner(cmd: &'static [&'static str]) -> Runner {
        Runner::new(Arc::new(move |_: &Value| {
            let mut c = Command::new(cmd[0]);
            c.args(&cmd[1..]);
            Fx::start(c)
                .map(|fx| (fx, json!({ "latency": 7 })))
                .map_err(|e| e.to_string())
        }))
    }

    /// Steps `r` with `frame` until a report comes (or 2 s): the reports.
    fn step_until_report(r: &mut Runner, version: u64, plugins: &Arc<Value>) -> Vec<Value> {
        let got = std::cell::RefCell::new(Vec::new());
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            let mut frame = vec![9i16; FRAME];
            r.step(&mut frame, version, plugins, &|v| got.borrow_mut().push(v));
            assert_eq!(
                frame,
                vec![9i16; FRAME],
                "cat or nothing: unchanged either way"
            );
            if got.borrow().iter().any(|v| v["state"] != "starting") {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        got.into_inner()
    }

    fn on() -> Arc<Value> {
        Arc::new(json!([{ "path": "x.clap", "id": "x", "on": true }]))
    }

    #[test]
    fn a_runner_starts_off_the_audio_thread_and_reports_on() {
        let mut r = runner(&["cat"]);
        let got = step_until_report(&mut r, 1, &on());
        assert_eq!(got[0]["state"], "starting");
        assert_eq!(got.last().unwrap()["state"], "on");
        assert_eq!(got.last().unwrap()["latency"], 7);
        // Running: frames come back, nothing more reported.
        let got = std::cell::RefCell::new(Vec::new());
        for _ in 0..20 {
            let mut frame = vec![3i16; FRAME];
            r.step(&mut frame, 1, &on(), &|v| got.borrow_mut().push(v));
        }
        assert!(got.borrow().is_empty(), "{:?}", got.borrow());
        assert!(r.fx.is_some());
    }

    #[test]
    fn three_late_frames_bypass_and_a_restart_restores() {
        let mut r = runner(&["sleep", "10"]);
        assert_eq!(
            step_until_report(&mut r, 1, &on()).last().unwrap()["state"],
            "on"
        );
        let got = std::cell::RefCell::new(Vec::new());
        for k in 0..3 {
            let mut frame = vec![4i16; FRAME];
            let started = Instant::now();
            r.step(&mut frame, 1, &on(), &|v| got.borrow_mut().push(v));
            assert!(started.elapsed() < Duration::from_millis(200));
            assert_eq!(frame, vec![4i16; FRAME], "late: sent dry");
            assert_eq!(
                got.borrow().len(),
                usize::from(k == 2),
                "bypassed on the third"
            );
        }
        assert_eq!(got.borrow()[0]["state"], "bypassed");
        assert!(r.fx.is_none());
        // Bypassed: frames go straight through without waiting.
        let started = Instant::now();
        r.step(&mut vec![4i16; FRAME], 1, &on(), &|_| {});
        assert!(started.elapsed() < Duration::from_millis(5));
        // Restart (the same chain, a new version) starts it again.
        r.start = runner(&["cat"]).start.clone();
        assert_eq!(
            step_until_report(&mut r, 2, &on()).last().unwrap()["state"],
            "on"
        );
    }

    #[test]
    fn a_crash_bypasses_at_once() {
        // `head` reads one byte of the first frame and exits.
        let mut r = runner(&["head", "-c", "1"]);
        assert_eq!(
            step_until_report(&mut r, 1, &on()).last().unwrap()["state"],
            "on"
        );
        let got = std::cell::RefCell::new(Vec::new());
        let until = Instant::now() + Duration::from_secs(2);
        while got.borrow().is_empty() && Instant::now() < until {
            r.step(&mut vec![1i16; FRAME], 1, &on(), &|v| {
                got.borrow_mut().push(v)
            });
        }
        assert_eq!(got.borrow()[0]["state"], "bypassed", "{:?}", got.borrow());
        assert!(
            got.borrow()[0]["error"]
                .as_str()
                .unwrap()
                .contains("crashed")
        );
    }

    #[test]
    fn no_plugins_on_starts_nothing_and_a_failed_load_is_reported() {
        let mut r = Runner::new(Arc::new(|_: &Value| panic!("nothing to start")));
        let off = Arc::new(json!([{ "path": "x.clap", "id": "x", "on": false }]));
        assert_eq!(step_until_report(&mut r, 1, &off)[0]["state"], "off");
        let mut r = Runner::new(Arc::new(|_: &Value| Err("x: no such plugin".to_owned())));
        let got = step_until_report(&mut r, 1, &on());
        assert_eq!(got.last().unwrap()["state"], "failed");
        assert_eq!(got.last().unwrap()["error"], "x: no such plugin");
    }

    /// A stuck mesh-fx (here: one that never reads) makes frames late,
    /// never blocks the caller, and a late answer isn't taken for the next.
    #[test]
    fn a_stuck_process_never_stalls_the_caller() {
        let mut fx = Fx::start({
            let mut c = Command::new("sleep");
            c.arg("10");
            c
        })
        .unwrap();
        let started = Instant::now();
        for _ in 0..500 {
            let mut frame = vec![5i16; FRAME];
            assert_eq!(
                fx.process(&mut frame, Duration::from_millis(1)),
                Err(FxError::Late)
            );
            assert_eq!(frame, vec![5i16; FRAME], "left as it was");
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }
}
