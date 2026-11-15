//! Shared by the process tests: a loopback relay, and a driver for the
//! helper as Mesh-Voice uses it.
#![allow(dead_code)] // each test file uses part of it

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{Value, json};

/// A plain-http relay on loopback, which `--relay` allows: no internet
/// needed, and nothing in the helper has to trust a self-signed relay.
pub struct Relay {
    pub url: String,
    // Runs the server; dropping it stops the relay.
    pub runtime: tokio::runtime::Runtime,
}

impl Relay {
    pub fn start() -> Self {
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let url = runtime.block_on(async {
            let mut config = ServerConfig::default();
            config.relay = Some(RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0)));
            let server = Server::spawn(config).await.unwrap();
            let url = format!("http://{}", server.http_addr().unwrap());
            // The server stops when dropped; the runtime outlives the test.
            std::mem::forget(server);
            url
        });
        Self { url, runtime }
    }
}

/// The longest a test waits for the helper to say anything.
const LINE_TIMEOUT: Duration = Duration::from_secs(90);

pub struct Helper {
    child: Child,
    stdin: ChildStdin,
    /// stdout's lines, read on their own thread so a wait can time out.
    stdout: mpsc::Receiver<String>,
    /// The latest `meshNet`: it comes whenever the node's state changes, so
    /// `event` sets it aside.
    pub net: Option<Value>,
    /// The latest `meshSocial` that answered no command (something changed
    /// by itself), set aside the same way.
    pub social: Option<Value>,
    /// Every `meshNote` so far: they come whenever a note arrives.
    pub notes: Vec<Value>,
    /// stderr so far, read on its own thread: a wait that times out can
    /// print it, and a full pipe never blocks the helper.
    err: Arc<Mutex<String>>,
    err_reader: JoinHandle<()>,
}

thread_local! {
    /// Each helper this test thread started: its data folder's name and stderr.
    static STARTED: RefCell<Vec<(String, Arc<Mutex<String>>)>> = const { RefCell::new(Vec::new()) };
}

/// Every helper's stderr so far (counts only), for a test that timed out.
pub fn stderr_dump() -> String {
    STARTED.with_borrow(|all| {
        all.iter()
            .map(|(name, err)| format!("--- {name} ---\n{}", err.lock().unwrap()))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// Fails the test, printing every helper's stderr first.
pub fn fail(why: &str) -> ! {
    eprintln!("{}", stderr_dump());
    panic!("{why}");
}

impl Helper {
    pub fn start(dir: &Path, relay: &Relay) -> Self {
        Self::start_with(dir, relay, &[])
    }

    pub fn start_with(dir: &Path, relay: &Relay, args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mesh-node"))
            .arg("--data")
            .arg(dir)
            .args(["--relay", &relay.url])
            .args(args)
            // Never the built-in (real) seed: only one a test passes with --seed.
            .env("MESH_SEEDS", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, stdout) = mpsc::channel();
        std::thread::spawn(move || {
            out.lines()
                .map_while(Result::ok)
                .for_each(|l| drop(tx.send(l)))
        });
        let err = Arc::new(Mutex::new(String::new()));
        let mut from = BufReader::new(child.stderr.take().unwrap());
        let to = err.clone();
        let err_reader = std::thread::spawn(move || {
            let mut line = String::new();
            while from.read_line(&mut line).is_ok_and(|n| n > 0) {
                to.lock().unwrap().push_str(&line);
                line.clear();
            }
        });
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        STARTED.with_borrow_mut(|all| all.push((name, err.clone())));
        Self {
            child,
            stdin,
            stdout,
            net: None,
            social: None,
            notes: Vec::new(),
            err,
            err_reader,
        }
    }

    /// stderr so far, while it runs.
    pub fn stderr_so_far(&self) -> String {
        self.err.lock().unwrap().clone()
    }

    /// The helper's process ID (a measurement reads its CPU time).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The next line's binding and decoded payload.
    pub fn line(&mut self) -> (String, Value) {
        let line = match self.stdout.recv_timeout(LINE_TIMEOUT) {
            Ok(line) => line,
            Err(mpsc::RecvTimeoutError::Timeout) => fail("mesh-node went quiet"),
            Err(mpsc::RecvTimeoutError::Disconnected) => fail("mesh-node exited"),
        };
        let frame: Value = serde_json::from_str(&line).unwrap();
        let payload = serde_json::from_str(frame["payload"].as_str().unwrap()).unwrap();
        (frame["binding"].as_str().unwrap().to_owned(), payload)
    }

    /// The next event other than `meshNet` or a `meshSocial` nobody asked for.
    pub fn event(&mut self) -> (String, Value) {
        loop {
            match self.line() {
                (binding, payload) if binding == "meshNet" => self.net = Some(payload),
                (binding, payload) if binding == "meshSocial" && payload["fn"].is_null() => {
                    self.social = Some(payload)
                }
                (binding, payload) if binding == "meshNote" => self.notes.push(payload),
                event => return event,
            }
        }
    }

    /// Waits for a `meshSocial` that satisfies `done`; it may already have
    /// come. Codes lists that come meanwhile are skipped.
    pub fn social_until(&mut self, done: impl Fn(&Value) -> bool) -> Value {
        loop {
            if let Some(social) = self.social.as_ref().filter(|s| done(s)) {
                return social.clone();
            }
            match self.line() {
                (binding, payload) if binding == "meshSocial" => self.social = Some(payload),
                (binding, payload) if binding == "meshNet" => self.net = Some(payload),
                (binding, payload) if binding == "meshNote" => self.notes.push(payload),
                (binding, _) if binding == "meshCodes" => {}
                (binding, payload) => panic!("unexpected {binding} {payload}"),
            }
        }
    }

    /// Waits for a `meshNet` that satisfies `done`; it may already have come.
    pub fn net(&mut self, done: impl Fn(&Value) -> bool) -> Value {
        loop {
            if let Some(net) = self.net.as_ref().filter(|n| done(n)) {
                return net.clone();
            }
            match self.line() {
                (binding, payload) if binding == "meshNet" => self.net = Some(payload),
                (binding, payload) if binding == "meshSocial" && payload["fn"].is_null() => {
                    self.social = Some(payload)
                }
                (binding, payload) if binding == "meshNote" => self.notes.push(payload),
                (binding, _) if binding == "meshCodes" => {}
                (binding, payload) => panic!("unexpected {binding} {payload}"),
            }
        }
    }

    /// Waits for a `meshNote` with this text; it may already have come.
    pub fn note_with(&mut self, text: &str) -> Value {
        let started = std::time::Instant::now();
        loop {
            assert!(started.elapsed() < LINE_TIMEOUT, "no note {text:?}");
            if let Some(note) = self.notes.iter().find(|n| n["text"] == text) {
                return note.clone();
            }
            match self.line() {
                (binding, payload) if binding == "meshNote" => self.notes.push(payload),
                (binding, payload) if binding == "meshNet" => self.net = Some(payload),
                (binding, payload) if binding == "meshSocial" => self.social = Some(payload),
                (binding, _) if binding == "meshCodes" => {}
                (binding, payload) => panic!("unexpected {binding} {payload}"),
            }
        }
    }

    pub fn net_state(&mut self, state: &str) -> Value {
        self.net(|n| n["state"] == state)
    }

    pub fn send(&mut self, func: &str, args: &[&str]) {
        writeln!(self.stdin, "{}", json!({ "fn": func, "args": args })).unwrap();
    }

    /// Sends a command and returns the first event it answers with.
    pub fn call(&mut self, func: &str, args: &[&str]) -> (String, Value) {
        self.send(func, args);
        self.event()
    }

    /// Sends a command that must answer with `binding`.
    /// A `meshCodes` from a background seed answer may come first; it's
    /// skipped unless that's what's expected.
    pub fn expect(&mut self, func: &str, args: &[&str], binding: &str) -> Value {
        let (mut got, mut payload) = self.call(func, args);
        while got == "meshCodes" && binding != "meshCodes" {
            (got, payload) = self.event();
        }
        assert_eq!(got, binding, "{func} answered {payload}");
        payload
    }

    /// Waits for a helper that must exit on its own, failing (`--crash-at`).
    /// Returns its stderr.
    pub fn crashed(mut self) -> String {
        assert!(!self.child.wait().unwrap().success(), "it crashed");
        all_stderr(self.err_reader, &self.err)
    }

    /// Closes stdin (Mesh quitting); the helper must exit. Returns its stderr.
    pub fn quit(self) -> String {
        let Self {
            mut child,
            stdin,
            err,
            err_reader,
            ..
        } = self;
        drop(stdin);
        assert!(child.wait().unwrap().success());
        all_stderr(err_reader, &err)
    }
}

/// stderr once the helper has exited: every line, none lost.
fn all_stderr(reader: JoinHandle<()>, err: &Mutex<String>) -> String {
    reader.join().unwrap();
    err.lock().unwrap().clone()
}

pub fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("mesh-node-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A `mesh-node seed` process on the test relay.
pub struct Seed {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Seed {
    pub fn start(dir: &Path, relay: &Relay) -> Self {
        Self::start_with(dir, relay, &[])
    }

    pub fn start_with(dir: &Path, relay: &Relay, args: &[&str]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mesh-node"));
        command
            .args(["seed", "--data"])
            .arg(dir)
            .args(["--relay", &relay.url])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // Its own process group, so `stop`'s Ctrl-Break reaches only the seed.
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut command, 0x200);
        let mut child = command.spawn().unwrap();
        let stderr = BufReader::new(child.stderr.take().unwrap());
        let (tx, lines) = mpsc::channel();
        // Its log goes in a timeout's dump too (counts only, D10).
        let err = Arc::new(Mutex::new(String::new()));
        let to = err.clone();
        std::thread::spawn(move || {
            stderr.lines().map_while(Result::ok).for_each(|l| {
                to.lock().unwrap().push_str(&format!("{l}\n"));
                drop(tx.send(l))
            })
        });
        STARTED.with_borrow_mut(|all| all.push(("seed".to_owned(), err)));
        Self {
            child,
            lines,
            log: Vec::new(),
        }
    }

    /// Waits for the ticket the seed logs once it's online.
    pub fn ticket(&mut self) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(30))
                .expect("the seed went quiet");
            self.log.push(line.clone());
            if let Some(ticket) = line.strip_prefix("mesh-node seed: ticket ") {
                return ticket.to_owned();
            }
        }
    }

    /// Waits for a log line that `done` accepts.
    pub fn line_with(&mut self, done: impl Fn(&str) -> bool) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(30))
                .expect("the seed went quiet");
            self.log.push(line.clone());
            if done(&line) {
                return line;
            }
        }
    }

    /// The log lines that have come since the last look, without waiting.
    pub fn drain(&mut self) -> Vec<String> {
        let lines: Vec<String> = self.lines.try_iter().collect();
        self.log.extend(lines.iter().cloned());
        lines
    }

    /// SIGTERM, as Docker and systemd stop it (Ctrl-Break on Windows);
    /// returns the whole log.
    pub fn stop(mut self) -> Vec<String> {
        #[cfg(unix)]
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        #[cfg(windows)]
        {
            unsafe extern "system" {
                fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
            }
            // CTRL_BREAK_EVENT to the seed's process group.
            assert_ne!(unsafe { GenerateConsoleCtrlEvent(1, self.child.id()) }, 0);
        }
        assert!(self.child.wait().unwrap().success(), "exits cleanly");
        // The seed has exited, so its stderr ends: every line, none lost.
        self.log.extend(self.lines.iter());
        std::mem::take(&mut self.log)
    }
}

/// A failing test mustn't leave a seed running: it doesn't exit with us.
impl Drop for Seed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
