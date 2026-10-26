//! Shared by the process tests: a loopback relay, and a driver for the
//! helper as Mesh-Voice uses it.
#![allow(dead_code)] // each test file uses part of it

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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

pub struct Helper {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// The latest `meshNet`: it comes whenever the node's state changes, so
    /// `event` sets it aside.
    pub net: Option<Value>,
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            net: None,
        }
    }

    /// The next line's binding and decoded payload.
    pub fn line(&mut self) -> (String, Value) {
        let mut line = String::new();
        assert!(
            self.stdout.read_line(&mut line).unwrap() > 0,
            "mesh-node exited"
        );
        let frame: Value = serde_json::from_str(&line).unwrap();
        let payload = serde_json::from_str(frame["payload"].as_str().unwrap()).unwrap();
        (frame["binding"].as_str().unwrap().to_owned(), payload)
    }

    /// The next event other than `meshNet`.
    pub fn event(&mut self) -> (String, Value) {
        loop {
            match self.line() {
                (binding, payload) if binding == "meshNet" => self.net = Some(payload),
                event => return event,
            }
        }
    }

    /// Waits for a `meshNet` that satisfies `done`; it may already have come.
    pub fn net(&mut self, done: impl Fn(&Value) -> bool) -> Value {
        loop {
            if let Some(net) = self.net.as_ref().filter(|n| done(n)) {
                return net.clone();
            }
            let (binding, payload) = self.line();
            assert_eq!(binding, "meshNet", "unexpected {payload}");
            self.net = Some(payload);
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
    pub fn expect(&mut self, func: &str, args: &[&str], binding: &str) -> Value {
        let (got, payload) = self.call(func, args);
        assert_eq!(got, binding, "{func} answered {payload}");
        payload
    }

    /// Closes stdin (Mesh quitting); the helper must exit. Returns its stderr.
    pub fn quit(mut self) -> String {
        drop(self.stdin);
        assert!(self.child.wait().unwrap().success());
        let mut err = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        err
    }
}

pub fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("mesh-node-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}
