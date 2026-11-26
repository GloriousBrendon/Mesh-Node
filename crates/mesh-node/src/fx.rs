//! mesh-node's end of `mesh-fx` (SPEC-voice-quality F2, F4): a person's own
//! plugins run in that process; frames go there and back over its pipe.
//! A writer and a reader thread own the pipe, so the audio thread never
//! blocks on it: a frame that isn't back in time, or can't even be queued,
//! is `Late`, and the caller sends it dry.

// ponytail: nothing calls this until the chain is wired (Task 4).
#![cfg_attr(not(test), allow(dead_code))]

use std::io;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

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
