//! `mesh-fx serve`: answers mesh-node's messages (proto.rs) until stdin ends.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use serde_json::{Value, json};

use crate::chain::Chain;
use crate::proto::{self, Msg};

/// Serves `r` into `w`; `Ok` at a clean end, `Err` on malformed input or a
/// plugin that fails while processing (mesh-node then sends the voice dry).
/// `r` is read on its own thread, so an open editor keeps running between
/// messages; closing one saves the chain's state and says so unasked
/// (`{"event": "editorClosed", "plugin": at, "saved": n}`).
pub fn serve(r: impl Read + Send + 'static, mut w: impl Write) -> io::Result<()> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut r = r;
        loop {
            let msg = proto::read(&mut r);
            let end = !matches!(msg, Ok(Some(_)));
            if tx.send(msg).is_err() || end {
                break;
            }
        }
    });
    let mut chain: Option<Chain> = None;
    loop {
        let editing = chain.as_ref().is_some_and(Chain::editing);
        let next = match editing {
            true => match rx.recv_timeout(Duration::from_millis(5)) {
                Ok(msg) => Some(msg),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            },
            false => match rx.recv() {
                Ok(msg) => Some(msg),
                Err(_) => return Ok(()),
            },
        };
        if let Some(c) = chain.as_mut() {
            for at in c.pump() {
                let saved = c.save();
                let told = json!({ "event": "editorClosed", "plugin": at, "saved": saved });
                proto::write(&mut w, &Msg::Control(told.to_string().into_bytes()))?;
            }
        }
        let Some(msg) = next else { continue };
        let Some(msg) = msg? else { return Ok(()) };
        let reply = match msg {
            Msg::Audio(seq, mut pcm) => {
                if let Some(c) = chain.as_mut() {
                    c.run(&mut pcm).map_err(io::Error::other)?;
                }
                Msg::Audio(seq, pcm)
            }
            Msg::Control(json) => {
                let v: Value = serde_json::from_slice(&json)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let at = v["plugin"].as_u64().unwrap_or(u64::MAX) as usize;
                let on = |f: &mut dyn FnMut(&mut Chain) -> Result<Value, String>,
                          chain: &mut Option<Chain>| {
                    match chain.as_mut() {
                        Some(c) => f(c).unwrap_or_else(|e| json!({ "error": e })),
                        None => json!({ "error": "no chain" }),
                    }
                };
                let mut answer = match v["cmd"].as_str() {
                    Some("chain") => {
                        chain = None;
                        match Chain::load(&v["plugins"]) {
                            Ok((c, info)) => {
                                chain = Some(c);
                                info
                            }
                            Err(e) => json!({ "error": e }),
                        }
                    }
                    Some("save") => on(&mut |c| Ok(json!({ "saved": c.save() })), &mut chain),
                    Some("params") => on(&mut |c| c.params(at), &mut chain),
                    Some("param") => {
                        let (id, value) = (
                            v["param"].as_u64().unwrap_or(u64::MAX) as u32,
                            v["value"].as_f64().unwrap_or(0.0),
                        );
                        on(&mut |c| c.set_param(at, id, value), &mut chain)
                    }
                    Some("edit") => on(&mut |c| c.edit(at), &mut chain),
                    Some("editClose") => on(&mut |c| c.close_editor(at), &mut chain),
                    _ => json!({ "error": "unknown command" }),
                };
                answer["id"] = v.get("id").cloned().unwrap_or_default();
                answer["cmd"] = v.get("cmd").cloned().unwrap_or_default();
                answer["plugin"] = v.get("plugin").cloned().unwrap_or_default();
                Msg::Control(answer.to_string().into_bytes())
            }
        };
        proto::write(&mut w, &reply)?;
    }
}

/// The protocol's own copy of stdout; stdout itself then points at stderr,
/// so a plugin that prints can't corrupt the protocol.
#[cfg(unix)]
pub fn protocol_out() -> io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain fd calls; the new fd is owned by the returned File.
    unsafe {
        let fd = libc::dup(1);
        if fd < 0 || libc::dup2(2, 1) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(std::fs::File::from_raw_fd(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_comes_back_and_control_is_answered_by_id() {
        let mut input = Vec::new();
        proto::write(&mut input, &Msg::Audio(5, vec![3; proto::FRAME])).unwrap();
        proto::write(
            &mut input,
            &Msg::Control(br#"{"id":9,"cmd":"nope"}"#.to_vec()),
        )
        .unwrap();
        let mut out = Vec::new();
        serve(std::io::Cursor::new(input), &mut out).unwrap();
        let mut r = out.as_slice();
        assert_eq!(
            proto::read(&mut r).unwrap(),
            Some(Msg::Audio(5, vec![3; proto::FRAME]))
        );
        let Some(Msg::Control(reply)) = proto::read(&mut r).unwrap() else {
            panic!()
        };
        let v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(v["id"], 9);
    }

    #[test]
    fn malformed_input_ends_it_with_an_error() {
        let mut out = Vec::new();
        assert!(serve(std::io::Cursor::new(vec![7u8, 0, 0, 0, 0]), &mut out).is_err());
        assert!(
            serve(
                std::io::Cursor::new(vec![proto::CONTROL, 3, 0, 0, 0, b'n', b'o', b'!']),
                &mut out
            )
            .is_err(),
            "not JSON"
        );
        assert!(out.is_empty());
    }
}
