//! `mesh-fx serve`: answers mesh-node's messages (proto.rs) until stdin ends.

use std::io::{self, Read, Write};

use serde_json::{Value, json};

use crate::chain::Chain;
use crate::proto::{self, Msg};

/// Serves `r` into `w`; `Ok` at a clean end, `Err` on malformed input or a
/// plugin that fails while processing (mesh-node then sends the voice dry).
pub fn serve(mut r: impl Read, mut w: impl Write) -> io::Result<()> {
    let mut chain: Option<Chain> = None;
    while let Some(msg) = proto::read(&mut r)? {
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
                    _ => json!({ "error": "unknown command" }),
                };
                answer["id"] = v.get("id").cloned().unwrap_or_default();
                Msg::Control(answer.to_string().into_bytes())
            }
        };
        proto::write(&mut w, &reply)?;
    }
    Ok(())
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
        serve(input.as_slice(), &mut out).unwrap();
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
        assert!(serve([7u8, 0, 0, 0, 0].as_slice(), &mut out).is_err());
        assert!(
            serve(
                &[proto::CONTROL, 3, 0, 0, 0, b'n', b'o', b'!'][..],
                &mut out
            )
            .is_err(),
            "not JSON"
        );
        assert!(out.is_empty());
    }
}
