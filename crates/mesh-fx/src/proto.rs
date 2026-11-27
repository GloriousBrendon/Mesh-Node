//! mesh-node ⇄ mesh-fx messages over mesh-fx's stdin/stdout
//! (PLAN-voice-quality): `[tag u8][len u32 LE][payload]`. Audio is
//! `[seq u32 LE][960 × i16 LE]`, answered with the same `seq`; control is a
//! JSON object with an `id`, answered with that `id`. Both crates include
//! this file by path, so neither depends on the other.

use std::io::{self, Read, Write};

pub const AUDIO: u8 = 1;
pub const CONTROL: u8 = 2;
/// Samples in a frame: 20 ms at 48 kHz.
pub const FRAME: usize = 960;
const AUDIO_LEN: usize = 4 + FRAME * 2;
/// Control JSON above this is malformed (a parameter list fits easily).
const CONTROL_MAX: usize = 1 << 20;

#[derive(Debug, PartialEq)]
pub enum Msg {
    Audio(u32, Vec<i16>),
    Control(Vec<u8>),
}

pub fn write(w: &mut impl Write, msg: &Msg) -> io::Result<()> {
    let mut buf = Vec::with_capacity(5 + AUDIO_LEN);
    match msg {
        Msg::Audio(seq, pcm) => {
            assert_eq!(pcm.len(), FRAME, "a frame is {FRAME} samples");
            buf.push(AUDIO);
            buf.extend((AUDIO_LEN as u32).to_le_bytes());
            buf.extend(seq.to_le_bytes());
            pcm.iter().for_each(|s| buf.extend(s.to_le_bytes()));
        }
        Msg::Control(json) => {
            buf.push(CONTROL);
            buf.extend((json.len() as u32).to_le_bytes());
            buf.extend(json);
        }
    }
    w.write_all(&buf)?;
    w.flush()
}

/// The next message; `None` at a clean end (EOF between messages).
/// Malformed input is `InvalidData`, a message cut short `UnexpectedEof`.
pub fn read(r: &mut impl Read) -> io::Result<Option<Msg>> {
    let mut head = [0u8; 5];
    let mut got = 0;
    while got < head.len() {
        match r.read(&mut head[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    match head[0] {
        AUDIO if len == AUDIO_LEN => {
            let mut body = vec![0u8; len];
            r.read_exact(&mut body)?;
            let seq = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let pcm = body[4..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| i16::from_le_bytes(*b))
                .collect();
            Ok(Some(Msg::Audio(seq, pcm)))
        }
        CONTROL if len <= CONTROL_MAX => {
            let mut body = vec![0u8; len];
            r.read_exact(&mut body)?;
            Ok(Some(Msg::Control(body)))
        }
        tag => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed message: tag {tag}, {len} bytes"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(msgs: &[Msg]) -> Vec<u8> {
        let mut out = Vec::new();
        msgs.iter().for_each(|m| write(&mut out, m).unwrap());
        out
    }

    #[test]
    fn messages_round_trip_in_order() {
        let msgs = [
            Msg::Audio(1, (0..FRAME as i16).collect()),
            Msg::Control(br#"{"id":1}"#.to_vec()),
            Msg::Audio(2, vec![-7; FRAME]),
        ];
        let data = bytes(&msgs);
        let mut r = data.as_slice();
        for m in &msgs {
            assert_eq!(read(&mut r).unwrap().as_ref(), Some(m));
        }
        assert_eq!(read(&mut r).unwrap(), None, "clean end");
    }

    #[test]
    fn malformed_and_cut_short_are_errors() {
        let kind = |data: &[u8]| read(&mut &data[..]).unwrap_err().kind();
        assert_eq!(
            kind(&[9, 0, 0, 0, 0]),
            io::ErrorKind::InvalidData,
            "unknown tag"
        );
        assert_eq!(
            kind(&[AUDIO, 1, 0, 0, 0, 0]),
            io::ErrorKind::InvalidData,
            "wrong audio size"
        );
        // A huge length is refused before anything is allocated.
        assert_eq!(
            kind(&[CONTROL, 255, 255, 255, 255]),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            kind(&[AUDIO, 1]),
            io::ErrorKind::UnexpectedEof,
            "cut in the header"
        );
        let data = bytes(&[Msg::Control(b"{}".to_vec())]);
        assert_eq!(
            kind(&data[..data.len() - 1]),
            io::ErrorKind::UnexpectedEof,
            "cut in the body"
        );
    }
}
