//! What a stream carries (SPEC-transport D6): a service tag first, then
//! length-prefixed frames. Tag: one length byte and 1–32 printable ASCII
//! bytes. Frame: a big-endian `u32` length and at most 1 MiB of bytes.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The longest service tag.
pub const MAX_TAG: usize = 32;
/// The largest frame; bigger things get their own streams in their modules.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("service tag must be 1 to {MAX_TAG} printable ASCII characters")]
    BadTag,
    #[error("frame of {0} bytes is over the {MAX_FRAME}-byte limit")]
    TooBig(usize),
    #[error("the stream ended in the middle of a frame")]
    Truncated,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn valid_tag(tag: &[u8]) -> bool {
    (1..=MAX_TAG).contains(&tag.len()) && tag.iter().all(u8::is_ascii_graphic)
}

/// Starts a stream for a service (`ping`, `hello`, later `dm`…).
pub async fn write_tag<W: AsyncWrite + Unpin>(w: &mut W, tag: &str) -> Result<(), FrameError> {
    if !valid_tag(tag.as_bytes()) {
        return Err(FrameError::BadTag);
    }
    // Checked above: the length fits in a byte.
    w.write_u8(tag.len() as u8).await?;
    w.write_all(tag.as_bytes()).await?;
    Ok(())
}

/// Reads the service tag a stream starts with.
pub async fn read_tag<R: AsyncRead + Unpin>(r: &mut R) -> Result<String, FrameError> {
    let len = r.read_u8().await.map_err(eof_is_truncated)? as usize;
    if !(1..=MAX_TAG).contains(&len) {
        return Err(FrameError::BadTag);
    }
    let mut tag = vec![0; len];
    r.read_exact(&mut tag).await.map_err(eof_is_truncated)?;
    if !valid_tag(&tag) {
        return Err(FrameError::BadTag);
    }
    // Printable ASCII, so valid UTF-8.
    String::from_utf8(tag).map_err(|_| FrameError::BadTag)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), FrameError> {
    if bytes.len() > MAX_FRAME {
        return Err(FrameError::TooBig(bytes.len()));
    }
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(bytes).await?;
    Ok(())
}

/// The next frame, or `None` when the stream ended cleanly between frames.
/// The length is checked before anything is allocated.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]).await? {
            0 if got == 0 => return Ok(None),
            0 => return Err(FrameError::Truncated),
            n => got += n,
        }
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooBig(len));
    }
    let mut bytes = vec![0; len];
    r.read_exact(&mut bytes).await.map_err(eof_is_truncated)?;
    Ok(Some(bytes))
}

fn eof_is_truncated(e: std::io::Error) -> FrameError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        FrameError::Truncated
    } else {
        FrameError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything written, as one stream to read back.
    async fn written(f: impl AsyncFnOnce(&mut Vec<u8>) -> Result<(), FrameError>) -> Vec<u8> {
        let mut buf = Vec::new();
        f(&mut buf).await.expect("write");
        buf
    }

    #[tokio::test]
    async fn round_trips() {
        let buf = written(async |w| {
            write_tag(w, "ping").await?;
            write_frame(w, b"hello").await?;
            write_frame(w, b"").await?;
            write_frame(w, &vec![7; MAX_FRAME]).await
        })
        .await;
        let mut r = buf.as_slice();
        assert_eq!(read_tag(&mut r).await.unwrap(), "ping");
        assert_eq!(
            read_frame(&mut r).await.unwrap().as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(read_frame(&mut r).await.unwrap().as_deref(), Some(&b""[..]));
        assert_eq!(
            read_frame(&mut r).await.unwrap().map(|f| f.len()),
            Some(MAX_FRAME)
        );
        assert!(read_frame(&mut r).await.unwrap().is_none(), "clean end");
    }

    #[tokio::test]
    async fn refuses_oversized_frames_both_ways() {
        let mut sink = Vec::new();
        assert!(matches!(
            write_frame(&mut sink, &vec![0; MAX_FRAME + 1]).await,
            Err(FrameError::TooBig(_))
        ));
        assert!(sink.is_empty(), "nothing written");
        // A length prefix claiming 4 GiB fails before allocating.
        let mut r = &[0xff, 0xff, 0xff, 0xff][..];
        assert!(matches!(
            read_frame(&mut r).await,
            Err(FrameError::TooBig(_))
        ));
    }

    #[tokio::test]
    async fn truncation_is_an_error() {
        let mut r = &[0, 0][..];
        assert!(
            matches!(read_frame(&mut r).await, Err(FrameError::Truncated)),
            "half a length"
        );
        let mut r = &[0, 0, 0, 5, b'h', b'i'][..];
        assert!(
            matches!(read_frame(&mut r).await, Err(FrameError::Truncated)),
            "short body"
        );
        let mut r = &[4, b'p', b'i'][..];
        assert!(
            matches!(read_tag(&mut r).await, Err(FrameError::Truncated)),
            "short tag"
        );
    }

    #[tokio::test]
    async fn bad_tags() {
        let mut sink = Vec::new();
        for tag in ["", "has space", "é", &"x".repeat(MAX_TAG + 1)] {
            assert!(
                matches!(write_tag(&mut sink, tag).await, Err(FrameError::BadTag)),
                "{tag:?}"
            );
        }
        assert!(write_tag(&mut sink, &"x".repeat(MAX_TAG)).await.is_ok());
        for bytes in [&[0u8][..], &[33u8][..], &[2, b'a', 0x07][..]] {
            let mut r = bytes;
            assert!(
                matches!(read_tag(&mut r).await, Err(FrameError::BadTag)),
                "{bytes:?}"
            );
        }
    }
}
