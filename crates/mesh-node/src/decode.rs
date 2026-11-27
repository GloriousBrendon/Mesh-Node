//! Capped decoding of a friend's profile files (SPEC-profile PR8): a
//! picture or a song from someone else is untrusted input. Only Rust's
//! memory-safe decoders (`image`, `symphonia`, and libopus through the
//! `opus` crate calls already use), and every limit is checked from the
//! file's header before anything is allocated, then again while decoding.
//! Whatever breaks a limit is an error, which Aflos shows as a placeholder.

use std::io::Cursor;

use image::{AnimationDecoder, ImageDecoder, ImageFormat, ImageReader, Limits, RgbaImage};

/// Pixels on a side, a frame (PR8).
pub const MAX_SIDE: u32 = 4096;
/// Frames in an animation (PR8).
pub const MAX_FRAMES: usize = 300;
/// An animation's length, one loop, in milliseconds (PR8).
pub const MAX_ANIMATION_MS: u64 = 30_000;
/// Decoded bytes, all of a picture's frames together (PR8): 64 MB.
pub const MAX_DECODED: u64 = 64 * 1024 * 1024;
/// A song's length: PR7's 6 minutes (`mesh_dm::profile::MAX_SONG_SECONDS`),
/// and a little over for encoders' padding.
pub const MAX_SONG_SECONDS: u64 = 6 * 60 + 2;
/// The rate Aflos plays songs at, and Opus decodes at.
const OPUS_RATE: u32 = 48_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("the file isn't a {0}")]
    NotThatKind(&'static str),
    #[error("the picture is bigger than 4096 pixels on a side")]
    TooWide,
    #[error("the animation has more than 300 frames")]
    TooManyFrames,
    #[error("the animation is longer than 30 seconds")]
    TooLongAnimation,
    #[error("the picture takes more than 64 MB to show")]
    TooMuchMemory,
    #[error("the song is longer than 6 minutes")]
    TooLongSong,
    #[error("the file is damaged: {0}")]
    Damaged(String),
}

/// One frame: its pixels and how long it shows (0 for a still picture).
pub struct Frame {
    pub rgba: RgbaImage,
    pub delay_ms: u64,
}

/// A decoded picture: one frame, or an animation's frames in order.
pub struct Picture {
    pub width: u32,
    pub height: u32,
    pub frames: Vec<Frame>,
}

/// A decoded song: interleaved 16-bit samples, one or two channels.
#[derive(Debug)]
pub struct Song {
    pub rate: u32,
    pub channels: u16,
    pub samples: Vec<i16>,
}

impl Song {
    pub fn seconds(&self) -> f64 {
        self.samples.len() as f64 / f64::from(self.channels) / f64::from(self.rate)
    }
}

fn damaged(e: impl std::fmt::Display) -> DecodeError {
    DecodeError::Damaged(e.to_string())
}

fn limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_DECODED);
    limits
}

/// What a declared kind of picture must be (the manifest's `mime`): the
/// bytes have to agree with it, so a file can't pose as another kind.
fn format_of(mime: &str) -> Option<ImageFormat> {
    Some(match mime {
        "image/png" | "image/apng" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/webp" => ImageFormat::WebP,
        "image/gif" => ImageFormat::Gif,
        _ => return None,
    })
}

/// Decodes a picture declared as `mime`, within every limit.
pub fn picture(bytes: &[u8], mime: &str) -> Result<Picture, DecodeError> {
    let declared = format_of(mime).ok_or(DecodeError::NotThatKind("picture"))?;
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(damaged)?;
    if reader.format() != Some(declared) {
        return Err(DecodeError::NotThatKind("picture of the kind it says"));
    }
    // The header first: a 1-pixel file claiming 100,000 pixels a side stops
    // here, before any pixels are made.
    let (width, height) = reader.into_dimensions().map_err(damaged)?;
    if width > MAX_SIDE || height > MAX_SIDE || width == 0 || height == 0 {
        return Err(DecodeError::TooWide);
    }
    let frame_bytes = u64::from(width) * u64::from(height) * 4;
    if frame_bytes > MAX_DECODED {
        return Err(DecodeError::TooMuchMemory);
    }
    let cursor = Cursor::new(bytes);
    match declared {
        ImageFormat::Gif => {
            let mut d = image::codecs::gif::GifDecoder::new(cursor).map_err(damaged)?;
            d.set_limits(limits()).map_err(limit_error)?;
            frames(d, width, height)
        }
        ImageFormat::Png => {
            let mut d = image::codecs::png::PngDecoder::new(cursor).map_err(damaged)?;
            d.set_limits(limits()).map_err(limit_error)?;
            if d.is_apng().map_err(damaged)? {
                frames(d.apng().map_err(damaged)?, width, height)
            } else {
                still(d, width, height)
            }
        }
        ImageFormat::WebP => {
            let mut d = image::codecs::webp::WebPDecoder::new(cursor).map_err(damaged)?;
            d.set_limits(limits()).map_err(limit_error)?;
            if d.has_animation() {
                frames(d, width, height)
            } else {
                still(d, width, height)
            }
        }
        _ => {
            let mut d = image::codecs::jpeg::JpegDecoder::new(cursor).map_err(damaged)?;
            d.set_limits(limits()).map_err(limit_error)?;
            still(d, width, height)
        }
    }
}

fn limit_error(e: image::ImageError) -> DecodeError {
    match e {
        image::ImageError::Limits(_) => DecodeError::TooMuchMemory,
        e => damaged(e),
    }
}

fn still(d: impl ImageDecoder, width: u32, height: u32) -> Result<Picture, DecodeError> {
    let image = image::DynamicImage::from_decoder(d).map_err(limit_error)?;
    if image.width() != width || image.height() != height {
        return Err(damaged("its size changed while decoding"));
    }
    Ok(Picture {
        width,
        height,
        frames: vec![Frame {
            rgba: image.to_rgba8(),
            delay_ms: 0,
        }],
    })
}

/// An animation's frames, one at a time, stopping at the first limit.
fn frames<'a>(
    d: impl AnimationDecoder<'a>,
    width: u32,
    height: u32,
) -> Result<Picture, DecodeError> {
    let frame_bytes = u64::from(width) * u64::from(height) * 4;
    let mut out = Vec::new();
    let mut total_ms = 0u64;
    for frame in d.into_frames() {
        let frame = frame.map_err(limit_error)?;
        if out.len() == MAX_FRAMES {
            return Err(DecodeError::TooManyFrames);
        }
        if (out.len() as u64 + 1) * frame_bytes > MAX_DECODED {
            return Err(DecodeError::TooMuchMemory);
        }
        let (numer, denom) = frame.delay().numer_denom_ms();
        let delay_ms = u64::from(numer) / u64::from(denom.max(1));
        total_ms += delay_ms;
        if total_ms > MAX_ANIMATION_MS {
            return Err(DecodeError::TooLongAnimation);
        }
        let rgba = frame.into_buffer();
        if rgba.width() != width || rgba.height() != height {
            return Err(damaged("a frame isn't the picture's size"));
        }
        out.push(Frame { rgba, delay_ms });
    }
    if out.is_empty() {
        return Err(damaged("no frames"));
    }
    Ok(Picture {
        width,
        height,
        frames: out,
    })
}

/// Decodes a song declared as `mime` (Q4: Opus or Vorbis in Ogg, MP3,
/// FLAC), within 6 minutes. More than two channels are mixed to two.
pub fn song(bytes: &[u8], mime: &str) -> Result<Song, DecodeError> {
    use symphonia::core::codecs::{
        CODEC_TYPE_FLAC, CODEC_TYPE_MP3, CODEC_TYPE_OPUS, CODEC_TYPE_VORBIS, DecoderOptions,
    };
    use symphonia::core::errors::Error;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;
    use symphonia::core::probe::Hint;

    let (extension, codecs): (&str, &[_]) = match mime {
        "audio/ogg" => ("ogg", &[CODEC_TYPE_OPUS, CODEC_TYPE_VORBIS]),
        "audio/mpeg" => ("mp3", &[CODEC_TYPE_MP3]),
        "audio/flac" => ("flac", &[CODEC_TYPE_FLAC]),
        _ => return Err(DecodeError::NotThatKind("song")),
    };
    let stream = MediaSourceStream::new(Box::new(Cursor::new(bytes.to_vec())), Default::default());
    let mut hint = Hint::new();
    hint.with_extension(extension);
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            stream,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|_| DecodeError::NotThatKind("song"))?;
    let mut format = probed.format;
    let track = format
        .default_track()
        .ok_or(DecodeError::NotThatKind("song"))?
        .clone();
    let params = &track.codec_params;
    if !codecs.contains(&params.codec) {
        return Err(DecodeError::NotThatKind("song of the kind it says"));
    }
    let opus = params.codec == CODEC_TYPE_OPUS;
    let rate = if opus {
        OPUS_RATE
    } else {
        params
            .sample_rate
            .ok_or_else(|| damaged("no sample rate"))?
    };
    let source_channels = params
        .channels
        .map_or(if opus { 2 } else { 0 }, |c| c.count());
    if rate == 0 || !(1..=8).contains(&source_channels) {
        return Err(damaged("no channels"));
    }
    let channels = source_channels.min(2);
    // What the header says first; then the decoded length, since a header
    // can leave its length out or lie.
    if let Some(n) = params.n_frames
        && n / u64::from(rate) > MAX_SONG_SECONDS
    {
        return Err(DecodeError::TooLongSong);
    }
    let cap = MAX_SONG_SECONDS * u64::from(rate) * channels as u64;

    let mut samples: Vec<i16> = Vec::new();
    let mut push = |interleaved: &[f32], from: usize| -> Result<(), DecodeError> {
        for frame in interleaved.chunks(from) {
            if from > 2 && channels == 2 {
                // Odd channels left, even right.
                let (mut l, mut r) = (0.0, 0.0);
                for (i, s) in frame.iter().enumerate() {
                    if i % 2 == 0 { l += s } else { r += s }
                }
                let half = (from as f32 / 2.0).max(1.0);
                samples.push(to_i16(l / half));
                samples.push(to_i16(r / half));
            } else {
                samples.extend(frame.iter().take(channels).map(|s| to_i16(*s)));
            }
            if samples.len() as u64 > cap {
                return Err(DecodeError::TooLongSong);
            }
        }
        Ok(())
    };

    if opus {
        let layout = if source_channels == 1 {
            opus::Channels::Mono
        } else {
            opus::Channels::Stereo
        };
        let from = if source_channels == 1 { 1 } else { 2 };
        let mut decoder = opus::Decoder::new(OPUS_RATE, layout).map_err(damaged)?;
        // The longest Opus packet: 120 ms.
        let mut pcm = vec![0f32; 5760 * from];
        loop {
            let packet = match format.next_packet() {
                Ok(p) => p,
                Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(damaged(e)),
            };
            if packet.track_id() != track.id {
                continue;
            }
            let n = decoder
                .decode_float(&packet.data, &mut pcm, false)
                .map_err(damaged)?;
            push(&pcm[..n * from], from)?;
        }
    } else {
        use symphonia::core::audio::SampleBuffer;
        let mut decoder = symphonia::default::get_codecs()
            .make(params, &DecoderOptions::default())
            .map_err(damaged)?;
        let mut buffer: Option<SampleBuffer<f32>> = None;
        loop {
            let packet = match format.next_packet() {
                Ok(p) => p,
                Err(Error::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(damaged(e)),
            };
            if packet.track_id() != track.id {
                continue;
            }
            let decoded = match decoder.decode(&packet) {
                Ok(d) => d,
                // A damaged packet is skipped, as players do.
                Err(Error::DecodeError(_)) => continue,
                Err(e) => return Err(damaged(e)),
            };
            let spec = *decoded.spec();
            let from = spec.channels.count();
            if spec.rate != rate || from != source_channels {
                return Err(damaged("its format changed partway"));
            }
            let buf = match &mut buffer {
                Some(b) if b.capacity() >= decoded.capacity() => b,
                _ => buffer.insert(SampleBuffer::new(decoded.capacity() as u64, spec)),
            };
            buf.copy_interleaved_ref(decoded);
            push(buf.samples(), from)?;
        }
    }
    if samples.is_empty() {
        return Err(damaged("no sound"));
    }
    Ok(Song {
        rate,
        channels: channels as u16,
        samples,
    })
}

fn to_i16(s: f32) -> i16 {
    (s.clamp(-1.0, 1.0) * f32::from(i16::MAX)) as i16
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::gif::GifEncoder;
    use image::{Delay, Rgba};
    use std::time::{Duration, Instant};

    const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/media/");

    fn media(name: &str) -> Vec<u8> {
        std::fs::read(format!("{MEDIA}{name}")).unwrap()
    }

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::new();
        RgbaImage::from_pixel(w, h, Rgba([216, 143, 146, 255]))
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    fn gif(frames: usize, w: u32, h: u32, delay_ms: u32) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = GifEncoder::new(&mut out);
            let frames = (0..frames).map(|i| {
                let px = Rgba([(i % 256) as u8, 0, 0, 255]);
                image::Frame::from_parts(
                    RgbaImage::from_pixel(w, h, px),
                    0,
                    0,
                    Delay::from_numer_denom_ms(delay_ms, 1),
                )
            });
            enc.encode_frames(frames).unwrap();
        }
        out
    }

    /// The table-driven CRC-32 PNG chunks carry, to forge a header.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for b in bytes {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A real 1×1 PNG whose header claims `w`×`h`, with a valid checksum.
    fn png_claiming(w: u32, h: u32) -> Vec<u8> {
        let mut bytes = png(1, 1);
        // Signature (8), length (4), then "IHDR" and width, height.
        bytes[16..20].copy_from_slice(&w.to_be_bytes());
        bytes[20..24].copy_from_slice(&h.to_be_bytes());
        let crc = crc32(&bytes[12..29]);
        bytes[29..33].copy_from_slice(&crc.to_be_bytes());
        bytes
    }

    fn quick<T>(f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let out = f();
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "took {:?}",
            start.elapsed()
        );
        out
    }

    #[test]
    fn a_still_picture() {
        let p = picture(&png(3, 2), "image/png").unwrap();
        assert_eq!((p.width, p.height, p.frames.len()), (3, 2, 1));
        assert_eq!(
            p.frames[0].rgba.get_pixel(0, 0),
            &Rgba([216, 143, 146, 255])
        );
    }

    #[test]
    fn an_animation_keeps_its_frames_and_timing() {
        let p = picture(&gif(5, 4, 4, 100), "image/gif").unwrap();
        assert_eq!(p.frames.len(), 5);
        assert!(p.frames.iter().all(|f| f.delay_ms == 100));
    }

    #[test]
    fn the_kind_must_match_what_it_says() {
        assert_eq!(
            picture(&png(1, 1), "image/gif").err(),
            Some(DecodeError::NotThatKind("picture of the kind it says"))
        );
        assert_eq!(
            picture(&png(1, 1), "image/svg+xml").err(),
            Some(DecodeError::NotThatKind("picture"))
        );
        assert!(matches!(
            picture(b"not a picture", "image/png"),
            Err(DecodeError::NotThatKind(_))
        ));
    }

    #[test]
    fn a_header_bomb_stops_at_the_header() {
        let bomb = png_claiming(100_000, 100_000);
        assert_eq!(
            quick(|| picture(&bomb, "image/png").err()),
            Some(DecodeError::TooWide)
        );
        // Within the side limit but past 64 MB: 4096 × 4096 × 4 is exactly 64 MiB.
        assert!(
            picture(&png_claiming(4096, 4096), "image/png").is_err(),
            "a forged 1×1 still fails"
        );
        assert_eq!(
            picture(&png_claiming(4097, 10), "image/png").err(),
            Some(DecodeError::TooWide)
        );
    }

    #[test]
    fn a_gif_claiming_a_huge_canvas() {
        let mut bomb = gif(1, 1, 1, 100);
        // The logical screen's width and height, right after "GIF89a".
        bomb[6..10].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            quick(|| picture(&bomb, "image/gif").err()),
            Some(DecodeError::TooWide)
        );
    }

    #[test]
    fn too_many_frames() {
        let ok = picture(&gif(MAX_FRAMES, 1, 1, 10), "image/gif").unwrap();
        assert_eq!(ok.frames.len(), MAX_FRAMES);
        let many = gif(10_000, 1, 1, 0);
        assert_eq!(
            picture(&many, "image/gif").err(),
            Some(DecodeError::TooManyFrames)
        );
    }

    #[test]
    fn too_long_an_animation() {
        assert!(
            picture(&gif(30, 1, 1, 1000), "image/gif").is_ok(),
            "30 s exactly"
        );
        assert_eq!(
            picture(&gif(31, 1, 1, 1000), "image/gif").err(),
            Some(DecodeError::TooLongAnimation)
        );
    }

    #[test]
    fn frames_that_together_take_too_much_memory() {
        // 1024 × 1024 × 4 = 4 MiB a frame: 16 fit in 64 MiB, the 17th doesn't.
        assert!(picture(&gif(16, 1024, 1024, 10), "image/gif").is_ok());
        assert_eq!(
            picture(&gif(17, 1024, 1024, 10), "image/gif").err(),
            Some(DecodeError::TooMuchMemory)
        );
    }

    #[test]
    fn songs_of_each_kind() {
        for (file, mime, channels) in [
            ("song.opus.ogg", "audio/ogg", 2),
            ("song.vorbis.ogg", "audio/ogg", 1),
            ("song.mp3", "audio/mpeg", 1),
            ("song.flac", "audio/flac", 1),
        ] {
            let s = song(&media(file), mime).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(s.channels, channels, "{file}");
            assert!(
                (0.9..1.2).contains(&s.seconds()),
                "{file}: {} s",
                s.seconds()
            );
            assert!(
                s.samples.iter().any(|x| x.unsigned_abs() > 1000),
                "{file} is silent"
            );
        }
    }

    #[test]
    fn a_song_must_be_what_it_says() {
        assert_eq!(
            song(&media("song.flac"), "audio/mpeg").err(),
            Some(DecodeError::NotThatKind("song of the kind it says"))
        );
        assert_eq!(
            song(&media("song.flac"), "audio/wav").err(),
            Some(DecodeError::NotThatKind("song"))
        );
        assert!(matches!(
            song(&png(1, 1), "audio/flac"),
            Err(DecodeError::NotThatKind(_))
        ));
    }

    #[test]
    fn a_long_song_stops_at_its_header() {
        // 6 minutes 10 seconds of silence, 8 kHz mono.
        let long = media("long.flac");
        assert_eq!(
            quick(|| song(&long, "audio/flac").err()),
            Some(DecodeError::TooLongSong)
        );
    }

    #[test]
    fn a_long_song_whose_header_hides_its_length() {
        let mut long = media("long.flac");
        // STREAMINFO's 36-bit total, after "fLaC" and the block header: 0 means unknown.
        long[8 + 13] &= 0xf0;
        long[8 + 14..8 + 18].fill(0);
        assert_eq!(
            song(&long, "audio/flac").err(),
            Some(DecodeError::TooLongSong)
        );
    }
}
