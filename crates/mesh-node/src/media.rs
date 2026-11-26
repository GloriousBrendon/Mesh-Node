//! A call's audio (SPEC-calls C1, C2, C5, C10): our voice, gated and
//! Opus-encoded, goes as a datagram to every device in the call; each
//! device's datagrams wait in their own jitter buffer, and the decoded
//! streams are mixed and played.
//!
//! A datagram is `[MEDIA][call id 8][seq 4, big-endian][opus]`. The sequence
//! counts every 20 ms frame, sent or not, so a gap is a loss (concealed) or a
//! silence (the buffer runs dry and waits to fill again). It's 4 bytes, not
//! the spec's 2, so it never wraps in a call.
//!
//! Tests replace the microphone with a tone (`--tone`) and the speakers with
//! a file of what was played (`--heard`), and can drop incoming datagrams
//! (`--drop`). No audio, device name or ID reaches the log.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opus::{Application, Bitrate, Channels, Decoder, Encoder};

use crate::audio::{self, FRAME_SAMPLES, SAMPLE_RATE};

/// A datagram's first byte: call media (C2).
pub const MEDIA: u8 = 1;
/// Opus at 32 kbit/s (Q6).
const BITRATE: i32 = 32_000;
/// Frames a buffer holds before it starts playing (60 ms, C5).
const JITTER_START: usize = 3;
/// Frames it may grow to on a late path (200 ms).
const JITTER_MAX: usize = 10;
/// Frames past `next` kept at most; older ones are dropped.
const JITTER_HOLD: usize = 50;
/// Loud enough to count as speaking (an RMS in `i16` units).
const SPEAKING_RMS: f64 = 500.0;
/// The quietest the voice gate opens for, whatever the room (about −55
/// dBFS). It was `SPEAKING_RMS` in 0.5.0, which cut off a quiet mic's
/// speech entirely; the room's noise floor (×3) does the real work.
const GATE_MIN: f64 = 60.0;
/// How long someone stays "speaking" after their last loud frame, and how
/// long the gate stays open after ours.
const HANGOVER: Duration = Duration::from_millis(300);
/// Played audio queued for the speakers at most (200 ms): past it, the
/// oldest goes, so a stalled device can't make the call lag.
const PLAYBACK_MAX: usize = FRAME_SAMPLES * 10;

/// Where the audio comes from and goes to.
#[derive(Debug, Clone, Default)]
pub struct Io {
    /// Microphone and speakers by name; `None` is the system's default.
    pub input: Option<String>,
    pub output: Option<String>,
    /// `--tone <hz>`: a sine wave instead of the microphone.
    pub tone: Option<f32>,
    /// `--heard <file>`: what's played, appended as raw 48 kHz mono `i16`
    /// (little-endian), instead of the speakers.
    pub heard: Option<PathBuf>,
    /// `--drop <percent>`: incoming datagrams dropped (spec test 5).
    pub drop: u8,
}

/// What the media tasks share with the call.
struct Shared {
    call: [u8; 8],
    /// The devices in the call with us: we send to these and play only them.
    peers: Mutex<HashSet<[u8; 32]>>,
    muted: AtomicBool,
    deafened: AtomicBool,
    /// Push-to-talk (C10): `PTT_OFF` (the voice gate), `PTT_UP` or `PTT_DOWN`.
    ptt: std::sync::atomic::AtomicU8,
    /// Input volume, in percent (SPEC-audio A3): 100 leaves the mic as it is.
    gain: std::sync::atomic::AtomicU32,
    /// The switches and sensitivity (SPEC-audio A3), changed live.
    audio: Mutex<Audio>,
    /// Told the mic's level (dBFS) and whether it goes out (A5).
    level: Box<dyn Fn(f32, bool) + Send + Sync>,
    /// Each peer device's volume, in percent, where it isn't 100 (A6).
    volumes: Mutex<HashMap<[u8; 32], u32>>,
}

impl Shared {
    fn new(call: [u8; 8], level: impl Fn(f32, bool) + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            call,
            peers: Mutex::new(HashSet::new()),
            muted: AtomicBool::new(false),
            deafened: AtomicBool::new(false),
            ptt: std::sync::atomic::AtomicU8::new(PTT_OFF),
            gain: std::sync::atomic::AtomicU32::new(100),
            audio: Mutex::new(Audio::default()),
            level: Box::new(level),
            volumes: Mutex::new(HashMap::new()),
        })
    }
}

/// The mic, or a test's tone (which noise suppression would take out).
fn mic(
    io: &Io,
    stop: &Arc<AtomicBool>,
) -> Result<(Frames, Option<audio::CaptureHandle>, Option<Denoise>), String> {
    Ok(match io.tone {
        Some(hz) => (tone(hz, stop.clone()), None, None),
        None => {
            let (handle, rx) = audio::start_capture(io.input.clone())?;
            (rx, Some(handle), Some(Denoise::new()))
        }
    })
}

/// The speakers, or a test's file.
fn speakers(io: &Io) -> Result<(Sink, Option<audio::PlaybackHandle>), String> {
    Ok(match &io.heard {
        Some(path) => (Sink::File(path.clone()), None),
        None => {
            let (handle, buffer) = audio::start_playback(io.output.clone())?;
            (Sink::Device(buffer), Some(handle))
        }
    })
}

/// Frames the mic test plays back late (0.5 s).
const TEST_LATE: usize = 25;

/// What the mic goes through, as the person set it (SPEC-audio A3).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Audio {
    pub echo: bool,
    pub noise: bool,
    pub gain: bool,
    /// A manual gate threshold in dBFS; `None` is Automatic (A4).
    pub threshold: Option<f32>,
    /// What we hear, in percent (A3).
    pub output: u32,
}

impl Default for Audio {
    fn default() -> Self {
        Self {
            echo: true,
            noise: true,
            gain: true,
            threshold: None,
            output: 100,
        }
    }
}

pub const PTT_OFF: u8 = 0;
pub const PTT_UP: u8 = 1;
pub const PTT_DOWN: u8 = 2;

/// A call's running audio. Dropping it stops everything.
pub struct Media {
    shared: Arc<Shared>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    _capture: Option<audio::CaptureHandle>,
    _playback: Option<audio::PlaybackHandle>,
}

impl Drop for Media {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Media {
    /// Starts capture, sending, receiving and playback for `call`.
    /// `speaking` hears who's speaking (device keys, ours included) when it
    /// changes.
    pub fn start(
        node: crate::nodes::Nodes,
        call: [u8; 8],
        me: [u8; 32],
        io: &Io,
        speaking: impl Fn(Vec<[u8; 32]>) + Send + 'static,
        level: impl Fn(f32, bool) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let shared = Shared::new(call, level);
        let stop = Arc::new(AtomicBool::new(false));
        let (frames, capture, denoise) = mic(io, &stop)?;
        let (sink, playback) = speakers(io)?;
        let mut encoder = Encoder::new(SAMPLE_RATE, Channels::Mono, Application::Voip)
            .map_err(|e| format!("opus: {e}"))?;
        encoder
            .set_bitrate(Bitrate::Bits(BITRATE))
            .and_then(|()| encoder.set_inband_fec(true))
            .and_then(|()| encoder.set_packet_loss_perc(10))
            .map_err(|e| format!("opus: {e}"))?;
        let us = Arc::new(Mutex::new(Speakers::default()));
        let (played_tx, played_rx) = tokio::sync::mpsc::unbounded_channel();
        let jitter: Arc<Mutex<HashMap<[u8; 32], Jitter>>> = Arc::default();
        let tasks = vec![
            tokio::spawn(send(
                node.clone(),
                shared.clone(),
                frames,
                Chain::new(denoise, played_rx),
                encoder,
                me,
                us.clone(),
            )),
            tokio::spawn(receive(node, shared.clone(), jitter.clone(), io.drop)),
            tokio::spawn(mix(
                shared.clone(),
                jitter,
                sink,
                played_tx,
                me,
                us,
                speaking,
            )),
        ];
        Ok(Self {
            shared,
            tasks,
            stop,
            _capture: capture,
            _playback: playback,
        })
    }

    /// The mic test (SPEC-audio A5): the mic through the whole chain, its
    /// level reported, sent nowhere; with `hear`, played back half a second
    /// late. Stops when dropped.
    pub fn test(
        io: &Io,
        hear: bool,
        level: impl Fn(f32, bool) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let shared = Shared::new([0; 8], level);
        let stop = Arc::new(AtomicBool::new(false));
        let (frames, capture, denoise) = mic(io, &stop)?;
        let (played_tx, played_rx) = tokio::sync::mpsc::unbounded_channel();
        let (sink, playback) = match hear {
            true => {
                let (sink, handle) = speakers(io)?;
                (Some((sink, played_tx)), handle)
            }
            false => (None, None),
        };
        let chain = Chain::new(denoise, played_rx);
        let tasks = vec![tokio::spawn(test(shared.clone(), frames, chain, sink))];
        Ok(Self {
            shared,
            tasks,
            stop,
            _capture: capture,
            _playback: playback,
        })
    }

    /// The devices in the call with us now.
    pub fn set_peers(&self, devices: impl IntoIterator<Item = [u8; 32]>) {
        *lock(&self.shared.peers) = devices.into_iter().collect();
    }

    pub fn set_muted(&self, on: bool) {
        self.shared.muted.store(on, Ordering::Relaxed);
    }

    pub fn set_deafened(&self, on: bool) {
        self.shared.deafened.store(on, Ordering::Relaxed);
    }

    pub fn set_ptt(&self, mode: u8) {
        self.shared.ptt.store(mode, Ordering::Relaxed);
    }

    /// Each peer device's volume, in percent (SPEC-audio A6); a device
    /// left out is at 100.
    pub fn set_volumes(&self, volumes: HashMap<[u8; 32], u32>) {
        *lock(&self.shared.volumes) = volumes;
    }

    /// The switches and sensitivity, from the next frame on.
    pub fn set_audio(&self, audio: Audio) {
        *lock(&self.shared.audio) = audio;
    }

    /// Input volume, 0 to 200 percent.
    pub fn set_gain(&self, percent: u32) {
        self.shared
            .gain
            .store(percent.min(MAX_GAIN), Ordering::Relaxed);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A sine wave at `hz`, a 20 ms frame every 20 ms, for tests.
fn tone(hz: f32, stop: Arc<AtomicBool>) -> tokio::sync::mpsc::UnboundedReceiver<Vec<i16>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        let mut n = 0u64;
        while !stop.load(Ordering::Relaxed) {
            tick.tick().await;
            let frame: Vec<i16> = (0..FRAME_SAMPLES)
                .map(|i| {
                    let t = (n + i as u64) as f32 / SAMPLE_RATE as f32;
                    ((t * hz * std::f32::consts::TAU).sin() * 8000.0) as i16
                })
                .collect();
            n += FRAME_SAMPLES as u64;
            if tx.send(frame).is_err() {
                break;
            }
        }
    });
    rx
}

/// Our microphone's 20 ms frames.
type Frames = tokio::sync::mpsc::UnboundedReceiver<Vec<i16>>;
/// What the mix played, with how long it'll take to reach the speakers
/// (ms): the echo canceller's far end (SPEC-audio A1).
type Played = tokio::sync::mpsc::UnboundedReceiver<(Vec<i16>, i32)>;
/// Where the mix (or the mic test) says what it played.
type PlayedTx = tokio::sync::mpsc::UnboundedSender<(Vec<i16>, i32)>;
/// A device's own delay past our queue, about (ms).
const DEVICE_DELAY_MS: i32 = 20;

/// Noise suppression on our microphone (Q2): RNNoise, on each 20 ms frame's
/// two 10 ms halves. Its first output is silent (its own delay).
struct Denoise(Box<nnnoiseless::DenoiseState<'static>>);

impl Denoise {
    fn new() -> Self {
        Self(nnnoiseless::DenoiseState::new())
    }

    fn frame(&mut self, frame: &[i16]) -> Vec<i16> {
        let mut out = Vec::with_capacity(frame.len());
        let mut half = [0f32; nnnoiseless::FRAME_SIZE];
        for chunk in frame.chunks(nnnoiseless::FRAME_SIZE) {
            if chunk.len() < nnnoiseless::FRAME_SIZE {
                out.extend_from_slice(chunk);
                continue;
            }
            // It takes and gives `i16`'s range as floats.
            let input: Vec<f32> = chunk.iter().map(|&s| f32::from(s)).collect();
            self.0.process_frame(&mut half, &input);
            out.extend(half.iter().map(|s| s.clamp(-32768.0, 32767.0) as i16));
        }
        out
    }
}

/// The highest input volume, in percent.
pub const MAX_GAIN: u32 = 200;

/// `frame` at `percent` volume, clipped to `i16`.
fn scale(frame: &mut [i16], percent: u32) {
    if percent == 100 {
        return;
    }
    for s in frame.iter_mut() {
        let v = i32::from(*s) * percent as i32 / 100;
        *s = v.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
    }
}

/// The frames heard, each at its device's volume, summed, at `output`
/// (SPEC-audio A3, A6).
fn mix_at(
    frames: &[([u8; 32], Vec<i16>)],
    volumes: &HashMap<[u8; 32], u32>,
    output: u32,
) -> Vec<i16> {
    let scaled: Vec<Vec<i16>> = (frames.iter())
        .map(|(device, f)| {
            let mut f = f.clone();
            scale(&mut f, volumes.get(device).copied().unwrap_or(100));
            f
        })
        .collect();
    let mut out = mixed(scaled.iter().map(Vec::as_slice));
    scale(&mut out, output);
    out
}

fn rms(frame: &[i16]) -> f64 {
    let sum: f64 = frame.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
    (sum / frame.len().max(1) as f64).sqrt()
}

/// The voice gate (C10): open while the level is well above the room's
/// noise, and for `HANGOVER` after.
#[derive(Debug)]
struct Gate {
    floor: f64,
    open_until: Option<Instant>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            floor: 200.0,
            open_until: None,
        }
    }
}

impl Gate {
    /// Whether a frame at `level` goes out: above the room's noise
    /// (Automatic), or above `threshold` dBFS (manual, A4).
    fn pass(&mut self, level: f64, now: Instant, threshold: Option<f32>) -> bool {
        // The floor follows quiet at once and noise slowly.
        self.floor = if level < self.floor {
            level.max(20.0)
        } else {
            self.floor * 1.002
        };
        let at = match threshold {
            Some(db) => 32768.0 * 10f64.powf(f64::from(db) / 20.0),
            None => (self.floor * 3.0).max(GATE_MIN),
        };
        if level > at {
            self.open_until = Some(now + HANGOVER);
        }
        self.open_until.is_some_and(|until| now < until)
    }
}

/// Who's been loud lately, by device.
#[derive(Default)]
struct Speakers {
    last_loud: HashMap<[u8; 32], Instant>,
}

impl Speakers {
    fn now(&self, now: Instant) -> Vec<[u8; 32]> {
        let mut who: Vec<[u8; 32]> = (self.last_loud.iter())
            .filter(|(_, at)| now.duration_since(**at) < HANGOVER)
            .map(|(d, _)| *d)
            .collect();
        who.sort();
        who
    }
}

/// Our frames: gated, encoded, and sent to every peer device.
/// The mic's way to the encoder (SPEC-audio A1), the same in a call and
/// in the mic test: echo and high-pass, noise, gain, volume, the gate; and
/// the level, reported about 15 times a second.
struct Chain {
    gate: Gate,
    processing: crate::processing::Processing,
    agc: crate::processing::Gain,
    denoise: Option<Denoise>,
    played: Played,
    delay: i32,
    frames: u32,
}

impl Chain {
    fn new(denoise: Option<Denoise>, played: Played) -> Self {
        Self {
            gate: Gate::default(),
            processing: crate::processing::Processing::new(),
            agc: crate::processing::Gain::new(),
            denoise,
            played,
            delay: DEVICE_DELAY_MS,
            frames: 0,
        }
    }

    /// Processes `frame` in place; whether it goes out.
    fn step(&mut self, frame: &mut Vec<i16>, shared: &Shared, now: Instant) -> bool {
        // What was played since, first, so the canceller knows the far end.
        while let Ok((far, at)) = self.played.try_recv() {
            self.processing.render(&far);
            self.delay = at;
        }
        let audio = *lock(&shared.audio);
        if audio.echo {
            self.processing.capture(frame, self.delay);
        }
        if let Some(d) = self.denoise.as_mut().filter(|_| audio.noise) {
            *frame = d.frame(frame);
        }
        if audio.gain {
            self.agc.process(frame);
        }
        scale(frame, shared.gain.load(Ordering::Relaxed));
        // Push-to-talk sends while the key is held, whatever the level;
        // otherwise the gate decides.
        let level = rms(frame);
        let open = match shared.ptt.load(Ordering::Relaxed) {
            PTT_DOWN => true,
            PTT_UP => false,
            _ => self.gate.pass(level, now, audio.threshold),
        };
        self.frames = self.frames.wrapping_add(1);
        if self.frames.is_multiple_of(3) {
            let db = 20.0 * (level.max(1.0) / 32768.0).log10();
            (shared.level)(db as f32, open && !shared.muted.load(Ordering::Relaxed));
        }
        open
    }
}

/// Our frames: processed, gated, encoded, and sent to every peer device.
async fn send(
    node: crate::nodes::Nodes,
    shared: Arc<Shared>,
    mut frames: Frames,
    mut chain: Chain,
    mut encoder: Encoder,
    me: [u8; 32],
    us: Arc<Mutex<Speakers>>,
) {
    let mut seq: u32 = 0;
    let mut out = vec![0u8; 1500];
    while let Some(mut frame) = frames.recv().await {
        seq = seq.wrapping_add(1);
        let now = Instant::now();
        let open = chain.step(&mut frame, &shared, now);
        if shared.muted.load(Ordering::Relaxed) || !open {
            continue;
        }
        lock(&us).last_loud.insert(me, now);
        let Ok(len) = encoder.encode(&frame, &mut out) else {
            continue;
        };
        let mut datagram = Vec::with_capacity(13 + len);
        datagram.push(MEDIA);
        datagram.extend_from_slice(&shared.call);
        datagram.extend_from_slice(&seq.to_be_bytes());
        datagram.extend_from_slice(&out[..len]);
        let peers: Vec<[u8; 32]> = lock(&shared.peers).iter().copied().collect();
        for device in peers {
            if let Some(addr) = mesh_transport::MeshAddr::from_device(&device) {
                node.send_datagram(&addr.device, datagram.clone());
            }
        }
    }
}

/// The mic test (SPEC-audio A5): the chain with nobody to send to; what it
/// lets out plays back half a second late if `hear`.
async fn test(
    shared: Arc<Shared>,
    mut frames: Frames,
    mut chain: Chain,
    sink: Option<(Sink, PlayedTx)>,
) {
    let mut late: std::collections::VecDeque<Vec<i16>> = std::collections::VecDeque::new();
    while let Some(mut frame) = frames.recv().await {
        let open = chain.step(&mut frame, &shared, Instant::now());
        let Some((sink, played)) = &sink else {
            continue;
        };
        late.push_back(if open { frame } else { vec![0; FRAME_SAMPLES] });
        if late.len() > TEST_LATE {
            let frame = late.pop_front().expect("over the limit");
            let delay = sink.play(&frame);
            let _ = played.send((frame, delay));
        }
    }
}

/// Parses a media datagram: its call and sequence number, and the Opus.
pub fn parse(datagram: &[u8]) -> Option<([u8; 8], u32, &[u8])> {
    if datagram.len() < 13 || datagram[0] != MEDIA {
        return None;
    }
    let call = datagram[1..9].try_into().ok()?;
    let seq = u32::from_be_bytes(datagram[9..13].try_into().ok()?);
    Some((call, seq, &datagram[13..]))
}

/// Peers' datagrams into their buffers.
async fn receive(
    node: crate::nodes::Nodes,
    shared: Arc<Shared>,
    jitter: Arc<Mutex<HashMap<[u8; 32], Jitter>>>,
    drop: u8,
) {
    let mut n: u32 = 0;
    while let Some((peer, datagram)) = node.next_datagram().await {
        let Some((call, seq, opus)) = parse(&datagram) else {
            continue;
        };
        let device = *peer.device.as_bytes();
        if call != shared.call || !lock(&shared.peers).contains(&device) {
            continue;
        }
        // An even spread, not random: a test's 10% is 10%.
        n = n.wrapping_add(1);
        if drop > 0 && (n.wrapping_mul(37) % 100) < u32::from(drop) {
            continue;
        }
        let mut buffers = lock(&jitter);
        if let std::collections::hash_map::Entry::Vacant(e) = buffers.entry(device) {
            let Ok(decoder) = Decoder::new(SAMPLE_RATE, Channels::Mono) else {
                continue;
            };
            e.insert(Jitter::new(decoder));
        }
        if let Some(j) = buffers.get_mut(&device) {
            j.push(seq, opus.to_vec());
        }
    }
}

/// Where the mix goes.
enum Sink {
    Device(audio::Played),
    File(PathBuf),
}

impl Sink {
    /// Plays `frame`; how long until its end is heard, in ms.
    fn play(&self, frame: &[i16]) -> i32 {
        match self {
            Sink::Device(buffer) => {
                let mut b = lock(buffer);
                b.extend(frame.iter().copied());
                let over = b.len().saturating_sub(PLAYBACK_MAX);
                b.drain(..over);
                (b.len() * 1000 / SAMPLE_RATE as usize) as i32 + DEVICE_DELAY_MS
            }
            Sink::File(path) => {
                let bytes: Vec<u8> = frame.iter().flat_map(|s| s.to_le_bytes()).collect();
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path);
                if let Err(e) = file.and_then(|mut f| f.write_all(&bytes)) {
                    eprintln!("mesh-node: couldn't write what was heard: {e}");
                }
                0
            }
        }
    }
}

/// Every 20 ms: a frame from each buffer, summed and played (C5); and who's
/// speaking, when it changes.
async fn mix(
    shared: Arc<Shared>,
    jitter: Arc<Mutex<HashMap<[u8; 32], Jitter>>>,
    sink: Sink,
    played: PlayedTx,
    me: [u8; 32],
    us: Arc<Mutex<Speakers>>,
    speaking: impl Fn(Vec<[u8; 32]>) + Send + 'static,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let mut told: Vec<[u8; 32]> = Vec::new();
    loop {
        tick.tick().await;
        let now = Instant::now();
        let frames: Vec<([u8; 32], Vec<i16>)> = {
            let mut buffers = lock(&jitter);
            let peers = lock(&shared.peers).clone();
            buffers.retain(|d, _| peers.contains(d));
            (buffers.iter_mut())
                .filter_map(|(d, j)| j.pop().map(|f| (*d, f)))
                .collect()
        };
        {
            let mut s = lock(&us);
            for (device, frame) in &frames {
                if rms(frame) > SPEAKING_RMS {
                    s.last_loud.insert(*device, now);
                }
            }
            s.last_loud
                .retain(|d, at| *d == me || now.duration_since(*at) < HANGOVER * 4);
            let who = s.now(now);
            if who != told {
                told.clone_from(&who);
                speaking(who);
            }
        }
        if frames.is_empty() || shared.deafened.load(Ordering::Relaxed) {
            continue;
        }
        let out = mix_at(&frames, &lock(&shared.volumes), lock(&shared.audio).output);
        let delay = sink.play(&out);
        let _ = played.send((out, delay));
    }
}

/// Frames summed. A sum past `i16` is scaled down as a whole, not clipped:
/// several people at once stay voices, not distortion.
fn mixed<'a>(frames: impl Iterator<Item = &'a [i16]>) -> Vec<i16> {
    let mut sum = vec![0i32; FRAME_SAMPLES];
    for frame in frames {
        for (acc, s) in sum.iter_mut().zip(frame) {
            *acc += i32::from(*s);
        }
    }
    let peak = sum.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
    let scale = if peak > i16::MAX as u32 {
        f64::from(i16::MAX) / f64::from(peak)
    } else {
        1.0
    };
    sum.into_iter()
        .map(|s| (f64::from(s) * scale).round() as i16)
        .collect()
}

/// One device's incoming voice, in sequence order (C5).
struct Jitter {
    decoder: Decoder,
    packets: BTreeMap<u32, Vec<u8>>,
    /// The next frame to play, once playing.
    next: Option<u32>,
    /// Frames to gather before playing; grows on a late path.
    target: usize,
}

impl Jitter {
    fn new(decoder: Decoder) -> Self {
        Self {
            decoder,
            packets: BTreeMap::new(),
            next: None,
            target: JITTER_START,
        }
    }

    fn push(&mut self, seq: u32, opus: Vec<u8>) {
        if let Some(next) = self.next
            && seq < next
        {
            // Too late to play: wait a little longer from now on.
            self.target = (self.target + 1).min(JITTER_MAX);
            return;
        }
        self.packets.insert(seq, opus);
        while self.packets.len() > JITTER_HOLD {
            self.packets.pop_first();
        }
    }

    /// The next 20 ms to play, or `None` while it gathers or is silent.
    fn pop(&mut self) -> Option<Vec<i16>> {
        let next = match self.next {
            Some(next) => next,
            None if self.packets.len() >= self.target => *self.packets.keys().next()?,
            None => return None,
        };
        if self.packets.is_empty() {
            // Ran dry: a silence (the gate closed) or a stall; gather again.
            self.next = None;
            return None;
        }
        let mut pcm = vec![0i16; FRAME_SAMPLES];
        let decoded = match self.packets.remove(&next) {
            Some(opus) => self.decoder.decode(&opus, &mut pcm, false),
            // Lost: the next frame's FEC copy if it's here, else concealment.
            None => match self.packets.get(&(next + 1)) {
                Some(opus) => self.decoder.decode(opus, &mut pcm, true),
                None => self.decoder.decode(&[], &mut pcm, false),
            },
        };
        self.next = Some(next + 1);
        match decoded {
            Ok(n) => {
                pcm.truncate(n.min(FRAME_SAMPLES));
                pcm.resize(FRAME_SAMPLES, 0);
                Some(pcm)
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(frames: usize) -> Vec<Vec<u8>> {
        let mut enc = Encoder::new(SAMPLE_RATE, Channels::Mono, Application::Voip).unwrap();
        enc.set_inband_fec(true).unwrap();
        let mut out = vec![0u8; 1500];
        (0..frames)
            .map(|k| {
                let frame: Vec<i16> = (0..FRAME_SAMPLES)
                    .map(|i| {
                        let t = (k * FRAME_SAMPLES + i) as f32 / SAMPLE_RATE as f32;
                        ((t * 440.0 * std::f32::consts::TAU).sin() * 8000.0) as i16
                    })
                    .collect();
                let n = enc.encode(&frame, &mut out).unwrap();
                out[..n].to_vec()
            })
            .collect()
    }

    fn jitter() -> Jitter {
        Jitter::new(Decoder::new(SAMPLE_RATE, Channels::Mono).unwrap())
    }

    /// It waits for 60 ms, then plays in order, out-of-order arrivals too.
    #[test]
    fn plays_in_order_after_60_ms() {
        let packets = encoded(6);
        let mut j = jitter();
        j.push(2, packets[1].clone());
        assert!(j.pop().is_none(), "one frame isn't enough");
        j.push(1, packets[0].clone());
        j.push(3, packets[2].clone());
        assert_eq!(j.next, None);
        assert!(j.pop().is_some());
        assert_eq!(j.next, Some(2), "starts at the first");
        assert!(j.pop().is_some() && j.pop().is_some());
        assert!(j.pop().is_none(), "dry: gathers again");
    }

    /// A lost frame is concealed, not skipped; a late one grows the buffer.
    #[test]
    fn a_loss_is_concealed_and_late_grows_it() {
        let packets = encoded(8);
        let mut j = jitter();
        for (seq, p) in [(1, 0), (2, 1), (4, 3), (5, 4)] {
            j.push(seq, packets[p].clone());
        }
        let played: Vec<bool> = (0..4).map(|_| j.pop().is_some()).collect();
        assert_eq!(
            played,
            [true, true, true, true],
            "3 is concealed between 2 and 4"
        );
        assert_eq!(j.next, Some(5));
        j.push(3, packets[2].clone());
        assert_eq!(j.target, JITTER_START + 1);
    }

    /// Quiet frames add up as they are; loud ones are scaled down together,
    /// keeping their shape.
    #[test]
    fn the_mix_sums_and_clips() {
        let a = vec![20_000i16; FRAME_SAMPLES];
        let b = vec![20_000i16; FRAME_SAMPLES];
        let c = vec![-5i16; FRAME_SAMPLES];
        assert_eq!(mixed([a.as_slice(), b.as_slice()].into_iter())[0], i16::MAX);
        assert_eq!(mixed([a.as_slice(), c.as_slice()].into_iter())[0], 19_995);
        let half: Vec<i16> = (0..FRAME_SAMPLES)
            .map(|i| if i % 2 == 0 { 20_000 } else { 10_000 })
            .collect();
        let m = mixed([half.as_slice(), half.as_slice()].into_iter());
        assert_eq!((m[0], m[1]), (i16::MAX, 16_384), "the ratio holds");
    }

    /// A datagram's layout (C2).
    #[test]
    fn a_datagram_parses() {
        let mut d = vec![MEDIA];
        d.extend_from_slice(&[7; 8]);
        d.extend_from_slice(&5u32.to_be_bytes());
        d.extend_from_slice(b"opus");
        assert_eq!(parse(&d), Some(([7; 8], 5, &b"opus"[..])));
        assert_eq!(parse(&d[..12]), None);
        d[0] = 2;
        assert_eq!(parse(&d), None);
    }

    /// Steady hiss is cut: after a second or so of it, the output is under
    /// 60% of its level (measured: about half). Seeded noise, so it's the
    /// same every run.
    #[test]
    fn noise_is_suppressed() {
        let mut d = Denoise::new();
        let mut x: u32 = 7;
        let (mut heard, mut fed) = (0.0, 0.0);
        for k in 0..150 {
            let frame: Vec<i16> = (0..FRAME_SAMPLES)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    ((x % 2001) as i32 - 1000) as i16
                })
                .collect();
            let out = d.frame(&frame);
            assert_eq!(out.len(), FRAME_SAMPLES);
            if k >= 90 {
                (heard, fed) = (heard + rms(&out), fed + rms(&frame));
            }
        }
        assert!(
            heard < fed * 0.6,
            "{:.0} of {:.0}",
            heard / 60.0,
            fed / 60.0
        );
    }

    /// Speech opens the gate and it stays open for the hangover; quiet
    /// doesn't.
    #[test]
    fn the_gate() {
        let mut g = Gate::default();
        let t = Instant::now();
        assert!(!g.pass(50.0, t, None));
        assert!(g.pass(5000.0, t, None));
        assert!(g.pass(50.0, t + Duration::from_millis(100), None));
        assert!(!g.pass(50.0, t + Duration::from_millis(400), None));
    }

    /// The 0.5.0 bug: a quiet mic in a quiet room (speech at RMS 200, about
    /// −44 dBFS, over a floor of 30) never opened the gate. It does now,
    /// and the room alone still doesn't.
    #[test]
    fn a_quiet_mic_opens_the_gate() {
        let mut g = Gate::default();
        let t = Instant::now();
        for i in 0..200 {
            assert!(
                !g.pass(30.0, t + Duration::from_millis(20 * i), None),
                "the room alone"
            );
        }
        assert!(
            g.pass(200.0, t + Duration::from_secs(5), None),
            "quiet speech"
        );
    }

    /// A manual threshold (SPEC-audio A4): only what's above it goes out,
    /// whatever the room.
    #[test]
    fn a_manual_threshold_holds() {
        let mut g = Gate::default();
        let t = Instant::now();
        // -30 dBFS is RMS 1036: a voice at RMS 700 stays out, 2000 goes.
        assert!(!g.pass(700.0, t, Some(-30.0)));
        assert!(g.pass(2000.0, t, Some(-30.0)));
        // Automatic would have let the 700 through over a quiet room.
        let mut auto = Gate::default();
        assert!(auto.pass(700.0, t, None));
    }

    /// SPEC-audio A6: one person at 50% is half, the other as they were;
    /// the output volume scales what's heard.
    #[test]
    fn per_person_and_output_volume() {
        let (ann, ben) = ([1u8; 32], [2u8; 32]);
        let frame = |v: i16| vec![v; FRAME_SAMPLES];
        let half = HashMap::from([(ann, 50u32)]);
        let none = HashMap::new();
        // Alone, each as set.
        assert_eq!(mix_at(&[(ann, frame(1000))], &half, 100)[0], 500);
        assert_eq!(mix_at(&[(ben, frame(1000))], &half, 100)[0], 1000);
        // Together: Ann's half adds less than Ben's whole.
        let both = mix_at(&[(ann, frame(1000)), (ben, frame(1000))], &half, 100)[0];
        let even = mix_at(&[(ann, frame(1000)), (ben, frame(1000))], &none, 100)[0];
        assert!(both < even, "{both} vs {even}");
        assert!(
            mix_at(&[(ann, frame(1000)), (ben, frame(1000))], &none, 0)
                .iter()
                .all(|&s| s == 0)
        );
    }

    #[test]
    fn input_volume() {
        let mut frame = vec![1000, -1000, 30_000];
        scale(&mut frame, 100);
        assert_eq!(frame, [1000, -1000, 30_000]);
        scale(&mut frame, 200);
        assert_eq!(frame, [2000, -2000, i16::MAX], "louder, clipped");
        scale(&mut frame, 0);
        assert_eq!(frame, [0, 0, 0]);
    }
}
