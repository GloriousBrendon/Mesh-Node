//! A call's capture processing from WebRTC's audio processing, through
//! `sonora` (SPEC-audio A1, A2): the high-pass filter and echo
//! cancellation (AEC3), fed what we play as the far end. Our frames are
//! 20 ms at 48 kHz; sonora works on 10 ms, so each frame is two halves.

use crate::audio::{FRAME_SAMPLES, SAMPLE_RATE};
use sonora::config::{AdaptiveDigital, EchoCanceller, GainController2, HighPassFilter};
use sonora::{AudioProcessing, Config, StreamConfig};

/// sonora's frame: 10 ms.
const HALF: usize = FRAME_SAMPLES / 2;

pub struct Processing {
    apm: AudioProcessing,
    scratch: [i16; HALF],
}

impl Processing {
    pub fn new() -> Self {
        let config = Config {
            high_pass_filter: Some(HighPassFilter::default()),
            echo_canceller: Some(EchoCanceller::default()),
            ..Default::default()
        };
        let stream = StreamConfig::new(SAMPLE_RATE, 1);
        Self {
            apm: AudioProcessing::builder()
                .config(config)
                .capture_config(stream)
                .render_config(stream)
                .build(),
            scratch: [0; HALF],
        }
    }

    /// A frame we played: what the echo canceller removes from the mic.
    pub fn render(&mut self, frame: &[i16]) {
        for half in frame.as_chunks::<HALF>().0 {
            let _ = self.apm.process_render_i16(half, &mut self.scratch);
        }
    }

    /// A mic frame, processed in place. `delay_ms` is how long played
    /// audio takes to come back into the mic, as near as we know it.
    pub fn capture(&mut self, frame: &mut [i16], delay_ms: i32) {
        for half in frame.as_chunks_mut::<HALF>().0 {
            let _ = self.apm.set_stream_delay_ms(delay_ms.clamp(0, 500));
            if self
                .apm
                .process_capture_i16(half, &mut self.scratch)
                .is_ok()
            {
                half.copy_from_slice(&self.scratch);
            }
        }
    }
}

/// Automatic gain (AGC2's adaptive digital gain and limiter, SPEC-audio
/// A1): its own sonora instance, so noise suppression sits between it and
/// the echo canceller, as WebRTC orders them.
pub struct Gain {
    apm: AudioProcessing,
    scratch: [i16; HALF],
}

impl Gain {
    pub fn new() -> Self {
        let config = Config {
            gain_controller2: Some(GainController2 {
                input_volume_controller: false,
                adaptive_digital: Some(AdaptiveDigital::default()),
                fixed_digital: Default::default(),
            }),
            ..Default::default()
        };
        let stream = StreamConfig::new(SAMPLE_RATE, 1);
        Self {
            apm: AudioProcessing::builder()
                .config(config)
                .capture_config(stream)
                .render_config(stream)
                .build(),
            scratch: [0; HALF],
        }
    }

    /// A mic frame, brought towards a normal speaking level, in place.
    pub fn process(&mut self, frame: &mut [i16]) {
        for half in frame.as_chunks_mut::<HALF>().0 {
            if self
                .apm
                .process_capture_i16(half, &mut self.scratch)
                .is_ok()
            {
                half.copy_from_slice(&self.scratch);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The quiet voice clip's samples (tests/data, public domain).
    pub(crate) fn quiet_voice() -> Vec<i16> {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/quiet-voice.wav"
        ))
        .expect("tests/data/quiet-voice.wav");
        // The samples follow the "data" chunk's 8-byte header.
        let at = bytes
            .windows(4)
            .position(|w| w == b"data")
            .expect("a data chunk")
            + 8;
        bytes[at..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b))
            .collect()
    }

    fn energy(x: &[i16]) -> f64 {
        x.iter().map(|&s| f64::from(s) * f64::from(s)).sum::<f64>() / x.len().max(1) as f64
    }

    /// How much an echo `delay` ms late at half level is cut, with the
    /// canceller told `told` ms, over the clip's second half (once it's
    /// converged), in dB.
    fn echo_cut(delay: usize, told: i32) -> f64 {
        // A talker at a normal level (the clip is at -50 dBFS; +28 dB).
        let far: Vec<i16> = quiet_voice()
            .iter()
            .map(|&s| s.saturating_mul(25))
            .collect();
        let lag = SAMPLE_RATE as usize * delay / 1000;
        let near: Vec<i16> = (0..far.len())
            .map(|i| if i >= lag { far[i - lag] / 2 } else { 0 })
            .collect();
        let mut p = Processing::new();
        let mut out = near.clone();
        for (i, frame) in out
            .as_chunks_mut::<FRAME_SAMPLES>()
            .0
            .iter_mut()
            .enumerate()
        {
            p.render(&far[i * FRAME_SAMPLES..(i + 1) * FRAME_SAMPLES]);
            p.capture(frame, told);
        }
        let half = far.len() / 2;
        10.0 * (energy(&near[half..]) / energy(&out[half..]).max(1e-9)).log10()
    }

    #[test]
    fn an_echo_of_what_we_play_is_cut() {
        let cut = echo_cut(40, 40);
        assert!(cut >= 20.0, "cut by {cut:.1} dB");
        // A delay estimate 40 ms out still cancels most of it.
        let off = echo_cut(40, 80);
        assert!(off >= 15.0, "cut by {off:.1} dB with the delay 40 ms off");
    }

    fn dbfs(x: &[i16]) -> f64 {
        10.0 * (energy(x) / (32768.0f64 * 32768.0)).log10()
    }

    /// PLAN-audio Task 3: a quiet voice (the clip, -50 dBFS) comes out
    /// within 10 dB of -20 dBFS once the gain has settled (after 5 s).
    #[test]
    fn a_quiet_voice_is_brought_up() {
        let voice = quiet_voice();
        let mut g = Gain::new();
        let mut out = voice.clone();
        for frame in out.as_chunks_mut::<FRAME_SAMPLES>().0 {
            g.process(frame);
        }
        let settled = SAMPLE_RATE as usize * 5;
        let (before, after) = (dbfs(&voice[settled..]), dbfs(&out[settled..]));
        eprintln!("gain: {before:.1} dBFS in, {after:.1} dBFS out");
        assert!(
            (after + 20.0).abs() <= 10.0,
            "{before:.1} dBFS in, {after:.1} out"
        );
    }

    #[test]
    fn our_own_voice_with_no_echo_comes_through() {
        // Nothing played: the mic's speech isn't cancelled.
        let voice: Vec<i16> = quiet_voice()
            .iter()
            .map(|&s| s.saturating_mul(25))
            .collect();
        let mut p = Processing::new();
        let mut out = voice.clone();
        for frame in out.as_chunks_mut::<FRAME_SAMPLES>().0 {
            p.capture(frame, 40);
        }
        let half = voice.len() / 2;
        let kept = 10.0 * (energy(&out[half..]) / energy(&voice[half..])).log10();
        assert!(kept > -3.0, "our voice lost {:.1} dB", -kept);
    }
}
