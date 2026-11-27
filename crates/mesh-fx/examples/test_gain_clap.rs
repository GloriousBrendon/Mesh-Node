//! A CLAP gain for mesh-fx's tests (PLAN-voice-quality Task 7): one
//! parameter, "Gain" in dB (-60 to +24), kept in its state. It starts at
//! `MESH_FX_TEST_GAIN_DB` (default 0) and, with `MESH_FX_TEST_SLEEP_MS`,
//! takes that long over every block, to test a plugin that's too slow.

use std::ffi::CStr;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use clack_extensions::params::*;
use clack_extensions::state::{PluginState, PluginStateImpl};
use clack_plugin::events::event_types::ParamValueEvent;
use clack_plugin::prelude::*;
use clack_plugin::stream::{InputStream, OutputStream};

const GAIN: u32 = 1;

pub struct Shared {
    /// The gain in dB, as f32 bits.
    db: AtomicU32,
    sleep: Option<Duration>,
}

impl Shared {
    fn db(&self) -> f32 {
        f32::from_bits(self.db.load(Ordering::Relaxed))
    }
    fn set_db(&self, db: f64) {
        self.db
            .store((db.clamp(-60.0, 24.0) as f32).to_bits(), Ordering::Relaxed);
    }
    fn take(&self, events: &InputEvents) {
        for e in events {
            if let Some(p) = e.as_event::<ParamValueEvent>()
                && p.param_id().map(|id| id.get()) == Some(GAIN)
            {
                self.set_db(p.value());
            }
        }
    }
}

impl PluginShared<'_> for Shared {}

pub struct TestGain;

impl Plugin for TestGain {
    type AudioProcessor<'a> = Processor<'a>;
    type Shared<'a> = Shared;
    type MainThread<'a> = Main<'a>;

    fn declare_extensions(builder: &mut PluginExtensions<Self>, _shared: Option<&Shared>) {
        builder.register::<PluginParams>().register::<PluginState>();
    }
}

impl DefaultPluginFactory for TestGain {
    fn get_descriptor() -> PluginDescriptor {
        PluginDescriptor::new("aflos.test.gain", "Aflos test gain")
    }

    fn new_shared(_host: HostSharedHandle<'_>) -> Result<Shared, PluginError> {
        let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<f64>().ok());
        let s = Shared {
            db: AtomicU32::new(0f32.to_bits()),
            sleep: env("MESH_FX_TEST_SLEEP_MS")
                .map(|ms| Duration::from_micros((ms * 1000.0) as u64)),
        };
        s.set_db(env("MESH_FX_TEST_GAIN_DB").unwrap_or(0.0));
        Ok(s)
    }

    fn new_main_thread<'a>(
        _host: HostMainThreadHandle<'a>,
        shared: &'a Shared,
    ) -> Result<Main<'a>, PluginError> {
        Ok(Main(shared))
    }
}

pub struct Main<'a>(&'a Shared);

impl<'a> PluginMainThread<'a, Shared> for Main<'a> {}

impl PluginMainThreadParams for Main<'_> {
    fn count(&self) -> u32 {
        1
    }

    fn get_info(&self, index: u32, info: &mut ParamInfoWriter) {
        if index == 0 {
            info.set(&ParamInfo {
                id: ClapId::new(GAIN),
                flags: ParamInfoFlags::IS_AUTOMATABLE,
                cookie: Default::default(),
                name: b"Gain",
                module: b"",
                min_value: -60.0,
                max_value: 24.0,
                default_value: 0.0,
            });
        }
    }

    fn get_value(&self, id: ClapId) -> Option<f64> {
        (id.get() == GAIN).then(|| f64::from(self.0.db()))
    }

    fn value_to_text(
        &self,
        _id: ClapId,
        value: f64,
        writer: &mut ParamDisplayWriter,
    ) -> std::fmt::Result {
        use std::fmt::Write as _;
        write!(writer, "{value:.1} dB")
    }

    fn text_to_value(&self, _id: ClapId, text: &CStr) -> Option<f64> {
        text.to_str()
            .ok()?
            .trim_end_matches(" dB")
            .trim()
            .parse()
            .ok()
    }

    fn flush(&self, input: &InputEvents, _output: &mut OutputEvents) {
        self.0.take(input);
    }
}

impl PluginStateImpl for Main<'_> {
    fn save(&self, output: &mut OutputStream) -> Result<(), PluginError> {
        output.write_all(&self.0.db().to_le_bytes())?;
        Ok(())
    }

    fn load(&self, input: &mut InputStream) -> Result<(), PluginError> {
        let mut b = [0u8; 4];
        input.read_exact(&mut b)?;
        let db = f32::from_le_bytes(b);
        if !db.is_finite() {
            return Err(PluginError::Message("a damaged state"));
        }
        self.0.set_db(f64::from(db));
        Ok(())
    }
}

pub struct Processor<'a>(&'a Shared);

impl<'a> PluginAudioProcessor<'a, Shared, Main<'a>> for Processor<'a> {
    fn activate(
        _host: HostAudioProcessorHandle<'a>,
        _main: &Main<'a>,
        shared: &'a Shared,
        _config: PluginAudioConfiguration,
    ) -> Result<Self, PluginError> {
        Ok(Self(shared))
    }

    fn process(
        &mut self,
        _process: Process,
        mut audio: Audio,
        events: Events,
    ) -> Result<ProcessStatus, PluginError> {
        self.0.take(events.input);
        if let Some(d) = self.0.sleep {
            std::thread::sleep(d);
        }
        let g = 10f32.powf(self.0.db() / 20.0);
        for mut port in &mut audio {
            let Some(channels) = port.channels()?.into_f32() else {
                continue;
            };
            for pair in channels {
                match pair {
                    ChannelPair::InputOnly(_) => {}
                    ChannelPair::OutputOnly(b) => b.fill(0.0),
                    ChannelPair::InputOutput(i, o) => i.iter().zip(o).for_each(|(i, o)| *o = i * g),
                    ChannelPair::InPlace(b) => b.iter_mut().for_each(|s| *s *= g),
                }
            }
        }
        Ok(ProcessStatus::Continue)
    }
}

impl PluginAudioProcessorParams for Processor<'_> {
    fn flush(&mut self, input: &InputEvents, _output: &mut OutputEvents) {
        self.0.take(input);
    }
}

clack_export_entry!(SinglePluginEntry<TestGain>);
