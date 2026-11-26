//! CLAP plugins through clack-host: list, process, editor.

use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::time::{Duration, Instant};

use clack_extensions::audio_ports::{AudioPortInfoBuffer, PluginAudioPorts};
use clack_extensions::gui::{GuiApiType, GuiConfiguration, PluginGui, Window};
use clack_extensions::latency::PluginLatency;
use clack_extensions::timer::{HostTimer, HostTimerImpl, PluginTimer, TimerId};
use clack_host::prelude::*;

use crate::{BLOCK, Info, RATE};

pub struct Host;

pub struct Shared;

impl SharedHandler<'_> for Shared {
    fn request_restart(&self) {}
    fn request_process(&self) {}
    fn request_callback(&self) {}
}

/// Timers the plugin asked for: id, period, last tick.
#[derive(Default)]
pub struct Main {
    timers: RefCell<Vec<(u32, Duration, Instant)>>,
    next: Cell<u32>,
}

impl MainThreadHandler<'_> for Main {}

impl HostTimerImpl for Main {
    fn register_timer(&self, period_ms: u32) -> Result<TimerId, HostError> {
        let id = self.next.get();
        self.next.set(id + 1);
        let period = Duration::from_millis(u64::from(period_ms.max(15)));
        self.timers.borrow_mut().push((id, period, Instant::now()));
        Ok(TimerId(id))
    }

    fn unregister_timer(&self, timer_id: TimerId) -> Result<(), HostError> {
        self.timers.borrow_mut().retain(|t| t.0 != timer_id.0);
        Ok(())
    }
}

impl HostHandlers for Host {
    type Shared<'a> = Shared;
    type MainThread<'a> = Main;
    type AudioProcessor<'a> = ();

    fn declare_extensions(builder: &mut HostExtensions<Self>, _shared: &Self::Shared<'_>) {
        builder.register::<HostTimer>();
    }
}

fn host_info() -> HostInfo {
    HostInfo::new(
        "Aflos",
        "Aflos",
        "https://github.com/GloriousBrendon/Aflos",
        "0.5.3",
    )
    .unwrap()
}

pub fn load(path: &str) -> Result<PluginEntry, String> {
    // SAFETY: loading a plugin runs its code; that's why this is its own process (F2).
    unsafe { PluginEntry::load(path) }.map_err(|e| format!("load {path}: {e}"))
}

/// The plugins in `path`.
pub fn list(path: &str) -> Result<Vec<Info>, String> {
    let entry = load(path)?;
    let factory = entry.get_plugin_factory().ok_or("no plugin factory")?;
    Ok(factory
        .plugin_descriptors()
        .filter_map(|d| {
            Some(Info {
                id: d.id()?.to_string_lossy().into_owned(),
                name: d
                    .name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                vendor: d
                    .vendor()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            })
        })
        .collect())
}

pub struct Instance {
    _entry: PluginEntry,
    instance: PluginInstance<Host>,
    /// Channels on the main input and output port.
    channels: (usize, usize),
}

pub fn open(path: &str, id: &str) -> Result<Instance, String> {
    let entry = load(path)?;
    let cid = CString::new(id).map_err(|e| e.to_string())?;
    let mut instance =
        PluginInstance::<Host>::new(|_| Shared, |_| Main::default(), &entry, &cid, &host_info())
            .map_err(|e| format!("instantiate {id}: {e}"))?;
    let channels = {
        let h = instance.plugin_handle();
        let count = |input| {
            h.get_extension::<PluginAudioPorts>()
                .and_then(|p| {
                    let mut buf = AudioPortInfoBuffer::new();
                    p.get(&h, 0, input, &mut buf)
                        .map(|i| i.channel_count as usize)
                })
                .unwrap_or(2)
        };
        (count(true), count(false))
    };
    Ok(Instance {
        _entry: entry,
        instance,
        channels,
    })
}

impl Instance {
    pub fn latency(&mut self) -> u32 {
        let h = self.instance.plugin_handle();
        h.get_extension::<PluginLatency>().map_or(0, |l| l.get(&h))
    }

    /// Runs `input` (mono) through the plugin in 960-frame blocks; mono out,
    /// and the time each block took.
    pub fn process(&mut self, input: &[f32]) -> Result<(Vec<f32>, Vec<Duration>), String> {
        let config = PluginAudioConfiguration {
            sample_rate: f64::from(RATE),
            min_frames_count: BLOCK as u32,
            max_frames_count: BLOCK as u32,
        };
        let stopped = self
            .instance
            .activate(|_, _| (), config)
            .map_err(|e| format!("activate: {e}"))?;
        let mut processor = stopped
            .start_processing()
            .map_err(|e| format!("start: {e}"))?;
        let (ins, outs) = self.channels;
        let mut in_bufs = vec![vec![0f32; BLOCK]; ins];
        let mut out_bufs = vec![vec![0f32; BLOCK]; outs];
        let mut in_ports = AudioPorts::with_capacity(ins, 1);
        let mut out_ports = AudioPorts::with_capacity(outs, 1);
        let events_in = EventBuffer::new();
        let mut events_out = EventBuffer::new();
        let (mut out, mut times) = (Vec::with_capacity(input.len()), Vec::new());
        for (k, block) in input.chunks_exact(BLOCK).enumerate() {
            for ch in &mut in_bufs {
                ch.copy_from_slice(block);
            }
            let started = Instant::now();
            let audio_in = in_ports.with_input_buffers([AudioPortBuffer {
                latency: 0,
                channels: AudioPortBufferType::f32_input_only(
                    in_bufs
                        .iter_mut()
                        .map(|b| InputChannel::variable(b.as_mut_slice())),
                ),
            }]);
            let mut audio_out = out_ports.with_output_buffers([AudioPortBuffer {
                latency: 0,
                channels: AudioPortBufferType::f32_output_only(
                    out_bufs.iter_mut().map(|b| b.as_mut_slice()),
                ),
            }]);
            processor
                .process(
                    &audio_in,
                    &mut audio_out,
                    &InputEvents::from_buffer(&events_in),
                    &mut OutputEvents::from_buffer(&mut events_out),
                    Some((k * BLOCK) as u64),
                    None,
                )
                .map_err(|e| format!("process: {e}"))?;
            times.push(started.elapsed());
            events_out.clear();
            // Stereo out averaged to mono (F7).
            for i in 0..BLOCK {
                out.push(out_bufs.iter().map(|c| c[i]).sum::<f32>() / outs.max(1) as f32);
            }
        }
        let stopped = processor.stop_processing();
        self.instance.deactivate(stopped);
        Ok((out, times))
    }

    /// Opens the plugin's own window for `secs`, pumping its timers; floating
    /// if it can, else embedded in an X11 window of ours.
    pub fn edit(&mut self, secs: u64) -> Result<String, String> {
        let api = GuiApiType::default_for_current_platform().ok_or("no GUI API here")?;
        let gui = {
            let h = self.instance.plugin_handle();
            h.get_extension::<PluginGui>()
                .ok_or("plugin has no editor")?
        };
        let floating = GuiConfiguration {
            api_type: api,
            is_floating: true,
        };
        let embedded = GuiConfiguration {
            api_type: api,
            is_floating: false,
        };
        let h = self.instance.plugin_handle();
        let how;
        #[cfg(target_os = "linux")]
        let mut parent = None;
        if gui.is_api_supported(&h, floating) {
            gui.create(&h, floating)
                .map_err(|e| format!("create floating: {e:?}"))?;
            gui.suggest_title(&h, c"Aflos plugin");
            how = "floating";
        } else if gui.is_api_supported(&h, embedded) {
            gui.create(&h, embedded)
                .map_err(|e| format!("create embedded: {e:?}"))?;
            let size = gui.get_size(&h).unwrap_or(clack_extensions::gui::GuiSize {
                width: 800,
                height: 500,
            });
            #[cfg(target_os = "linux")]
            {
                let x = crate::x11::Parent::new(size.width as u16, size.height as u16)?;
                // SAFETY: the window lives in `parent` until after destroy below.
                unsafe { gui.set_parent(&h, Window::from_x11_handle(x.id.into())) }
                    .map_err(|e| format!("set_parent: {e:?}"))?;
                parent = Some(x);
            }
            #[cfg(not(target_os = "linux"))]
            return Err("embedding only on Linux in the spike".into());
            how = "embedded";
        } else {
            return Err("no supported editor API".into());
        }
        gui.show(&h).map_err(|e| format!("show: {e:?}"))?;
        let size = gui.get_size(&h);
        let timer_ext = h.get_extension::<PluginTimer>();
        let until = Instant::now() + Duration::from_secs(secs);
        let mut ticks = 0u32;
        while Instant::now() < until {
            let now = Instant::now();
            let due: Vec<u32> = self.instance.access_handler(|m| {
                let mut t = m.timers.borrow_mut();
                t.iter_mut()
                    .filter(|(_, p, last)| now.duration_since(*last) >= *p)
                    .map(|(id, _, last)| {
                        *last = now;
                        *id
                    })
                    .collect()
            });
            let h = self.instance.plugin_handle();
            if let Some(t) = &timer_ext {
                for id in due {
                    t.on_timer(&h, TimerId(id));
                    ticks += 1;
                }
            }
            self.instance.call_on_main_thread_callback();
            #[cfg(target_os = "linux")]
            if let Some(p) = &parent {
                p.pump();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let h = self.instance.plugin_handle();
        let _ = gui.hide(&h);
        gui.destroy(&h);
        Ok(format!("{how} editor, size {size:?}, {ticks} timer ticks"))
    }
}
