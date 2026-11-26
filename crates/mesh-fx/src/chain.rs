//! A person's plugins in order, as `serve` runs them (SPEC-voice-quality F3, F7).

use serde_json::{Value, json};

use crate::{BLOCK, clap, vst3host};

enum Plugin {
    Clap(clap::Instance),
    Vst3(vst3host::Instance),
}

impl Plugin {
    fn open(path: &str, id: &str) -> Result<Self, String> {
        Ok(if path.trim_end_matches(['/', '\\']).ends_with(".vst3") {
            Plugin::Vst3(vst3host::open(path, id)?)
        } else {
            Plugin::Clap(clap::open(path, id)?)
        })
    }

    fn start(&mut self) -> Result<(), String> {
        match self {
            Plugin::Clap(p) => p.start(),
            Plugin::Vst3(p) => p.start(),
        }
    }

    fn latency(&mut self) -> u32 {
        match self {
            Plugin::Clap(p) => p.latency(),
            Plugin::Vst3(p) => p.latency(),
        }
    }

    fn block(&mut self, buf: &mut [f32; BLOCK]) -> Result<(), String> {
        match self {
            Plugin::Clap(p) => p.block(buf),
            Plugin::Vst3(p) => p.block(buf),
        }
    }
}

pub struct Chain(Vec<Plugin>);

impl Chain {
    /// Loads and starts `plugins` (`[{path, id, on}]`, in order; those with
    /// `on: false` are left out). Answers with the total latency in samples.
    pub fn load(plugins: &Value) -> Result<(Chain, Value), String> {
        let mut chain = Vec::new();
        let mut latency = 0;
        for p in plugins.as_array().into_iter().flatten() {
            if p["on"] == false {
                continue;
            }
            let (path, id) = (
                p["path"].as_str().unwrap_or(""),
                p["id"].as_str().unwrap_or(""),
            );
            let mut plugin = Plugin::open(path, id)
                .and_then(|mut plugin| plugin.start().map(|()| plugin))
                .map_err(|e| format!("{id}: {e}"))?;
            latency += plugin.latency();
            chain.push(plugin);
        }
        Ok((Chain(chain), json!({ "latency": latency })))
    }

    /// One frame through every plugin, in place.
    pub fn run(&mut self, pcm: &mut [i16]) -> Result<(), String> {
        let mut buf = [0f32; BLOCK];
        for (b, s) in buf.iter_mut().zip(pcm.iter()) {
            *b = f32::from(*s) / 32768.0;
        }
        for plugin in &mut self.0 {
            plugin.block(&mut buf)?;
        }
        for (s, b) in pcm.iter_mut().zip(buf) {
            *s = (b * 32768.0).round().clamp(-32768.0, 32767.0) as i16;
        }
        Ok(())
    }
}
