//! A person's plugins in order, as `serve` runs them (SPEC-voice-quality F3, F7).

use std::path::PathBuf;

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

    fn state(&mut self) -> Result<Vec<u8>, String> {
        match self {
            Plugin::Clap(p) => p.state(),
            Plugin::Vst3(p) => p.state(),
        }
    }

    fn set_state(&mut self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Plugin::Clap(p) => p.set_state(bytes),
            Plugin::Vst3(p) => p.set_state(bytes),
        }
    }

    fn params(&mut self) -> Vec<Value> {
        match self {
            Plugin::Clap(p) => p.params(),
            Plugin::Vst3(p) => p.params(),
        }
    }

    fn set_param(&mut self, id: u32, value: f64) -> Result<(), String> {
        match self {
            Plugin::Clap(p) => p.set_param(id, value),
            Plugin::Vst3(p) => p.set_param(id, value),
        }
    }

    fn open_editor(&mut self) -> Result<String, String> {
        match self {
            Plugin::Clap(p) => p.open_editor(),
            Plugin::Vst3(p) => p.open_editor(),
        }
    }

    fn editor_open(&self) -> bool {
        match self {
            Plugin::Clap(p) => p.editor_open(),
            Plugin::Vst3(p) => p.editor_open(),
        }
    }

    fn pump(&mut self) -> bool {
        match self {
            Plugin::Clap(p) => p.pump(),
            Plugin::Vst3(p) => p.pump(),
        }
    }

    fn close_editor(&mut self) {
        match self {
            Plugin::Clap(p) => p.close_editor(),
            Plugin::Vst3(p) => p.close_editor(),
        }
    }
}

/// A plugin in the chain: its place in the list mesh-node sent (off ones
/// count too), and where its state is kept.
struct Slot {
    at: usize,
    plugin: Plugin,
    state: Option<PathBuf>,
}

pub struct Chain(Vec<Slot>);

impl Chain {
    /// Loads and starts `plugins` (`[{path, id, on, state}]`, in order;
    /// those with `on: false` are left out), each from its saved state if
    /// it has one. A state that won't load is ignored and logged, never
    /// fatal. Answers with the total latency in samples.
    pub fn load(plugins: &Value) -> Result<(Chain, Value), String> {
        let mut chain = Vec::new();
        let mut latency = 0;
        for (at, p) in plugins.as_array().into_iter().flatten().enumerate() {
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
            let state = p["state"].as_str().filter(|s| !s.is_empty()).map(PathBuf::from);
            if let Some(file) = &state
                && let Ok(bytes) = std::fs::read(file)
                && let Err(e) = plugin.set_state(&bytes)
            {
                eprintln!("mesh-fx: {id}: its saved state didn't load ({e}); starting fresh");
            }
            latency += plugin.latency();
            chain.push(Slot { at, plugin, state });
        }
        Ok((Chain(chain), json!({ "latency": latency })))
    }

    /// One frame through every plugin, in place.
    pub fn run(&mut self, pcm: &mut [i16]) -> Result<(), String> {
        let mut buf = [0f32; BLOCK];
        for (b, s) in buf.iter_mut().zip(pcm.iter()) {
            *b = f32::from(*s) / 32768.0;
        }
        for slot in &mut self.0 {
            slot.plugin.block(&mut buf)?;
        }
        for (s, b) in pcm.iter_mut().zip(buf) {
            *s = (b * 32768.0).round().clamp(-32768.0, 32767.0) as i16;
        }
        Ok(())
    }
}

impl Chain {
    fn slot(&mut self, at: usize) -> Result<&mut Slot, String> {
        self.0.iter_mut().find(|s| s.at == at).ok_or_else(|| "no such plugin on".to_owned())
    }

    /// Writes each plugin's state to its file (through a temporary file,
    /// so a crash never leaves half a state). The number saved.
    pub fn save(&mut self) -> usize {
        let mut saved = 0;
        for slot in &mut self.0 {
            let Some(file) = &slot.state else { continue };
            match slot.plugin.state() {
                Ok(bytes) => {
                    let tmp = file.with_extension("tmp");
                    let written = file.parent().map_or(Ok(()), std::fs::create_dir_all)
                        .and_then(|()| std::fs::write(&tmp, &bytes))
                        .and_then(|()| std::fs::rename(&tmp, file));
                    match written {
                        Ok(()) => saved += 1,
                        Err(e) => eprintln!("mesh-fx: couldn't save a plugin's state: {e}"),
                    }
                }
                Err(e) => eprintln!("mesh-fx: a plugin gave no state: {e}"),
            }
        }
        saved
    }

    pub fn params(&mut self, at: usize) -> Result<Value, String> {
        Ok(json!({ "params": self.slot(at)?.plugin.params() }))
    }

    pub fn set_param(&mut self, at: usize, id: u32, value: f64) -> Result<Value, String> {
        self.slot(at)?.plugin.set_param(id, value)?;
        Ok(json!({ "ok": true }))
    }

    pub fn edit(&mut self, at: usize) -> Result<Value, String> {
        Ok(json!({ "editor": self.slot(at)?.plugin.open_editor()? }))
    }

    pub fn close_editor(&mut self, at: usize) -> Result<Value, String> {
        self.slot(at)?.plugin.close_editor();
        Ok(json!({ "saved": self.save() }))
    }

    pub fn editing(&self) -> bool {
        self.0.iter().any(|s| s.plugin.editor_open())
    }

    /// One turn of every open editor; the places of those the person closed.
    pub fn pump(&mut self) -> Vec<usize> {
        let mut closed = Vec::new();
        for slot in &mut self.0 {
            if slot.plugin.editor_open() && !slot.plugin.pump() {
                closed.push(slot.at);
            }
        }
        closed
    }
}
