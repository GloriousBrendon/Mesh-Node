//! `mesh-fx`: hosts a person's own voice plugins (VST3, CLAP) outside
//! mesh-node's process (SPEC-voice-quality F2). Spike commands for now:
//!
//! mesh-fx list <file>                 the plugins in a .clap or .vst3
//! mesh-fx scan <file>                 the same as one JSON line, for mesh-node (Task 3)
//! mesh-fx gain <file> <id>            1 s of 440 Hz at -20 dBFS through it: dB change, block times
//! mesh-fx edit <file> <id> [secs]     opens its editor for secs (default 10)
//! mesh-fx serve                       mesh-node's end: messages on stdin/stdout (proto.rs)

mod clap;
mod proto;
mod serve;
mod vst3host;
#[cfg(target_os = "linux")]
mod x11;

use std::time::Duration;

pub const RATE: u32 = 48_000;
/// 20 ms, a call's frame (F7).
pub const BLOCK: usize = 960;

pub struct Info {
    pub id: String,
    pub name: String,
    pub vendor: String,
}

fn tone() -> Vec<f32> {
    (0..RATE as usize)
        .map(|i| level() * (i as f32 * 440.0 * std::f32::consts::TAU / RATE as f32).sin())
        .collect()
}

fn rms(s: &[f32]) -> f32 {
    (s.iter().map(|x| x * x).sum::<f32>() / s.len().max(1) as f32).sqrt()
}

fn run(args: &[String]) -> Result<(), String> {
    let arg = |i: usize| args.get(i).map(String::as_str).ok_or("missing argument");
    if args.first().map(String::as_str) == Some("serve") {
        return serve_stdio();
    }
    let file = arg(1)?;
    let vst3 = file.trim_end_matches('/').ends_with(".vst3");
    match arg(0)? {
        "list" => {
            let list = if vst3 {
                vst3host::list(file)?
            } else {
                clap::list(file)?
            };
            for p in list {
                println!("{}\t{}\t{}", p.id, p.name, p.vendor);
            }
        }
        "scan" => {
            let list = if vst3 {
                vst3host::list(file)?
            } else {
                clap::list(file)?
            };
            let plugins: Vec<_> = list
                .iter()
                .map(|p| serde_json::json!({"id": p.id, "name": p.name, "vendor": p.vendor}))
                .collect();
            let format = if vst3 { "vst3" } else { "clap" };
            println!(
                "{}",
                serde_json::json!({"format": format, "plugins": plugins})
            );
        }
        "gain" => {
            let input = tone();
            let (latency, (out, times)) = if vst3 {
                let mut inst = vst3host::open(file, arg(2)?)?;
                (inst.latency(), inst.process(&input)?)
            } else {
                let mut inst = clap::open(file, arg(2)?)?;
                (inst.latency(), inst.process(&input)?)
            };
            let half = input.len() / 2;
            let db = 20.0 * (rms(&out[half..]) / rms(&input[half..])).log10();
            let worst = times.iter().max().copied().unwrap_or_default();
            let mean = times.iter().sum::<Duration>() / times.len().max(1) as u32;
            println!(
                "gain {db:+.2} dB, latency {latency} samples, block mean {mean:?} worst {worst:?}"
            );
        }
        "edit" => {
            let secs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10);
            let report = if vst3 {
                #[cfg(target_os = "linux")]
                {
                    vst3host::open(file, arg(2)?)?.edit(secs)?
                }
                #[cfg(not(target_os = "linux"))]
                return Err("VST3 editors only on Linux in the spike".into());
            } else {
                clap::open(file, arg(2)?)?.edit(secs)?
            };
            println!("{report}");
        }
        other => return Err(format!("unknown command {other}")),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("mesh-fx: {e}");
        std::process::exit(1);
    }
}

/// The test tone's amplitude: `MESH_FX_LEVEL`, default 0.1 (-20 dBFS).
fn level() -> f32 {
    std::env::var("MESH_FX_LEVEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.1)
}

/// `serve` on stdin and the protocol's stdout; malformed input exits 2.
fn serve_stdio() -> Result<(), String> {
    #[cfg(unix)]
    let out = serve::protocol_out().map_err(|e| e.to_string())?;
    // ponytail: on Windows a plugin printing to stdout would corrupt the protocol; redirect it there too (Task 11).
    #[cfg(not(unix))]
    let out = std::io::stdout().lock();
    if let Err(e) = serve::serve(std::io::stdin().lock(), std::io::BufWriter::new(out)) {
        eprintln!("mesh-fx: {e}");
        std::process::exit(2);
    }
    Ok(())
}
