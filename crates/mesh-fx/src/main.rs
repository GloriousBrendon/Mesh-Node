//! `mesh-fx`: hosts a person's own voice plugins (VST3, CLAP) outside
//! mesh-node's process (SPEC-voice-quality F2). Spike commands for now:
//!
//! mesh-fx list <file>                 the plugins in a .clap or .vst3
//! mesh-fx gain <file> <id>            1 s of 440 Hz at -20 dBFS through it: dB change, block times
//! mesh-fx edit <file> <id> [secs]     opens its editor for secs (default 10)

mod clap;
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
    match args.first().map(String::as_str) {
        Some("pipe-echo") => return pipe_echo(),
        Some("pipe-bench") => return pipe_bench(),
        _ => {}
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

/// One 20 ms frame of i16 over the pipe (the planned audio message's size).
const FRAME_BYTES: usize = BLOCK * 2;

/// Spike: sends back every frame it reads.
fn pipe_echo() -> Result<(), String> {
    use std::io::{Read, Write};
    let (mut i, mut o) = (std::io::stdin().lock(), std::io::stdout().lock());
    let mut buf = [0u8; FRAME_BYTES];
    while i.read_exact(&mut buf).is_ok() {
        o.write_all(&buf)
            .and_then(|()| o.flush())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Spike: 1,000 frame round trips through a child `pipe-echo`.
fn pipe_bench() -> Result<(), String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut child = Command::new(me)
        .arg("pipe-echo")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let (mut to, mut from) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
    let frame = [7u8; FRAME_BYTES];
    let mut back = [0u8; FRAME_BYTES];
    let mut times = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let t = std::time::Instant::now();
        to.write_all(&frame).map_err(|e| e.to_string())?;
        from.read_exact(&mut back).map_err(|e| e.to_string())?;
        times.push(t.elapsed());
        assert_eq!(back, frame);
    }
    drop(to);
    let _ = child.wait();
    times.sort();
    println!(
        "round trip: median {:?}, p99 {:?}, max {:?}",
        times[500], times[990], times[999]
    );
    Ok(())
}
