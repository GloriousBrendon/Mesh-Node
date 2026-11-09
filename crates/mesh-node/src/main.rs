//! `mesh-node`: Mesh's networking engine. `mesh-node --data <dir>` is
//! Mesh-Voice's helper: commands arrive on stdin as `{"fn":..,"args":[..]}`
//! lines, events go out on stdout as `{"binding":..,"payload":"<json>"}`
//! lines, the same protocol as mesh-wa and mesh-dc. Logs go to stderr.
//! `--relay <url>` (repeatable) replaces n0's public relays; `--seed
//! <ticket>` (repeatable) the built-in seeds. `--record-ttl <secs>` shortens
//! how long address records last, for tests. Without `--seed`, the
//! `MESH_SEEDS` environment variable (space-separated tickets) is used.
//!
//! `mesh-node seed --data <dir>` is the headless seed (SPEC-seed).

mod addrs;
mod codes;
mod helper;
mod routing;
mod seed;

use mesh_transport::{MeshAddr, RelayUrl, Relays};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("mesh-node {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let seed = args.get(1).is_some_and(|a| a == "seed");
    // A seed always says where its key lives.
    let dir = args
        .iter()
        .position(|a| a == "--data")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or_else(|| default_data_dir().filter(|_| !seed));
    let Some(dir) = dir else {
        eprintln!("mesh-node: no data directory; pass --data <dir>");
        std::process::exit(2);
    };
    let relays: Vec<RelayUrl> = match args
        .windows(2)
        .filter(|w| w[0] == "--relay")
        .map(|w| relay(&w[1]))
        .collect()
    {
        Ok(relays) => relays,
        Err(e) => {
            eprintln!("mesh-node: {e}");
            std::process::exit(2);
        }
    };
    let mut seeds: Vec<&str> = args
        .windows(2)
        .filter(|w| w[0] == "--seed")
        .map(|w| w[1].as_str())
        .collect();
    // `MESH_SEEDS` (space-separated tickets) reaches the helper through
    // Mesh-Voice, which passes no flags: for trying a local seed by hand.
    let from_env = std::env::var("MESH_SEEDS").unwrap_or_default();
    if seeds.is_empty() {
        seeds = from_env.split_whitespace().collect();
    }
    if seeds.is_empty() {
        seeds = helper::SEEDS.to_vec();
    }
    let seeds: Vec<MeshAddr> = match seeds.iter().map(|t| MeshAddr::from_ticket(t)).collect() {
        Ok(seeds) => seeds,
        Err(e) => {
            eprintln!("mesh-node: bad --seed ticket: {e}");
            std::process::exit(2);
        }
    };
    // Tests shorten how long address records last (SPEC-routing D4).
    let record_ttl = match args.windows(2).find(|w| w[0] == "--record-ttl") {
        None => routing::RECORD_TTL,
        Some(w) => match w[1].parse::<u64>() {
            Ok(ttl) if (4..=routing::RECORD_TTL).contains(&ttl) => ttl,
            _ => {
                eprintln!(
                    "mesh-node: --record-ttl takes 4 to {} seconds",
                    routing::RECORD_TTL
                );
                std::process::exit(2);
            }
        },
    };
    let relays = if relays.is_empty() {
        Relays::Default
    } else {
        Relays::Custom(relays)
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("mesh-node: can't create {}: {e}", dir.display());
        std::process::exit(1);
    }
    // Identity commands run on this thread (Argon2 takes a second); the
    // runtime's workers keep the node's connections going meanwhile.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("mesh-node: can't start the async runtime: {e}");
            std::process::exit(1);
        }
    };
    if seed {
        if let Err(e) = runtime.block_on(seed::run(&dir, relays)) {
            eprintln!("mesh-node seed: {e}");
            std::process::exit(1);
        }
    } else {
        runtime.block_on(helper::run(&dir, relays, seeds, record_ttl));
    }
}

/// A relay from `--relay`: https, or plain http only on this machine (a
/// local test relay), so the relay link is never readable on the network.
fn relay(url: &str) -> Result<RelayUrl, String> {
    let parsed: RelayUrl = url.parse().map_err(|_| format!("bad relay URL {url}"))?;
    let host = parsed.host_str().unwrap_or("");
    let local = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if local => Ok(parsed),
        _ => Err(format!("relay {url} must use https")),
    }
}

/// `%APPDATA%\mesh\node` on Windows, `$XDG_DATA_HOME/mesh/node` (or
/// `~/.local/share/mesh/node`) elsewhere.
fn default_data_dir() -> Option<PathBuf> {
    let env = |name| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        env("APPDATA")?
    } else {
        env("XDG_DATA_HOME").or_else(|| env("HOME").map(|h| h.join(".local/share")))?
    };
    Some(base.join("mesh").join("node"))
}
