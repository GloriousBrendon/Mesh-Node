//! `mesh-node`: Mesh's networking engine. `mesh-node --data <dir>` is
//! Mesh-Voice's helper: commands arrive on stdin as `{"fn":..,"args":[..]}`
//! lines, events go out on stdout as `{"binding":..,"payload":"<json>"}`
//! lines, the same protocol as mesh-wa and mesh-dc. Logs go to stderr.
//! `--relay <url>` (repeatable) replaces the built-in relays (n0's); `--seed <ticket>` (repeatable) the built-in seed. `--record-ttl <secs>` shortens
//! how long address records last, for tests. Without `--seed`, the
//! `MESH_SEEDS` environment variable (space-separated tickets) is used; set
//! but empty, there are no seeds.
//!
//! `mesh-node seed --data <dir>` is the headless seed (SPEC-seed). On a
//! machine with a public address, `--port <udp>` fixes its port and
//! `--public <ip:port>` puts that address in its ticket, so callers reach it
//! direct (D8c). `--relay-only` is the opposite: no direct paths at all, so
//! its address is never shown; it takes exactly one `--relay`, which its
//! ticket names, and neither `--port` nor `--public`. `--report-every <secs>` shortens the hourly counts, for
//! tests. `--mail` turns on the mail services (SPEC-mailbox; off by default);
//! `--mail-token <secret>` closes them to anyone without it, and
//! `--mail-max <bytes>` caps what they hold (2 GiB by default).
//!
//! `--clock-offset <secs>`, on either, moves the process's clock, for tests
//! only (SPEC-mailbox), as `--record-ttl` is.
//! `--cut seed` and `--cut live` (either or both), on the helper and for
//! tests only, start it cut off from its seeds, or from live connections
//! with its contacts, until a `cutOff` command. `--crash-at records`, for
//! tests only, exits between a record read's two saves (SPEC-mailbox M15).
//!
//! `--hide-ip` starts the helper with Hide my IP on (SPEC-connection-privacy
//! P6): no direct node, everyone relayed; `netPrivacy` changes it.
//!
//! `--holder <ticket>` (repeatable, up to three) names the seeds that keep
//! this device's mail (SPEC-mailbox, *Choosing your own holder*); without
//! it, `MESH_HOLDERS` (space-separated tickets); with neither, the first
//! three seeds.

mod addrs;
#[cfg(feature = "audio")]
mod audio;
mod codes;
mod e2ee;
mod helper;
mod knocks;
mod maillog;
mod mailstore;
#[cfg(feature = "audio")]
mod media;
mod nodes;
#[cfg(feature = "audio")]
mod processing;
mod routing;
mod saved;
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
    // Tests only (SPEC-mailbox decided Q14): this process's clock, moved.
    if let Some(w) = args.windows(2).find(|w| w[0] == "--clock-offset") {
        let moved = w[1]
            .parse::<i64>()
            .is_ok_and(mesh_identity::set_clock_offset);
        if !moved {
            eprintln!(
                "mesh-node: --clock-offset takes seconds, at most {}",
                mesh_identity::MAX_CLOCK_OFFSET
            );
            std::process::exit(2);
        }
    }
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
    // Set but empty means no seeds at all (the tests use that).
    let from_env = std::env::var("MESH_SEEDS").ok();
    if seeds.is_empty() {
        seeds = match &from_env {
            Some(tickets) => tickets.split_whitespace().collect(),
            None => helper::SEEDS.to_vec(),
        };
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
    // Tests shorten how long an idle Space peer's connection stays open
    // (SPEC-spaces S14).
    let peer_idle = match args.windows(2).find(|w| w[0] == "--peer-idle") {
        None => helper::PEER_IDLE,
        Some(w) => match w[1].parse::<u64>() {
            Ok(secs) if (1..=helper::PEER_IDLE.as_secs()).contains(&secs) => {
                std::time::Duration::from_secs(secs)
            }
            _ => {
                eprintln!(
                    "mesh-node: --peer-idle takes 1 to {} seconds",
                    helper::PEER_IDLE.as_secs()
                );
                std::process::exit(2);
            }
        },
    };
    let relays = Relays::Custom(if relays.is_empty() {
        default_relays()
    } else {
        relays
    });
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
        let options = match seed_options(&args, &relays) {
            Ok(options) => options,
            Err(e) => {
                eprintln!("mesh-node seed: {e}");
                std::process::exit(2);
            }
        };
        if let Err(e) = runtime.block_on(seed::run(&dir, relays, options)) {
            eprintln!("mesh-node seed: {e}");
            std::process::exit(1);
        }
    } else {
        let mut cut = helper::Cut::default();
        for w in args.windows(2).filter(|w| w[0] == "--cut") {
            match w[1].as_str() {
                "seed" => cut.seed = true,
                "live" => cut.live = true,
                _ => {
                    eprintln!("mesh-node: --cut takes seed or live");
                    std::process::exit(2);
                }
            }
        }
        let mut holders: Vec<&str> = args
            .windows(2)
            .filter(|w| w[0] == "--holder")
            .map(|w| w[1].as_str())
            .collect();
        let holders_env = std::env::var("MESH_HOLDERS").ok();
        if holders.is_empty()
            && let Some(tickets) = &holders_env
        {
            holders = tickets.split_whitespace().collect();
        }
        if let Some(Err(e)) = holders
            .iter()
            .map(|t| MeshAddr::from_ticket(t))
            .find(Result::is_err)
        {
            eprintln!("mesh-node: bad --holder ticket: {e}");
            std::process::exit(2);
        }
        let holders: Vec<String> = holders.into_iter().map(str::to_owned).collect();
        if holders.len() > mesh_identity::MAX_HOLDERS {
            eprintln!("mesh-node: at most {} holders", mesh_identity::MAX_HOLDERS);
            std::process::exit(2);
        }
        let options = helper::Options {
            record_ttl,
            peer_idle,
            cut,
            holders,
            crash_at_records: args
                .windows(2)
                .any(|w| w[0] == "--crash-at" && w[1] == "records"),
            no_calls: args.iter().any(|a| a == "--no-calls"),
            hide_ip: args.iter().any(|a| a == "--hide-ip"),
            #[cfg(feature = "audio")]
            audio: audio_options(&args),
        };
        runtime.block_on(helper::run(&dir, relays, seeds, options));
    }
}

/// The seed's `--port`, `--public`, `--relay-only` and `--report-every`.
fn seed_options(args: &[String], relays: &Relays) -> Result<seed::Options, String> {
    let value = |flag: &str| {
        args.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].as_str())
    };
    let port = value("--port")
        .map(|p| p.parse::<u16>().map_err(|_| "--port takes a UDP port"))
        .transpose()?;
    let public = value("--public")
        .map(|a| a.parse().map_err(|_| "--public takes an ip:port"))
        .transpose()?;
    let relay_only = args.iter().any(|a| a == "--relay-only");
    if relay_only && (port.is_some() || public.is_some()) {
        return Err("--relay-only can't go with --port or --public".into());
    }
    // One relay, so the ticket names the relay the seed is really on.
    if relay_only
        && !matches!(relays, Relays::Custom(r) if r.len() == 1 && args.iter().any(|a| a == "--relay"))
    {
        return Err("--relay-only takes exactly one --relay".into());
    }
    let report = match value("--report-every") {
        None => seed::REPORT_EVERY,
        Some(s) => std::time::Duration::from_secs(
            s.parse::<u64>()
                .ok()
                .filter(|&s| s > 0)
                .ok_or("--report-every takes seconds")?,
        ),
    };
    Ok(seed::Options {
        port,
        public,
        relay_only,
        report,
        mail: args.iter().any(|a| a == "--mail"),
        mail_settings: mail_settings(value("--mail-token"), value("--mail-max"))?,
    })
}

/// `--mail-token` (letters, digits, `-` and `_`, 16 to 64 of them, so it
/// fits a ticket) and `--mail-max` (bytes).
fn mail_settings(token: Option<&str>, max: Option<&str>) -> Result<mailstore::Settings, String> {
    let token = token
        .map(|t| {
            let fits = (16..=mailstore::MAX_TOKEN).contains(&t.len())
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            fits.then(|| t.as_bytes().to_vec())
                .ok_or("--mail-token takes 16 to 64 letters, digits, - or _")
        })
        .transpose()?;
    let max = match max {
        None => mailstore::MAIL_STORE_MAX,
        Some(m) => m
            .parse::<u64>()
            .ok()
            .filter(|&m| m > 0)
            .ok_or("--mail-max takes bytes")?,
    };
    Ok(mailstore::Settings { token, max })
}

/// n0's relays; iroh makes whichever answers fastest the home relay. There's
/// no relay of our own any more (SPEC-seed D5 as changed).
fn default_relays() -> Vec<RelayUrl> {
    mesh_transport::public_relays()
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

/// The calls' test flags (SPEC-calls *Acceptance tests*): `--tone <hz>`
/// for the microphone, `--heard <file>` for the speakers, and `--drop
/// <percent>` of incoming voice.
#[cfg(feature = "audio")]
fn audio_options(args: &[String]) -> media::Io {
    let value = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone());
    let fail = |msg: &str| -> ! {
        eprintln!("mesh-node: {msg}");
        std::process::exit(2);
    };
    media::Io {
        tone: value("--tone").map(|v| {
            v.parse()
                .unwrap_or_else(|_| fail("--tone takes a frequency in Hz"))
        }),
        heard: value("--heard").map(PathBuf::from),
        drop: value("--drop").map_or(0, |v| match v.parse::<u8>() {
            Ok(p) if p <= 100 => p,
            _ => fail("--drop takes 0 to 100"),
        }),
        mic_file: value("--mic-file").map(PathBuf::from),
        echo: value("--echo").map(|v| {
            let parsed = v
                .split_once(',')
                .and_then(|(ms, at)| Some((ms.parse().ok()?, at.parse().ok()?)));
            parsed.unwrap_or_else(|| fail("--echo takes <ms>,<level>, as 40,0.5"))
        }),
        ..media::Io::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_lists_parse() {
        let relays = default_relays();
        assert_eq!(relays.len(), 4, "n0's four");
        let eu = &relays[2];
        assert_eq!(eu.as_str(), "https://euc1-1.relay.n0.iroh.link./");
        for ticket in helper::SEEDS {
            let seed = MeshAddr::from_ticket(ticket).expect("a valid ticket");
            assert_eq!(
                seed.relay.as_ref(),
                Some(eu),
                "the seed is on n0's EU relay"
            );
            assert!(seed.direct.is_empty(), "the seed's address is never shown");
        }
        assert!(relay("http://example.org").is_err());
        assert!(relay("http://127.0.0.1:3340").is_ok());
    }
}
