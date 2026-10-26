//! `mesh-node`: Mesh's networking engine. `mesh-node --data <dir>` is
//! Mesh-Voice's helper: commands arrive on stdin as `{"fn":..,"args":[..]}`
//! lines, events go out on stdout as `{"binding":..,"payload":"<json>"}`
//! lines, the same protocol as mesh-wa and mesh-dc. Logs go to stderr.

mod helper;

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("mesh-node {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let dir = args
        .iter()
        .position(|a| a == "--data")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or_else(default_data_dir);
    let Some(dir) = dir else {
        eprintln!("mesh-node: no data directory; pass --data <dir>");
        std::process::exit(2);
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
    runtime.block_on(helper::run(&dir));
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
