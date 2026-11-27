//! Finding a person's plugins (SPEC-voice-quality F8): the standard
//! folders plus the ones they added, one throwaway `mesh-fx scan` per file
//! so a plugin that crashes on load only marks itself broken, and a cache
//! (`fx/scan.json`) so an unchanged file isn't loaded again.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde_json::{Value, json};

/// How long one file may take to load and list.
pub const SCAN_LIMIT: Duration = Duration::from_secs(10);
/// Folders inside a plugin folder we look into (vendor/product nesting).
const DEPTH: usize = 4;

/// The standard plugin folders here, plus `CLAP_PATH` (the CLAP spec's).
pub fn standard_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("CLAP_PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    #[cfg(windows)]
    if let Some(common) = std::env::var_os("CommonProgramFiles") {
        let common = PathBuf::from(common);
        dirs.extend([common.join("VST3"), common.join("CLAP")]);
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            dirs.extend([home.join(".vst3"), home.join(".clap")]);
        }
        dirs.extend(
            [
                "/usr/lib/vst3",
                "/usr/local/lib/vst3",
                "/usr/lib/clap",
                "/usr/local/lib/clap",
            ]
            .map(PathBuf::from),
        );
    }
    dirs
}

/// Plugin files under `dirs`: `.clap` files and `.vst3` bundles or files.
pub fn find(dirs: &[PathBuf]) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some(e) if e.eq_ignore_ascii_case("clap") || e.eq_ignore_ascii_case("vst3") => {
                    out.push(path)
                }
                _ if depth > 0 && path.is_dir() => walk(&path, depth - 1, out),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    dirs.iter().for_each(|d| walk(d, DEPTH, &mut out));
    out.sort();
    out.dedup();
    out
}

/// A file's modified time, as the cache keys it.
// ponytail: a .vst3 bundle's folder time; an update that rewrites only the library inside isn't seen until Rescan clears the cache.
fn modified(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// One file through `scanner scan <file>`: its plugins, or why it's broken.
fn scan_file(scanner: &Path, file: &Path, limit: Duration) -> Result<Value, String> {
    let mut child = Command::new(scanner)
        .arg("scan")
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("couldn't start the scanner: {e}"))?;
    // Read while it runs: a big list could fill the pipe and stall it.
    let drain = |r: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            buf
        })
    };
    let stdout = drain(child.stdout.take().map(|r| Box::new(r) as _));
    let stderr = drain(child.stderr.take().map(|r| Box::new(r) as _));
    let until = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "took longer than {} s to load",
                limit.as_secs_f32()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (out, err) = (
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default(),
    );
    if !status.success() {
        let said = String::from_utf8_lossy(&err);
        let last = said.lines().last().unwrap_or("").trim();
        return Err(if last.is_empty() {
            format!("crashed while loading ({status})")
        } else {
            last.to_owned()
        });
    }
    serde_json::from_slice::<Value>(&out)
        .ok()
        .filter(|v| v["plugins"].is_array())
        .ok_or_else(|| "the scanner's answer didn't read".into())
}

/// Scans `files` with `scanner`, reusing `cache` entries whose file hasn't
/// changed; the new cache, and how many files were actually loaded.
pub fn scan(scanner: &Path, files: &[PathBuf], cache: &Value, limit: Duration) -> (Value, usize) {
    let mut out = serde_json::Map::new();
    let mut loaded = 0;
    for file in files {
        let key = file.to_string_lossy().into_owned();
        let at = modified(file);
        let entry = match cache.get(&key) {
            Some(e) if e["modified"] == at => e.clone(),
            _ => {
                loaded += 1;
                match scan_file(scanner, file, limit) {
                    Ok(v) => {
                        json!({"modified": at, "format": v["format"], "plugins": v["plugins"]})
                    }
                    Err(error) => json!({"modified": at, "error": error}),
                }
            }
        };
        out.insert(key, entry);
    }
    (Value::Object(out), loaded)
}

/// The cache as `meshFxPlugins` shows it: every plugin, and the broken files.
pub fn event(cache: &Value) -> Value {
    let (mut plugins, mut broken) = (Vec::new(), Vec::new());
    for (path, e) in cache.as_object().into_iter().flatten() {
        if let Some(error) = e.get("error") {
            broken.push(json!({"path": path, "error": error}));
            continue;
        }
        for p in e["plugins"].as_array().into_iter().flatten() {
            plugins.push(json!({"path": path, "format": e["format"], "id": p["id"], "name": p["name"], "vendor": p["vendor"]}));
        }
    }
    json!({"plugins": plugins, "broken": broken})
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in scanner: `.clap` files answer, `crash` ones die on a
    /// signal, `hang` ones never finish; every call is counted.
    fn scanner(dir: &Path) -> PathBuf {
        let path = dir.join("fake-mesh-fx");
        let calls = dir.join("calls");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho x >> '{}'\ncase \"$2\" in\n  *crash*) kill -SEGV $$ ;;\n  *hang*) sleep 30 ;;\n  *) echo '{{\"format\":\"clap\",\"plugins\":[{{\"id\":\"a\",\"name\":\"A\",\"vendor\":\"V\"}}]}}' ;;\nesac\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn calls(dir: &Path) -> usize {
        std::fs::read_to_string(dir.join("calls")).map_or(0, |s| s.lines().count())
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mesh-fxscan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn finds_plugins_in_nested_folders_and_not_inside_bundles() {
        let d = temp("find");
        std::fs::create_dir_all(d.join("Vendor/Thing.vst3/Contents/x86_64-linux")).unwrap();
        std::fs::write(
            d.join("Vendor/Thing.vst3/Contents/x86_64-linux/Thing.so"),
            "",
        )
        .unwrap();
        std::fs::write(d.join("eq.clap"), "").unwrap();
        std::fs::write(d.join("readme.txt"), "").unwrap();
        let found = find(&[d.clone(), d.join("missing")]);
        assert_eq!(found, vec![d.join("Vendor/Thing.vst3"), d.join("eq.clap")]);
    }

    #[test]
    fn broken_files_are_listed_and_unchanged_ones_are_not_loaded_again() {
        let d = temp("scan");
        let fake = scanner(&d);
        let files: Vec<PathBuf> = ["good.clap", "crash.clap", "hang.clap"]
            .iter()
            .map(|n| d.join(n))
            .collect();
        files.iter().for_each(|f| std::fs::write(f, "").unwrap());
        let started = Instant::now();
        let (cache, loaded) = scan(&fake, &files, &Value::Null, Duration::from_millis(500));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(loaded, 3);
        let shown = event(&cache);
        assert_eq!(shown["plugins"].as_array().unwrap().len(), 1);
        assert_eq!(shown["plugins"][0]["name"], "A");
        let broken = shown["broken"].as_array().unwrap();
        assert_eq!(broken.len(), 2, "{shown}");
        assert!(
            broken
                .iter()
                .any(|b| b["error"].as_str().unwrap().contains("crashed")),
            "{shown}"
        );
        assert!(
            broken
                .iter()
                .any(|b| b["error"].as_str().unwrap().contains("longer than")),
            "{shown}"
        );
        // Again with nothing changed: no scanner started.
        let before = calls(&d);
        let (again, loaded) = scan(&fake, &files, &cache, Duration::from_millis(500));
        assert_eq!((loaded, calls(&d)), (0, before));
        assert_eq!(again, cache);
    }
}
