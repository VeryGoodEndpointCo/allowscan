//! allowscan - fast offline allowlist builder (AirDrag replacement).
//! No arguments: opens the window. With arguments: command line.

mod engine;
#[cfg(all(windows, not(feature = "linux-test")))]
mod gui;
#[cfg_attr(feature = "linux-test", allow(dead_code))]
mod win;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use engine::*;

pub use engine::hex;

const USAGE: &str = r#"allowscan                         (no arguments) opens the window
allowscan <folder> [<folder> ...] [options]
  -n, --name <text>    Software name     } XML saved as "<name>-<version>.xml"
  -v, --version <text> Software version  } unless -o is given
  -o, --xml <file>     Write XML
  --csv <file>         Write CSV
  -t, --threads <n>    Worker threads (default: CPU count)
  --no-catalog         Skip catalog lookup"#;

fn parse() -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut next = || args.next().ok_or_else(|| format!("missing value for {a}"));
        match a.as_str() {
            "-h" | "--help" | "/?" => return Err(String::new()),
            "-n" | "--name" => o.name = Some(next()?),
            "-v" | "--version" => o.version = Some(next()?),
            "-o" | "--xml" => o.xml = Some(next()?.into()),
            "--csv" => o.csv = Some(next()?.into()),
            "-t" | "--threads" => {
                o.threads = Some(next()?.parse().ok().filter(|&n| n > 0).ok_or("--threads must be a positive number")?)
            }
            "--no-catalog" => o.no_catalog = true,
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => {
                let p = std::path::absolute(s).map_err(|e| format!("{s}: {e}"))?;
                if !p.is_dir() {
                    return Err(format!("folder not found: {}", p.display()));
                }
                o.roots.push(p);
            }
        }
    }
    if o.roots.is_empty() {
        return Err("no folder given".into());
    }
    if o.xml.is_none()
        && let Some(n) = o.name.as_deref().filter(|n| !n.trim().is_empty()) {
            o.xml = Some(format!("{}.xml", file_name_for(n, o.version.as_deref())).into());
        }
    if o.xml.is_none() && o.csv.is_none() {
        o.csv = Some("allowscan.csv".into());
    }
    Ok(o)
}

fn main() {
    #[cfg(all(windows, not(feature = "linux-test")))]
    if std::env::args().len() == 1 {
        win::hide_console_if_owned(); // double-clicked: show only the window
        std::process::exit(gui::run());
    }

    let o = match parse() {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let Some(n) = o.threads {
        rayon::ThreadPoolBuilder::new().num_threads(n).build_global().expect("thread pool");
    }

    let start = Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let progress = {
        let done = done.clone();
        std::thread::spawn(move || {
            let mut hash_start = None;
            while !done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                if hash_start.is_none() && HASHING.load(Ordering::Relaxed) {
                    hash_start = Some(Instant::now()); // rate/ETA from hashing start, not counting
                }
                eprint!("\r  {:<88}", progress_line(hash_start));
            }
        })
    };

    #[cfg(not(feature = "linux-test"))]
    let awake = win::KeepAwake::new(); // no idle sleep while scanning
    let recs = scan(&o).unwrap_or_default(); // the command line never cancels
    #[cfg(not(feature = "linux-test"))]
    drop(awake);
    done.store(true, Ordering::Relaxed);
    let _ = progress.join();

    let result = (|| -> io::Result<()> {
        if let Some(p) = &o.xml {
            write_xml(p, &recs, &o)?;
        }
        if let Some(p) = &o.csv {
            write_csv(p, &recs)?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("\nfailed to write output: {e}");
        std::process::exit(1);
    }

    let errors = recs.iter().filter(|r| !r.error.is_empty()).count();
    eprintln!("\nDone in {:.1}s: {}", start.elapsed().as_secs_f64(), summary(&recs));
    for p in o.xml.iter().chain(o.csv.iter()) {
        eprintln!("  {}", p.display());
    }
    std::process::exit(if errors > 0 { 1 } else { 0 });
}
