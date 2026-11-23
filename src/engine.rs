//! Scan engine shared by the command line and the window: finding files, hashing,
//! signatures, progress counters and the AirDrag-compatible XML/CSV output.

use crate::win;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use md5::Md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use walkdir::WalkDir;

// Non-executable types AirDrag captures by extension - measured with a 105-file test folder.
// Executables (exe, dll, sys, sfx, renamed copies...) are found by content instead: see looks_like_pe.
const EXTENSIONS: &[&str] = &[
    "bat", "cmd", "chm", "hta", "jar", "js", "msi", "ps1", "psm1", "py", "pyc", "pyw", "sct", "vbe", "vbs", "wsc", "wsf",
];

#[derive(Default)]
pub struct Opts {
    pub roots: Vec<PathBuf>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub xml: Option<PathBuf>,
    pub csv: Option<PathBuf>,
    pub threads: Option<usize>,
    pub no_catalog: bool,
}

#[derive(Default)]
pub struct Rec {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub sha384: String,
    pub sha512: String,
    pub created: u64,  // Unix seconds
    pub modified: u64, // Unix seconds
    pub captured: u64, // Unix seconds, when this file was hashed
    /// AirDrag's publisher: signer name, "Not Signed", or "" for file types Windows can't sign.
    pub xml_publisher: String,
    pub publisher: String,
    pub sig_type: &'static str,
    pub sig_status: String,
    pub subject: String,
    pub issuer: String,
    pub thumbprint: String,
    pub catalog: String,
    pub error: String,
}

impl Rec {
    fn apply(&mut self, c: &win::CertInfo) {
        self.publisher.clone_from(&c.publisher);
        self.subject.clone_from(&c.subject);
        self.issuer.clone_from(&c.issuer);
        self.thumbprint.clone_from(&c.thumbprint);
    }
}

thread_local! {
    static CATALOGS: win::Catalogs = win::Catalogs::new();
    static BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 1 << 20]);
}

// Each .cat is parsed once, however many files it covers.
static CATALOG_SIGNERS: LazyLock<Mutex<HashMap<String, Option<win::CertInfo>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// Progress shared with the reporting thread.
pub static FOUND: AtomicU64 = AtomicU64::new(0); // files listed during counting
pub static TOTAL: AtomicU64 = AtomicU64::new(0); // set once counting finishes
pub static SCANNED: AtomicU64 = AtomicU64::new(0); // files hashed + checked
pub static HASHING: AtomicBool = AtomicBool::new(false); // false = counting phase
/// Set to stop a running scan (the window's Cancel button).
pub static CANCEL: AtomicBool = AtomicBool::new(false);

/// Clears the progress counters before a new scan.
#[cfg_attr(not(windows), allow(dead_code))] // used by the window
pub fn reset_progress() {
    for c in [&FOUND, &TOTAL, &SCANNED] {
        c.store(0, Ordering::Relaxed);
    }
    HASHING.store(false, Ordering::Relaxed);
    CANCEL.store(false, Ordering::Relaxed);
}

pub fn summary(recs: &[Rec]) -> String {
    let signed = recs.iter().filter(|r| matches!(r.sig_type, "Embedded" | "Catalog")).count();
    let unsigned = recs.iter().filter(|r| r.sig_type == "None").count();
    let errors = recs.iter().filter(|r| !r.error.is_empty()).count();
    format!("{} files ({signed} signed, {unsigned} unsigned, {errors} errors)", recs.len())
}

/// Lowercase hex, as in the capture XML.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn looks_like_pe(p: &Path) -> bool {
    let mut mz = [0u8; 2];
    File::open(p).and_then(|mut f| f.read_exact(&mut mz)).is_ok() && &mz == b"MZ"
}

pub fn wanted(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXTENSIONS.iter().any(|x| x.eq_ignore_ascii_case(e)))
}

fn hash_file(path: &Path, r: &mut Rec) -> io::Result<()> {
    let mut f = File::open(path)?; // std opens with FILE_SHARE_READ|WRITE|DELETE
    let meta = f.metadata()?;
    r.size = meta.len();
    r.created = meta.created().map(unix).unwrap_or(0);
    r.modified = meta.modified().map(unix).unwrap_or(0);

    // All five hashes the capture XML carries, from one read.
    let mut s256 = Sha256::new();
    let mut s1 = Sha1::new();
    let mut m5 = Md5::new();
    let mut s384 = Sha384::new();
    let mut s512 = Sha512::new();

    BUF.with(|buf| -> io::Result<()> {
        let mut buf = buf.borrow_mut();
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            s256.update(chunk);
            s1.update(chunk);
            m5.update(chunk);
            s384.update(chunk);
            s512.update(chunk);
        }
        Ok(())
    })?;

    r.sha256 = hex(&s256.finalize());
    r.sha1 = hex(&s1.finalize());
    r.md5 = hex(&m5.finalize());
    r.sha384 = hex(&s384.finalize());
    r.sha512 = hex(&s512.finalize());
    r.captured = unix(SystemTime::now());
    Ok(())
}

fn catalog_signer(cat: &str) -> Option<win::CertInfo> {
    let key = cat.to_lowercase();
    if let Some(v) = CATALOG_SIGNERS.lock().unwrap().get(&key) {
        return v.clone();
    }
    let v = win::signer_cert(&win::wide(cat));
    CATALOG_SIGNERS.lock().unwrap().insert(key, v.clone());
    v
}

fn signature(r: &mut Rec, o: &Opts) {
    #[cfg(feature = "linux-test")]
    {
        let _ = o;
        r.sig_type = "None";
        r.sig_status = "Unsigned".into();
        r.xml_publisher = "Not Signed".into();
        return;
    }
    #[cfg(not(feature = "linux-test"))]
    signature_windows(r, o);
}

#[cfg(not(feature = "linux-test"))]
fn signature_windows(r: &mut Rec, o: &Opts) {
    let wpath = win::wide(&win::native_path(&r.path));

    let hr = win::verify_embedded(&wpath);
    // AirDrag: "Not Signed" for signable types with no signature, "" for types Windows can't sign (.chm, .bat).
    r.xml_publisher = if win::is_no_signature(hr) { "Not Signed".into() } else { String::new() };
    if !win::is_unsigned(hr) {
        r.sig_type = "Embedded";
        r.sig_status = if hr == 0 { "Valid".into() } else { format!("Invalid (0x{:08X})", hr as u32) };
        if let Some(c) = win::signer_cert(&wpath) {
            r.apply(&c);
        }
        r.xml_publisher.clone_from(&r.publisher);
        return;
    }

    if !o.no_catalog
        && let Some(cat) = CATALOGS.with(|c| c.find(&wpath)) {
            r.sig_type = "Catalog";
            r.sig_status = "Valid".into();
            if let Some(c) = catalog_signer(&cat) {
                r.apply(&c);
            }
            r.xml_publisher.clone_from(&r.publisher);
            r.catalog = cat;
            return;
        }

    r.sig_type = "None";
    r.sig_status = "Unsigned".into();
}

fn process(path: &Path, o: &Opts) -> Option<Rec> {
    if CANCEL.load(Ordering::Relaxed) {
        return None;
    }
    // AirDrag's rule: one of its script/installer extensions, or an executable by content (whatever the name).
    let keep = wanted(path) || looks_like_pe(path);
    let rec = keep.then(|| {
        let mut r = Rec { path: path.to_string_lossy().into_owned(), ..Default::default() };
        match hash_file(path, &mut r) {
            Ok(()) => signature(&mut r, o),
            Err(e) => r.error = format!("hash: {e}"),
        }
        r
    });
    SCANNED.fetch_add(1, Ordering::Relaxed);
    rec
}

/// Runs a scan. Returns `None` if it was cancelled.
pub fn scan(o: &Opts) -> Option<Vec<Rec>> {
    // Phase 1: list matching files (directory entries only - quick) so we have a total.
    let files: Vec<PathBuf> = o
        .roots
        .iter()
        .flat_map(|root| WalkDir::new(root).follow_links(false)) // junctions/symlinks not followed
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file()) // every file: executables are recognised by content, like AirDrag
        .take_while(|_| !CANCEL.load(Ordering::Relaxed))
        .map(|e| {
            FOUND.fetch_add(1, Ordering::Relaxed);
            e.into_path()
        })
        .collect();
    if CANCEL.load(Ordering::Relaxed) {
        return None;
    }
    TOTAL.store(files.len() as u64, Ordering::Relaxed);

    // Phase 2: hash + signatures in parallel.
    HASHING.store(true, Ordering::Relaxed);
    let mut recs: Vec<Rec> = files.par_iter().filter_map(|p| process(p, o)).collect();
    if CANCEL.load(Ordering::Relaxed) {
        return None;
    }
    recs.sort_by_cached_key(|r| r.path.to_lowercase());
    Some(recs)
}

pub fn progress_line(hash_start: Option<Instant>) -> String {
    if !HASHING.load(Ordering::Relaxed) {
        return format!("Finding files... {} found", FOUND.load(Ordering::Relaxed));
    }
    let done = SCANNED.load(Ordering::Relaxed);
    let total = TOTAL.load(Ordering::Relaxed);
    let pct = (done * 100).checked_div(total).unwrap_or(100);
    let secs = hash_start.map_or(0.0, |t| t.elapsed().as_secs_f64());
    let rate = if secs > 0.0 { done as f64 / secs } else { 0.0 };
    let mut line = format!("{done} of {total} files ({pct}%) - {rate:.0}/s");
    if secs >= 2.0 && rate > 0.0 && done < total {
        let left = ((total - done) as f64 / rate).ceil() as u64;
        let eta = match left {
            0..60 => format!("{left} s"),
            60..3600 => format!("{} min {} s", left / 60, left % 60),
            _ => format!("{} h {} min", left / 3600, (left % 3600) / 60),
        };
        line.push_str(&format!(" - about {eta} left"));
    }
    line
}

// ---------- output ----------

fn cdata(s: &str) -> String {
    format!("<![CDATA[{}]]>", s.replace("]]>", "]]]]><![CDATA[>"))
}

/// Capture XML, matching AirDrag's Offline Application Export:
/// same elements and order, CDATA where AirDrag uses it, lowercase hashes, Unix-seconds times, tab indents.
pub fn write_xml(path: &Path, recs: &[Rec], o: &Opts) -> io::Result<()> {
    let mut w: Vec<u8> = Vec::new(); // built in memory, then written with CRLF line endings like AirDrag
    let name = o.name.as_deref().unwrap_or("").trim();
    let version = o.version.as_deref().unwrap_or("").trim();
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();

    writeln!(w, r#"<?xml version="1.0" encoding="utf-8"?>"#)?;
    writeln!(w, "<AirlockCapture>")?;
    writeln!(w, "\t<Name>{}</Name>", cdata(name))?;
    writeln!(w, "\t<ID>{}</ID>", uuid::Uuid::new_v4())?;
    if version.is_empty() {
        writeln!(w, "\t<Version />")?;
    } else {
        writeln!(w, "\t<Version>{}</Version>", cdata(version))?;
    }
    writeln!(w, "\t<HostName>{}</HostName>", cdata(&host))?;
    writeln!(w, "\t<User>{}</User>", cdata(&user))?;
    writeln!(w, "\t<Timestamp>{}</Timestamp>", unix(SystemTime::now()))?;
    writeln!(w, "\t<Status>4</Status>")?; // value AirDrag uses for offline captures
    writeln!(w, "\t<ResultsSection>")?;
    for r in recs.iter().filter(|r| !r.sha256.is_empty()) {
        writeln!(w, "\t\t<fileload>")?;
        writeln!(w, "\t\t\t<path>{}</path>", cdata(&r.path))?;
        writeln!(w, "\t\t\t<sha256>{}</sha256>", r.sha256)?;
        writeln!(w, "\t\t\t<sha1>{}</sha1>", r.sha1)?;
        writeln!(w, "\t\t\t<md5>{}</md5>", r.md5)?;
        writeln!(w, "\t\t\t<sha384>{}</sha384>", r.sha384)?;
        writeln!(w, "\t\t\t<sha512>{}</sha512>", r.sha512)?;
        writeln!(w, "\t\t\t<time>{}</time>", r.captured)?;
        writeln!(w, "\t\t\t<filesize>{}</filesize>", r.size)?;
        writeln!(w, "\t\t\t<createtime>{}</createtime>", r.created)?;
        writeln!(w, "\t\t\t<modtime>{}</modtime>", r.modified)?;
        writeln!(w, "\t\t\t<publisher>{}</publisher>", cdata(&r.xml_publisher))?;
        writeln!(w, "\t\t</fileload>")?;
    }
    writeln!(w, "\t</ResultsSection>")?;
    write!(w, "</AirlockCapture>")?; // no trailing newline, like AirDrag
    let text = String::from_utf8_lossy(&w).replace('\n', "\r\n");
    std::fs::write(path, text)
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\r', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_owned() }
}

pub fn write_csv(path: &Path, recs: &[Rec]) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    w.write_all(b"\xEF\xBB\xBF")?; // BOM so Excel reads UTF-8
    writeln!(w, "Path,SHA256,SHA1,MD5,SHA384,SHA512,Size,Created,Modified,Publisher,SignatureType,SignatureStatus,Subject,Issuer,Thumbprint,CatalogFile,Error")?;
    for r in recs {
        let row = [
            r.path.as_str(), &r.sha256, &r.sha1, &r.md5, &r.sha384, &r.sha512, &r.size.to_string(),
            &r.created.to_string(), &r.modified.to_string(), &r.xml_publisher, r.sig_type, &r.sig_status,
            &r.subject, &r.issuer, &r.thumbprint, &r.catalog, &r.error,
        ];
        let line: Vec<String> = row.iter().map(|s| csv_field(s)).collect();
        writeln!(w, "{}", line.join(","))?;
    }
    w.flush()
}

pub fn file_name_for(name: &str, version: Option<&str>) -> String {
    let raw = match version.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => format!("{}-{v}", name.trim()), // AirDrag's "<name>-<version>"
        None => name.trim().to_owned(),
    };
    let clean: String =
        raw.chars().map(|c| if r#"<>:"/\|?*"#.contains(c) || (c as u32) < 0x20 { '_' } else { c }).collect();
    let clean = clean.trim_end_matches(['.', ' ']).to_owned();
    if clean.is_empty() { "scan".into() } else { clean }
}

// ---------- cli ----------

