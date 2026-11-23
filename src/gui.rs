//! The window: native Win32 controls through winsafe, same layout and behaviour as the C# version.
//!
//! The scan runs on a background thread (the engine spreads it across all cores).
//! The window never touches the scan directly: a 250 ms timer on the UI thread reads the
//! engine's progress counters and picks up the result, so no UI call ever crosses threads.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use winsafe::{self as w, co, gui, prelude::*};

use crate::engine::{self, Opts};
use crate::win::KeepAwake;

const TIMER_ID: usize = 1;
const TITLE: &str = "allowscan – offline allowlist builder";

/// What the background thread hands back.
enum Outcome {
    Saved(String), // summary line
    Cancelled,
    Failed(String),
}

/// A scan in progress.
struct Job {
    outcome: Arc<Mutex<Option<Outcome>>>,
    xml: PathBuf,
    started: Instant,
    hash_started: Option<Instant>,
    _awake: KeepAwake, // no idle sleep while this exists; created and dropped on the UI thread
}

#[derive(Default)]
struct State {
    job: Option<Job>,
    last_output: Option<PathBuf>,
}

#[derive(Clone)]
struct Main {
    wnd: gui::WindowMain,
    min_size: Rc<std::cell::Cell<(i32, i32)>>, // outer window size at creation = smallest allowed
    name: gui::Edit,
    version: gui::Edit,
    folders: gui::ListBox,
    add: gui::Button,
    remove: gui::Button,
    clear: gui::Button,
    out_dir: gui::Edit,
    browse: gui::Button,
    file_name: gui::Label,
    catalog: gui::CheckBox,
    csv: gui::CheckBox,
    bar: gui::ProgressBar,
    status: gui::Label,
    scan: gui::Button,
    new_scan: gui::Button,
    show_file: gui::Button,
    state: Rc<RefCell<State>>,
}

/// Opens the window and runs until it's closed. Returns the process exit code.
pub fn run() -> i32 {
    // COM is needed for the folder picker.
    let _com = w::CoInitializeEx(co::COINIT::APARTMENTTHREADED | co::COINIT::DISABLE_OLE1DDE);
    match Main::new().wnd.run_main(None) {
        Ok(code) => code,
        Err(e) => {
            let _ = w::HWND::NULL.MessageBox(&e.to_string(), TITLE, co::MB::ICONERROR);
            1
        }
    }
}

// Layout helpers, in 96-DPI pixels scaled to the screen.
fn pos(x: i32, y: i32) -> (i32, i32) {
    gui::dpi(x, y)
}
fn dx(v: i32) -> i32 {
    gui::dpi_x(v)
}
fn dy(v: i32) -> i32 {
    gui::dpi_y(v)
}

const FIXED: (gui::Horz, gui::Vert) = (gui::Horz::None, gui::Vert::None);
const STRETCH_X: (gui::Horz, gui::Vert) = (gui::Horz::Resize, gui::Vert::None);
const BOTTOM: (gui::Horz, gui::Vert) = (gui::Horz::None, gui::Vert::Repos);
const BOTTOM_STRETCH_X: (gui::Horz, gui::Vert) = (gui::Horz::Resize, gui::Vert::Repos);
const BOTTOM_RIGHT: (gui::Horz, gui::Vert) = (gui::Horz::Repos, gui::Vert::Repos);

impl Main {
    fn new() -> Self {
        let wnd = gui::WindowMain::new(gui::WindowMainOpts {
            title: TITLE,
            class_icon: gui::Icon::Id(1), // res/allowscan.ico, embedded by build.rs
            size: pos(760, 512),
            style: gui::WindowMainOpts::default().style | co::WS::MINIMIZEBOX | co::WS::MAXIMIZEBOX | co::WS::SIZEBOX,
            ex_style: co::WS_EX::LEFT | co::WS_EX::ACCEPTFILES, // drag folders in from Explorer
            ..Default::default()
        });

        let label = |text: &str, x: i32, y: i32, w: i32, rb| {
            gui::Label::new(&wnd, gui::LabelOpts {
                text,
                position: pos(x, y),
                size: pos(w, 20),
                resize_behavior: rb,
                ..Default::default()
            })
        };
        let edit = |x: i32, y: i32, w: i32, rb| {
            gui::Edit::new(&wnd, gui::EditOpts {
                position: pos(x, y),
                width: dx(w),
                height: dy(23),
                resize_behavior: rb,
                ..Default::default()
            })
        };
        let button = |text: &str, x: i32, y: i32, w: i32, h: i32, rb| {
            gui::Button::new(&wnd, gui::ButtonOpts {
                text,
                position: pos(x, y),
                width: dx(w),
                height: dy(h),
                resize_behavior: rb,
                ..Default::default()
            })
        };
        let check = |text: &str, x: i32, y: i32, w: i32, checked: bool| {
            gui::CheckBox::new(&wnd, gui::CheckBoxOpts {
                text,
                position: pos(x, y),
                size: pos(w, 20),
                resize_behavior: BOTTOM,
                check_state: if checked { co::BST::CHECKED } else { co::BST::UNCHECKED },
                ..Default::default()
            })
        };

        label("Software name", 12, 15, 100, FIXED);
        let name = edit(120, 12, 628, STRETCH_X);
        label("Version", 12, 44, 100, FIXED);
        let version = edit(120, 41, 628, STRETCH_X);

        label("Folders to scan", 12, 74, 100, FIXED);
        let folders = gui::ListBox::new(&wnd, gui::ListBoxOpts {
            position: pos(120, 72),
            size: pos(520, 216),
            control_style: co::LBS::NOTIFY | co::LBS::EXTENDEDSEL | co::LBS::NOINTEGRALHEIGHT,
            window_style: gui::ListBoxOpts::default().window_style | co::WS::HSCROLL | co::WS::VSCROLL,
            resize_behavior: (gui::Horz::Resize, gui::Vert::Resize),
            ..Default::default()
        });
        let add = button("Add folders…", 650, 71, 98, 28, (gui::Horz::Repos, gui::Vert::None));
        let remove = button("Remove", 650, 103, 98, 28, (gui::Horz::Repos, gui::Vert::None));
        let clear = button("Clear list", 650, 135, 98, 28, (gui::Horz::Repos, gui::Vert::None));
        label("Tip: drag folders from Explorer onto this window.", 120, 294, 628, BOTTOM_STRETCH_X);

        label("Save to", 12, 325, 100, BOTTOM);
        let out_dir = edit(120, 322, 520, BOTTOM_STRETCH_X);
        let browse = button("Browse…", 650, 320, 98, 28, BOTTOM_RIGHT);
        let file_name = label("", 120, 351, 628, BOTTOM_STRETCH_X);

        let catalog = check("Look up catalog signatures", 120, 376, 210, true);
        let csv = check("Also save CSV", 340, 376, 150, false);

        let bar = gui::ProgressBar::new(&wnd, gui::ProgressBarOpts {
            position: pos(120, 404),
            size: pos(628, 16),
            window_style: co::WS::CHILD, // hidden until a scan starts
            resize_behavior: BOTTOM_STRETCH_X,
            ..Default::default()
        });
        let status = label("Ready.", 120, 426, 628, BOTTOM_STRETCH_X);

        let show_file = button("Show file", 472, 470, 88, 30, BOTTOM_RIGHT);
        let new_scan = button("New scan", 566, 470, 88, 30, BOTTOM_RIGHT);
        let scan = button("Scan", 660, 470, 88, 30, BOTTOM_RIGHT);

        let me = Self {
            wnd,
            name,
            version,
            folders,
            add,
            remove,
            clear,
            out_dir,
            browse,
            file_name,
            catalog,
            csv,
            bar,
            status,
            scan,
            new_scan,
            show_file,
            min_size: Rc::new(std::cell::Cell::new((0, 0))),
            state: Rc::new(RefCell::new(State::default())),
        };
        me.events();
        me
    }

    // ---------- events ----------

    fn events(&self) {
        // Don't let the window shrink below its designed size: the controls would overlap.
        let me = self.clone();
        self.wnd.on().wm_get_min_max_info(move |p| {
            let (w, h) = me.min_size.get();
            if w > 0 {
                p.info.ptMinTrackSize.x = w;
                p.info.ptMinTrackSize.y = h;
            }
            Ok(())
        });

        let me = self.clone();
        self.wnd.on().wm_create(move |_| {
            let rc = me.wnd.hwnd().GetWindowRect()?;
            me.min_size.set((rc.right - rc.left, rc.bottom - rc.top));
            let docs = std::env::var("USERPROFILE").map(|h| format!(r"{h}\Documents")).unwrap_or_default();
            me.out_dir.set_text(&docs)?;
            me.update_ui()?;
            me.name.hwnd().SetFocus();
            Ok(0)
        });

        let me = self.clone();
        self.add.on().bn_clicked(move || {
            for path in pick_folders(me.wnd.hwnd(), true, "Choose one or more folders to scan (subfolders are included)")? {
                me.add_folder(&path)?;
            }
            me.update_ui()
        });

        let me = self.clone();
        self.remove.on().bn_clicked(move || {
            let selected: Vec<u32> = me.folders.items().iter_selected()?.map(|r| r.map(|(i, _)| i)).collect::<Result<_, _>>()?;
            for i in selected.into_iter().rev() {
                me.folders.items().delete(i)?;
            }
            me.update_ui()
        });

        let me = self.clone();
        self.clear.on().bn_clicked(move || {
            me.folders.items().delete_all();
            me.update_ui()
        });

        let me = self.clone();
        self.browse.on().bn_clicked(move || {
            if let Some(dir) = pick_folders(me.wnd.hwnd(), false, "Where should the XML be saved?")?.into_iter().next() {
                me.out_dir.set_text(&dir)?;
            }
            Ok(())
        });

        for edit in [&self.name, &self.version, &self.out_dir] {
            let me = self.clone();
            edit.on().en_change(move || me.update_ui());
        }

        let me = self.clone();
        self.wnd.on().wm_drop_files(move |p| {
            for path in p.hdrop.DragQueryFile()? {
                me.add_folder(&path?)?;
            }
            me.update_ui()
        });

        let me = self.clone();
        self.scan.on().bn_clicked(move || {
            if me.state.borrow().job.is_some() {
                engine::CANCEL.store(true, Ordering::Relaxed);
                me.status.hwnd().SetWindowText("Cancelling…")?;
                Ok(())
            } else {
                me.start_scan()
            }
        });

        let me = self.clone();
        self.new_scan.on().bn_clicked(move || {
            if me.state.borrow().job.is_some() {
                return Ok(());
            }
            me.name.set_text("")?;
            me.version.set_text("")?;
            me.folders.items().delete_all();
            me.state.borrow_mut().last_output = None;
            me.status.hwnd().SetWindowText("Ready.")?;
            me.update_ui()?;
            me.name.hwnd().SetFocus();
            Ok(()) // save folder and checkboxes are kept: usually the same between scans
        });

        let me = self.clone();
        self.show_file.on().bn_clicked(move || {
            if let Some(path) = me.state.borrow().last_output.clone() {
                show_in_explorer(&path);
            }
            Ok(())
        });

        let me = self.clone();
        self.wnd.on().wm_timer(TIMER_ID, move || me.tick());

        let me = self.clone();
        self.wnd.on().wm_close(move || {
            if me.state.borrow().job.is_some() {
                let answer = me.wnd.hwnd().MessageBox(
                    "A scan is running. Cancel it and close?",
                    TITLE,
                    co::MB::YESNO | co::MB::ICONQUESTION,
                )?;
                if answer != co::DLGID::YES {
                    return Ok(());
                }
                engine::CANCEL.store(true, Ordering::Relaxed);
            }
            me.wnd.hwnd().DestroyWindow()?;
            Ok(())
        });
    }

    // ---------- folders ----------

    fn add_folder(&self, path: &str) -> w::AnyResult<()> {
        let p = Path::new(path);
        if !p.is_dir() {
            return Ok(()); // dropped files are ignored, only folders count
        }
        let mut full = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf()).display().to_string();
        while full.len() > 3 && full.ends_with('\\') {
            full.pop(); // "D:\Apps\" -> "D:\Apps", but keep "D:\"
        }
        for existing in self.folders.items().iter()? {
            if existing?.eq_ignore_ascii_case(&full) {
                return Ok(());
            }
        }
        self.folders.items().add(&[&full])?;
        self.folders.set_horizontal_extend(dx(8 * full.len() as i32)); // horizontal scroll for long paths
        Ok(())
    }

    fn folder_list(&self) -> w::AnyResult<Vec<PathBuf>> {
        Ok(self.folders.items().iter()?.map(|r| r.map(PathBuf::from)).collect::<Result<_, _>>()?)
    }

    // ---------- scan ----------

    fn output_base(&self) -> w::AnyResult<Option<PathBuf>> {
        let name = self.name.text()?;
        if name.trim().is_empty() {
            return Ok(None);
        }
        let base = engine::file_name_for(&name, Some(&self.version.text()?));
        Ok(Some(PathBuf::from(self.out_dir.text()?.trim()).join(base)))
    }

    fn start_scan(&self) -> w::AnyResult<()> {
        let hwnd = self.wnd.hwnd();
        let roots = self.folder_list()?;
        let Some(base) = self.output_base()? else {
            hwnd.MessageBox("Enter a software name first.", TITLE, co::MB::ICONINFORMATION)?;
            return Ok(());
        };
        if roots.is_empty() {
            hwnd.MessageBox("Add at least one folder to scan.", TITLE, co::MB::ICONINFORMATION)?;
            return Ok(());
        }
        if !base.parent().is_some_and(Path::is_dir) {
            hwnd.MessageBox("The 'Save to' folder doesn't exist.", TITLE, co::MB::ICONINFORMATION)?;
            return Ok(());
        }

        let xml = with_suffix(&base, "xml");
        if xml.exists() {
            let file = xml.file_name().unwrap_or_default().to_string_lossy();
            let answer = hwnd.MessageBox(
                &format!("\"{file}\" already exists. Replace it?"),
                TITLE,
                co::MB::YESNO | co::MB::ICONWARNING,
            )?;
            if answer != co::DLGID::YES {
                return Ok(());
            }
        }

        let opts = Opts {
            roots,
            name: Some(self.name.text()?.trim().to_owned()),
            version: Some(self.version.text()?.trim().to_owned()),
            xml: Some(xml.clone()),
            csv: self.csv.is_checked().then(|| with_suffix(&base, "csv")),
            threads: None,
            no_catalog: !self.catalog.is_checked(),
        };

        engine::reset_progress();
        let outcome = Arc::new(Mutex::new(None));
        std::thread::spawn({
            let outcome = outcome.clone();
            move || {
                let result = match engine::scan(&opts) {
                    None => Outcome::Cancelled,
                    Some(recs) => {
                        let write = || -> std::io::Result<()> {
                            if let Some(p) = &opts.xml {
                                engine::write_xml(p, &recs, &opts)?;
                            }
                            if let Some(p) = &opts.csv {
                                engine::write_csv(p, &recs)?;
                            }
                            Ok(())
                        };
                        match write() {
                            Ok(()) => Outcome::Saved(engine::summary(&recs)),
                            Err(e) => Outcome::Failed(format!("Couldn't save the output: {e}")),
                        }
                    }
                };
                *outcome.lock().unwrap() = Some(result);
            }
        });

        {
            let mut st = self.state.borrow_mut();
            st.last_output = None;
            st.job = Some(Job { outcome, xml, started: Instant::now(), hash_started: None, _awake: KeepAwake::new() });
        }
        self.bar.set_marquee(true);
        self.bar.hwnd().ShowWindow(co::SW::SHOW);
        self.status.hwnd().SetWindowText("Finding files… 0 found")?;
        hwnd.SetTimer(TIMER_ID, 250, None)?;
        self.update_ui()
    }

    /// Every 250 ms while scanning: show progress, or finish up when the thread is done.
    fn tick(&self) -> w::AnyResult<()> {
        // Finished? Take the job out first, so no RefCell borrow is held during any message box.
        let finished = {
            let st = self.state.borrow();
            match &st.job {
                Some(job) => job.outcome.lock().unwrap().take(),
                None => return Ok(()),
            }
        };
        if let Some(outcome) = finished {
            let job = self.state.borrow_mut().job.take().expect("job present");
            self.wnd.hwnd().KillTimer(TIMER_ID)?;
            self.bar.set_marquee(false);
            self.bar.hwnd().ShowWindow(co::SW::HIDE);
            let elapsed = fmt_elapsed(job.started.elapsed());
            let file = job.xml.file_name().unwrap_or_default().to_string_lossy().into_owned();
            match outcome {
                Outcome::Saved(summary) => {
                    self.state.borrow_mut().last_output = Some(job.xml.clone());
                    self.status.hwnd().SetWindowText(&format!("Done in {elapsed}: {summary}. Saved \"{file}\"."))?;
                }
                Outcome::Cancelled => self.status.hwnd().SetWindowText("Scan cancelled. Nothing was saved.")?,
                Outcome::Failed(e) => {
                    self.status.hwnd().SetWindowText(&format!("Scan failed: {e}"))?;
                    self.wnd.hwnd().MessageBox(&e, "Scan failed", co::MB::ICONERROR)?;
                }
            }
            drop(job); // releases the keep-awake request, on the UI thread that made it
            return self.update_ui();
        }

        // Still running: show progress.
        let mut st = self.state.borrow_mut();
        let job = st.job.as_mut().expect("job present");
        if engine::HASHING.load(Ordering::Relaxed) {
            if job.hash_started.is_none() {
                // Total known now: switch from the sliding bar to a real percentage.
                job.hash_started = Some(Instant::now());
                self.bar.set_marquee(false);
                self.bar.set_range(0, engine::TOTAL.load(Ordering::Relaxed).max(1) as u32);
            }
            self.bar.set_position(engine::SCANNED.load(Ordering::Relaxed) as u32);
        }
        let line = engine::progress_line(job.hash_started);
        drop(st);
        if !engine::CANCEL.load(Ordering::Relaxed) {
            self.status.hwnd().SetWindowText(&line)?;
        }
        Ok(())
    }

    // ---------- state of the controls ----------

    fn update_ui(&self) -> w::AnyResult<()> {
        let (running, has_output) = {
            let st = self.state.borrow();
            (st.job.is_some(), st.last_output.as_ref().is_some_and(|p| p.exists()))
        };
        let folder_count = self.folders.items().count()?;
        let has_name = !self.name.text()?.trim().is_empty();

        for h in [
            self.name.hwnd(),
            self.version.hwnd(),
            self.folders.hwnd(),
            self.add.hwnd(),
            self.out_dir.hwnd(),
            self.browse.hwnd(),
            self.catalog.hwnd(),
            self.csv.hwnd(),
        ] {
            h.EnableWindow(!running);
        }
        self.remove.hwnd().EnableWindow(!running && folder_count > 0);
        self.clear.hwnd().EnableWindow(!running && folder_count > 0);
        self.new_scan.hwnd().EnableWindow(!running);
        self.show_file.hwnd().EnableWindow(!running && has_output);
        self.scan.hwnd().SetWindowText(if running { "Cancel" } else { "Scan" })?;
        self.scan.hwnd().EnableWindow(running || (has_name && folder_count > 0));

        let preview = match self.output_base()? {
            Some(base) => format!("Will save as: {}", with_suffix(&base, "xml").file_name().unwrap_or_default().to_string_lossy()),
            None => String::new(),
        };
        self.file_name.hwnd().SetWindowText(&preview)?;
        Ok(())
    }
}

// ---------- helpers ----------

/// "Foo-1.2.3" + "xml" -> "Foo-1.2.3.xml" (not with_extension, which would eat the ".3").
fn with_suffix(base: &Path, ext: &str) -> PathBuf {
    let mut s = base.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}", s / 60, s % 60)
}

/// Windows' own folder picker (the Vista-style one), optionally allowing several folders.
fn pick_folders(owner: &w::HWND, multi: bool, title: &str) -> w::AnyResult<Vec<String>> {
    let dlg = w::CoCreateInstance::<w::IFileOpenDialog>(
        &co::CLSID::FileOpenDialog,
        None::<&w::IUnknown>,
        co::CLSCTX::INPROC_SERVER,
    )?;
    let mut flags = dlg.GetOptions()? | co::FOS::PICKFOLDERS | co::FOS::FORCEFILESYSTEM;
    if multi {
        flags |= co::FOS::ALLOWMULTISELECT;
    }
    dlg.SetOptions(flags)?;
    dlg.SetTitle(title)?;
    if !dlg.Show(owner)? {
        return Ok(Vec::new()); // cancelled
    }
    let mut paths = Vec::new();
    for item in dlg.GetResults()?.iter()? {
        paths.push(item?.GetDisplayName(co::SIGDN::FILESYSPATH)?);
    }
    Ok(paths)
}

/// Opens Explorer with the file selected.
fn show_in_explorer(path: &Path) {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("explorer.exe").raw_arg(format!("/select,\"{}\"", path.display())).spawn();
}
