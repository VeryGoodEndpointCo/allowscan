# allowscan (Rust)

A fast offline replacement for AirDrag, an offline application capture tool for application allowlisting. Point it at one or more folders and it writes a capture XML in the same format as AirDrag's **Offline Application Export**, so it imports the same way.

This is the Rust version. It's a single native exe of about 650 KB with no runtime to install. It has the same window and output as the C# version. The window uses native Windows controls through [winsafe](https://crates.io/crates/winsafe), so it works on packaging VMs without a GPU and over RDP.

## Build

You need Windows and Rust stable (`rustup`, MSVC toolchain).

```powershell
cargo build --release
```

The result is `target\release\allowscan.exe`. The icon and manifest are compiled in with `rc.exe`, which comes with the Visual Studio Build Tools that Rust's MSVC toolchain already needs. To make a fully static exe with no Visual C++ runtime dependency:

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release
```

## Using the window

Double-click `allowscan.exe`.

1. Enter the **Software name** and **Version**. These go into the XML and the file name.
2. Add folders with **Add folders…**, which lets you select several at once, or drag folders from Explorer onto the window. Subfolders are always included. **Remove** takes off the selected folders (Ctrl- or Shift-click to select several), and **Clear list** empties the list.
3. Choose where to **Save to**. The window shows the file name it will use.
4. Press **Scan**. The bar slides while it finds files, then shows the real percentage, with the speed and time left in the status line.
5. When it's done, the status line shows the signed, unsigned and error counts. **Show file** opens Explorer with the XML selected.
6. Press **New scan** to clear the name, version and folder list for the next package. The save folder and options stay as they are.

**Scan** turns into **Cancel** while a scan runs, and a cancelled scan saves nothing. Closing the window during a scan asks first. The PC won't go to sleep during a scan, though the screen can still turn off and the PC can still lock.

Options: **Look up catalog signatures** (on by default) finds the publisher of catalog-signed Windows and driver files. **Also save CSV** writes a `.csv` next to the XML with every field.

## Using the command line

Running it with any arguments uses the command line instead of the window.

```powershell
# Saves "Contoso Agent-4.2.1.xml" in the current folder
allowscan.exe "D:\Packages\Contoso\Program Files" "D:\Packages\Contoso\ProgramData" -n "Contoso Agent" -v 4.2.1

# Choose the file names yourself and add a CSV
allowscan.exe "C:\Program Files\7-Zip" -n 7zip -o "D:\Captures\7zip.xml" --csv "D:\Captures\7zip.csv"
```

| Option | What it does |
| --- | --- |
| `-n`, `--name <text>` | Software name. Without `-o`, the XML is saved as `<name>-<version>.xml`. |
| `-v`, `--version <text>` | Software version. |
| `-o`, `--xml <file>` | Write the XML to this file. |
| `--csv <file>` | Also write a CSV with every field. |
| `-t`, `--threads <n>` | Worker threads. The default is one per CPU core. Use 2 to 4 for spinning disks and network shares. |
| `--no-catalog` | Skip catalog signature lookups. This is faster, but catalog-signed files show as `Not Signed`. |

If you give neither a name nor an output file, it writes `allowscan.csv`. It exits with code 1 if any file couldn't be read, and 2 for a bad argument.

Progress is shown on one updating line in two phases. First `Finding files… N found` while it lists the files, then `X of Y files (Z%) - rate/s - about T left` while it hashes and checks them. The PC won't go to sleep while a scan runs.

## What it captures

These rules were measured by running AirDrag on a test folder of 105 file types. The same folder scanned with this version gave the same 24 files with the same hashes.

- **Executables, by content.** Any file that starts with `MZ` is captured, whatever it's called, so `.exe`, `.dll`, `.sys`, `.sfx` and renamed copies are all included. A file named `.exe` that isn't really an executable is skipped, as AirDrag does.
- **These other types, by extension:** `bat cmd chm hta jar js msi ps1 psm1 py pyc pyw sct vbe vbs wsc wsf`.

Hidden and system files are included. Junctions and symlinked folders are not followed.

## The XML

The output matches AirDrag's offline export, compared line by line against real AirDrag captures:

- the same elements in the same order, with CDATA in the same places
- all five hashes (`md5`, `sha1`, `sha256`, `sha384`, `sha512`) in lowercase
- times as Unix seconds: `time` (when the file was hashed), `createtime` and `modtime`
- tab indents, Windows line endings, and no line break at the end
- `Status` of `4`, a new `ID` for every capture, and this PC's host name and user
- an empty `<Version />` when no version is given

**Publisher** follows AirDrag's rule:

| File | Publisher |
| --- | --- |
| Signed, by an embedded signature or a catalog | The signer certificate's name, such as `Contoso Ltd` |
| A type Windows can sign, but unsigned (exe, dll, ps1, psm1, js, vbs, vbe, wsf…) | `Not Signed` |
| A type Windows can't sign (bat, cmd, chm, hta, py, sct…) | empty |

## Why it's fast

1. **No revocation checks.** Signatures are checked with `WinVerifyTrust` using `WTD_REVOCATION_CHECK_NONE` and `WTD_CACHE_ONLY_URL_RETRIEVAL`, so it never waits on the network.
2. **Parallel.** [rayon](https://crates.io/crates/rayon) spreads hashing and signature checks across every core.
3. **One read per file.** All five hashes come from the same 1 MiB reads.
4. **Catalogs parsed once.** Each `.cat` file's signer is read once and reused.

## Notes

- Catalog lookups use the catalog database of the machine running the scan. If you scan a mounted image from a different Windows build, its catalog-signed files only resolve if this machine has the same catalogs.
- Files that can't be read, for example because they're locked, are left out of the XML and listed with their error in the CSV.

## Development

| File | Contents |
| --- | --- |
| `src/main.rs` | Entry point: opens the window, or runs the command line when given arguments |
| `src/engine.rs` | The scan engine shared by both: finding files, hashing, signatures, progress, cancelling, XML and CSV output |
| `src/gui.rs` | The window |
| `src/win.rs` | Windows API calls: signature checks, signer certificate, catalog lookup, sleep prevention, console handling |
| `build.rs`, `res/` | Embeds the app icon and the Windows manifest (modern controls, DPI awareness, long paths) |

All Windows API calls go through Microsoft's `windows-sys` bindings, with no other wrappers.

`cargo clippy --release` checks the engine and all Windows API calls on any OS. The window module only compiles for Windows targets.

To run the scan and XML output on Linux or macOS for testing, build with the `linux-test` feature. It skips the signature checks and marks every file `Not Signed`:

```bash
cargo build --release --features linux-test
```
