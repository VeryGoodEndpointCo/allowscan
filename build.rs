//! Embeds the Windows resources: the app icon and the manifest
//! (modern themed controls, DPI awareness, long paths, UTF-8).
//! Uses rc.exe with the MSVC toolchain and windres with MinGW.

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_resource::compile("res/allowscan.rc", embed_resource::NONE)
            .manifest_required()
            .expect("couldn't compile the Windows resources (icon + manifest)");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=res");
}
