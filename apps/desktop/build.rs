//! Build script: generates the Tauri context (config, capabilities, icons) and
//! embeds the app icon into the desktop shell binary.

fn main() {
    // tauri-build only watches tauri.conf.json and capabilities/, so a
    // regenerated icon.ico would otherwise leave the old icon resource linked
    // into the exe (and extracted by the MSI for ARP and shortcuts).
    println!("cargo:rerun-if-changed=icons");
    tauri_build::build();
}
