//! Build script: generates the Tauri context (config, capabilities, icons) and
//! embeds the app icon into the desktop shell binary.

fn main() {
    tauri_build::build();
}
