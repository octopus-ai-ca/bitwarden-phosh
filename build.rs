//! Compile les ressources (icônes propres à Coffre) avec `glib-compile-resources`.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let dir = "data/resources";
    let manifest = format!("{dir}/coffre.gresource.xml");
    println!("cargo:rerun-if-changed={dir}");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("coffre.gresource");
    let status = Command::new("glib-compile-resources")
        .arg(format!("--sourcedir={dir}"))
        .arg(format!("--target={}", out.display()))
        .arg(&manifest)
        .status()
        .expect("glib-compile-resources introuvable (paquet glib-dev / libglib2.0-dev-bin)");
    assert!(status.success(), "échec de glib-compile-resources");
}
