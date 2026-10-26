//! Makes `src/bin/hkdfguard.rs` includable by the `cli_args` target: a copy
//! in OUT_DIR with its inner doc comments (`//!`, which `include!` rejects)
//! turned into plain comments. The source itself is never touched.
use std::{env, fs, path::Path};

fn main() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/bin/hkdfguard.rs");
    println!("cargo:rerun-if-changed={}", src.display());
    let text = fs::read_to_string(&src).expect("read src/bin/hkdfguard.rs");
    let text: String = text
        .lines()
        .map(|l| if let Some(rest) = l.strip_prefix("//!") { format!("//{rest}\n") } else { format!("{l}\n") })
        .collect();
    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("cli.rs");
    fs::write(out, text).unwrap();
}
