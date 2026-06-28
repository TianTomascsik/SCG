//! Build script: regenerate the C header (`include/scg_client.h`) from the
//! crate's `extern "C"` surface using cbindgen.
//!
//! Generation is best-effort: a failure (for example, a read-only checkout in
//! CI) emits a `cargo:warning` rather than failing the library build, since the
//! committed header is what downstream C/C++ consumers actually compile against.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    let out = PathBuf::from(&crate_dir)
        .join("include")
        .join("scg_client.h");

    let config = cbindgen::Config::from_root_or_default(&crate_dir);
    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&out);
        }
        Err(e) => {
            println!("cargo:warning=cbindgen: failed to generate scg_client.h: {e}");
        }
    }

    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
