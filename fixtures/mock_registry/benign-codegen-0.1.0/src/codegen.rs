// A perfectly ordinary build/codegen helper: it walks the consuming project's
// source tree to collect every `.rs` module so it can generate a registry of
// them. This is exactly what real proc-macro / build-time codegen crates do.
//
// Crucially: this module reads `.rs` files but does NOT touch the network and
// handles NO secret material. On its own it is harmless. The crate's HTTP usage
// lives in a SEPARATE module (`client.rs`). The malicious source-exfil
// fingerprint requires source-scanning AND (network OR secrets) to coincide in
// ONE file; here they never do, so rustinel must stay silent.

use std::path::Path;

pub fn collect_modules(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    // Count the public items so the generated registry is stable.
                    let items = text.matches("pub fn ").count();
                    out.push(format!("{}:{items}", path.display()));
                }
            }
        }
    }
    out
}
