// The crate's network layer. It makes an ordinary outbound HTTP request and
// does NOT read the project's `.rs` source and handles NO secret material.
//
// Network capability lives here; the source-scanning capability lives in
// `codegen.rs`. Because the source-exfil fingerprint must see source-scanning
// and network/secret use in the SAME file, splitting them across modules (as a
// normal crate naturally does) must NOT be flagged.

pub fn fetch_release_notes(tag: &str) -> Option<String> {
    let url = format!("https://api.github.com/repos/rust-lang/rust/releases/tags/{tag}");
    let resp = reqwest::blocking::get(url).ok()?;
    resp.text().ok()
}
