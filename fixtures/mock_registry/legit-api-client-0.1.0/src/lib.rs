// Fixture: a perfectly ordinary HTTP client. It reads a config env var and makes
// a network request to a well-known API — the kind of code thousands of legit
// crates contain. None of the malicious *conjunctions* are present (it does not
// also spawn a process, does not contact an exfiltration domain, does not read
// the project's `.rs` files, handles no wallet material). rustinel must NOT flag
// it — this fixture is the low-false-positive regression guard.

pub fn fetch_repo() {
    let _base = std::env::var("API_BASE_URL").unwrap_or_default();
    let _resp = reqwest::blocking::get("https://api.github.com/repos/rust-lang/rust");
}
