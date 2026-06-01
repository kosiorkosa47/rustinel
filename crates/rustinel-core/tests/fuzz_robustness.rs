//! Deterministic robustness ("poor-man's fuzz") tests for the untrusted-input
//! parsers. rustinel must never panic, hang, or over-read on hostile input —
//! these feed thousands of pseudo-random and mutated byte buffers through the
//! public parse entry points and assert the process simply returns.
//!
//! Stable + offline + deterministic (fixed PRNG seed), so it runs in CI on every
//! commit. A dedicated `cargo fuzz` target (nightly) lives under `fuzz/` for
//! deeper coverage; this guards the same surface without nightly.

use rustinel_core::{lockfile, policy};

/// Tiny deterministic xorshift64* PRNG — no `rand` dependency, reproducible.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// Bytes drawn from a "structurally interesting" alphabet so we hit TOML/lock
/// control characters far more often than uniform random would.
const ALPHABET: &[u8] = b"[]{}\"'=#\n\t package version source checksum dependencies \
    [[package]] name 0123456789.+-_/\\:@ \x00\x7f<>%&";

fn random_blob(rng: &mut Rng, max_len: usize) -> String {
    let len = (rng.next_u64() as usize) % max_len;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        let b = if rng.byte() & 1 == 0 {
            ALPHABET[(rng.next_u64() as usize) % ALPHABET.len()]
        } else {
            rng.byte()
        };
        bytes.push(b);
    }
    // Parsers take &str; lossy conversion mirrors how the CLI reads files.
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn lockfile_parser_never_panics_on_garbage() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..5000 {
        let blob = random_blob(&mut rng, 512);
        // Must return Ok/Err, never panic, never hang.
        let _ = lockfile::parse_lockfile_str("fuzz".into(), &blob);
    }
}

#[test]
fn policy_parser_never_panics_on_garbage() {
    let mut rng = Rng(0x0bad_c0de_dead_beef);
    for _ in 0..5000 {
        let blob = random_blob(&mut rng, 512);
        let _ = policy::parse_policy_toml(&blob);
    }
}

#[test]
fn mutated_valid_lockfile_never_panics() {
    // Start from a valid lockfile and bit-flip / truncate / inject bytes.
    let base = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
        checksum = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n";
    let mut rng = Rng(0xfeed_face_cafe_babe);
    for _ in 0..5000 {
        let mut bytes = base.as_bytes().to_vec();
        // Apply 1..8 random mutations.
        let muts = 1 + (rng.next_u64() as usize) % 8;
        for _ in 0..muts {
            if bytes.is_empty() {
                break;
            }
            let idx = (rng.next_u64() as usize) % bytes.len();
            match rng.byte() % 3 {
                0 => bytes[idx] ^= rng.byte(),      // bit-flip
                1 => bytes.truncate(idx),           // truncate
                _ => bytes.insert(idx, rng.byte()), // insert
            }
        }
        let blob = String::from_utf8_lossy(&bytes).into_owned();
        let _ = lockfile::parse_lockfile_str("fuzz".into(), &blob);
    }
}

#[test]
fn pathological_inputs_are_bounded() {
    // Deeply repeated structure and huge tokens must not blow up.
    let cases = [
        "[[package]]\n".repeat(50_000),
        format!(
            "version = 3\n[[package]]\nname = \"{}\"\n",
            "a".repeat(100_000)
        ),
        "dependencies = [".to_string() + &"\"x\",".repeat(50_000) + "]",
        "\u{0}".repeat(10_000),
        "#".repeat(100_000),
    ];
    for case in cases {
        let _ = lockfile::parse_lockfile_str("fuzz".into(), &case);
        let _ = policy::parse_policy_toml(&case);
    }
}
