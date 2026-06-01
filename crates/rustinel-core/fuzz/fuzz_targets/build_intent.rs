#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        rustinel_core::fuzz_api::fuzz_build_intent(s);
    }
});
