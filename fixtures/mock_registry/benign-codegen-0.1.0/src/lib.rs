// Benign cross-file fixture. See codegen.rs (reads `.rs`) and client.rs (HTTP).
// Neither file alone satisfies the source-exfil conjunction, so the crate must
// not be flagged as `suspicious_source_exfil`.

pub mod client;
pub mod codegen;
