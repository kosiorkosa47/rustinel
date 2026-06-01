use std::path::PathBuf;

/// All fallible operations in `rustinel-core` return this error.
///
/// Messages are written to be human-readable; the CLI surfaces them directly.
#[derive(Debug, thiserror::Error)]
pub enum RustinelError {
    #[error("I/O error while reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Could not parse Cargo.lock at {path}: {message}")]
    LockfileParse { path: PathBuf, message: String },

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("Could not load advisory database at {path}: {message}")]
    AdvisoryDb { path: PathBuf, message: String },

    #[error("Network error: {0}")]
    Network(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl RustinelError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn lockfile_parse(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::LockfileParse {
            path: path.into(),
            message: message.into(),
        }
    }
}
