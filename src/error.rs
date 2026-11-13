//! Error type shared by all modules. Every error carries enough context to
//! tell the user what failed, which package/file was involved and (via
//! `hint`) how to fix it.

use std::fmt;
use std::path::Path;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid data: {0}")]
    Parse(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("{0}")]
    NotFound(String),
    #[error("cannot resolve dependencies: {0}")]
    Resolve(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("another ast operation is running (lock: {0})")]
    Locked(String),
    #[error("aborted by user")]
    Aborted,
    #[error("blocked: {0}")]
    Untested(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("build failed: {0}")]
    Build(String),
    #[error("unsafe archive: {0}")]
    UnsafeArchive(String),
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::Config(_) => 3,
            Error::NotFound(_) => 4,
            Error::Resolve(_) | Error::Conflict(_) => 5,
            Error::Verify(_) | Error::UnsafeArchive(_) => 6,
            Error::Locked(_) => 7,
            Error::Aborted => 8,
            Error::Untested(_) => 9,
            Error::Build(_) => 10,
            Error::Network(_) => 11,
            _ => 1,
        }
    }

    /// A short suggestion on how to fix the problem, if we know one.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Error::Usage(_) => Some("run `ast -h`"),
            Error::Config(_) => Some("check /etc/ast/ast.toml and /etc/ast/repos.toml (or run `ast init`)"),
            Error::NotFound(_) => Some("run `ast -u` and check `ast repo list`"),
            Error::Verify(_) => Some("the file may be corrupted or tampered with; run `ast clean` and `ast -u`, and check the repository key"),
            Error::Locked(_) => Some("wait for the other ast process to finish; if none is running, remove the lock file"),
            Error::Untested(_) => Some("set `allow_untested = true` in [packages] to be asked for confirmation"),
            Error::Network(_) => Some("check network access and the repository URL in repos.toml"),
            Error::Conflict(_) => Some("remove the conflicting package first, or pick a different package"),
            _ => None,
        }
    }

    pub fn io(context: impl fmt::Display, source: std::io::Error) -> Error {
        Error::Io { context: context.to_string(), source }
    }
}

/// Attach context (usually a path) to `io::Result`.
pub trait IoCtx<T> {
    fn ctx(self, what: &str, path: &Path) -> Result<T>;
}

impl<T> IoCtx<T> for std::io::Result<T> {
    fn ctx(self, what: &str, path: &Path) -> Result<T> {
        self.map_err(|e| Error::io(format!("{what} {}", path.display()), e))
    }
}
