//! Error types for the KERI library

use thiserror::Error;

/// Error types for the KERI library
#[derive(Error, Debug)]
pub enum Error {
    #[error("serialization error: {0}")]
    Serialization(String),
    
    #[error("parsing error: {0}")]
    Parsing(String),
    
    #[error("crypto error: {0}")]
    Crypto(String),
    
    #[error("general error: {0}")]
    Other(String),
}

/// Result type for KERI operations
pub type Result<T> = std::result::Result<T, Error>;
