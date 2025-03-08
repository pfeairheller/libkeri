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
    
    #[error("invalid code: {0}")]
    InvalidCode(String),
    
    #[error("invalid size: {0}")]
    InvalidSize(String),
    
    #[error("empty material")]
    EmptyMaterial,
    
    #[error("raw material error: {0}")]
    RawMaterial(String),
    
    #[error("soft material error: {0}")]
    SoftMaterial(String),
    
    #[error("general error: {0}")]
    Other(String),
}

/// Result type for KERI operations
pub type Result<T> = std::result::Result<T, Error>;
