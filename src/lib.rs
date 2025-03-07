//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

use thiserror::Error;
use serde::{Serialize, Deserialize};

/// Error types for the KERI library
#[derive(Error, Debug)]
pub enum KeriError {
    #[error("general error: {0}")]
    General(String),
    
    #[error("crypto error: {0}")]
    Crypto(String),
    
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type for KERI operations
pub type Result<T> = std::result::Result<T, KeriError>;

/// Initialize the KERI library
pub fn init() -> Result<()> {
    // Initialize sodiumoxide
    if !sodiumoxide::init() {
        return Err(KeriError::Crypto("Failed to initialize sodiumoxide".into()));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
}
