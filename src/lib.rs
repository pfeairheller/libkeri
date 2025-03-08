//! KERI (Key Event Receipt Infrastructure) library implementation in Rust.

// Error handling module
mod errors;
// Core cryptographic material module
mod matter;

// Re-export Error type
pub use errors::Error;
pub use errors::Result;
pub use matter::*;

/// Initialize the KERI library
pub fn init() -> Result<()> {
    // Initialize sodiumoxide
    if let Err(_) = sodiumoxide::init() {
        return Err(Error::Crypto("Failed to initialize sodiumoxide".into()));
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
