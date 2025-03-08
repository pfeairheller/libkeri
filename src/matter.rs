//! Matter module for cryptographic material handling
//! 
//! This module provides the core traits and implementations for handling
//! cryptographic material in KERI, including derivation codes, serialization,
//! and verification.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashMap;
use crate::{Error, Result};

/// Derivation codes for Matter
pub mod mtr_dex {
    pub const ED25519_SEED: &str = "A";
    pub const ED25519N: &str = "B";
    pub const X25519: &str = "C";
    pub const ED25519: &str = "D";
    pub const BLAKE3_256: &str = "E";
    pub const BLAKE2B_256: &str = "F";
    pub const BLAKE2S_256: &str = "G";
    pub const SHA3_256: &str = "H";
    pub const SHA2_256: &str = "I";
    pub const ECDSA_256K1_SEED: &str = "J";
    pub const ED448_SEED: &str = "K";
    pub const X448: &str = "L";
    pub const SHORT: &str = "M";
    pub const BIG: &str = "N";
    pub const X25519_PRIVATE: &str = "O";
    pub const X25519_CIPHER_SEED: &str = "P";
    pub const ECDSA_256R1_SEED: &str = "Q";
    // ... other codes can be added as needed
}

/// Digest codes
pub const DIG_CODES: &[&str] = &[
    mtr_dex::BLAKE3_256,
    mtr_dex::BLAKE2B_256,
    mtr_dex::BLAKE2S_256,
    mtr_dex::SHA3_256,
    mtr_dex::SHA2_256,
    // ... other digest codes
];

/// Non-transferable codes
pub const NON_TRANS_CODES: &[&str] = &[
    mtr_dex::ED25519N,
    // ... other non-transferable codes
];

/// Prefix codes
pub const PRE_CODES: &[&str] = &[
    mtr_dex::ED25519N,
    mtr_dex::ED25519,
    mtr_dex::BLAKE3_256,
    mtr_dex::BLAKE2B_256,
    mtr_dex::BLAKE2S_256,
    mtr_dex::SHA3_256,
    mtr_dex::SHA2_256,
    // ... other prefix codes
];

/// Verifier codes
pub const VERFER_CODES: &[&str] = &[
    mtr_dex::ED25519N,
    mtr_dex::ED25519,
    // ... other verifier codes
];

/// Size information for derivation codes
#[derive(Debug, Clone, Copy)]
pub struct Sizage {
    pub hs: usize,  // hard size
    pub ss: usize,  // soft size
    pub xs: usize,  // extra size
    pub fs: Option<usize>,  // full size (None for variable sized)
    pub ls: usize,  // lead size
}

/// Core trait for all cryptographic material
pub trait Matter {
    /// Get the derivation code
    fn code(&self) -> &str;
    
    /// Get the raw cryptographic material
    fn raw(&self) -> &[u8];
    
    /// Get the fully qualified Base64 representation
    fn qb64(&self) -> String;
    
    /// Get the fully qualified Base64 representation as bytes
    fn qb64b(&self) -> Vec<u8>;
    
    /// Get the fully qualified binary representation
    fn qb2(&self) -> Vec<u8>;
    
    /// Check if the material is transferable
    fn is_transferable(&self) -> bool;
    
    /// Check if the material is digestive
    fn is_digestive(&self) -> bool;
    
    /// Check if the material is prefixive
    fn is_prefixive(&self) -> bool;
}

/// Trait for material that can verify signatures
pub trait Verifiable {
    /// Verify a signature against serialized data
    fn verify(&self, sig: &[u8], ser: &[u8]) -> bool;
}

/// Trait for material that can verify digests
pub trait DigestVerifiable {
    /// Verify a digest against serialized data
    fn verify(&self, ser: &[u8]) -> bool;
    
    /// Compare with another digest
    fn compare(&self, ser: &[u8], dig: Option<&[u8]>, diger: Option<&dyn DigestVerifiable>) -> bool;
}

/// Base struct for all cryptographic material
pub struct BaseMatter {
    code: String,
    raw: Vec<u8>,
    soft: String,
}

impl BaseMatter {
    /// Create a new BaseMatter from raw bytes and code
    pub fn new(raw: Option<Vec<u8>>, code: &str, soft: &str) -> Result<Self> {
        // Get size information for the code
        let sizes = get_sizes(code)?;
        
        // Validate raw size
        let raw = match raw {
            Some(r) => {
                if let Some(fs) = sizes.fs {
                    if r.len() != raw_size(code)? {
                        return Err(Error::RawMaterial(format!(
                            "Invalid raw size for code {}: expected {}, got {}",
                            code, raw_size(code)?, r.len()
                        )));
                    }
                }
                r
            },
            None => Vec::new(),
        };
        
        Ok(Self {
            code: code.to_string(),
            raw,
            soft: soft.to_string(),
        })
    }
    
    /// Create from qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        let qb64b = qb64.as_bytes();
        Self::from_qb64b(qb64b)
    }
    
    /// Create from qb64b bytes
    pub fn from_qb64b(qb64b: &[u8]) -> Result<Self> {
        let mut matter = Self {
            code: String::new(),
            raw: Vec::new(),
            soft: String::new(),
        };
        matter.exfil(qb64b)?;
        Ok(matter)
    }
    
    /// Create from qb2 bytes
    pub fn from_qb2(qb2: &[u8]) -> Result<Self> {
        let mut matter = Self {
            code: String::new(),
            raw: Vec::new(),
            soft: String::new(),
        };
        matter.bexfil(qb2)?;
        Ok(matter)
    }
    
    // Helper methods for serialization/deserialization
    fn infil(&self) -> Vec<u8> {
        // Implementation details for creating qb64b from raw and code
        // This is a placeholder - actual implementation would be more complex
        let mut result = self.code.as_bytes().to_vec();
        result.extend_from_slice(&self.raw);
        result
    }
    
    fn binfil(&self) -> Vec<u8> {
        // Implementation details for creating qb2 from raw and code
        // This is a placeholder - actual implementation would be more complex
        let mut result = Vec::new();
        // Convert code to binary representation
        // Add raw bytes
        result.extend_from_slice(&self.raw);
        result
    }
    
    fn exfil(&mut self, qb64b: &[u8]) -> Result<()> {
        // Implementation details for extracting code and raw from qb64b
        // This is a placeholder - actual implementation would be more complex
        if qb64b.is_empty() {
            return Err(Error::EmptyMaterial);
        }
        
        // Extract first character to determine code length
        let first = qb64b[0] as char;
        let hs = get_hard_size(first)?;
        
        if qb64b.len() < hs {
            return Err(Error::Parsing(format!("Need {} more characters", hs - qb64b.len())));
        }
        
        // Extract code
        self.code = std::str::from_utf8(&qb64b[..hs])?.to_string();
        
        // Get size information
        let sizes = get_sizes(&self.code)?;
        
        // Extract soft part if any
        if sizes.ss > 0 {
            if qb64b.len() < hs + sizes.ss {
                return Err(Error::Parsing(format!("Need {} more characters", hs + sizes.ss - qb64b.len())));
            }
            self.soft = std::str::from_utf8(&qb64b[hs..hs+sizes.ss])?.to_string();
        }
        
        // Calculate full size
        let fs = match sizes.fs {
            Some(fs) => fs,
            None => {
                // Variable sized - calculate from soft part
                // This is a placeholder - actual implementation would be more complex
                hs + sizes.ss + 4 // Simplified calculation
            }
        };
        
        if qb64b.len() < fs {
            return Err(Error::Parsing(format!("Need {} more characters", fs - qb64b.len())));
        }
        
        // Extract raw
        let raw_start = hs + sizes.ss;
        let raw_end = fs;
        let raw_b64 = &qb64b[raw_start..raw_end];
        
        // Decode Base64 to get raw bytes
        self.raw = URL_SAFE_NO_PAD.decode(raw_b64)?;
        
        Ok(())
    }
    
    fn bexfil(&mut self, qb2: &[u8]) -> Result<()> {
        // Implementation details for extracting code and raw from qb2
        // This is a placeholder - actual implementation would be more complex
        if qb2.is_empty() {
            return Err(Error::EmptyMaterial);
        }
        
        // Extract code from binary
        // Extract raw from binary
        
        Ok(())
    }
}

impl Matter for BaseMatter {
    fn code(&self) -> &str {
        &self.code
    }
    
    fn raw(&self) -> &[u8] {
        &self.raw
    }
    
    fn qb64(&self) -> String {
        String::from_utf8(self.qb64b()).unwrap_or_default()
    }
    
    fn qb64b(&self) -> Vec<u8> {
        self.infil()
    }
    
    fn qb2(&self) -> Vec<u8> {
        self.binfil()
    }
    
    fn is_transferable(&self) -> bool {
        !NON_TRANS_CODES.contains(&self.code.as_str())
    }
    
    fn is_digestive(&self) -> bool {
        DIG_CODES.contains(&self.code.as_str())
    }
    
    fn is_prefixive(&self) -> bool {
        PRE_CODES.contains(&self.code.as_str())
    }
}

/// Verification key implementation
pub struct Verfer {
    matter: BaseMatter,
}

impl Verfer {
    pub fn new(raw: Option<Vec<u8>>, code: &str) -> Result<Self> {
        let matter = BaseMatter::new(raw, code, "")?;
        
        // Validate code is appropriate for a verifier
        if !VERFER_CODES.contains(&matter.code()) {
            return Err(Error::InvalidCode(format!("Invalid code for verifier: {}", matter.code())));
        }
        
        Ok(Self { matter })
    }
    
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        let matter = BaseMatter::from_qb64(qb64)?;
        
        // Validate code is appropriate for a verifier
        if !VERFER_CODES.contains(&matter.code()) {
            return Err(Error::InvalidCode(format!("Invalid code for verifier: {}", matter.code())));
        }
        
        Ok(Self { matter })
    }
    
    pub fn from_qb64b(qb64b: &[u8]) -> Result<Self> {
        let matter = BaseMatter::from_qb64b(qb64b)?;
        
        // Validate code is appropriate for a verifier
        if !VERFER_CODES.contains(&matter.code()) {
            return Err(Error::InvalidCode(format!("Invalid code for verifier: {}", matter.code())));
        }
        
        Ok(Self { matter })
    }
}

impl Matter for Verfer {
    fn code(&self) -> &str { self.matter.code() }
    fn raw(&self) -> &[u8] { self.matter.raw() }
    fn qb64(&self) -> String { self.matter.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.matter.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.matter.qb2() }
    fn is_transferable(&self) -> bool { self.matter.is_transferable() }
    fn is_digestive(&self) -> bool { self.matter.is_digestive() }
    fn is_prefixive(&self) -> bool { self.matter.is_prefixive() }
}

impl Verifiable for Verfer {
    fn verify(&self, sig: &[u8], ser: &[u8]) -> bool {
        match self.matter.code() {
            mtr_dex::ED25519N | mtr_dex::ED25519 => self.verify_ed25519(sig, ser),
            // Add other verification methods as needed
            _ => false,
        }
    }
}

impl Verfer {
    fn verify_ed25519(&self, sig: &[u8], ser: &[u8]) -> bool {
        // Implementation for Ed25519 verification
        // This is a placeholder - actual implementation would use sodiumoxide
        false
    }
}

/// Signature with verification capability
pub struct Cigar {
    matter: BaseMatter,
    verfer: Option<Verfer>,
}

impl Cigar {
    pub fn new(raw: Option<Vec<u8>>, code: &str, verfer: Option<Verfer>) -> Result<Self> {
        let matter = BaseMatter::new(raw, code, "")?;
        
        Ok(Self { matter, verfer })
    }
}

impl Matter for Cigar {
    fn code(&self) -> &str { self.matter.code() }
    fn raw(&self) -> &[u8] { self.matter.raw() }
    fn qb64(&self) -> String { self.matter.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.matter.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.matter.qb2() }
    fn is_transferable(&self) -> bool { self.matter.is_transferable() }
    fn is_digestive(&self) -> bool { self.matter.is_digestive() }
    fn is_prefixive(&self) -> bool { self.matter.is_prefixive() }
}

/// Digest implementation
pub struct Diger {
    matter: BaseMatter,
}

impl Diger {
    pub fn new(raw: Option<Vec<u8>>, ser: Option<&[u8]>, code: &str) -> Result<Self> {
        let raw = match (raw, ser) {
            (Some(r), _) => Some(r),
            (None, Some(s)) => Some(digest(s, code)?),
            _ => return Err(Error::EmptyMaterial),
        };
        
        let matter = BaseMatter::new(raw, code, "")?;
        
        // Validate code is appropriate for a digest
        if !DIG_CODES.contains(&matter.code()) {
            return Err(Error::InvalidCode(format!("Invalid code for digest: {}", matter.code())));
        }
        
        Ok(Self { matter })
    }
}

impl Matter for Diger {
    fn code(&self) -> &str { self.matter.code() }
    fn raw(&self) -> &[u8] { self.matter.raw() }
    fn qb64(&self) -> String { self.matter.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.matter.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.matter.qb2() }
    fn is_transferable(&self) -> bool { self.matter.is_transferable() }
    fn is_digestive(&self) -> bool { self.matter.is_digestive() }
    fn is_prefixive(&self) -> bool { self.matter.is_prefixive() }
}

impl DigestVerifiable for Diger {
    fn verify(&self, ser: &[u8]) -> bool {
        let computed = match digest(ser, self.code()) {
            Ok(d) => d,
            Err(_) => return false,
        };
        
        computed == self.raw()
    }
    
    fn compare(&self, ser: &[u8], dig: Option<&[u8]>, diger: Option<&dyn DigestVerifiable>) -> bool {
        if let Some(d) = dig {
            return d == self.qb64b().as_slice();
        }
        
        if let Some(d) = diger {
            if d.qb64() == self.qb64() {
                return true;
            }
            
            if d.verify(ser) && self.verify(ser) {
                return true;
            }
        }
        
        false
    }
}

// Helper functions

/// Get the hard size for a derivation code first character
fn get_hard_size(first: char) -> Result<usize> {
    match first {
        'A'..='Z' | 'a'..='z' => Ok(1),
        '0'..='9' => Ok(2),
        _ => Err(Error::InvalidCode(format!("Invalid first character: {}", first))),
    }
}

/// Get size information for a derivation code
fn get_sizes(code: &str) -> Result<Sizage> {
    // This is a simplified implementation - actual would have a complete table
    match code {
        mtr_dex::ED25519_SEED => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::ED25519N => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::ED25519 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::BLAKE3_256 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        _ => Err(Error::InvalidCode(format!("Unknown code: {}", code))),
    }
}

/// Calculate raw size for a derivation code
fn raw_size(code: &str) -> Result<usize> {
    let sizes = get_sizes(code)?;
    
    if let Some(fs) = sizes.fs {
        // Fixed size
        let cs = sizes.hs + sizes.ss;
        Ok((((fs - cs) * 3) / 4) - sizes.ls)
    } else {
        // Variable size
        Err(Error::InvalidSize(format!("Variable sized code: {}", code)))
    }
}

/// Compute digest of serialized data
fn digest(ser: &[u8], code: &str) -> Result<Vec<u8>> {
    // This is a simplified implementation - actual would support multiple digest algorithms
    match code {
        mtr_dex::BLAKE3_256 => {
            let hash = blake3::hash(ser);
            Ok(hash.as_bytes().to_vec())
        },
        _ => Err(Error::InvalidCode(format!("Unsupported digest code: {}", code))),
    }
}

// Implement std::str::FromStr for BaseMatter
impl std::str::FromStr for BaseMatter {
    type Err = Error;
    
    fn from_str(s: &str) -> Result<Self> {
        Self::from_qb64(s)
    }
}

// Implement std::convert::TryFrom for BaseMatter
impl std::convert::TryFrom<&[u8]> for BaseMatter {
    type Error = Error;
    
    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_qb64b(value)
    }
}

// Implement necessary traits for Error conversions
impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::Parsing(format!("UTF-8 error: {}", err))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Parsing(format!("Base64 decode error: {}", err))
    }
}
