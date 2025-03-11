//! Matter module for cryptographic material handling
//! 
//! This module provides the core traits and implementations for handling
//! cryptographic material in KERI, including derivation codes, serialization,
//! and verification.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sodiumoxide::crypto::sign::ed25519;
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
    pub const ECDSA_256K1R1_SEED: &str = "R";
    pub const TBD0S: &str = "1__-";
    pub const TBD0: &str = "1___";
    pub const TBD1: &str = "2___";
    pub const TBD2: &str = "3___";
    pub const TBD3: &str = "4___";
    pub const BYTES_L0: &str = "4B";
    pub const BYTES_L1: &str = "5B";
    pub const BYTES_L2: &str = "6B";
    pub const ED25519_SIG: &str = "0B";
    pub const TAG3: &str = "X";

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
    
    // Compare with another digest
    // fn compare(&self, ser: &[u8], dig: Option<&[u8]>, diger: Option<&dyn Matter>) -> bool;
}

/// Base struct for all cryptographic material
#[derive(Clone)]
pub struct BaseMatter {
    code: String,
    raw: Vec<u8>,
    soft: String,
}

impl BaseMatter {
    /// Map of first character of code to hard size
    pub fn hards() -> std::collections::HashMap<char, usize> {
        let mut hards = std::collections::HashMap::new();
        // Single character codes
        for c in 'A'..='Z' {
            hards.insert(c, 1);
        }
        for c in 'a'..='z' {
            hards.insert(c, 1);
        }
        // Two character codes
        for c in '0'..='9' {
            hards.insert(c, 2);
        }
        hards
    }

    /// Map of first character of code to code type
    pub fn bards() -> std::collections::HashMap<char, &'static str> {
        let mut bards = std::collections::HashMap::new();
        // Basic codes
        for c in 'A'..='Z' {
            bards.insert(c, "basic");
        }
        for c in 'a'..='z' {
            bards.insert(c, "basic");
        }
        // Indexed codes
        for c in '0'..='9' {
            bards.insert(c, "indexed");
        }
        bards
    }
}

impl BaseMatter {
    /// Check if this is a special code
    pub fn special(&self) -> bool {
        // Special codes include Tag3 and TBD0S
        self.code() == mtr_dex::TAG3 || self.code() == mtr_dex::TBD0S
    }
    
    /// Get the soft part
    pub fn soft(&self) -> &str {
        &self.soft
    }
    
    /// Create a new BaseMatter from raw bytes and code
    pub fn new(raw: Option<Vec<u8>>, code: &str, soft: &str) -> Result<Self> {
        // Get size information for the code
        let sizes = get_sizes(code)?;
        
        // Validate raw size
        let raw = match raw {
            Some(r) => {
                if let Some(_fs) = sizes.fs {
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
        // Implementation matching Python _infil logic
        let code = &self.code;  // hard part of full code
        let both = format!("{}{}", self.code, self.soft);  // code + soft, soft may be empty
        let raw = &self.raw;  // raw bytes, may be empty
        let rs = raw.len();  // raw size
        
        // Get size information for the code
        let sizes = match get_sizes(code) {
            Ok(s) => s,
            Err(_) => return Vec::new(),  // Return empty on error
        };
        
        let hs = sizes.hs;
        let ss = sizes.ss;
        let xs = sizes.xs;
        let fs = sizes.fs;
        let ls = sizes.ls;
        let cs = hs + ss;
        
        // Validate code size
        if cs != both.len() {
            return Vec::new();  // Return empty on error
        }
        
        let result = if fs.is_none() {  // variable sized
            // Ensure both full code (B64) and lead+raw (B2) are 24-bit aligned
            if (ls + rs) % 3 != 0 || cs % 4 != 0 {
                return Vec::new();  // Return empty on error
            }
            
            // When ls+rs is 24-bit aligned, encodeB64 has no trailing pad chars
            // Prepad raw with ls zero bytes and convert
            let mut padded_raw = vec![0u8; ls];
            padded_raw.extend_from_slice(raw);
            
            let mut result = both.as_bytes().to_vec();
            result.extend_from_slice(&URL_SAFE_NO_PAD.encode(padded_raw).as_bytes());
            result
        } else {  // fixed size
            // Calculate padding needed for 24-bit alignment
            let ps = (3 - ((rs + ls) % 3)) % 3;  // net pad size given raw with lead
            
            // Validate padding size matches code size remainder
            if ps != (cs % 4) {
                return Vec::new();  // Return empty on error
            }
            
            // Prepad raw with ps+ls zero bytes to ensure encodeB64 has no trailing pad chars
            let mut padded_raw = vec![0u8; ps + ls];
            padded_raw.extend_from_slice(raw);
            
            // Encode the padded raw and skip first ps characters
            let encoded = URL_SAFE_NO_PAD.encode(padded_raw);
            let encoded_bytes = encoded.as_bytes();
            let encoded_without_pad = if ps < encoded_bytes.len() {
                &encoded_bytes[ps..]
            } else {
                &[]
            };
            
            let mut result = both.as_bytes().to_vec();
            result.extend_from_slice(encoded_without_pad);
            result
        };
        
        // Validate final size
        if (result.len() % 4 != 0) || (fs.is_some() && result.len() != fs.unwrap()) {
            return Vec::new();  // Return empty on error
        }
        
        result
    }
    
    fn binfil(&self) -> Vec<u8> {
        // Implementation matching Python _binfil logic
        let code = &self.code;  // hard part of full code
        let both = format!("{}{}", self.code, self.soft);  // code + soft, soft may be empty
        let raw = &self.raw;  // raw bytes, may be empty
        
        // Get size information for the code
        let sizes = match get_sizes(code) {
            Ok(s) => s,
            Err(_) => return Vec::new(),  // Return empty on error
        };
        
        let hs = sizes.hs;
        let ss = sizes.ss;
        let fs = sizes.fs;
        let ls = sizes.ls;
        let cs = hs + ss;
        
        // Calculate number of binary bytes needed to hold base64 code
        let n = (cs * 3 + 3) / 4;  // ceiling of cs * 3 / 4
        
        // Convert code to binary representation
        // First convert to integer, then left shift by pad bits, then to bytes
        let b64_int = match b64_to_int(&both) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };
        
        // Left shift by pad bits (2 bits per character of padding)
        let shifted = b64_int << (2 * (cs % 4));
        
        // Convert to bytes with big-endian order
        let mut bcode = Vec::new();
        let mut temp = shifted;
        for _ in 0..n {
            bcode.insert(0, (temp & 0xFF) as u8);
            temp >>= 8;
        }
        
        // Ensure bcode is the right length (n bytes)
        while bcode.len() < n {
            bcode.insert(0, 0);
        }
        
        // Combine code bytes, lead bytes, and raw bytes
        let mut full = bcode;
        full.extend_from_slice(&vec![0; ls]);  // Add lead bytes
        full.extend_from_slice(raw);  // Add raw bytes
        
        // Validate size
        let bfs = full.len();
        let computed_fs = if let Some(fs_val) = fs {
            fs_val
        } else {
            // For variable size, compute fs
            hs + ss + ((raw.len() + ls) * 4 + 2) / 3  // ceiling of (raw.len() + ls) * 4 / 3
        };
        
        if bfs % 3 != 0 || (bfs * 4 + 2) / 3 != computed_fs {
            return Vec::new();  // Invalid size
        }
        
        full
    }
    
    fn exfil(&mut self, qb64b: &[u8]) -> Result<()> {
        // Implementation matching Python _exfil logic
        if qb64b.is_empty() {
            return Err(Error::EmptyMaterial);
        }
        
        // Extract first character to determine code length
        let first = qb64b[0] as char;
        
        // Check if first character is valid using Hards map
        let hards = Self::hards();
        if !hards.contains_key(&first) {
            if first == '-' {
                return Err(Error::Parsing("Unexpected count code start while extracting Matter".to_string()));
            } else if first == '_' {
                return Err(Error::Parsing("Unexpected op code start while extracting Matter".to_string()));
            } else {
                return Err(Error::InvalidCode(format!("Unsupported code start char={}", first)));
            }
        }
        
        let hs = *hards.get(&first).unwrap();
        
        if qb64b.len() < hs {
            return Err(Error::Parsing(format!("Need {} more characters", hs - qb64b.len())));
        }
        
        // Extract hard code
        let hard = std::str::from_utf8(&qb64b[..hs])?;
        
        // Validate hard code
        let sizes = get_sizes(hard)?;
        
        let ss = sizes.ss;
        let xs = sizes.xs;  // Prefix with underscore to indicate intentionally unused
        let ls = sizes.ls;
        let cs = hs + ss; // Combined hard and soft size
        
        // Extract soft part including extra padding if any
        if qb64b.len() < cs {
            return Err(Error::Parsing(format!("Need {} more characters", cs - qb64b.len())));
        }
        
        let soft_with_xtra = if ss > 0 {
            std::str::from_utf8(&qb64b[hs..hs+ss])?
        } else {
            ""
        };
        
        // Extract extra padding from soft part
        let xtra = &soft_with_xtra[..xs.min(soft_with_xtra.len())];
        let soft = &soft_with_xtra[xs.min(soft_with_xtra.len())..];
        
        // Validate extra padding
        if xtra != "A".repeat(xs) {
            return Err(Error::InvalidCode(format!("Invalid prepad xtra={}", xtra)));
        }
        
        // Calculate full size
        let fs = match sizes.fs {
            Some(fs) => fs,
            None => {
                // Variable sized - calculate from soft part
                if soft.is_empty() {
                    return Err(Error::Parsing("Empty soft part for variable sized code".to_string()));
                }
                
                // Convert base64 to integer and calculate full size
                let size_int = b64_to_int(soft)?;
                (size_int * 4) + cs
            }
        };
        
        if qb64b.len() < fs {
            return Err(Error::Parsing(format!("Need {} more characters", fs - qb64b.len())));
        }
        
        // Calculate padding bytes needed for 24-bit alignment
        let ps = cs % 4; // Net prepad bytes
        
        // Create base with padding 'A's + the base64 of (lead + raw)
        let mut base = vec![b'A'; ps];
        base.extend_from_slice(&qb64b[cs..fs]);
        
        // Decode base64 to get padded raw bytes
        let paw = URL_SAFE_NO_PAD.decode(&base)?;
        
        // Check for non-zero padding bytes
        if ps + ls > 0 {
            let mut pad_bytes = vec![0u8; ps + ls];
            if paw.len() >= ps + ls {
                pad_bytes.copy_from_slice(&paw[..ps + ls]);
                let pi = bytes_to_int(&pad_bytes);
                if pi != 0 {
                    return Err(Error::Conversion(format!("Nonzero midpad bytes=0x{:0width$x}", pi, width=(ps + ls) * 2)));
                }
            }
        }
        
        // Extract raw bytes after padding
        let raw = if ps + ls < paw.len() {
            paw[ps + ls..].to_vec()
        } else {
            vec![]
        };
        
        // Verify raw length
        let expected_raw_len = ((fs - cs) * 3) / 4 - ls;
        if raw.len() != expected_raw_len {
            return Err(Error::Conversion(format!("Improperly qualified material")));
        }
        
        // Set the extracted values
        self.code = hard.to_string();
        self.soft = soft.to_string();
        self.raw = raw;
        
        Ok(())
    }
    
    fn bexfil(&mut self, qb2: &[u8]) -> Result<()> {
        // Implementation for extracting code and raw from binary qb2
        if qb2.is_empty() {
            return Err(Error::EmptyMaterial);
        }
        
        // First byte determines the code type
        let first_byte = qb2[0];
        
        // Determine the hard size from the first byte
        let first_char = match first_byte {
            // ASCII range for letters and numbers
            b'A'..=b'Z' | b'a'..=b'z' => first_byte as char,
            // For 2-byte codes, we need to convert the first two bytes to base64
            _ => {
                if qb2.len() < 2 {
                    return Err(Error::Parsing("Need more bytes for code".to_string()));
                }
                
                // Convert first two bytes to a base64 character
                let val = ((first_byte as usize) << 8) | (qb2[1] as usize);
                let idx = val >> 10;  // Get the 6 most significant bits
                
                match idx {
                    0..=25 => (b'A' + idx as u8) as char,
                    26..=51 => (b'a' + (idx - 26) as u8) as char,
                    52..=61 => (b'0' + (idx - 52) as u8) as char,
                    62 => '-',
                    63 => '_',
                    _ => return Err(Error::InvalidCode("Invalid binary code".to_string())),
                }
            }
        };
        
        // Get hard size for the first character
        let hs = get_hard_size(first_char)?;
        
        // Convert binary to base64 for the code part
        let mut qb64b = Vec::new();
        
        // For single character codes
        if hs == 1 {
            qb64b.push(first_byte);
        } else {
            // For multi-character codes, convert binary to base64
            let code_bytes = &qb2[0..ceil_div(hs * 6, 8)];
            let code_b64 = URL_SAFE_NO_PAD.encode(code_bytes);
            qb64b.extend_from_slice(code_b64.as_bytes());
            
            // Ensure we have the right number of characters
            if qb64b.len() < hs {
                return Err(Error::Parsing(format!("Invalid code bytes, expected {} chars", hs)));
            }
            
            // Trim to the exact hard size
            qb64b.truncate(hs);
        }
        
        // Get the code as a string
        let code_str = std::str::from_utf8(&qb64b[0..hs])?;
        
        // Get size information for the code
        let sizes = get_sizes(code_str)?;
        let ss = sizes.ss;
        let ls = sizes.ls;
        
        // If there's a soft part, extract it
        let mut soft = String::new();
        if ss > 0 {
            // Calculate how many binary bytes we need for the soft part
            let _soft_bin_size = ceil_div(ss * 6, 8);
            
            // Ensure we have enough bytes
            if qb2.len() < ceil_div((hs + ss) * 6, 8) {
                return Err(Error::Parsing("Not enough bytes for soft part".to_string()));
            }
            
            // Extract and convert the soft part
            let soft_bytes = &qb2[ceil_div(hs * 6, 8)..ceil_div((hs + ss) * 6, 8)];
            let soft_b64 = URL_SAFE_NO_PAD.encode(soft_bytes);
            
            // Ensure we have enough characters and trim to exact size
            if soft_b64.len() < ss {
                return Err(Error::Parsing(format!("Invalid soft bytes, expected {} chars", ss)));
            }
            
            // Store soft part
            soft = soft_b64[..ss].to_string();
        }
        
        // Now extract the raw bytes
        let cs = hs + ss;
        let cs_bin_size = ceil_div(cs * 6, 8);
        
        // Calculate full size
        let fs = match sizes.fs {
            Some(fs) => fs,
            None => {
                // For variable size, we need to extract from the soft part
                if ss == 0 {
                    return Err(Error::Parsing("Variable sized code with no soft part".to_string()));
                }
                
                let soft = std::str::from_utf8(&qb64b[hs..hs+ss])?;
                let size_int = b64_to_int(soft)?;
                (size_int * 4) + cs
            }
        };
        
        // Calculate how many binary bytes we need for the full representation
        let fs_bin_size = ceil_div(fs * 6, 8);
        
        // Ensure we have enough bytes
        if qb2.len() < fs_bin_size {
            return Err(Error::Parsing(format!("Need {} more bytes", fs_bin_size - qb2.len())));
        }
        
        // Extract raw bytes (after code and lead bytes)
        let raw = if cs_bin_size + ls < qb2.len() {
            qb2[cs_bin_size + ls..fs_bin_size].to_vec()
        } else {
            Vec::new()
        };
        
        // Set the extracted values
        self.code = code_str.to_string();
        self.soft = soft;
        self.raw = raw;
        
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
#[derive(Clone)]
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
        // Implementation for Ed25519 verification using sodiumoxide
        if sig.len() != ed25519::SIGNATUREBYTES {
            return false;
        }
        
        if self.raw().len() != ed25519::PUBLICKEYBYTES {
            return false;
        }
        
        // Convert raw bytes to sodiumoxide public key
        let pk = match ed25519::PublicKey::from_slice(self.raw()) {
            Some(pk) => pk,
            None => return false,
        };
        
        // Convert signature bytes to sodiumoxide signature
        let signature = match ed25519::Signature::from_bytes(sig) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        // Verify the signature
        ed25519::verify_detached(&signature, ser, &pk)
    }
}

/// Signature with verification capability
#[derive(Clone)]
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
#[derive(Clone)]
pub struct Diger {
    matter: BaseMatter,
}

impl Diger {
    /// Create a new Diger with serialized data
    pub fn new_with_ser(ser: &[u8], code: &str) -> Result<Self> {
        Self::new(None, Some(ser), code)
    }
    
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
    
    // fn compare(&self, ser: &[u8], dig: Option<&[u8]>, diger: Option<&dyn Matter>) -> bool {
    //     if let Some(d) = dig {
    //         return d == self.qb64b().as_slice();
    //     }
    //
    //     if let Some(d) = diger {
    //         if d.qb64() == self.qb64() {
    //             return true;
    //         }
    //
    //         if d.verify(ser) && self.verify(ser) {
    //             return true;
    //         }
    //     }
    //
    //     false
    // }
}

// Helper functions

/// Check if a character is a valid hard character
fn is_valid_hard_char(first: char) -> bool {
    BaseMatter::hards().contains_key(&first)
}

/// Get the hard size for a derivation code first character
fn get_hard_size(first: char) -> Result<usize> {
    match BaseMatter::hards().get(&first) {
        Some(size) => Ok(*size),
        None => Err(Error::InvalidCode(format!("Invalid first character: {}", first))),
    }
}

/// Convert base64 string to integer
fn b64_to_int(b64: &str) -> Result<usize> {
    if b64.is_empty() {
        return Ok(0);
    }
    
    let mut result: usize = 0;
    for c in b64.chars() {
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as usize,
            'a'..='z' => (c as u8 - b'a' + 26) as usize,
            '0'..='9' => (c as u8 - b'0' + 52) as usize,
            '-' => 62,
            '_' => 63,
            _ => return Err(Error::Parsing(format!("Invalid base64 character: {}", c))),
        };
        result = result * 64 + val;
    }
    
    Ok(result)
}

/// Convert bytes to integer
fn bytes_to_int(bytes: &[u8]) -> usize {
    let mut result: usize = 0;
    for &byte in bytes {
        result = (result << 8) | byte as usize;
    }
    result
}

/// Calculate ceiling of a division
fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

/// Get size information for a derivation code
fn get_sizes(code: &str) -> Result<Sizage> {
    match code {
        // Basic codes
        mtr_dex::ED25519_SEED => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::ED25519N => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::ED25519 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::X25519 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::BLAKE3_256 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::BLAKE2B_256 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::BLAKE2S_256 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::SHA3_256 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        mtr_dex::SHA2_256 => Ok(Sizage { hs: 1, ss: 0, xs: 0, fs: Some(44), ls: 0 }),
        
        // Fixed size codes from tests
        mtr_dex::TBD0 => Ok(Sizage { hs: 4, ss: 0, xs: 0, fs: Some(8), ls: 0 }),
        mtr_dex::TBD1 => Ok(Sizage { hs: 4, ss: 0, xs: 0, fs: Some(8), ls: 1 }),
        mtr_dex::TBD2 => Ok(Sizage { hs: 4, ss: 0, xs: 0, fs: Some(8), ls: 2 }),
        mtr_dex::TBD3 => Ok(Sizage { hs: 4, ss: 0, xs: 0, fs: Some(8), ls: 0 }),
        
        // Variable size codes from tests
        mtr_dex::BYTES_L0 => Ok(Sizage { hs: 2, ss: 2, xs: 0, fs: None, ls: 0 }),
        mtr_dex::BYTES_L1 => Ok(Sizage { hs: 2, ss: 2, xs: 0, fs: None, ls: 1 }),
        mtr_dex::BYTES_L2 => Ok(Sizage { hs: 2, ss: 2, xs: 0, fs: None, ls: 2 }),
        
        // Special codes from tests
        mtr_dex::TAG3 => Ok(Sizage { hs: 1, ss: 3, xs: 0, fs: Some(4), ls: 0 }),
        mtr_dex::TBD0S => Ok(Sizage { hs: 4, ss: 2, xs: 0, fs: None, ls: 0 }),
        
        // Signature code
        mtr_dex::ED25519_SIG => Ok(Sizage { hs: 2, ss: 0, xs: 0, fs: Some(88), ls: 0 }),
        
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matter_codex() {
        // Test that MtrDex constants are defined correctly
        assert_eq!(mtr_dex::ED25519_SEED, "A");
        assert_eq!(mtr_dex::ED25519N, "B");
        assert_eq!(mtr_dex::X25519, "C");
        assert_eq!(mtr_dex::ED25519, "D");
        assert_eq!(mtr_dex::BLAKE3_256, "E");
        assert_eq!(mtr_dex::BLAKE2B_256, "F");
        assert_eq!(mtr_dex::BLAKE2S_256, "G");
        assert_eq!(mtr_dex::SHA3_256, "H");
        assert_eq!(mtr_dex::SHA2_256, "I");

        // Test that Sizage values are correct for some codes
        let sizes = get_sizes(mtr_dex::ED25519_SEED).unwrap();
        assert_eq!(sizes.hs, 1);
        assert_eq!(sizes.ss, 0);
        assert_eq!(sizes.xs, 0);
        assert_eq!(sizes.fs, Some(44));
        assert_eq!(sizes.ls, 0);

        let sizes = get_sizes(mtr_dex::ED25519N).unwrap();
        assert_eq!(sizes.hs, 1);
        assert_eq!(sizes.ss, 0);
        assert_eq!(sizes.xs, 0);
        assert_eq!(sizes.fs, Some(44));
        assert_eq!(sizes.ls, 0);

        let sizes = get_sizes(mtr_dex::BLAKE3_256).unwrap();
        assert_eq!(sizes.hs, 1);
        assert_eq!(sizes.ss, 0);
        assert_eq!(sizes.xs, 0);
        assert_eq!(sizes.fs, Some(44));
        assert_eq!(sizes.ls, 0);

        // Test raw_size function
        assert_eq!(raw_size(mtr_dex::ED25519).unwrap(), 32);
        assert_eq!(raw_size(mtr_dex::ED25519N).unwrap(), 32);
        assert_eq!(raw_size(mtr_dex::BLAKE3_256).unwrap(), 32);
    }

    #[test]
    fn test_matter_basic() {
        // Test with empty material
        let result = BaseMatter::new(None, "", "");
        assert!(result.is_err());

        // Test with raw bytes but no code
        let verkey = b"iN\x89Gi\xe6\xc3&~\x8bG|%\x90(L\xd6G\xddB\xef`\x07\xd2T\xfc\xe1\xcd.\x9b\xe4#";
        let result = BaseMatter::new(Some(verkey.to_vec()), "", "");
        assert!(result.is_err());

        // Test with valid raw and code
        let result = BaseMatter::new(Some(verkey.to_vec()), mtr_dex::ED25519N, "");
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.raw(), verkey);

        // Test qb64 generation
        let qb64 = matter.qb64();
        assert_eq!(qb64, "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj");

        // Test from qb64
        let matter2 = BaseMatter::from_qb64(&qb64).unwrap();
        assert_eq!(matter2.code(), mtr_dex::ED25519N);
        assert_eq!(matter2.raw(), verkey);
        assert_eq!(matter2.qb64(), qb64);

        // Test qb2 generation and conversion
        let qb2 = matter.qb2();
        let matter3 = BaseMatter::try_from(qb2.as_slice()).unwrap();
        assert_eq!(matter3.code(), mtr_dex::ED25519N);
        assert_eq!(matter3.raw(), verkey);
        assert_eq!(matter3.qb64(), qb64);

        // Test transferable property
        assert!(!matter.is_transferable());

        // Test with transferable code
        let result = BaseMatter::new(Some(verkey.to_vec()), mtr_dex::ED25519, "");
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519);
        assert!(matter.is_transferable());

        // Test digestive property
        assert!(!matter.is_digestive());

        // Test with digest code
        let digest = [0u8; 32];
        let result = BaseMatter::new(Some(digest.to_vec()), mtr_dex::BLAKE3_256, "");
        assert!(result.is_ok());
        let matter = result.unwrap();
        assert_eq!(matter.code(), mtr_dex::BLAKE3_256);
        assert!(matter.is_digestive());

        // Test prefixive property
        assert!(matter.is_prefixive());
    }

    #[test]
    fn test_matter_from_qb64() {
        let prefix = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";
        let matter = BaseMatter::from_qb64(prefix).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);

        let result = matter.qb64();
        assert_eq!(result, prefix);

        // Test with full identifier
        let both = format!("{}:mystuff/mypath/toresource?query=what#fragment", prefix);
        let matter = BaseMatter::from_qb64(&both).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);
        assert!(!matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(matter.is_prefixive());
    }

    #[test]
    fn test_matter_from_qb64b() {
        let prefix = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";
        let prefixb = prefix.as_bytes();
        let matter = BaseMatter::from_qb64b(prefixb).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);

        // Test with full identifier
        let both = format!("{}:mystuff/mypath/toresource?query=what#fragment", prefix);
        let bothb = both.as_bytes();
        let matter = BaseMatter::from_qb64b(bothb).unwrap();
        assert_eq!(matter.code(), mtr_dex::ED25519N);
        assert_eq!(matter.qb64(), prefix);
        assert!(!matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(matter.is_prefixive());
    }

    #[test]
    fn test_matter_from_qb2() {
        let prefix = "BGlOiUdp5sMmfotHfCWQKEzWR91C72AH0lT84c0um-Qj";
        let matter = BaseMatter::from_qb64(prefix).unwrap();
        let qb2 = matter.qb2();

        let matter2 = BaseMatter::from_qb2(&qb2).unwrap();
        assert_eq!(matter2.code(), mtr_dex::ED25519N);
        assert_eq!(matter2.qb64(), prefix);
        assert!(!matter2.is_transferable());
        assert!(!matter2.is_digestive());
        assert!(matter2.is_prefixive());
    }

    #[test]
    fn test_matter_with_fixed_sizes() {
        // Test TBD0 code with fixed size and lead size 0
        let code = mtr_dex::TBD0;
        let raw = b"abc";
        let qb64 = "1___YWJj";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, "").unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test TBD1 code with fixed size and lead size 1
        let code = mtr_dex::TBD1;
        let raw = b"ab";
        let qb64 = "2___AGFi";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, "").unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test TBD2 code with fixed size and lead size 2
        let code = mtr_dex::TBD2;
        let raw = b"z";
        let qb64 = "3___AAB6";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, "").unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);
    }

    #[test]
    fn test_matter_with_variable_sizes() {
        // Test Bytes_L0 code with variable size and lead size 0
        let code = mtr_dex::BYTES_L0;
        let raw = b"abcdef";
        let qb64 = "4BACYWJjZGVm";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, "").unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test Bytes_L1 code with variable size and lead size 1
        let code = mtr_dex::BYTES_L1;
        let raw = b"abcde";
        let qb64 = "5BACAGFiY2Rl";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, "").unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);

        // Test Bytes_L2 code with variable size and lead size 2
        let code = mtr_dex::BYTES_L2;
        let raw = b"abcd";
        let qb64 = "6BACAABhYmNk";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, "").unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.is_transferable());
        assert!(!matter.is_digestive());
        assert!(!matter.is_prefixive());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.raw(), raw);
    }

    #[test]
    fn test_matter_with_special_codes() {
        // Test Tag3 code with special soft value
        let code = mtr_dex::TAG3;
        let soft = "icp";
        let qb64 = "Xicp";
        let raw = b"";

        let matter = BaseMatter::new(None, code, soft).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.soft, soft);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.special());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.soft, soft);
        assert_eq!(matter2.raw(), raw);

        // Test TBD0S code with special soft value and non-empty raw
        let code = mtr_dex::TBD0S;
        let soft = "TG";
        let raw = b"uvwx";
        let qb64 = "1__-TGB1dnd4";

        let matter = BaseMatter::new(Some(raw.to_vec()), code, soft).unwrap();
        assert_eq!(matter.code(), code);
        assert_eq!(matter.soft, soft);
        assert_eq!(matter.raw(), raw);
        assert_eq!(matter.qb64(), qb64);
        assert!(matter.special());

        let matter2 = BaseMatter::from_qb64(qb64).unwrap();
        assert_eq!(matter2.code(), code);
        assert_eq!(matter2.soft, soft);
        assert_eq!(matter2.raw(), raw);
    }

    #[test]
    fn test_verfer() {
        // Initialize sodiumoxide
        sodiumoxide::init().expect("Sodium initialization failed");
        
        // Generate a test key pair
        let seed = ed25519::Seed::from_slice(&[0u8; 32]).unwrap(); // Use a fixed seed for deterministic testing
        let (pk, sk) = ed25519::keypair_from_seed(&seed);
        let verkey = pk.as_ref();

        // Create a Verfer with non-transferable code
        let verfer = Verfer::new(Some(verkey.to_vec()), mtr_dex::ED25519N).unwrap();
        assert_eq!(verfer.code(), mtr_dex::ED25519N);
        assert_eq!(verfer.raw(), verkey);
        assert!(!verfer.is_transferable());

        // Create a signature to verify
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let sig = ed25519::sign_detached(ser, &sk);
        
        // Verify the signature
        assert!(verfer.verify(sig.as_ref(), ser));

        // Modify the signature and verify it fails
        let mut bad_sig = sig.as_ref().to_vec();
        bad_sig[0] = bad_sig[0].wrapping_add(1);
        assert!(!verfer.verify(&bad_sig, ser));

        // Create a Verfer with transferable code
        let verfer = Verfer::new(Some(verkey.to_vec()), mtr_dex::ED25519).unwrap();
        assert_eq!(verfer.code(), mtr_dex::ED25519);
        assert_eq!(verfer.raw(), verkey);
        assert!(verfer.is_transferable());

        // Verify the signature with transferable code
        assert!(verfer.verify(sig.as_ref(), ser));
    }

    #[test]
    fn test_diger() {
        // Test creating a Diger with raw digest
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let dig = blake3::hash(ser).as_bytes().to_vec();

        let diger = Diger::new(Some(dig.clone()), None, mtr_dex::BLAKE3_256).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);
        assert_eq!(diger.raw(), dig);
        assert!(diger.is_digestive());

        // Test creating a Diger from serialization
        let diger = Diger::new_with_ser(ser, mtr_dex::BLAKE3_256).unwrap();
        assert_eq!(diger.code(), mtr_dex::BLAKE3_256);
        assert!(diger.verify(ser));

        // Test verification with correct serialization
        assert!(diger.verify(ser));

        // Test verification with incorrect serialization
        let bad_ser = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
        assert!(!diger.verify(bad_ser));
        // Test compare method with matching digests
        // let diger2 = Diger::new_with_ser(ser, mtr_dex::BLAKE3_256).unwrap();
        // assert!(diger.compare(ser, Some(diger2.qb64().as_bytes()), None));
        // assert!(diger.compare(ser, None, Some(&diger2)));
        //
        // // Test compare method with non-matching digests
        // let diger3 = Diger::new_with_ser(bad_ser, mtr_dex::BLAKE3_256).unwrap();
        // assert!(!diger.compare(ser, Some(diger3.qb64().as_bytes()), None));
        // assert!(!diger.compare(ser, None, Some(&diger3)));
        //
        // // Test with different digest algorithms
        // let diger4 = Diger::new_with_ser(ser, mtr_dex::SHA3_256).unwrap();
        // assert!(diger.compare(ser, None, Some(&diger4)));
    }

    #[test]
    fn test_cigar() {
        // Initialize sodiumoxide
        sodiumoxide::init().expect("Sodium initialization failed");
        
        // Generate a test key pair
        let seed = ed25519::Seed::from_slice(&[0u8; 32]).unwrap(); // Use a fixed seed for deterministic testing
        let (pk, sk) = ed25519::keypair_from_seed(&seed);
        let verkey = pk.as_ref().to_vec();

        // Create a signature
        let ser = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let sig = ed25519::sign_detached(ser, &sk);
        let sig_bytes = sig.as_ref().to_vec();

        // Create a Verfer
        let verfer = Verfer::new(Some(verkey), mtr_dex::ED25519).unwrap();

        // Create a Cigar with the signature
        let cigar = Cigar::new(Some(sig_bytes.clone()), mtr_dex::ED25519_SIG, Some(verfer.clone())).unwrap();
        assert_eq!(cigar.code(), mtr_dex::ED25519_SIG);
        assert_eq!(cigar.raw(), sig_bytes);

        // Verify the signature using the verfer in the cigar
        assert!(cigar.verfer.clone().unwrap().verify(&cigar.raw(), ser));
        
        // Create a Cigar without a verfer
        let cigar = Cigar::new(Some(sig_bytes.clone()), mtr_dex::ED25519_SIG, None).unwrap();
        assert_eq!(cigar.code(), mtr_dex::ED25519_SIG);
        assert_eq!(cigar.raw(), sig_bytes);
        assert!(cigar.verfer.is_none());

        // Set the verfer after creation
        let mut cigar = cigar;
        cigar.verfer = Some(verfer.clone());
        assert!(cigar.verfer.is_some());
        assert!(cigar.verfer.clone().unwrap().verify(&cigar.raw(), ser));
    }
}
