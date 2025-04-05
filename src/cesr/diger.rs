use crate::cesr::{dig_dex, mtr_dex, BaseMatter};
use crate::errors::MatterError;
use crate::Matter;
use blake2::{Blake2b512, Blake2s256, Digest as Blake2Digest};
use blake3::{Hasher as Blake3Hasher};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};

///  Diger is Matter subclass with method to verify digest of serialization
pub struct Diger {
    base: BaseMatter,
}

impl Diger {
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, soft: Option<&str>, rize: Option<usize>) -> Result<Self, MatterError> {
        if !dig_dex::TUPLE.contains(&(code.unwrap())) {
            return Err(MatterError::UnsupportedCodeError(String::from(code.unwrap())));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Diger {
            base,
        })
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, Some(mtr_dex::BLAKE3_256), None, None)?;

        Ok(Diger {
            base,
        })
    }

    pub fn from_qb64b(qb64b: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(qb64b)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Diger {
            base,
        })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Diger {
            base,
        })
    }

    pub fn from_qb2(qb2: &[u8]) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(qb2)?;
        if !dig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Diger {
            base,
        })
    }

    pub fn from_ser(ser: &[u8]) -> Result<Self, MatterError> {
        Diger::from_ser_and_code(ser, dig_dex::BLAKE3_256)
    }

    pub fn from_ser_and_code(ser: &[u8], code: &str) -> Result<Self, MatterError> {
        let raw = Diger::digest(ser, code)?;
        let base = BaseMatter::new(Some(&raw), Some(code), None, None)?;
        Ok(Diger {
            base,
        })
    }

    pub fn digest(ser: &[u8], code: &str) -> Result<Vec<u8>, MatterError> {
        match code {
            code if code == dig_dex::BLAKE3_256 => {
                let result = Diger::digest_blake3_256(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::BLAKE3_512 => {
                let result = Diger::digest_blake3_512(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::SHA3_256 => {
                let result = Diger::digest_sha3_256(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::SHA2_256 => {
                let result = Diger::digest_sha2_256(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::SHA3_512 => {
                let result = Diger::digest_sha3_512(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::SHA2_512 => {
                let result = Diger::digest_sha2_512(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::BLAKE2S_256 => {
                let result = Diger::digest_blake2s_256(ser)?;
                Ok(result.to_vec())
            },
            code if code == dig_dex::BLAKE2B_512 => {
                let result = Diger::digest_blake2b_512(ser)?;
                Ok(result.to_vec())
            },
            // code if code == dig_dex::BLAKE2B_256 => {
            //     let result = Diger::digest_blake2b_256(ser)?;
            //     Ok(result.to_vec())
            // },
            // This should never happen because we validate in the constructor
            _ => Err(MatterError::UnsupportedCodeError(String::from(code))),
        }
    }

    /// Calculate Blake3 256-bit hash (default output size of Blake3)
    fn digest_blake3_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let result = blake3::hash(data).into();
        Ok(result)
    }

    /// Calculate Blake2b 512-bit hash
    fn digest_blake2b_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    // /// Calculate Blake2b 256-bit hash
    // fn digest_blake2b_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
    //     let mut hasher = Blake2b::new_with_params(32);
    //     hasher.update(data);
    //     let result = hasher.finalize();
    //     let mut digest = [0u8; 32];
    //     digest.copy_from_slice(&result[..32]);
    //     Ok(digest)
    // }
    //


    /// Calculate Blake2s 256-bit hash
    fn digest_blake2s_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate Blake3 512-bit hash
    fn digest_blake3_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let mut digest = [0u8; 64];
        hasher.finalize_xof().fill(&mut digest);
        Ok(digest)
    }
    /// Calculate SHA3-256 hash
    fn digest_sha3_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate SHA2-256 hash
    fn digest_sha2_256(data: &[u8]) -> Result<[u8; 32], MatterError> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate SHA3-512 hash
    fn digest_sha3_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    /// Calculate SHA2-512 hash
    fn digest_sha2_512(data: &[u8]) -> Result<[u8; 64], MatterError> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result);
        Ok(digest)
    }

    fn verify(&self, ser: &[u8]) -> bool {
        match Diger::digest(ser, self.base.code()) {
            Ok(raw) => self.base.raw() == raw.as_slice(),
            Err(_) => false,
        }
    }

    fn compare_with_diger(&self, other: &Self) -> bool {
        self.base.qb64() == other.base.qb64()
    }

    fn compare_with_qb64(&self, other: &str) -> bool {
        self.base.qb64() == other
    }
}

impl Matter for Diger {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.base.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
}
