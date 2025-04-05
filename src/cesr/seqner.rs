use crate::cesr::{mtr_dex, non_trans_dex, BaseMatter};
use crate::errors::MatterError;
use crate::Matter;

/// Seqner represents sequence numbers or first-seen numbers
pub struct Seqner {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Seqner {
    pub fn from_sn(sn: u64) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&sn.to_be_bytes());
        let raw = bytes.to_vec();
        let base = BaseMatter::new(Some(&raw), Some(mtr_dex::SALT_128), None, None).unwrap();
        Seqner {base}
    }

    pub fn from_snh(snh: &str) -> Result<Self, MatterError> {
        let sn = u64::from_str_radix(snh, 16).unwrap();
        let seqner = Seqner::from_sn(sn);
        Ok(seqner)
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, Some(mtr_dex::SALT_128), None, None)?;

        Ok(Seqner {
            base,
        })
    }

    pub fn from_qb64b(qb64b: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(qb64b)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Seqner {
            base,
        })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Seqner {
            base,
        })
    }

    pub fn from_qb2(qb2: &[u8]) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(qb2)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Seqner {
            base,
        })
    }

    /// Returns the sequence number
    pub fn sn(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.base.raw()[0..8]);
        u64::from_be_bytes(bytes)
    }

    /// Returns hex string representation of the sequence number
    pub fn snh(&self) -> String {
        format!("{:x}", self.sn())
    }
}

impl Matter for Seqner {
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
