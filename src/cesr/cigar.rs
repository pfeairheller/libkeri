use crate::cesr::{non_trans_dex, BaseMatter};
use crate::cesr::verfer::Verfer;
use crate::errors::MatterError;
use crate::Matter;

///  Cigar is Matter subclass holding a nonindexed signature with verfer property.
///  From Matter .raw is signature and .code is signature cipher suite
///  Adds .verfer property to hold Verfer instance of associated verifier public key
///  Verfer's .raw as verifier key and .code is verifier cipher suite.

pub struct Cigar {
    base: BaseMatter,
    verfer: Option<Verfer>,
}

impl Cigar {
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, soft: Option<&str>, rize: Option<usize>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        if !non_trans_dex::TUPLE.contains(&(code.unwrap())) {
            return Err(MatterError::UnsupportedCodeError(String::from(code.unwrap())));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Cigar {
            base,
            verfer,
        })
    }

    pub fn from_raw(raw: Option<&[u8]>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_raw(raw)?;

        Ok(Cigar {
            base,
            verfer
        })
    }

    pub fn from_qb64b(qb64b: Option<&[u8]>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(qb64b)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Cigar {
            base,
            verfer
        })
    }

    pub fn from_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Cigar {
            base,
            verfer
        })
    }

    pub fn from_qb2(qb2: &[u8], verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(qb2)?;
        if !non_trans_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Cigar {
            base,
            verfer
        })
    }

    pub fn verfer(&self) -> &Verfer {
        self.verfer.as_ref().unwrap()
    }
}

impl Matter for Cigar {
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
