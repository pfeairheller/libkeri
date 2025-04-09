use crate::cesr::indexing::{idx_sig_dex, BaseIndexer, Indexer};
use crate::cesr::verfer::Verfer;
use crate::errors::MatterError;

///  Cigar is Matter subclass holding a nonindexed signature with verfer property.
///  From Matter .raw is signature and .code is signature cipher suite
///  Adds .verfer property to hold Verfer instance of associated verifier public key
///  Verfer's .raw as verifier key and .code is verifier cipher suite.

#[derive(Debug, Clone)]
pub struct Siger {
    base: BaseIndexer,
    verfer: Option<Verfer>,
}

impl Siger {
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, index: Option<u32>, ondex: Option<u32>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        if !idx_sig_dex::TUPLE.contains(&(code.unwrap())) {
            return Err(MatterError::UnsupportedCodeError(String::from(code.unwrap())));
        }

        let base = BaseIndexer::new(raw, code, index, ondex)?;
        Ok(Siger {
            base,
            verfer,
        })
    }

    pub fn from_raw(raw: Option<&[u8]>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseIndexer::from_raw(raw)?;

        Ok(Siger {
            base,
            verfer
        })
    }

    pub fn from_qb64b(qb64b: Option<&[u8]>, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseIndexer::from_qb64b(qb64b)?;
        if !idx_sig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Siger {
            base,
            verfer
        })
    }

    pub fn from_qb64(qb64: &str, verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseIndexer::from_qb64(qb64)?;
        if !idx_sig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Siger {
            base,
            verfer
        })
    }

    pub fn from_qb2(qb2: &[u8], verfer: Option<Verfer>) -> Result<Self, MatterError> {
        let base = BaseIndexer::from_qb2(qb2)?;
        if !idx_sig_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Siger {
            base,
            verfer
        })
    }

    pub fn verfer(&self) -> &Verfer {
        self.verfer.as_ref().unwrap()
    }
}

impl Indexer for Siger {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb64b(&self) -> Vec<u8> { self.base.qb64b() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn index(&self) -> u32 { self.base.index() }
    fn ondex(&self) -> u32 { self.base.ondex() }
}


