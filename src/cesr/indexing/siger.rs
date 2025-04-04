use crate::cesr::indexing::{BaseIndexer, Indexer};

///  Cigar is Matter subclass holding a nonindexed signature with verfer property.
///  From Matter .raw is signature and .code is signature cipher suite
///  Adds .verfer property to hold Verfer instance of associated verifier public key
///  Verfer's .raw as verifier key and .code is verifier cipher suite.

pub struct Siger {
    base: BaseIndexer
}

impl Siger {

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
