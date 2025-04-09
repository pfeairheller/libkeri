use crate::cesr::BaseMatter;
use crate::Matter;

///  Saider is Matter subclass for self-addressing identifier prefix using
///  derivation as determined by code from ked
#[derive(Debug, Clone)]
pub struct Pather {
    base: BaseMatter,
}

impl Pather {

}

impl Matter for Pather {
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
