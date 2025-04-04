use crate::cesr::BaseMatter;
use crate::Matter;

///  Texter is subclass of Matter, cryptographic material, for variable length
///  text strings as bytes not unicode. Unicode strings converted to bytes.

pub struct Texter {
    base: BaseMatter,
}

impl Texter {

}

impl Matter for Texter {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
}
