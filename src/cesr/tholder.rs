use crate::cesr::BaseMatter;
use crate::errors::MatterError;
use crate::Matter;

/// Number represents ordinal counting numbers
pub struct Tholder {
    base: BaseMatter,
}

impl Tholder {
    pub fn from_str(ths: &str) -> Result<Self, MatterError> {
        unimplemented!()
    }
}

#[allow(dead_code)]
impl Matter for Tholder {
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