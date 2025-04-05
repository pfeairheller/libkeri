use crate::cesr::BaseMatter;
use crate::Matter;

///  Bexter is subclass of Matter, cryptographic material, for variable length
///  strings that only contain Base64 URL safe characters, i.e. Base64 text (bext).
///  When created using the 'bext' paramaeter, the encoded matter in qb64 format
///  in the text domain is more compact than would be the case if the string were
///  passed in as raw bytes. The text is used as is to form the value part of the
///  qb64 version not including the leader.
/// 
///  Due to ambiguity that arises from pre-padding bext whose length is a multiple of
///  three with one or more 'A' chars. Any bext that starts with an 'A' and whose length
///  is either a multiple of 3 or 4 may not round trip. Bext with a leading 'A'
///  whose length is a multiple of four may have the leading 'A' stripped when
///  round tripping.
pub struct Bexter {
    base: BaseMatter,
}

impl Bexter {

}

impl Matter for Bexter {
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
