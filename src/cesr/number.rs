use crate::cesr::BaseMatter;
use crate::errors::MatterError;
use crate::Matter;

/// Number represents ordinal counting numbers
pub struct Number {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Number {
    /// Creates a new Number from a numeric value
    pub fn new(num: u128, code: &str) -> Result<Self, MatterError> {
        // TODO: Implement conversion of numeric value to raw bytes
        // 1. Check if the provided code is valid for Number
        // 2. Convert the number to big-endian bytes
        // 3. Verify the number fits within the size allowed by the code
        // 4. Create a BaseMatter with the provided code and raw bytes
        let raw = num.to_be_bytes().to_vec();

        Ok(Self {
            base: BaseMatter::new(Some(&*raw), Some(code), None, None)?,
        })
    }

    /// Returns the numeric value
    pub fn num(&self) -> u128 {
        // TODO: Implement conversion from raw bytes to u128
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.base.raw()[0..16]);
        u128::from_be_bytes(bytes)
    }
}

impl Matter for Number {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
}

