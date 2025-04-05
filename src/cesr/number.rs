use num_bigint::BigUint;
use crate::cesr::{num_dex, BaseMatter};
use num_traits::pow;
use crate::errors::MatterError;
use crate::Matter;

/// Number represents ordinal counting numbers
pub struct Number {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Number {

    pub fn from_num(num: &BigUint) -> Result<Self, MatterError> {
        let code = number_code(num)?;
        let raw = num.to_bytes_be();
        let base = BaseMatter::new(Some(&raw), Some(code), None, None)?;
        Ok(Number {
            base
        })
    }

    pub fn from_numh(numh: &str) -> Result<Self, MatterError> {
        let num = u64::from_str_radix(numh, 16).unwrap();
        let biguint = BigUint::from(num);
        Number::from_num(&biguint)
    }


    /// Creates a new Number from a numeric value
    pub fn new(raw: Option<&[u8]>, code: Option<&str>, soft: Option<&str>, rize: Option<usize>) -> Result<Self, MatterError> {
        if !num_dex::TUPLE.contains(&(code.unwrap())) {
            return Err(MatterError::UnsupportedCodeError(String::from(code.unwrap_or("None"))));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Number {
            base
        })
    }

    pub fn from_qb64b(qb64b: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(qb64b)?;
        if !num_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Number {
            base
        })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if !num_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Number {
            base
        })
    }

    pub fn from_qb2(qb2: &[u8]) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(qb2)?;
        if !num_dex::TUPLE.contains(&(base.code())) {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Number {
            base
        })
    }

    /// Returns the numeric value
    pub fn num(&self) -> u128 {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&self.base.raw()[0..16]);
        u128::from_be_bytes(bytes)
    }
}

pub fn number_code(num: &BigUint) -> Result<&str, MatterError> {
    let base = BigUint::from(256u32);

    // Check for Short (256^2 - 1)
    let short_limit = pow(base.clone(), 2u32 as usize) - 1u32;
    if num <= &short_limit {
        return Ok(num_dex::SHORT);
    }

    // Check for Tall (256^5 - 1)
    let tall_limit = pow(base.clone(), 5u32 as usize) - 1u32;
    if num <= &tall_limit {
        return Ok(num_dex::TALL);
    }

    // Check for Big (256^8 - 1)
    let big_limit = pow(base.clone(), 8u32 as usize) - 1u32;
    if num <= &big_limit {
        return Ok(num_dex::BIG);
    }

    // Check for Large (256^11 - 1)
    let large_limit = pow(base.clone(), 11u32 as usize) - 1u32;
    if num <= &large_limit {
        return Ok(num_dex::LARGE);
    }

    // Check for Great (256^14 - 1)
    let great_limit = pow(base.clone(), 14u32 as usize) - 1u32;
    if num <= &great_limit {
        return Ok(num_dex::GREAT);
    }

    // Check for Vast (256^17 - 1)
    let vast_limit = pow(base.clone(), 17u32 as usize) - 1u32;
    if num <= &vast_limit {
        return Ok(num_dex::VAST);
    }

    // Too large, return error
    Err(MatterError::InvalidValue(num.to_string()))
}

impl Matter for Number {
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

