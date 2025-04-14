use crate::cesr::{mtr_dex, BaseMatter};
use crate::errors::MatterError;
use crate::Matter;

/// Dater represents RFC-3339 formatted datetimes
#[derive(Debug, Clone)]
pub struct Dater {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Dater {

    pub fn from_dt(dt: chrono::DateTime<chrono::Utc>) -> Self {
        let dts = dt.to_rfc3339();
        let raw = dts.as_bytes().to_vec();
        let base = BaseMatter::new(Some(&raw), Some(mtr_dex::DATE_TIME), None, None).unwrap();
        Dater {base}
    }

    pub fn new(raw: Option<&[u8]>, code: Option<&str>, soft: Option<&str>, rize: Option<usize>) -> Result<Self, MatterError> {
        if code.unwrap() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(code.unwrap_or("None"))));
        }

        let base = BaseMatter::new(raw, code, soft, rize)?;
        Ok(Dater {
            base,
        })
    }

    pub fn from_raw(raw: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::new(raw, Some(mtr_dex::DATE_TIME), None, None)?;

        Ok(Dater {
            base
        })
    }

    pub fn from_qb64b(qb64b: Option<&[u8]>) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64b(qb64b)?;
        if base.code() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Dater {
            base
        })
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb64(qb64)?;
        if base.code() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Dater {
            base
        })
    }

    pub fn from_qb2(qb2: &[u8]) -> Result<Self, MatterError> {
        let base = BaseMatter::from_qb2(qb2)?;
        if base.code() != mtr_dex::DATE_TIME {
            return Err(MatterError::UnsupportedCodeError(String::from(base.code())));
        }

        Ok(Dater {
            base
        })
    }

    /// Returns the datetime string
    pub fn dts(&self) -> String {
        String::from_utf8_lossy(self.base.raw()).to_string()
    }

    /// Returns the datetime as a DateTime<Utc> object
    pub fn dt(&self) -> Result<chrono::DateTime<chrono::Utc>, MatterError> {
        let dts = self.dts();
        chrono::DateTime::parse_from_rfc3339(&dts)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|_| MatterError::InvalidFormat)
    }
}

impl Matter for Dater {
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
