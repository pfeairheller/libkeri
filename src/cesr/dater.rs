use crate::cesr::BaseMatter;
use crate::errors::MatterError;
use crate::Matter;

/// Dater represents RFC-3339 formatted datetimes
pub struct Dater {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Dater {
    /// Creates a new Dater from a DateTime<Utc> object
    pub fn new(dt: chrono::DateTime<chrono::Utc>) -> Result<Self, MatterError> {
        // TODO: Implement conversion of datetime to raw bytes and create BaseMatter
        let dt_str = dt.to_rfc3339();
        let raw = dt_str.as_bytes().to_vec();
        let code = "1A"; // Appropriate code for datetime

        Ok(Self {
            base: BaseMatter::new(Some(&*raw), Some(code), None, None)?,
        })
    }

    /// Returns the datetime string
    pub fn dts(&self) -> String {
        // TODO: Implement conversion from raw bytes to datetime string
        String::from_utf8_lossy(self.base.raw()).to_string()
    }

    /// Returns the datetime as a DateTime<Utc> object
    pub fn dt(&self) -> Result<chrono::DateTime<chrono::Utc>, MatterError> {
        // TODO: Implement conversion from raw bytes to DateTime<Utc>
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
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
}
