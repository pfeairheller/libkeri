use crate::cesr::BaseMatter;
use crate::errors::MatterError;
use crate::Matter;

/// Seqner represents sequence numbers or first-seen numbers
pub struct Seqner {
    base: BaseMatter,
}

#[allow(dead_code)]
impl Seqner {
    /// Creates a new Seqner from a sequence number
    pub fn new(sn: u64) -> Result<Self, MatterError> {
        // TODO: Implement conversion of sequence number to raw bytes
        // 1. Convert the sequence number to big-endian bytes
        // 2. Ensure the size matches the expected size for Salt_128
        // 3. Create a BaseMatter with the appropriate code
        let raw = sn.to_be_bytes().to_vec();
        let code = "0A"; // MtrDex::Salt_128

        Ok(Self {
            base: BaseMatter::new(Some(&*raw), Some(code), None, None)?,
        })
    }

    /// Returns the sequence number
    pub fn sn(&self) -> u64 {
        // TODO: Implement conversion from raw bytes to u64
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.base.raw()[0..8]);
        u64::from_be_bytes(bytes)
    }

    /// Returns hex string representation of the sequence number
    pub fn snh(&self) -> String {
        format!("{:x}", self.sn())
    }
}

impl Matter for Seqner {
    fn code(&self) -> &str { self.base.code() }
    fn raw(&self) -> &[u8] { self.base.raw() }
    fn qb64(&self) -> String { self.base.qb64() }
    fn qb2(&self) -> Vec<u8> { self.base.qb2() }
    fn is_transferable(&self) -> bool { self.base.is_transferable() }
    fn is_digestive(&self) -> bool { self.base.is_digestive() }
    fn is_prefixive(&self) -> bool { self.base.is_prefixive() }
    fn is_special(&self) -> bool { self.base.is_special() }
}
