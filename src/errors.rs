use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Parsing error: {0}")]
    ParsingError(String),

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("Other error: {0}")]
    Other(String),
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum MatterError {
    #[error("Invalid code: {0}")]
    InvalidCode(String),

    #[error("Invalid code size: {0}")]
    InvalidCodeSize(String),

    #[error("Invalid size for raw material")]
    InvalidSize,

    #[error("Invalid format for encoded material")]
    InvalidFormat,

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid QB64")]
    InvalidQb64,

    #[error("Invalid qb64 length")]
    InvalidQb64Length,

    #[error("Invalid base64")]
    InvalidBase64,

    #[error("Invalid raw size")]
    InvalidRawSize,

    #[error("Shortage: {0}")]
    ShortageError(String),

    #[error("Unexpected count code: {0}")]
    UnexpectedCountCodeError(String),

    #[error("Unexpected op code: {0}")]
    UnexpectedOpCodeError(String),

    #[error("Unexpected code: {0}")]
    UnexpectedCodeError(String),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("Empty material: {0}")]
    EmptyMaterial(String),

    #[error("Type Error: {0}")]
    TypeError(String),

    #[error("Invalid raw size: {0}")]
    InvalidVarRawSize(String),

    #[error("Soft material: {0}")]
    SoftMaterial(String),

    #[error("Invalid soft: {0}")]
    InvalidSoft(String),

    #[error("Raw material: {0}")]
    RawMaterial(String),

    #[error("Shortage error: {0}")]
    Shortage(String),

    #[error("Unexpected count code: {0}")]
    UnexpectedCountCode(String),

    #[error("Unexpected op code: {0}")]
    UnexpectedOpCode(String),

    #[error("Unexpected code: {0}")]
    UnexpectedCode(String),

    #[error("Conversion error: {0}")]
    Conversion(String),

    #[error("Invalid base64 index: {0}")]
    InvalidBase64Index(usize),

    #[error("Invalid soft error: {0}")]
    InvalidSoftError(String),

    #[error("Soft material error: {0}")]
    SoftMaterialError(String),

}