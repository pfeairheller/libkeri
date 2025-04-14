use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DBError {
    #[error("Invalid code: {0}")]
    CoreError(String),

    #[error("DB IoError: {0}")]
    IoError(String),

    #[error("Filer Error: {0}")]
    FilerError(String),

    #[error("Database Error: {0}")]
    DatabaseError(String),

    #[error("Key Error: {0}")]
    KeyError(String),

    #[error("Value error: {0}")]
    ValueError(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}