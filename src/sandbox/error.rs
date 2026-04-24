#[derive(Debug, thiserror::Error)]
pub enum DevlockError {
    #[error("policy error: {0}")]
    Policy(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("exec error: {0}")]
    Exec(#[from] std::io::Error),
}
