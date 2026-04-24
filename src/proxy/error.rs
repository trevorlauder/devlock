#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("body too large (limit: {limit} bytes)")]
    BodyTooLarge { limit: usize },
    #[error("{0}")]
    Http(#[from] hyper::http::Error),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
