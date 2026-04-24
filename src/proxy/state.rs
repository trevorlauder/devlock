use crate::policy::agent::ProxyConfig;
use crate::proxy::ProxyCredentials;
use crate::proxy::http::ClientBody;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use zeroize::{Zeroize, Zeroizing};

pub type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    ClientBody,
>;

pub type SharedToken = Arc<Zeroizing<String>>;

pub struct ProxyState {
    pub access_token: RwLock<SharedToken>,
    pub refresh_token: RwLock<SharedToken>,
    /// Unix epoch milliseconds. Zero means no expiry tracking.
    pub expires_at_ms: RwLock<u64>,
    pub session_token: String,
    pub client: HttpsClient,
    pub proxy: ProxyConfig,
    /// Serializes token refresh so only one request refreshes at a time.
    pub refresh_lock: Mutex<()>,
}

fn shared(token: String) -> SharedToken {
    Arc::new(Zeroizing::new(token))
}

impl ProxyState {
    pub fn new(credentials: ProxyCredentials, proxy: ProxyConfig) -> anyhow::Result<Self> {
        let ProxyCredentials {
            access_token,
            refresh_token,
            expires_at_ms,
            session_token,
        } = credentials;
        // install_default returns Err only if a provider was already
        // installed in this process, in which case the existing one is
        // kept. In the fresh proxy child that never happens, but we
        // still ignore the error so a repeat call in tests is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(Self {
            access_token: RwLock::new(shared(access_token)),
            refresh_token: RwLock::new(shared(refresh_token)),
            expires_at_ms: RwLock::new(expires_at_ms),
            session_token,
            client,
            proxy,
            refresh_lock: Mutex::new(()),
        })
    }

    pub async fn set_access_token(&self, token: String) {
        *self.access_token.write().await = shared(token);
    }

    pub async fn set_refresh_token(&self, token: String) {
        *self.refresh_token.write().await = shared(token);
    }
}

impl Drop for ProxyState {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}
