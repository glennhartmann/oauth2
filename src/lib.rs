pub mod dpop;
mod http_server;

use std::{str::from_utf8, time::Duration};

use dpop::KeyData;

use chrono::DateTime;
use rand::{
    SeedableRng, TryRng,
    rngs::{StdRng, SysRng},
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Config data for the oauth2 flow. Some fields may be optional depending on the operation you
/// want to perform.
pub struct Cfg {
    /// Port that a local http server can listen on. Required if you plan to use the `auth` flow.
    pub listen_port: Option<u16>,

    /// Client ID. You can find create one on your Google Cloud console.
    pub client_id: String,

    /// Oauth Scope for the APIs you want to call. Required for the `auth` flow.
    pub scope: Option<String>,

    /// URL for the auth server you want to connect to. For Google, you probably want
    /// `https://accounts.google.com/o/oauth2/auth`. Required for the `auth` flow.
    pub auth_server_url: Option<String>,

    /// URL for the token server you want to connect to. For Google, that means
    /// `https://oauth2.googleapis.com/token`.
    pub token_server_url: String,

    /// Client secret from Google Cloud console.
    pub client_secret: String,

    /// Refresh token, from the last time you went through the `auth` flow. Required to go through
    /// the `refresh` flow.
    pub refresh_token: Option<String>,

    /// Cryptographic key data for signing DPoPs. If omitted, a DPoP will not be used (this is less
    /// secure).
    pub key_data: Option<KeyData>,

    /// DPoP nonce previously returned from the server, if applicable.
    pub dpop_nonce: Option<String>,
}

/// The response from the initial step of the `auth` flow (user authorization).
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    /// The CSRF `state` field.
    state: String,

    /// The `code` returned by the Oauth server.
    code: String,

    /// The API `scope` returned by the Oauth server.
    scope: String,
}

/// The (internal) parsed json response from the Token Exchange part of the `auth` flow.
#[derive(Deserialize, Debug)]
struct ExchangeResponse {
    /// The new access token returned by the Oauth server. This can be used to call APIs.
    access_token: String,

    /// How many seconds the access token is valid for.
    expires_in: u32,

    /// The token used to get a new access token when the original access token expires.
    refresh_token: String,

    /// How many seconds the refresh token is valid for.
    refresh_token_expires_in: Option<u32>,

    /// The authorized scope for the access and refresh tokens.
    scope: String,
    // This should always be "Bearer".
    // token_type: String, // TODO: parse and check this
}

/// The tokens returned from the Token Exchange part of the `auth` flow.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tokens {
    /// The new access token returned by the Oauth server. This can be used to call APIs.
    pub access_token: String,

    /// The expiry time for the `access_token`.
    pub expires_at: DateTime<chrono::Local>,

    /// The token used to get a new access token when the original access token expires.
    pub refresh_token: String,

    /// The expiry time for the `refresh_token`.
    pub refresh_token_expires_at: Option<DateTime<chrono::Local>>,

    /// The authorized scope for the access and refresh tokens.
    pub scope: String,

    /// DPoP nonce returned from the server, if applicable. Should be provided and sent to the
    /// server for the next request.
    pub dpop_nonce: Option<String>,
}

impl Tokens {
    /// Merges the `Tokens` data with a `RefreshResult`. The latter takes precedence.
    pub fn merge(&mut self, refresh_result: &RefreshResult) {
        self.access_token = refresh_result.access_token.clone();
        self.expires_at = refresh_result.expires_at;
        self.scope = refresh_result.scope.clone();
        self.dpop_nonce = refresh_result.dpop_nonce.clone();
    }
}

/// The (internal) response from the `refresh` flow, if successful.
#[derive(Deserialize, Debug)]
struct RefreshResponseSuccess {
    /// The new access token.
    access_token: String,

    /// How many seconds the `access_token` is valid for.
    expires_in: u32,

    /// The API scope that the `access_token` is valid for.
    scope: String,
    // Should always be "Bearer".
    // token_type: String, // TODO: parse and check this
}

/// JSON error returned from the server for bad refresh requests.
#[derive(Deserialize, Debug)]
struct RefreshResponseError {
    /// Short error code string.
    error: String,

    /// Longer explanation of what went wrong.
    error_description: String,
}

/// The token returned by the `refresh` flow.
#[derive(Serialize, Deserialize, Debug)]
pub struct RefreshResult {
    /// The new access token. Like the previous one, it can be used to call APIs.
    pub access_token: String,

    /// The expiry time for the new `access_token`.
    pub expires_at: DateTime<chrono::Local>,

    /// The authorized scope for the new `access_token`.
    pub scope: String,

    /// DPoP nonce returned by the server, if applicable.
    pub dpop_nonce: Option<String>,
}

/// Client info JSON struct, as created by the Google Cloud Console.
#[derive(Deserialize)]
pub struct ClientInfo {
    /// The real client info is nested under this field.
    pub installed: InstalledClientInfo,
}

/// Client info JSON sub-struct.
#[derive(Deserialize)]
pub struct InstalledClientInfo {
    /// Google Cloud client ID.
    pub client_id: String,

    /// Google Cloud project ID.
    pub project_id: String,

    /// URL of the auth server.
    pub auth_uri: String,

    /// URL of the token server.
    pub token_uri: String,

    /// URL of x509 certificates.
    pub auth_provider_x509_cert_url: String,

    /// Google Cloud client secret.
    pub client_secret: String,

    /// List of allowed redirect URLs.
    pub redirect_uris: Vec<String>,
}

/// The main oauth object. There are 2 main flows you might want to use it for: `auth` or
/// `refresh`.
pub struct Oauth2 {
    /// The client's configuration.
    cfg: Cfg,

    /// The cryptographically randomly-generated "code verifier" for the challenge-response process.
    code_verifier: Option<String>,

    /// The hashed and encoded `code_verifier`.
    code_challenge: Option<String>,

    /// The `state` parameter for the Oauth flow. Here used as a CSRF token.
    state: Option<String>,

    /// The `code` returned by the Oauth server.
    code: Option<String>,
}

impl Oauth2 {
    /// Creates a new `Oauth2` object.
    pub fn new(cfg: Cfg) -> Self {
        Oauth2 {
            cfg,
            code_verifier: None,
            code_challenge: None,
            state: None,
            code: None,
        }
    }

    /// The first step in the `auth` flow. Generates a URL for the user to open in their browser,
    /// and starts an http server to listen for the initial user authorization response.
    ///
    /// See
    /// <https://developers.google.com/identity/protocols/oauth2/native-app#step-2:-send-a-request-to-googles-oauth-2.0-server>.
    ///
    /// `await`ing the returned `Future` will block until the http server receives a response. The
    /// http server will shut down gracefully upon receiving its first response.
    pub fn auth_get_url_and_listen(
        &mut self,
    ) -> anyhow::Result<(String, impl Future<Output = anyhow::Result<AuthResponse>>)> {
        self.code_verifier = Some(create_code_verifier()?);
        self.code_challenge = Some(self.create_code_challenge()?);
        self.state = Some(create_code_verifier()?);
        Ok((
            self.get_auth_request_url()?,
            http_server::serve_async(
                self.cfg
                    .listen_port
                    .ok_or(anyhow::anyhow!("listen_port is None"))?,
            ),
        ))
    }

    /// The second step in the `auth` flow. Exchanges the `code` from the first step for a
    /// `access_token` and a `refresh_token`.
    ///
    /// See
    /// <https://developers.google.com/identity/protocols/oauth2/native-app#exchange-authorization-code>.
    pub async fn auth_exchange(&mut self, r: AuthResponse) -> anyhow::Result<reqwest::Response> {
        let self_state = self
            .state
            .as_ref()
            .ok_or(anyhow::anyhow!("state is None"))?;
        if &r.state != self_state {
            anyhow::bail!("state doesn't match: {} vs {}", r.state, self_state);
        }

        let cfg_scope = self
            .cfg
            .scope
            .as_ref()
            .ok_or(anyhow::anyhow!("scope is None"))?;
        if &r.scope != cfg_scope {
            anyhow::bail!("scope doesn't match: {} vs {}", r.scope, cfg_scope);
        }

        self.code = Some(r.code);

        let request = self.get_exchange_request()?;
        self.send_exchange_request(request).await
    }

    /// The third and final part of the `auth` flow. Handles the Token Exchange response.
    pub async fn auth_handle_exchange_response(
        &self,
        r: reqwest::Response,
    ) -> anyhow::Result<Tokens> {
        let dpop_nonce =
            try_get_dpop_nonce(&r).map_err(RefreshHandleResponseError::TryGetDpopNonce)?;

        if self.cfg.key_data.is_some() && dpop_nonce.is_none() {
            anyhow::bail!("we sent a DPoP in the request, but didn't receive a nonce back");
        }

        let j = r.json::<ExchangeResponse>().await?;

        let now = chrono::Local::now();
        let expires_in = Duration::from_secs(u64::from(j.expires_in) - 5u64);
        let refresh_token_expires_in = j
            .refresh_token_expires_in
            .map(|ei| Duration::from_secs(u64::from(ei) - 5u64));

        Ok(Tokens {
            access_token: j.access_token,
            expires_at: now + expires_in,
            refresh_token: j.refresh_token,
            refresh_token_expires_at: refresh_token_expires_in.map(|ei| now + ei),
            scope: j.scope,
            dpop_nonce,
        })
    }

    /// The first step of the `refresh` flow. Sends a request to the token server.
    ///
    /// See <https://developers.google.com/identity/protocols/oauth2/native-app#offline>.
    pub async fn refresh(&self) -> anyhow::Result<reqwest::Response> {
        let request = self.get_refresh_request()?;
        self.send_refresh_request(request).await
    }

    /// The second and final part of the `refresh` flow. Handles the refresh response.
    pub async fn refresh_handle_response(
        &self,
        resp: reqwest::Response,
    ) -> Result<RefreshResult, RefreshHandleResponseError> {
        let dpop_nonce =
            try_get_dpop_nonce(&resp).map_err(RefreshHandleResponseError::TryGetDpopNonce)?;

        let status = resp.status();
        if status.is_success() {
            let j = resp.json::<RefreshResponseSuccess>().await.map_err(|err| {
                RefreshHandleResponseError::JsonDecode(err, "RefreshResponseSuccess".to_string())
            })?;

            let now = chrono::Local::now();
            let expires_in = Duration::from_secs(u64::from(j.expires_in) - 5u64);

            if self.cfg.key_data.is_some() && dpop_nonce.is_none() {
                return Err(RefreshHandleResponseError::ExpectedNonce);
            }

            return Ok(RefreshResult {
                access_token: j.access_token,
                expires_at: now + expires_in,
                scope: j.scope,
                dpop_nonce,
            });
        }

        let status_code = status.as_u16();
        let canonical_reason_str = status.canonical_reason().unwrap_or("<unknown>").to_string();
        if status.is_client_error() {
            let j = resp.json::<RefreshResponseError>().await.map_err(|err| {
                RefreshHandleResponseError::JsonDecode(err, "RefreshResponseError".to_string())
            })?;

            return Err(if j.error == "use_dpop_nonce" {
                let dpop_nonce =
                    dpop_nonce.ok_or(RefreshHandleResponseError::UseDpopNonceButNoNonceGiven(
                        j.error_description.clone(),
                    ))?;
                RefreshHandleResponseError::UseDpopNonce {
                    error_description: j.error_description,
                    dpop_nonce,
                }
            } else {
                RefreshHandleResponseError::OtherClient(status_code, canonical_reason_str)
            });
        }

        Err(RefreshHandleResponseError::Server(
            status_code,
            canonical_reason_str,
        ))
    }

    /// Hashes and encodes the `code_verifier`. See
    /// https://developers.google.com/identity/protocols/oauth2/native-app#create-code-challenge.
    fn create_code_challenge(&self) -> anyhow::Result<String> {
        Ok(base64_url::encode(&Sha256::digest(
            self.code_verifier
                .as_ref()
                .ok_or(anyhow::anyhow!("code_verifier is None"))?,
        )))
    }

    /// Creates an auth request URL for the user to visit in their browser. See
    /// https://developers.google.com/identity/protocols/oauth2/native-app#create-code-challenge.
    fn get_auth_request_url(&self) -> anyhow::Result<String> {
        Ok(Url::parse_with_params(
            self.cfg
                .auth_server_url
                .as_ref()
                .ok_or(anyhow::anyhow!("auth_server_url is None"))?
                .as_str(),
            [
                ("client_id", self.cfg.client_id.as_str()),
                (
                    "redirect_uri",
                    format!(
                        "http://localhost:{}",
                        self.cfg
                            .listen_port
                            .ok_or(anyhow::anyhow!("listen_port is None"))?
                    )
                    .as_str(),
                ),
                ("response_type", "code"),
                (
                    "scope",
                    self.cfg
                        .scope
                        .as_ref()
                        .ok_or(anyhow::anyhow!("scope is None"))?
                        .as_str(),
                ),
                (
                    "code_challenge",
                    self.code_challenge
                        .as_ref()
                        .ok_or(anyhow::anyhow!("code_challenge is None"))?,
                ),
                ("code_challenge_method", "S256"),
                (
                    "state",
                    self.state
                        .as_ref()
                        .ok_or(anyhow::anyhow!("state is None"))?,
                ),
            ],
        )?
        .as_str()
        .to_string())
    }

    /// Creates an http request for the token exchange.
    fn get_exchange_request(&self) -> anyhow::Result<reqwest::RequestBuilder> {
        let code = self.code.as_ref().ok_or(anyhow::anyhow!("code is None"))?;
        let mut request_builder = reqwest::Client::new()
            .post(self.cfg.token_server_url.as_str())
            .form(&[
                ("client_id", self.cfg.client_id.as_str()),
                ("code", code),
                (
                    "code_verifier",
                    self.code_verifier
                        .as_ref()
                        .ok_or(anyhow::anyhow!("code_verifier is None"))?,
                ),
                ("grant_type", "authorization_code"),
                (
                    "redirect_uri",
                    format!(
                        "http://localhost:{}",
                        self.cfg
                            .listen_port
                            .ok_or(anyhow::anyhow!("listen_port is None"))?
                    )
                    .as_str(),
                ),
                ("client_secret", self.cfg.client_secret.as_str()),
            ]);
        if let Some(key_data) = self.cfg.key_data.as_ref() {
            let dpop = dpop::create_auth(key_data, code, &self.cfg.token_server_url)?;
            request_builder = request_builder.header("DPoP", dpop);
        }

        Ok(request_builder)
    }

    /// Sends the exchange request.
    async fn send_exchange_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::Response> {
        Ok(request.send().await?)
    }

    /// Creates a token refresh request.
    fn get_refresh_request(&self) -> anyhow::Result<reqwest::RequestBuilder> {
        let mut request_builder = reqwest::Client::new()
            .post(self.cfg.token_server_url.as_str())
            .form(&[
                ("client_id", self.cfg.client_id.as_str()),
                ("client_secret", self.cfg.client_secret.as_str()),
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    self.cfg
                        .refresh_token
                        .as_ref()
                        .ok_or(anyhow::anyhow!("refresh_token is None"))?,
                ),
            ]);
        if let Some(key_data) = self.cfg.key_data.as_ref() {
            let dpop = dpop::create_refresh(
                key_data,
                &self.cfg.token_server_url,
                self.cfg
                    .dpop_nonce
                    .as_ref()
                    .ok_or(anyhow::anyhow!("dpop_nonce is None"))?,
            )?;
            request_builder = request_builder.header("DPoP", dpop);
        }

        Ok(request_builder)
    }

    /// Sends the token refresh request.
    async fn send_refresh_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::Response> {
        Ok(request.send().await?)
    }
}

/// Returned error type for `refresh_handle_response()`.
#[derive(thiserror::Error, Debug)]
pub enum RefreshHandleResponseError {
    /// Wrapped error from `try_get_dpop_nonce()`.
    #[error("failed to try to get DPoP nonce header")]
    TryGetDpopNonce(#[source] anyhow::Error),

    /// Error decoding the server response as a given JSON type.
    #[error("failed to decode as JSON type {1}")]
    JsonDecode(#[source] reqwest::Error, String),

    /// Returned when we are using DPoP, but the server didn't give us a nonce.
    #[error("we sent a DPoP in the request, but didn't receive a nonce back")]
    ExpectedNonce,

    /// A `use_dpop_nonce` error returned from the server. This means that a DPoP nonce was
    /// required but not provided, or that the provided nonce was invalid. The correct response is
    /// to retry the request using the new `dpop_nonce` embedded in this error.
    #[error("use_dpop_nonce: {error_description}")]
    UseDpopNonce {
        error_description: String,
        dpop_nonce: String,
    },

    /// The server returned a `use_dpop_nonce` error, but didn't include a DPoP nonce in its
    /// header.
    #[error("use_dpop_nonce error returned, but without a DPoP nonce: {0}")]
    UseDpopNonceButNoNonceGiven(String),

    /// Any client error returned by the server except `use_dpop_nonce`.
    #[error("client error {0}: {1}")]
    OtherClient(u16, String),

    /// Any server error returned by the server.
    #[error("server error {0}: {1}")]
    Server(u16, String),
}

/// Generates a cryptographically-random string using an alphabet of
/// {[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"} for the challenge-response mechanism. See
/// https://developers.google.com/identity/protocols/oauth2/native-app#create-code-challenge.
fn create_code_verifier() -> anyhow::Result<String> {
    const ALPHABET_LEN: usize = 66;
    const ALPHABET: &[u8; ALPHABET_LEN] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    const CODE_VERIFIER_LEN: usize = 128;
    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    let mut verifier = [0; CODE_VERIFIER_LEN];
    for item in verifier.iter_mut().take(CODE_VERIFIER_LEN) {
        *item = ALPHABET[usize::try_from(rng.try_next_u32()?)? % ALPHABET_LEN];
    }
    Ok(from_utf8(&verifier)?.to_string())
}

/// Attempt to read a `DPoP-Nonce` header. If the header doesn't exist, `Ok(None)` is returned. If
/// the header does exist, but cannot be converted into a string, an `Err` result will be returned.
/// Otherwise, an `Ok(Some(String))` value will be returned containing the nonce.
fn try_get_dpop_nonce(resp: &reqwest::Response) -> anyhow::Result<Option<String>> {
    let dpop_nonce = resp.headers().get("DPoP-Nonce");
    match dpop_nonce {
        Some(nonce) => Ok(Some(nonce.to_str()?.to_string())),
        None => Ok(None),
    }
}
