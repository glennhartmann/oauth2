#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{File, exists, read_to_string},
    io::Write,
    path::Path,
    time::Duration,
};

use oauth2::{ClientInfo, Oauth2, Tokens};

const TOKENS_UNSET_ERROR_STR: &str = "`tokens` is unset. Did you run `init()`?";

/// Config struct for `Oauth2Simple::with_cfg()`.
pub struct Cfg<'a> {
    /// Path to a "client info" JSON file.
    pub client_info_path: &'a str,

    /// Path to a tokens JSON file.
    pub tokens_path: &'a str,

    /// Port for the http server to listen on.
    pub port: u16,

    /// OAuth2 API scope to authorize.
    pub scope: &'a str,
}

impl<'a> Cfg<'a> {
    /// Merge a `Cfg` with a `CfgOverride`. The latter takes precedence.
    fn merge(self, other: &CfgOverride<'a>) -> Self {
        Self {
            client_info_path: other.client_info_path.unwrap_or(self.client_info_path),
            tokens_path: other.tokens_path.unwrap_or(self.tokens_path),
            port: other.port.unwrap_or(self.port),
            scope: other.scope,
        }
    }
}

/// Default `Cfg` values. Typically a client creates a `CfgOverride` with only certain fields set
/// to `Some` values, then calls `DEFAULT_CFG.merge()` on their `CfgOverride` to get a full `Cfg`
/// instance they can use.
pub const DEFAULT_CFG: Cfg = Cfg {
    client_info_path: "./client_info.json",
    tokens_path: "./token.json",
    port: 42684,
    scope: "",
};

/// `Cfg` struct, but with some `Option` values. The idea is that `CfgOverride` can have only
/// certain values filled in, and then use `Cfg::merge()` to override only those values of the
/// `Cfg` instance.
pub struct CfgOverride<'a> {
    /// Path to a "client info" JSON file.
    pub client_info_path: Option<&'a str>,

    /// Path to a tokens JSON file.
    pub tokens_path: Option<&'a str>,

    /// Port for the http server to listen on.
    pub port: Option<u16>,

    /// OAuth2 API scope to authorize.
    pub scope: &'a str,
}

/// Main struct for this library. Wraps an `oauth2::Oauth2`.
pub struct Oauth2Simple {
    /// The underlying `oauth2::Oauth2` struct with the actual logic.
    oauth2: Oauth2,

    /// Path to a tokens JSON file.
    tokens_path: String,

    /// Access and refresh token data.
    tokens: Option<Tokens>,
}

impl Oauth2Simple {
    /// Create a new instance. The `tokens_path` can point at a file that doesn't exist yet - one
    /// will be created when calling `init()`. `refresh()` should only be called if `tokens_path`
    /// already exists or after `init()` is called.
    pub fn new(client_info_path: &Path, tokens_path: &Path, scope: &str) -> anyhow::Result<Self> {
        let cfgo = CfgOverride {
            client_info_path: Some(
                client_info_path
                    .to_str()
                    .ok_or(anyhow::anyhow!("client_info_path is invalid"))?,
            ),
            tokens_path: Some(
                tokens_path
                    .to_str()
                    .ok_or(anyhow::anyhow!("tokens_path is invalid"))?,
            ),
            port: None,
            scope,
        };
        Self::from_default(&cfgo)
    }

    /// Make a new instance from `DEFAULT_CFG`, but with given values overridden from `cfgo`.
    pub fn from_default(cfgo: &CfgOverride) -> anyhow::Result<Self> {
        Self::with_cfg(DEFAULT_CFG.merge(cfgo))
    }

    /// Make a new instance with the given `Cfg`.
    pub fn with_cfg(cfg: Cfg) -> anyhow::Result<Self> {
        let client_info = read_to_string(cfg.client_info_path)?;
        let client_info: ClientInfo = serde_json::from_str(&client_info)?;

        // `cfg.tokens_path` may or may not exist yet. If it does, use its values, otherwise use
        // `None`.
        let (refresh_token, tokens) = if let Ok(e) = exists(cfg.tokens_path)
            && e
        {
            let tokens = read_to_string(cfg.tokens_path)?;
            let tokens: Tokens = serde_json::from_str(&tokens)?;
            (Some(tokens.refresh_token.clone()), Some(tokens))
        } else {
            (None, None)
        };

        Ok(Self {
            oauth2: Oauth2::new(oauth2::Cfg {
                listen_port: Some(cfg.port),
                client_id: client_info.installed.client_id,
                scope: Some(cfg.scope.to_string()),
                auth_server_url: Some(client_info.installed.auth_uri),
                token_server_url: client_info.installed.token_uri,
                client_secret: client_info.installed.client_secret,
                refresh_token,
            }),
            tokens_path: cfg.tokens_path.to_string(),
            tokens,
        })
    }

    /// Performs the initialization flow to create new `oauth2::Tokens` data from an
    /// `oauth2::ClientInfo`. Results are returned and also written to `tokens_path`.
    pub async fn init(&mut self) -> anyhow::Result<Tokens> {
        // Generate a URL that we can show the user, and start up an HTTP server.
        let (url, http_server_future) = self.oauth2.auth_get_url_and_listen()?;
        eprintln!("Open {} in your browser.", url);
        eprintln!();

        // Block until the user clicks on the link and goes through the authorization flow in their
        // browser. Once they do, their browser will redirect to our local HTTP server's URL, which
        // will resolve the `Future`.
        let http_server_result = http_server_future.await?;

        // Exchange `http_server_result` for an access token and a refresh token.
        let exchange_response = self.oauth2.auth_exchange(http_server_result).await?;
        let token_result = self
            .oauth2
            .auth_handle_exchange_response(exchange_response)
            .await?;

        // Update our internal state with the new tokens.
        self.tokens = Some(token_result.clone());

        // Write the result out to `tokens_path`.
        self.write_tokens(&token_result)?;

        Ok(token_result)
    }

    /// Performs the refresh flow to get new `Tokens` data from a refresh token. Must only be
    /// called if the `tokens_path` value in the `Cfg` pointed to a pre-existing file at the time
    /// of the `Oauth2Simple` construction, or if `init()` has already been called on this
    /// instance. Results are returned and also written to `tokens_path`.
    pub async fn refresh(&mut self) -> anyhow::Result<Tokens> {
        // Get a new access token from a refresh token.
        let resp = self.oauth2.refresh().await?;
        let new_token_result = self.oauth2.refresh_handle_response(resp).await?;

        // Write the new data back into `self.tokens`
        let tokens = self
            .tokens
            .as_mut()
            .ok_or(anyhow::anyhow!(TOKENS_UNSET_ERROR_STR))?;
        tokens.merge(&new_token_result);

        // Have to redo this to get an immutable ref, otherwise we can't call `write_tokens()`.
        // Annoying, but that's Rust for you.
        let tokens = self
            .tokens
            .as_ref()
            .ok_or(anyhow::anyhow!(TOKENS_UNSET_ERROR_STR))?;

        // Write the result out to `tokens_path`.
        self.write_tokens(tokens)?;

        Ok(tokens.clone())
    }

    /// Performs the initialization flow as in `init()`, but only if the file at `tokens_path`
    /// existed upon `Oauth2Simple` initialization.
    pub async fn init_if_needed(&mut self) -> anyhow::Result<Tokens> {
        if let Some(tokens) = self.tokens.as_ref() {
            Ok(tokens.clone())
        } else {
            self.init().await
        }
    }

    /// Refreshes the access token as in `refresh()`, but only if the previous access token has
    /// expired or is getting close to expiring. Fails if there was no previous access token.
    pub async fn refresh_if_needed(&mut self) -> anyhow::Result<Tokens> {
        let tokens = self
            .tokens
            .as_ref()
            .ok_or(anyhow::anyhow!(TOKENS_UNSET_ERROR_STR))?;
        if tokens.expires_at > chrono::Local::now() - Duration::from_mins(5) {
            Ok(tokens.clone())
        } else {
            // TODO: handle the case of the refresh token having already expired.
            self.refresh().await
        }
    }

    /// Gets an access token. If there was no existing access token, it does this by running the
    /// `init()` flow. If the previous access token expired already, then it instead runs the
    /// `refresh()` flow. Otherwise, it just returns the existing not-yet-expired token.
    pub async fn get_token(&mut self) -> anyhow::Result<Tokens> {
        self.init_if_needed().await?;
        self.refresh_if_needed().await
    }

    /// Write a `Tokens` struct out to JSON with correct permissions (on *nix systems).
    fn write_tokens(&self, tokens: &Tokens) -> anyhow::Result<()> {
        let js = serde_json::to_string_pretty(&tokens)?;

        let mut f = File::create(&self.tokens_path)?;

        #[cfg(unix)]
        {
            let md = f.metadata()?;
            let mut perms = md.permissions();
            perms.set_mode(0o600);
            f.set_permissions(perms)?;
        }

        f.write_all(&js.into_bytes())?;

        Ok(())
    }
}
