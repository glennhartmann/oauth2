#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{File, exists, read_to_string},
    io::Write,
    path::Path,
    time::Duration,
};

use oauth2::{
    ClientInfo, Oauth2, RefreshHandleResponseError, Tokens,
    dpop::{KeyData, Keypair, KeypairPemPkcs8},
};

use bon::Builder;

const TOKENS_UNSET_ERROR_STR: &str = "`tokens` is unset. Did you run `init()`?";

/// Config struct for `Oauth2Simple::with_cfg()`. Using `Cfg::builder()` allows clients to start
/// with a default config and just override the parts they want (`scope` is required, though).
#[derive(Builder)]
pub struct Cfg<'a> {
    /// Path to a "client info" JSON file.
    #[builder(default = "./client_info.json")]
    pub client_info_path: &'a str,

    /// Path to a tokens JSON file.
    #[builder(default = "./token.json")]
    pub tokens_path: &'a str,

    /// Port for the http server to listen on.
    #[builder(default = 42684)]
    pub port: u16,

    /// OAuth2 API scope to authorize.
    pub scope: &'a str,

    /// Paths to public and private keys for use with DPoPs. If a files don't already exist at
    /// these paths, public and private keys will be generated and written there. DPoPs will
    /// automatically be used if this is specified.
    pub key_paths: Option<KeyPaths>,
}

/// Paths to public and private keys.
#[derive(Clone)]
pub struct KeyPaths {
    /// Path to a public key.
    pub public_key_path: String,

    /// Path to a private key.
    pub private_key_path: String,
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
        Self::with_cfg(Self::new_basic_cfg_builder(client_info_path, tokens_path, scope)?.build())
    }

    /// Creates a new instance, as in `init()`, but includes cryptographic key data used to sign
    /// DPoPs.
    pub fn new_with_dpop(
        client_info_path: &Path,
        tokens_path: &Path,
        scope: &str,
        key_paths: &KeyPaths,
    ) -> anyhow::Result<Self> {
        let builder = Self::new_basic_cfg_builder(client_info_path, tokens_path, scope)?;
        let builder = builder.key_paths(key_paths.clone());
        Self::with_cfg(builder.build())
    }

    /// Make a new instance with the given `Cfg`.
    pub fn with_cfg(cfg: Cfg) -> anyhow::Result<Self> {
        let client_info = read_to_string(cfg.client_info_path)?;
        let client_info: ClientInfo = serde_json::from_str(&client_info)?;

        // `cfg.tokens_path` may or may not exist yet. If it does, use its values, otherwise use
        // `None`.
        let (refresh_token, dpop_nonce, tokens) = if exists(cfg.tokens_path)? {
            let tokens = read_to_string(cfg.tokens_path)?;
            let tokens: Tokens = serde_json::from_str(&tokens)?;
            (
                Some(tokens.refresh_token.clone()),
                tokens.dpop_nonce.clone(),
                Some(tokens),
            )
        } else {
            (None, None, None)
        };

        let key_data = maybe_set_up_keys(cfg.key_paths.as_ref())?;

        Ok(Self {
            oauth2: Oauth2::new(oauth2::Cfg {
                listen_port: Some(cfg.port),
                client_id: client_info.installed.client_id,
                scope: Some(cfg.scope.to_string()),
                auth_server_url: Some(client_info.installed.auth_uri),
                token_server_url: client_info.installed.token_uri,
                client_secret: client_info.installed.client_secret,
                refresh_token,
                key_data,
                dpop_nonce,
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
        let new_token_result = self.oauth2.refresh_handle_response(resp).await;

        // DPoP nonces are short-lived, so we have to explicitly handle the possibility that our nonce
        // is expired. In such an event, the server will return a `use_dpop_nonce` error code with a
        // new nonce in a header, and then we can retry the request with the new nonce.
        let new_token_result =
            if let Err(RefreshHandleResponseError::UseDpopNonce { dpop_nonce, .. }) =
                new_token_result
            {
                // Retry with the new nonce.
                self.oauth2.set_dpop_nonce(&dpop_nonce);

                let resp = self.oauth2.refresh().await?;
                self.oauth2.refresh_handle_response(resp).await?
            } else {
                new_token_result?
            };

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

    /// Creates a `CfgBuilder` whose `client_info_path`, `tokens_path`, and `scope` are already
    /// set.
    fn new_basic_cfg_builder<'a>(
        client_info_path: &'a Path,
        tokens_path: &'a Path,
        scope: &'a str,
    ) -> anyhow::Result<
        CfgBuilder<
            'a,
            cfg_builder::SetScope<cfg_builder::SetTokensPath<cfg_builder::SetClientInfoPath>>,
        >,
    > {
        Ok(Cfg::builder()
            .client_info_path(
                client_info_path
                    .to_str()
                    .ok_or(anyhow::anyhow!("client_info_path is invalid"))?,
            )
            .tokens_path(
                tokens_path
                    .to_str()
                    .ok_or(anyhow::anyhow!("tokens_path is invalid"))?,
            )
            .scope(scope))
    }

    /// Write a `Tokens` struct out to JSON with correct permissions (on *nix systems).
    fn write_tokens(&self, tokens: &Tokens) -> anyhow::Result<()> {
        let js = serde_json::to_string_pretty(&tokens)?;
        write_file_private(&self.tokens_path, &js.into_bytes())
    }
}

/// Set up `KeyData` if `paths` is `Some`, otherwise return `None`. If `paths` points to files that
/// don't exist yet, keys will be generated and saved there.
fn maybe_set_up_keys(paths: Option<&KeyPaths>) -> anyhow::Result<Option<KeyData>> {
    Ok(if let Some(paths) = paths {
        Some(set_up_keys(paths)?)
    } else {
        None
    })
}

/// Set up `KeyData`. If `paths` points to files that don't exist yet, keys will be generated and
/// saved there.
fn set_up_keys(paths: &KeyPaths) -> anyhow::Result<KeyData> {
    match (
        exists(&paths.public_key_path)?,
        exists(&paths.private_key_path)?,
    ) {
        (false, false) => generate_keys(paths),
        (true, true) => read_keys(paths),
        _ => Err(anyhow::anyhow!(
            "only one of `public_key_path` and `private_key_path` exists. Either both or neither must exist"
        )),
    }
}

/// Generate a keypair for DPoP signing, save the keys in `paths`, and return the relevant
/// `KeyData`.
fn generate_keys(paths: &KeyPaths) -> anyhow::Result<KeyData> {
    let keypair = Keypair::generate()?;
    let keypair_pem_pkcs8: KeypairPemPkcs8 = (&keypair)
        .try_into()
        .map_err(|e| anyhow::anyhow!("failed to convert keypair into PEM PKCS#8: {:?}", e))?;

    write_file_private(
        &paths.public_key_path,
        &keypair_pem_pkcs8.public_key.into_bytes(),
    )?;
    write_file_private(
        &paths.private_key_path,
        &keypair_pem_pkcs8.private_key.to_string().into_bytes(),
    )?;

    Ok((&keypair).into())
}

/// Write a file, and, if on *nix, set the permission to 0600.
fn write_file_private(path: &str, contents: &[u8]) -> anyhow::Result<()> {
    let mut f = File::create(path)?;

    #[cfg(unix)]
    {
        let md = f.metadata()?;
        let mut perms = md.permissions();
        perms.set_mode(0o600);
        f.set_permissions(perms)?;
    }

    f.write_all(contents)?;

    Ok(())
}

/// Read keys from `paths` and extract the relevant `KeyData`. Assumes that files already exist at
/// `paths` (won't crash if they don't exist, but also won't generate a new keypair).
fn read_keys(paths: &KeyPaths) -> anyhow::Result<KeyData> {
    let public_key_pem_pkcs8 = read_to_string(&paths.public_key_path)?;
    let private_key_pem_pkcs8 = read_to_string(&paths.private_key_path)?;

    let keypair_pem_pkcs8 =
        KeypairPemPkcs8::new(public_key_pem_pkcs8, private_key_pem_pkcs8.into());
    let keypair: Keypair = (&keypair_pem_pkcs8)
        .try_into()
        .map_err(|e| anyhow::anyhow!("failed to convert KeypairPemPkcs8 into Keypair: {:?}", e))?;

    Ok((&keypair).into())
}
