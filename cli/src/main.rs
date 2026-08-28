#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{File, read_to_string},
    io::Write,
    path::PathBuf,
};

use oauth2::{
    ClientInfo,
    dpop::{KeyData, Keypair, KeypairPemPkcs8},
};

use anyhow::Context;
use chrono::DateTime;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

/// Sample program to use OAuth2 authentication.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
}

/// CLI command.
#[derive(Subcommand, Debug)]
enum Command {
    /// Generates a keypair for use with DPoP for extra security.
    GenerateDpopKeys {
        /// Path to write public key to.
        #[arg(short, long, default_value = "./public_key.pem")]
        public_key_path: PathBuf,

        /// Path to write private key to.
        #[arg(short = 'k', long, default_value = "./private_key.pem")]
        private_key_path: PathBuf,
    },

    /// Set up the initial authorization and get an access token and a refresh token.
    Init {
        /// Port for the local http server to listen on.
        #[arg(short, long, default_value_t = 42684)]
        listen_port: u16,

        /// The Oauth2 API Scope you want to authorize.
        #[arg(short, long)]
        scope: String,

        /// Args that are common to both `init` and `refresh` subcommands.
        #[command(flatten)]
        init_refresh_args: InitRefreshArgs,
    },

    /// Get a new access token given that you already have a refresh token.
    Refresh {
        /// Path to a JSON file containing token info. Should contain the same data in the same
        /// format as what `oauth2-cli -o json init` generates.
        #[arg(short, long, default_value = "./token.json")]
        tokens_path: PathBuf,

        /// Args that are common to both `init` and `refresh` subcommands.
        #[command(flatten)]
        init_refresh_args: InitRefreshArgs,
    },
}

/// Args that are common to both `init` and `refresh` subcommands.
#[derive(Args, Debug)]
struct InitRefreshArgs {
    /// Output only the access token.
    #[arg(short = 'T', long, default_value_t = false)]
    terse: bool,

    /// Whether to output in regular human-readable text, or JSON.
    #[arg(value_enum, short, long, default_value_t = OutputMode::Text)]
    output_mode: OutputMode,

    /// Path to the JSON file from Google Cloud Console containing client info, including the
    /// client ID and client secret.
    #[arg(short, long, default_value = "./client_info.json")]
    client_info_path: PathBuf,

    /// Path of public key. If both this and --private-key-path are specified, we'll use DPoP for
    /// extra security.
    #[arg(short, long)]
    public_key_path: Option<PathBuf>,

    /// Path of private key. If both this and --public-key-path are specified, we'll use DPoP for
    /// extra security.
    #[arg(short = 'k', long)]
    private_key_path: Option<PathBuf>,
}

/// Human-readable text or JSON output.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputMode {
    /// Human-readable text.
    Text,

    /// Structured JSON.
    Json,
}

/// Output JSON struct containing tokens and associated metadata.
#[derive(Serialize, Deserialize, Debug)]
struct Tokens {
    /// OAuth2 API access token.
    access_token: String,

    /// Expiry date/time of `access_token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<chrono::Local>>,

    /// OAuth2 refresh token.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,

    /// Expiry date/time of `refresh_token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_expires_at: Option<DateTime<chrono::Local>>,

    /// Authorized scope of tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    /// The latest nonce returned by the server, to be used in the next DPoP, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_nonce: Option<String>,
}

impl Tokens {
    /// Creates a new `Tokens` struct.
    fn new(
        terse: bool,
        access_token: String,
        expires_at: Option<DateTime<chrono::Local>>,
        refresh_token: Option<String>,
        refresh_token_expires_at: Option<DateTime<chrono::Local>>,
        scope: Option<String>,
        dpop_nonce: Option<String>,
    ) -> Self {
        if terse {
            Self {
                access_token,
                expires_at: None,
                refresh_token: None,
                refresh_token_expires_at: None,
                scope: None,
                dpop_nonce: None,
            }
        } else {
            Self {
                access_token,
                expires_at,
                refresh_token,
                refresh_token_expires_at,
                scope,
                dpop_nonce,
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match &args.command {
        Command::GenerateDpopKeys {
            public_key_path,
            private_key_path,
        } => generate_dpop_keys(public_key_path, private_key_path),
        Command::Init {
            listen_port,
            scope,
            init_refresh_args,
        } => init(*listen_port, scope, init_refresh_args).await,
        Command::Refresh {
            tokens_path,
            init_refresh_args,
        } => refresh(tokens_path, init_refresh_args).await,
    };
}

/// Generates a DPoP cryptographic keypair.
fn generate_dpop_keys(public_key_path: &PathBuf, private_key_path: &PathBuf) {
    let keypair = Keypair::generate().expect("failed to generate keypair");
    let keypair_pem_pkcs8: KeypairPemPkcs8 = (&keypair)
        .try_into()
        .expect("failed to convert keypair into PEM PKCS#8");

    write_file_private(public_key_path, &keypair_pem_pkcs8.public_key.into_bytes())
        .expect("failed to write public key file");
    write_file_private(
        private_key_path,
        &keypair_pem_pkcs8.private_key.to_string().into_bytes(),
    )
    .expect("failed to write private key file");
}

/// Write a file, and, if on *nix, set the permission to 0600.
fn write_file_private(path: &PathBuf, contents: &[u8]) -> anyhow::Result<()> {
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

/// Performs the initialization flow to create new `Tokens` data from an `oauth2::ClientInfo`.
async fn init(listen_port: u16, scope: &str, args: &InitRefreshArgs) {
    let client_info = read_client_info(&args.client_info_path).expect("couldn't read client info");
    let key_data = key_data_from_paths(
        args.public_key_path.as_ref(),
        args.private_key_path.as_ref(),
    )
    .expect("failure in `key_data_from_paths()`");

    let mut oa2 = oauth2::Oauth2::new(oauth2::Cfg {
        listen_port: Some(listen_port),
        client_id: client_info.installed.client_id,
        scope: Some(scope.to_string()),
        auth_server_url: Some(client_info.installed.auth_uri),
        token_server_url: client_info.installed.token_uri,
        client_secret: client_info.installed.client_secret,
        refresh_token: None,
        key_data,
        dpop_nonce: None,
    });

    // Generate a URL that we can show the user, and start up an HTTP server.
    let (url, http_server_future) = oa2
        .auth_get_url_and_listen()
        .expect("error in `auth_get_url_and_listen()`");
    eprintln!("Open {} in your browser.", url);
    eprintln!();

    // Block until the user clicks on the link and goes through the authorization flow in their
    // browser. Once they do, their browser will redirect to our local HTTP server's URL, which
    // will resolve the `Future`.
    let http_server_result = http_server_future
        .await
        .expect("error awaiting http_server_future");

    // Exchange `http_server_result` for an access token and a refresh token.
    let exchange_response = oa2
        .auth_exchange(http_server_result)
        .await
        .expect("error in `auth_exchange()`");
    let token_result = oa2
        .auth_handle_exchange_response(exchange_response)
        .await
        .expect("error in `auth_handle_exchange_response()`");

    // Print the result to stdout.
    match args.output_mode {
        OutputMode::Text => {
            println!("access_token: {}", token_result.access_token);
            if !args.terse {
                println!("expires_at: {}", token_result.expires_at);
            }
            println!("refresh_token: {}", token_result.refresh_token);
            if !args.terse {
                if let Some(rtea) = token_result.refresh_token_expires_at {
                    println!("refresh_token_expires_at: {}", rtea);
                }
                println!("scope: {}", token_result.scope);
            }
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Tokens::new(
                    args.terse,
                    token_result.access_token,
                    Some(token_result.expires_at),
                    Some(token_result.refresh_token),
                    token_result.refresh_token_expires_at,
                    Some(token_result.scope),
                    token_result.dpop_nonce,
                ))
                .expect("error serializing Tokens to JSON")
            );
        }
    };
}

/// Read client info from disk and parse it as a `ClientInfo` JSON struct.
fn read_client_info(path: &PathBuf) -> anyhow::Result<ClientInfo> {
    let client_info = read_to_string(path).expect("couldn't read from `client_info_path`");
    let client_info: ClientInfo =
        serde_json::from_str(&client_info).expect("couldn't parse `client_info` JSON");
    Ok(client_info)
}

/// Performs the refresh flow to get new `Tokens` data from a refresh token.
async fn refresh(tokens_path: &PathBuf, args: &InitRefreshArgs) {
    let client_info = read_client_info(&args.client_info_path).expect("couldn't read client info");

    let tokens = read_to_string(tokens_path).expect("couldn't read from `tokens_path`");
    let tokens: oauth2::Tokens = serde_json::from_str(&tokens).expect("couldn't parse tokens JSON");

    let key_data = key_data_from_paths(
        args.public_key_path.as_ref(),
        args.private_key_path.as_ref(),
    )
    .expect("failure in `key_data_from_paths()`");

    let mut oa2 = oauth2::Oauth2::new(oauth2::Cfg {
        listen_port: None,
        client_id: client_info.installed.client_id,
        scope: None,
        auth_server_url: None,
        token_server_url: client_info.installed.token_uri,
        client_secret: client_info.installed.client_secret,
        refresh_token: Some(tokens.refresh_token.clone()),
        key_data,
        dpop_nonce: tokens.dpop_nonce,
    });

    // Get a new access token from a refresh token.
    let resp = oa2.refresh().await.expect("error in `refresh()`");
    let new_token_result = oa2.refresh_handle_response(resp).await;

    // DPoP nonces are short-lived, so we have to explicitly handle the possibility that our nonce
    // is expired. In such an event, the server will return a `use_dpop_nonce` error code with a
    // new nonce in a header, and then we can retry the request with the new nonce.
    let new_token_result = match new_token_result {
        Ok(result) => result,
        Err(oauth2::RefreshHandleResponseError::UseDpopNonce {
            error_description,
            dpop_nonce,
        }) => {
            eprintln!(
                "got `use_dpop_nonce` error from server ('{}'), retrying with new nonce...",
                error_description
            );

            // Retry with the new nonce.
            oa2.set_dpop_nonce(&dpop_nonce);

            let resp = oa2.refresh().await.expect("error in `refresh()`");
            oa2.refresh_handle_response(resp)
                .await
                .expect("error after retrying with new dpop nonce")
        }
        _ => new_token_result.expect("error in `refresh_handle_response()`"),
    };

    // Print the result to stdout.
    match args.output_mode {
        OutputMode::Text => {
            println!("access_token: {}", new_token_result.access_token);
            if !args.terse {
                println!("expires_at: {}", new_token_result.expires_at);
                println!("scope: {}", new_token_result.scope);
            }
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Tokens::new(
                    args.terse,
                    new_token_result.access_token,
                    Some(new_token_result.expires_at),
                    Some(tokens.refresh_token),
                    tokens.refresh_token_expires_at,
                    Some(new_token_result.scope),
                    new_token_result.dpop_nonce,
                ))
                .expect("error serializing Tokens to JSON")
            );
        }
    };
}

/// Read files (if `Some`) and parse them as cryptographic keys.
fn key_data_from_paths(
    public_key_path: Option<&PathBuf>,
    private_key_path: Option<&PathBuf>,
) -> anyhow::Result<Option<KeyData>> {
    if let (Some(public_key_path), Some(private_key_path)) = (public_key_path, private_key_path) {
        let public_key_pem_pkcs8 =
            read_to_string(public_key_path).context("couldn't read from `public_key_path`")?;
        let private_key_pem_pkcs8 =
            read_to_string(private_key_path).context("couldn't read from `private_key_path`")?;

        let keypair_pem_pkcs8 =
            KeypairPemPkcs8::new(public_key_pem_pkcs8, private_key_pem_pkcs8.into());
        let keypair: Keypair = (&keypair_pem_pkcs8)
            .try_into()
            .expect("failed to convert KeypairPemPkcs8 into Keypair");
        Ok(Some((&keypair).into()))
    } else if public_key_path.is_some() || private_key_path.is_some() {
        Err(anyhow::anyhow!(
            "only one of --public-key-path and --private-key-path was provided"
        ))
    } else {
        Ok(None)
    }
}
