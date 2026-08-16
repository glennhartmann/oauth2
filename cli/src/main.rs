use std::{fs::read_to_string, path::PathBuf};

use chrono::DateTime;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

/// Sample program to use OAuth2 authentication.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Output only the access token.
    #[arg(short, long, default_value_t = false)]
    terse: bool,

    /// Whether to output in regular human-readable text, or JSON.
    #[arg(value_enum, short, long, default_value_t = OutputMode::Text)]
    output_mode: OutputMode,

    /// Path to the JSON file from Google Cloud Console containing client info, including the
    /// client ID and client secret.
    #[arg(short, long, default_value = "./client_info.json")]
    client_info_path: PathBuf,

    #[command(subcommand)]
    command: Command,
}

/// CLI command.
#[derive(Subcommand, Debug)]
enum Command {
    /// Set up the initial authorization and get an access token and a refresh token.
    Init {
        /// Port for the local http server to listen on.
        #[arg(short, long, default_value_t = 42684)]
        listen_port: u16,

        /// The Oauth2 API Scope you want to authorize.
        #[arg(short, long)]
        scope: String,
    },

    /// Get a new access token given that you already have a refresh token.
    Refresh {
        /// Path to a JSON file containing token info. Should contain the same data in the same
        /// format as what `oauth2-cli -o json init` generates.
        #[arg(short, long, default_value = "./token.json")]
        tokens_path: PathBuf,
    },
}

/// Human-readable text or JSON output.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputMode {
    /// Human-readable text.
    Text,

    /// Structured JSON.
    Json,
}

/// Client info JSON struct, as created by the Google Cloud Console.
#[derive(Deserialize)]
struct ClientInfo {
    installed: InstalledClientInfo,
}

/// Client info JSON sub-struct.
#[derive(Deserialize)]
struct InstalledClientInfo {
    /// Google Cloud client ID.
    client_id: String,

    /// Google Cloud project ID.
    #[allow(dead_code)]
    project_id: String,

    /// URL of the auth server.
    auth_uri: String,

    /// URL of the token server.
    token_uri: String,

    /// URL of x509 certificates.
    #[allow(dead_code)]
    auth_provider_x509_cert_url: String,

    /// Google Cloud client secret.
    client_secret: String,

    // TODO: check that this includes localhost
    /// List of allowed redirect URLs.
    #[allow(dead_code)]
    redirect_uris: Vec<String>,
}

/// Output JSON struct containing tokens and associated metadata.
#[derive(Serialize, Deserialize, Debug)]
struct Tokens {
    /// OAuth2 API access token.
    access_token: String,

    /// Expiry date/time of `access_token`.
    expires_at: Option<DateTime<chrono::Local>>,

    /// OAuth2 refresh token.
    refresh_token: Option<String>,

    /// Expiry date/time of `refresh_token`.
    refresh_token_expires_at: Option<DateTime<chrono::Local>>,

    /// Authorized scope of tokens.
    scope: Option<String>,
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
    ) -> Self {
        if terse {
            Self {
                access_token,
                expires_at: None,
                refresh_token: None,
                refresh_token_expires_at: None,
                scope: None,
            }
        } else {
            Self {
                access_token,
                expires_at,
                refresh_token,
                refresh_token_expires_at,
                scope,
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let client_info =
        read_to_string(&args.client_info_path).expect("couldn't read from `client_info_path`");
    let client_info: ClientInfo = serde_json::from_str::<ClientInfo>(&client_info)
        .expect("couldn't parse `client_info` JSON");

    match &args.command {
        Command::Init { listen_port, scope } => init(&args, client_info, *listen_port, scope).await,
        Command::Refresh { tokens_path } => refresh(&args, client_info, tokens_path).await,
    };
}

/// Performs the initialization flow to create new `Tokens` data from a `ClientInfo`.
async fn init(args: &Args, client_info: ClientInfo, listen_port: u16, scope: &str) {
    let mut oa2 = oauth2::Oauth2::new(oauth2::Cfg {
        listen_port: Some(listen_port),
        client_id: client_info.installed.client_id,
        scope: Some(scope.to_string()),
        auth_server_url: Some(client_info.installed.auth_uri),
        token_server_url: client_info.installed.token_uri,
        client_secret: client_info.installed.client_secret,
        refresh_token: None,
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
                ))
                .expect("error serializing Tokens to JSON")
            );
        }
    };
}

/// Performs the refresh flow to get new `Tokens` data from a refresh token.
async fn refresh(args: &Args, client_info: ClientInfo, tokens_path: &PathBuf) {
    let tokens = read_to_string(tokens_path).expect("couldn't read from `tokens_path`");
    let tokens: Tokens = serde_json::from_str(&tokens).expect("couldn't parse tokens JSON");

    let refresh_token = tokens
        .refresh_token
        .expect("no refresh token found in JSON");

    let oa2 = oauth2::Oauth2::new(oauth2::Cfg {
        listen_port: None,
        client_id: client_info.installed.client_id,
        scope: None,
        auth_server_url: None,
        token_server_url: client_info.installed.token_uri,
        client_secret: client_info.installed.client_secret,
        refresh_token: Some(refresh_token.clone()),
    });

    // Get a new access token from a refresh token.
    let resp = oa2.refresh().await.expect("error in `refresh()`");
    let new_token_result = oa2
        .refresh_handle_response(resp)
        .await
        .expect("error in `refresh_handle_response()`");

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
                    Some(refresh_token),
                    tokens.refresh_token_expires_at,
                    Some(new_token_result.scope),
                ))
                .expect("error serializing Tokens to JSON")
            );
        }
    };
}
