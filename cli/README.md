# oauth2-cli

This is a small CLI project that demonstrates how to use the `oauth2` library.
It can also be used as a way for non-Rust applications to use the library.

[Rust Docs](https://glennhartmann.github.io/oauth2/cli/v0.0.3/oauth2_cli/index.html)

## Installing

```bash
cargo install \
  --git https://github.com/glennhartmann/oauth2.git \
  oauth2-cli
```

Or use [nix](https://nixos.org/).

## Basic Usage

`oauth2-cli` comes witih 2 commands: `init` and `refresh`.

`init` is used the first time you want to generate credentials, and includes a
step for the user to authorize the API usage.

`refresh` is for when you've already used `init`, but your original access
token has expired. It will generate a new access token from your refresh token.

If you plan to be able to refresh your initial access token, you will likely
want to save the `init` JSON output to a file:

```bash
oauth2-cli -o json \
  init --scope "${SCOPE}" \
  > token.json
```

Remember to store this file securely and ideally `chmod 0600` it, as it
contains sensitive credentials.

You'll also want to similarly store the JSON output of the `refresh` command
when that time comes.

For detailed usage, run `oauth2-cli --help`, `oauth2-cli init --help`, and
`oauth2-cli refresh --help`.

## Status

Like the `oauth2` library, this CLI should currently be considered a very early
and rough iteration, not generally meant for production use.

## Creating OAuth2 Credentials

`oauth2-cli` requires that you have a "client info" JSON file with your client
ID and client secret. See [create-client README](../doc/create-client/README.md)
for how to set one up.
