# oauth2

Rust OAuth2 library for Google desktop applications.

This is not a comprehensive robust OAuth2 solution in general. It is
specifically for the Google flow for desktop applications, as documented
[here](https://developers.google.com/identity/protocols/oauth2/native-app).

For a more comprehensive solution, maybe check out
https://docs.rs/oauth2/latest/oauth2/.

[Docs](https://glennhartmann.github.io/oauth2/v0.0.3/oauth2/index.html)

_Disclaimer: This is a personal project. The views, code, and opinions
expressed here are my own and do not represent those of my current or past
employers._

## Status

Pretty rough. No tests, unhelpful errors, no server error handling to speak of.
This is a very early iteration and generally should not be used in its current
state.

## Creating OAuth2 Credentials

See [create-client README](doc/create-client/README.md).

## Subprojects

* [oauth2-cli](cli): A small CLI program to use the library. Can be used as an
  API example for the library.
* [oauth2-simple](simple): A wrapper library around the main `oauth2` library.
  Slightly simpler API, but less customizable.
