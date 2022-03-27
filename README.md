# Axum Auth

High-level [http auth](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) extractors for [axum](https://github.com/tokio-rs/axum)

## Usage

Bearer Authentication:

```rust
use axum_auth::AuthBearer;
 
/// Handler for a typical axum route, takes a `token` and returns it
async fn handler(AuthBearer(token): AuthBearer) -> String {
    format!("Found a bearer token: {}", token)
}
```

Basic Authentication:

```rust
use axum_auth::AuthBasic;
 
/// Handler for a typical axum route, takes a `token` and returns it
async fn handler(AuthBasic((id, password)): AuthBasic) -> String {
    if let Some(password) = password {
        format!("User '{}' with password '{}'", id, password)
    } else {
        format!("User '{}' without password", id)
    }
}
```

Check out the [crate documentation](https://docs.rs/axum-auth) for more in-depth information into how both of these methods work!

## Installation

Simply place the following inside of your `Cargo.toml` file:

```toml
[dependencies]
axum-auth = "0.1"
```

## Security

Some essential security considerations to take into account are the following:

- This crate has not been audited by any security professionals. If you are willing to do or have already done an audit on this crate, please create an issue as it would help out enormously! 😊
- This crate purposefully does not limit the maximum length of headers arriving so please ensure your webserver configurations are set properly.

## Licensing

This project is dual-licensed under both the [MIT](https://github.com/Owez/argi/blob/master/LICENSE-MIT) and [Apache](https://github.com/Owez/argi/blob/master/LICENSE-APACHE), so feel free to use either at your discretion.
