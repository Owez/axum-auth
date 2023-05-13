# Auth for axum

High-level [http auth](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) extractors for [axum](https://github.com/tokio-rs/axum)

🚨 This crate provides an alternative to `TypedHeader<Authorization<Bearer>>` and `TypedHeader<Authorization<Basic>>` which you should probably [use](https://docs.rs/axum/latest/axum/struct.TypedHeader.html) instead. Take a look at the fantastic [axum-login](https://github.com/maxcountryman/axum-login) crate if your looking for more complicated session management. I will continue to maintain this crate.

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
 
/// Takes basic auth details and shows a message
async fn handler(AuthBasic((id, password)): AuthBasic) -> String {
    if let Some(password) = password {
        format!("User '{}' with password '{}'", id, password)
    } else {
        format!("User '{}' without password", id)
    }
}
```

You can also define custom extractors, letting you return custom extractors, status codes, and messages to users if the auth fails. Check out the [crate documentation](https://docs.rs/axum-auth) for more in-depth information into how everything works!

## Installation

Simply place the following inside of your `Cargo.toml` file for axum 0.6:

```toml
[dependencies]
axum-auth = "0.4"
```

If you're still on axum 0.5, you can use the `0.3` version. You can also enable just basic/bearer auth via features. To enable just basic auth, you can add this to the `Cargo.toml` file instead:

```toml
[dependencies]
axum-auth = { version = "0.4", default-features = false, features = ["auth-basic"] }
```

## Security

Some essential security considerations to take into account are the following:

- This crate has not been audited by any security professionals. If you are willing to do or have already done an audit on this crate, please create an issue as it would help out enormously! 😊
- This crate purposefully does not limit the maximum length of headers arriving so please ensure your webserver configurations are set properly.

## Licensing

This project is dual-licensed under both the [MIT](https://github.com/Owez/argi/blob/master/LICENSE-MIT) and [Apache](https://github.com/Owez/argi/blob/master/LICENSE-APACHE), so feel free to use either at your discretion.
