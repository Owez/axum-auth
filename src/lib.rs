//! High-level [http auth](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) extractors for [axum](https://github.com/tokio-rs/axum)
//!
//! # Usage
//!
//! Check out the following structures for more item-level documentation:
//!
//! - Basic auth: [AuthBasic]
//! - Bearer auth: [AuthBearer]
//!
//! That's all there is to it!

#[cfg(not(any(feature="auth-basic", feature="auth-bearer")))]
compile_error!(r#"At least one feature must be enabled!"#);

#[cfg(feature="auth-basic")] mod auth_basic;
#[cfg(feature="auth-bearer")] mod auth_bearer;

#[cfg(feature="auth-basic")] pub use auth_basic::AuthBasic;
#[cfg(feature="auth-bearer")] pub use auth_bearer::AuthBearer;