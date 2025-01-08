//! High-level [http auth](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) extractors for [axum](https://github.com/tokio-rs/axum)
//!
//! 🚨 This crate provides an alternative to `TypedHeader<Authorization<..>>` which you should probably [use](https://docs.rs/axum/latest/axum/struct.TypedHeader.html) instead. Take a look at the fantastic [axum-login](https://github.com/maxcountryman/axum-login) crate if your looking for more robust session management. I will continue to maintain this crate.
//!
//! # Usage
//!
//! Take a look at the following structures:
//!
//! - **Basic auth: [AuthBasic]**
//! - **Bearer auth: [AuthBearer]**
//!
//! If you need to implement custom errors (i.e., status codes and messages), use these:
//!
//! - Custom basic auth: [AuthBasicCustom]
//! - Custom bearer auth: [AuthBearerCustom]
//!
//! That's all there is to it! Check out the [repository](https://github.com/owez/axum-auth) for contributing or some more documentation.

#[cfg(not(any(feature = "auth-basic", feature = "auth-bearer")))]
compile_error!(r#"At least one feature must be enabled!"#);

#[cfg(feature = "auth-basic")]
mod auth_basic;
#[cfg(feature = "auth-bearer")]
mod auth_bearer;

#[cfg(feature = "auth-basic")]
pub use auth_basic::{AuthBasic, AuthBasicCustom};
#[cfg(feature = "auth-bearer")]
pub use auth_bearer::{AuthBearer, AuthBearerCustom};

use http::{header::AUTHORIZATION, request::Parts, StatusCode};

/// Rejection error used in the [AuthBasicCustom] and [AuthBearerCustom] extractors
pub type Rejection = (StatusCode, &'static str);

/// Default error status code used for the basic extractors
pub(crate) const ERR_DEFAULT: StatusCode = StatusCode::BAD_REQUEST;

/// The header is completely missing
pub(crate) const ERR_MISSING: &str = "`Authorization` header is missing";

/// The header has some invalid characters in it
pub(crate) const ERR_CHARS: &str = "`Authorization` header contains invalid characters";

/// The header couldn't be decoded properly for basic auth, might not have had a colon in the header
pub(crate) const ERR_DECODE: &str = "`Authorization` header could not be decoded";

/// The header was set as bearer authentication when we're expecting basic
pub(crate) const ERR_WRONG_BASIC: &str = "`Authorization` header must be for basic authentication";

/// The header was set as basic authentication when we're expecting bearer
pub(crate) const ERR_WRONG_BEARER: &str = "`Authorization` header must be a bearer token";

// NOTE: Never used as of axum 0.8.0, remove this block in >=0.9.0
// /// Helper trait for decoding [Parts] to a final extractor; this is the main interface into the decoding system
// pub(crate) trait DecodeRequestParts: Sized {
//     /// Decodes all provided [Parts] into a new instance of self, going through the entire decoding cycle
//     ///
//     /// To add custom errors here internally, set the `err_code` as something different
//     fn decode_request_parts(req: &mut Parts, err_code: StatusCode) -> Result<Self, Rejection>;
// }

/// Gets the auth header from [Parts] of the request or errors with [ERR_CHARS] or [ERR_MISSING] if wrong
pub(crate) fn get_header(parts: &mut Parts, err_code: StatusCode) -> Result<&str, Rejection> {
    parts
        .headers
        .get(AUTHORIZATION)
        .ok_or((err_code, ERR_MISSING))?
        .to_str()
        .map_err(|_| (err_code, ERR_CHARS))
}
