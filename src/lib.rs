//! Simple utility library for high-level basic/bearer auth in axum
//!
//! ## Installation
//!
//! Simply place the following inside of your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! axum-auth = "0.1"
//! ```
//!
//! ## Usage
//!
//! See [AuthBasic] and [AuthBearer] for documentation on how either work!

use axum::async_trait;
use axum::extract::{FromRequest, RequestParts};
use http::{header::AUTHORIZATION, StatusCode};

// TODO: basic authentication

/// **Bearer token** extractor which contains the innards of a bearer header as a string
///
/// # Example
///
/// This structure can be used like any other axum extractor:
///
/// ```no_run
/// use axum_auth::AuthBearer;
///
/// /// Handler for a typical axum route, takes a `token` and returns it
/// fn handler(AuthBearer(token): AuthBearer) -> String {
///     format!("Found a bearer token: {}", token)
/// }
/// ```
///
/// # Erroring
///
/// This extractor will give off a few different errors depending on what when wrong with a request's bearer token. These errors include:
///
/// - Completely missing header, returning: *`Authorization\` header is missing*
/// - Header with invalid chars (i.e. non-ASCII), returning: *`Authorization` header contains invalid characters*
/// - The type of authorization wasn't a bearer token, returning: *`Authorization` header must be a bearer token*
pub struct AuthBearer(String);

#[async_trait]
impl<B> FromRequest<B> for AuthBearer
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> std::result::Result<Self, Self::Rejection> {
        // Get authorisation header
        let authorisation = req
            .headers()
            .and_then(|headers| headers.get(AUTHORIZATION))
            .ok_or((StatusCode::BAD_REQUEST, "`Authorization` header is missing"))?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "`Authorization` header contains invalid characters",
                )
            })?;

        // Check that its a well-formed bearer and return
        let split = authorisation.split_once(' ');
        match split {
            Some((bearer, contents)) if bearer == "Bearer" && contents.len() == 44 => {
                Ok(Self(contents.to_string()))
            }
            _ => Err((
                StatusCode::BAD_REQUEST,
                "`Authorization` header must be a bearer token",
            )),
        }
    }
}
