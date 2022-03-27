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

use axum::async_trait;
use axum::extract::{FromRequest, RequestParts};
use http::{header::AUTHORIZATION, StatusCode};

/// Basic authentication extractor, containing an identifier as well as an optional password
///
/// # Example
///
/// Though this structure can be used like any other [axum] extractor, we recommend this pattern:
///
/// ```no_run
/// /// Handler for a typical [axum] route, takes a `token` and returns it
/// fn handler(AuthBasic((id, password)): AuthBasic) -> String {
///     if let Some(password) = password {
///         format!("User '{}' with password '{}'", id, password)
///     } else {
///         format!("User '{}' without password", id)
///     }
/// }
/// ```
///
/// # Errors
///
/// This extractor will give off a few different errors depending on what when wrong with a request's header. These errors include:
///
/// - COMING SOON
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBasic(pub (String, Option<String>));

// TODO: impl FromRequest

/// Bearer token extractor which contains the innards of a bearer header as a string
///
/// # Example
///
/// This structure can be used like any other [axum] extractor:
///
/// ```no_run
/// use axum_auth::AuthBearer;
///
/// /// Handler for a typical [axum] route, takes a `token` and returns it
/// fn handler(AuthBearer(token): AuthBearer) -> String {
///     format!("Found a bearer token: {}", token)
/// }
/// ```
///
/// # Errors
///
/// This extractor will give off a few different errors depending on what when wrong with a request's bearer token. These errors include:
///
/// - Completely missing header, returning:
/// ```none
/// `Authorization\` header is missing
/// ```
/// - Header with invalid chars (i.e. non-ASCII), returning:
/// ```none
/// `Authorization` header contains invalid characters
/// ```
/// - The type of authorization wasn't a bearer token, returning:
/// ```none
/// `Authorization` header must be a bearer token
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBearer(pub String);

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
