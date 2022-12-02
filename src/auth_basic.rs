//! Implementation of http basic authentication
//!
//! See [AuthBasic] for the most commonly-used data structure

use crate::{get_header, DecodeRequestParts, Rejection, ERR_DECODE, ERR_WRONG_BASIC};
use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use http::{request::Parts, StatusCode};

/// Basic authentication extractor, containing an identifier as well as an optional password
///
/// This is enabled via the `auth-basic` feature.
///
/// # Example
///
/// Though this structure can be used like any other [axum] extractor, we recommend this pattern:
///
/// ```no_run
/// use axum_auth::AuthBasic;
///
/// /// Takes basic auth details and shows a message
/// async fn handler(AuthBasic((id, password)): AuthBasic) -> String {
///     if let Some(password) = password {
///         format!("User '{}' with password '{}'", id, password)
///     } else {
///         format!("User '{}' without password", id)
///     }
/// }
/// ```
// TODO: errors
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBasic(pub (String, Option<String>));

#[async_trait]
impl<B> FromRequestParts<B> for AuthBasic
where
    B: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        Self::decode_request_parts(parts, StatusCode::BAD_REQUEST)
    }
}

impl DecodeRequestParts for AuthBasic {
    fn decode_request_parts(parts: &mut Parts, err_code: StatusCode) -> Result<Self, Rejection> {
        // Get authorization header
        let authorization = get_header(parts, err_code)?;

        // Check that its well-formed basic auth then decode and return
        let split = authorization.split_once(' ');
        match split {
            Some((name, contents)) if name == "Basic" => decode(contents, (err_code, ERR_DECODE)),
            _ => Err((err_code, ERR_WRONG_BASIC)),
        }
    }
}

/// Decodes the two parts of basic auth using the colon
fn decode(
    input: &str,
    err: (StatusCode, &'static str),
) -> Result<AuthBasic, (StatusCode, &'static str)> {
    // Decode from base64 into a string
    let decoded = base64::decode(input).map_err(|_| err)?;
    let decoded = String::from_utf8(decoded).map_err(|_| err)?;

    // Return depending on if password is present
    Ok(AuthBasic(
        if let Some((id, password)) = decoded.split_once(':') {
            (id.to_string(), Some(password.to_string()))
        } else {
            (decoded, None)
        },
    ))
}
