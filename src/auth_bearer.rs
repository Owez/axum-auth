//! Implementation of http bearer authentication
//!
//! See [AuthBearer] for the most commonly-used data structure

use crate::{DecodeRequestParts, Rejection, ERR_CHARS, ERR_MISSING, ERR_WRONG_BEARER};
use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use http::{header::AUTHORIZATION, request::Parts, StatusCode};

/// Bearer token extractor which contains the innards of a bearer header as a string
///
/// This is enabled via the `auth-bearer` feature.
///
/// # Example
///
/// This structure can be used like any other [axum] extractor:
///
/// ```no_run
/// use axum_auth::AuthBearer;
///
/// /// Handler for a typical [axum] route, takes a `token` and returns it
/// async fn handler(AuthBearer(token): AuthBearer) -> String {
///     format!("Found a bearer token: {}", token)
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBearer(pub String);

#[async_trait]
impl<B> FromRequestParts<B> for AuthBearer
where
    B: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(req: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        Self::decode_request_parts(req, StatusCode::BAD_REQUEST)
    }
}

impl DecodeRequestParts for AuthBearer {
    fn decode_request_parts(req: &mut Parts, err_code: StatusCode) -> Result<Self, Rejection> {
        // Get authorization header
        let authorization = req
            .headers
            .get(AUTHORIZATION)
            .ok_or((err_code, ERR_MISSING))?
            .to_str()
            .map_err(|_| (err_code, ERR_CHARS))?;

        // Check that its a well-formed bearer and return
        let split = authorization.split_once(' ');
        match split {
            Some((name, contents)) if name == "Bearer" => Ok(Self(contents.to_string())),
            _ => Err((err_code, ERR_WRONG_BEARER)),
        }
    }
}
