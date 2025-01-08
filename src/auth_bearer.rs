//! Implementation of http bearer authentication
//!
//! See [AuthBearer] for the most commonly-used data structure

use crate::{Rejection, ERR_CHARS, ERR_DEFAULT, ERR_MISSING, ERR_WRONG_BEARER};
use axum_core::extract::FromRequestParts;
use http::{header::AUTHORIZATION, request::Parts, StatusCode};

/// Bearer token extractor which contains the innards of a bearer header as a string
///
/// This is enabled via the `auth-bearer` feature
///
/// # Example
///
/// This structure can be used like any other axum extractor:
///
/// ```no_run
/// use axum_auth::AuthBearer;
///
/// /// Handler for a typical [axum] route, takes a `token` and returns it
/// async fn handler(AuthBearer(token): AuthBearer) -> String {
///     format!("Found a bearer token: {}", token)
/// }
/// ```
///
/// # Errors
///
/// There are a few errors which this extractor can make. By default, all invalid responses are `400 BAD REQUEST` with one of these messages:
///
/// - \`Authorization\` header must be a bearer token – Somebody tried to but basic auth here instead of bearer
/// - \`Authorization\` header is missing – The header was required but it wasn't found
/// - \`Authorization\` header contains invalid characters – The header couldn't be processed because of invalid characters
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBearer(pub String);

impl<B> FromRequestParts<B> for AuthBearer
where
    B: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(req: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        Self::decode_request_parts(req)
    }
}

impl AuthBearerCustom for AuthBearer {
    const ERROR_CODE: StatusCode = ERR_DEFAULT;
    const ERROR_OVERWRITE: Option<&'static str> = None;

    fn from_header(contents: &str) -> Self {
        Self(contents.to_string())
    }
}

/// Custom extractor trait for bearer allowing you to implement custom responses
///
/// This is enabled via the `auth-bearer` feature
///
/// # Usage
///
/// To create your own bearer auth extractor using this crate, you have to:
///
/// 1. Make the extractor struct, something like `struct Example(String);`
/// 2. Implement [FromRequestParts] that links to step 3, copy and paste this from the example below
/// 3. Implement [AuthBearerCustom] to generate your extractor with your custom options, see the example below
///
/// Once you've completed these steps, you should have a new extractor which is just as easy to use as [AuthBearer] but has all of your custom configuration options inside of it!
///
/// # Example
///
/// This is what a typical custom extractor should look like in full, copy-paste this and edit it:
///
/// ```rust
/// use async_trait::async_trait;
/// use axum::extract::FromRequestParts;
/// use axum_auth::{AuthBearerCustom, Rejection};
/// use http::{request::Parts, StatusCode};
///
/// /// Your custom bearer auth returning a fun 418 for errors
/// struct MyCustomBearerAuth(String);
///
/// // this is where you define your custom options
/// impl AuthBearerCustom for MyCustomBearerAuth {
///     const ERROR_CODE: StatusCode = StatusCode::IM_A_TEAPOT; // <-- define custom status code here
///     const ERROR_OVERWRITE: Option<&'static str> = None; // <-- define overwriting message here
///
///     fn from_header(contents: &str) -> Self {
///         Self(contents.to_string())
///     }
/// }
///
/// // this is just boilerplate, copy-paste this
/// #[async_trait]
/// impl<B> FromRequestParts<B> for MyCustomBearerAuth
/// where
///     B: Send + Sync,
/// {
///     type Rejection = Rejection;
///
///     async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
///         Self::decode_request_parts(parts)
///     }
/// }
/// ```
///
/// Some notes about this example for some more insight:
///
/// - There's no reason for the [FromRequestParts] to ever change out of this pattern unless you're doing something special
/// - It's recommended to use the `struct BearerExample(String);` pattern because it makes using it from routes easy
pub trait AuthBearerCustom: Sized {
    /// Error code to use instead of the typical `400 BAD REQUEST` error
    const ERROR_CODE: StatusCode;

    /// Message to overwrite all default ones with if required, leave as [None] ideally
    const ERROR_OVERWRITE: Option<&'static str>;

    /// Converts provided header contents to new instance of self; you need to implement this
    ///
    /// # Example
    ///
    /// With the typical `struct BearerExample(String);` pattern of structures, this can be implemented like so:
    ///
    /// ```rust
    /// use axum_auth::AuthBearerCustom;
    /// use http::StatusCode;
    ///
    /// struct BearerExample(String);
    ///
    /// impl AuthBearerCustom for BearerExample {
    ///     const ERROR_CODE: StatusCode = StatusCode::BAD_REQUEST;
    ///     const ERROR_OVERWRITE: Option<&'static str> = None;
    ///
    ///     fn from_header(contents: &str) -> Self {
    ///         Self(contents.to_string())
    ///     }
    /// }
    /// ```
    ///
    /// All this method does is let you put the automatically contents of the header into your resulting structure.
    fn from_header(contents: &str) -> Self;

    /// Decodes bearer token content into new instance of self from axum body parts; this is automatically implemented
    fn decode_request_parts(req: &mut Parts) -> Result<Self, Rejection> {
        // Get authorization header
        let authorization = req
            .headers
            .get(AUTHORIZATION)
            .ok_or((Self::ERROR_CODE, ERR_MISSING))?
            .to_str()
            .map_err(|_| (Self::ERROR_CODE, ERR_CHARS))?;

        // Check that its a well-formed bearer and return
        let split = authorization.split_once(' ');
        match split {
            // Found proper bearer
            Some((name, contents)) if name == "Bearer" => Ok(Self::from_header(contents)),
            // Found empty bearer; sometimes request libraries format them as this
            _ if authorization == "Bearer" => Ok(Self::from_header("")),
            // Found nothing
            _ => Err((Self::ERROR_CODE, ERR_WRONG_BEARER)),
        }
    }
}
