//! Implementation of http basic authentication
//!
//! See [AuthBasic] for the most commonly-used data structure

use crate::{get_header, Rejection, ERR_DECODE, ERR_DEFAULT, ERR_WRONG_BASIC};
use axum_core::extract::FromRequestParts;
use base64::Engine;
use http::{request::Parts, StatusCode};

/// Basic authentication extractor, containing an identifier as well as an optional password
///
/// This is enabled via the `auth-basic` feature
///
/// # Example
///
/// Though this structure can be used like any other axum extractor, we recommend this pattern:
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
///
/// # Errors
///
/// There are a few errors which this extractor can make. By default, all invalid responses are `400 BAD REQUEST` with one of these messages:
///
/// - \`Authorization\` header could not be decoded – The header couldn't be decoded, probably missing a colon
/// - \`Authorization\` header must be for basic authentication – Someone tried to use bearer auth instead of basic auth
/// - \`Authorization\` header is missing – The header was required but it wasn't found
/// - \`Authorization\` header contains invalid characters – The header couldn't be processed because of invalid characters
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBasic(pub (String, Option<String>));

impl<B> FromRequestParts<B> for AuthBasic
where
    B: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        Self::decode_request_parts(parts)
    }
}

impl AuthBasicCustom for AuthBasic {
    const ERROR_CODE: StatusCode = ERR_DEFAULT;
    const ERROR_OVERWRITE: Option<&'static str> = None;

    fn from_header(contents: (String, Option<String>)) -> Self {
        Self(contents)
    }
}

/// Custom extractor trait for basic auth allowing you to implement custom responses
///
/// This is enabled via the `auth-basic` feature
///
/// # Usage
///
/// To create your own basic auth extractor using this create, you have to:
///
/// 1. Make the extractor struct, something like `struct Example((String, Option<String>));`
/// 2. Implement [FromRequestParts] that links to step 3, copy and paste this from the example below
/// 3. Implement [AuthBasicCustom] to generate your extractor with your custom options, see the example below
///
/// Once you've completed these steps, you should have a new extractor which is just as easy to use as [AuthBasic] but has all of your custom configuration options inside of it!
///
/// # Example
///
/// This is what a typical custom extractor should look like in full, copy-paste this and edit it:
///
/// ```rust
/// use axum_auth::{AuthBasicCustom, Rejection};
/// use http::{request::Parts, StatusCode};
/// use axum::extract::FromRequestParts;
///
/// /// Your custom basic auth returning a fun 418 for errors
/// struct MyCustomBasicAuth((String, Option<String>));
///
/// // this is where you define your custom options
/// impl AuthBasicCustom for MyCustomBasicAuth {
///     const ERROR_CODE: StatusCode = StatusCode::IM_A_TEAPOT; // <-- define custom status code here
///     const ERROR_OVERWRITE: Option<&'static str> = None; // <-- define overwriting message here
///
///     fn from_header(contents: (String, Option<String>)) -> Self {
///         Self(contents)
///     }
/// }
///
/// // this is just boilerplate, copy-paste this
/// impl<B> FromRequestParts<B> for MyCustomBasicAuth
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
/// - It's recommended to use the `struct BasicExample((String, Option<String>));` pattern because it makes using it from routes easy
pub trait AuthBasicCustom: Sized {
    /// Error code to use instead of the typical `400 BAD REQUEST` error
    const ERROR_CODE: StatusCode;

    /// Message to overwrite all default ones with if required, leave as [None] ideally
    const ERROR_OVERWRITE: Option<&'static str>;

    /// Converts provided header contents to new instance of self; you need to implement this
    ///
    /// # Example
    ///
    /// With the typical `struct BasicExample((String, Option<String>));` pattern of structures, this can be implemented like so:
    ///
    /// ```rust
    /// use axum_auth::AuthBasicCustom;
    /// use http::StatusCode;
    ///
    /// struct BasicExample((String, Option<String>));
    ///
    /// impl AuthBasicCustom for BasicExample {
    ///     const ERROR_CODE: StatusCode = StatusCode::BAD_REQUEST;
    ///     const ERROR_OVERWRITE: Option<&'static str> = None;
    ///
    ///     fn from_header(contents: (String, Option<String>)) -> Self {
    ///         Self(contents)
    ///     }
    /// }
    /// ```
    ///
    /// All this method does is let you put the automatically contents of the header into your resulting structure.
    fn from_header(contents: (String, Option<String>)) -> Self;

    /// Decodes bearer token content into new instance of self from axum body parts; this is automatically implemented
    fn decode_request_parts(req: &mut Parts) -> Result<Self, Rejection> {
        // Get authorization header
        let authorization = get_header(req, Self::ERROR_CODE)?;

        // Check that its well-formed basic auth then decode and return
        let split = authorization.split_once(' ');
        match split {
            Some((name, contents)) if name == "Basic" => {
                let decoded = decode(contents, (Self::ERROR_CODE, ERR_DECODE))?;
                Ok(Self::from_header(decoded))
            }
            _ => Err((Self::ERROR_CODE, ERR_WRONG_BASIC)),
        }
    }
}

/// Decodes the two parts of basic auth using the colon
fn decode(input: &str, err: Rejection) -> Result<(String, Option<String>), Rejection> {
    // Decode from base64 into a string
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|_| err)?;
    let decoded = String::from_utf8(decoded).map_err(|_| err)?;

    // Return depending on if password is present
    Ok(if let Some((id, password)) = decoded.split_once(':') {
        (id.to_string(), Some(password.to_string()))
    } else {
        (decoded.to_string(), None)
    })
}
