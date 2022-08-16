use async_trait::async_trait;
use axum_core::extract::{FromRequest, RequestParts};
use http::{header::AUTHORIZATION, StatusCode};

/// Basic authentication extractor, containing an identifier as well as an optional password
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
///
/// # Errors
///
/// This extractor will give off a few different errors depending on what when wrong with a request's header. These errors include:
///
/// - COMING SOON
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBasic(pub (String, Option<String>));

#[async_trait]
impl<B> FromRequest<B> for AuthBasic
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> std::result::Result<Self, Self::Rejection> {
        // Get authorisation header
        let authorisation = req
            .headers()
            .get(AUTHORIZATION)
            .ok_or((StatusCode::BAD_REQUEST, "`Authorization` header is missing"))?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "`Authorization` header contains invalid characters",
                )
            })?;

        // Check that its a well-formed basic auth then decode and return
        let split = authorisation.split_once(' ');
        match split {
            Some((name, contents)) if name == "Basic" => decode_basic(contents),
            _ => Err((
                StatusCode::BAD_REQUEST,
                "`Authorization` header must be for basic authentication",
            )),
        }
    }
}

/// Decodes basic auth, returning the full tuple if present
fn decode_basic(input: &str) -> Result<AuthBasic, (StatusCode, &'static str)> {
    const ERR: (StatusCode, &'static str) = (
        StatusCode::BAD_REQUEST,
        "`Authorization` header's basic authentication was improperly encoded",
    );

    // Decode from base64 into a string
    let decoded = base64::decode(input).map_err(|_| ERR)?;
    let decoded = String::from_utf8(decoded).map_err(|_| ERR)?;

    // Return depending on if password is present
    Ok(AuthBasic(
        if let Some((id, password)) = decoded.split_once(':') {
            (id.to_string(), Some(password.to_string()))
        } else {
            (decoded, None)
        },
    ))
}
