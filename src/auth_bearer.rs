use axum::async_trait;
use axum::extract::{FromRequest, RequestParts};
use http::{header::AUTHORIZATION, StatusCode};

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
/// async fn handler(AuthBearer(token): AuthBearer) -> String {
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
            .get(AUTHORIZATION)
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
            Some((name, contents)) if name == "Bearer" => Ok(Self(contents.to_string())),
            _ => Err((
                StatusCode::BAD_REQUEST,
                "`Authorization` header must be a bearer token",
            )),
        }
    }
}
