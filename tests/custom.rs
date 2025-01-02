use axum::{extract::FromRequestParts, routing::get, Router};
use axum_auth::{AuthBasicCustom, AuthBearerCustom, Rejection};
use http::{request::Parts, StatusCode};

struct MyCustomBasic((String, Option<String>));

impl AuthBasicCustom for MyCustomBasic {
    const ERROR_CODE: StatusCode = StatusCode::IM_A_TEAPOT;
    const ERROR_OVERWRITE: Option<&'static str> = None;

    fn from_header(contents: (String, Option<String>)) -> Self {
        Self(contents)
    }
}

impl<B> FromRequestParts<B> for MyCustomBasic
where
    B: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        Self::decode_request_parts(parts)
    }
}

struct MyCustomBearer(String);

impl AuthBearerCustom for MyCustomBearer {
    const ERROR_CODE: StatusCode = StatusCode::IM_A_TEAPOT;
    const ERROR_OVERWRITE: Option<&'static str> = None;

    fn from_header(contents: &str) -> Self {
        Self(contents.to_string())
    }
}

impl<B> FromRequestParts<B> for MyCustomBearer
where
    B: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        Self::decode_request_parts(parts)
    }
}

/// Launches spin-off axum instance
async fn launcher() {
    // Make routes
    let app = Router::new()
        .route("/basic", get(tester_basic))
        .route("/bearer", get(auth_bearer));

    // Launch
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();

    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();

    async fn tester_basic(MyCustomBasic((id, password)): MyCustomBasic) -> String {
        format!("Got {} and {:?}", id, password)
    }

    async fn auth_bearer(MyCustomBearer(token): MyCustomBearer) -> String {
        format!("Got {}", token)
    }
}

fn url(end: &str) -> String {
    format!("http://127.0.0.1:3001{}", end)
}
#[tokio::test]
async fn tester() {
    // Launch axum instance
    tokio::task::spawn(launcher());

    // Wait for boot
    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

    // Try bad basic
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/basic"))
        .bearer_auth("My Crap Username")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::IM_A_TEAPOT.as_u16());
    assert_eq!(
        resp.text().await.unwrap(),
        String::from("`Authorization` header must be for basic authentication")
    );

    // Try bad bearer
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/bearer"))
        .basic_auth("My Crap Token", None::<&str>)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::IM_A_TEAPOT.as_u16());
    assert_eq!(
        resp.text().await.unwrap(),
        String::from("`Authorization` header must be a bearer token")
    )
}
