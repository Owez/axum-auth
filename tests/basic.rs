use axum::{routing::get, Router};
use axum_auth::{AuthBasic, AuthBearer};
use http::StatusCode;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Launches spin-off axum instance
async fn launcher() {
    // Make routes
    let app = Router::new()
        .route("/basic", get(tester_basic))
        .route("/bearer", get(auth_bearer));

    // Launch
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    axum::serve(
        TcpListener::bind(addr).await.unwrap(),
        app.into_make_service(),
    )
        .await
        .unwrap();

    async fn tester_basic(AuthBasic((id, password)): AuthBasic) -> String {
        format!("Got {} and {:?}", id, password)
    }

    async fn auth_bearer(AuthBearer(token): AuthBearer) -> String {
        format!("Got {}", token)
    }
}

fn url(end: &str) -> String {
    format!("http://127.0.0.1:3000{}", end)
}

#[tokio::test]
async fn tester() {
    // Launch axum instance
    tokio::task::spawn(launcher());

    // Wait for boot
    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

    // Tests
    good().await;
    switched().await;
    nothing().await;
}

/// The requests which should be returned fine
async fn good() {
    // Try good basic
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/basic"))
        .basic_auth("My Username", Some("My Password"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::OK);
    assert_eq!(
        resp.text().await.unwrap(),
        String::from("Got My Username and Some(\"My Password\")")
    );

    // Try good bearer
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/bearer"))
        .bearer_auth("My Token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), String::from("Got My Token"))
}

async fn switched() {
    // Try bearer in basic
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/basic"))
        .bearer_auth("123124nfienrign")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.text().await.unwrap(),
        String::from("`Authorization` header must be for basic authentication")
    );

    // Try basic in bearer
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/bearer"))
        .basic_auth("123", Some("Hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.text().await.unwrap(),
        String::from("`Authorization` header must be a bearer token")
    )
}

/// Sees if we can get nothing from basic or bearer successfully
async fn nothing() {
    // Try basic
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/basic"))
        .basic_auth("", Some(""))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::OK);
    assert_eq!(
        resp.text().await.unwrap(),
        String::from("Got  and Some(\"\")")
    );

    // Try bearer
    let client = reqwest::Client::new();
    let resp = client
        .get(url("/bearer"))
        .bearer_auth("")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), String::from("Got "))
}
