use authorization_server::{AppState, SharedAppState, register::register_client};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::util::ServiceExt;

#[tokio::test]
async fn test_client_registration() {
    // Create the shared client registry
    let client_registry: SharedAppState = Arc::new(Mutex::new(AppState {
        authorization_state: HashMap::new(),
        client_registry: HashMap::new(),
    }));

    // Build the application
    let app = Router::new()
        .route("/register", axum::routing::post(register_client))
        .with_state(client_registry.clone());

    // Simulate a /register request
    let registration_request_body = r#"
        {
            "client_name": "Test Client",
            "redirect_uris": ["http://localhost/callback"]
        }
    "#;

    let registration_request = Request::builder()
        .method("POST")
        .uri("/register")
        .header("Content-Type", "application/json")
        .body(Body::from(registration_request_body))
        .unwrap();

    let response = app.clone().oneshot(registration_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let registration_response: Value = serde_json::from_slice(&body).unwrap();

    assert!(registration_response["client_id"].as_str().is_some());
    assert!(registration_response["client_secret"].as_str().is_some());
}
