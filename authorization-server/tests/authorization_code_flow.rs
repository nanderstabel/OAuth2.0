use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

mod tests {
    use super::*;
    use authorization_server::{
        AppState, SharedAppState, authorize::authorize, register::register_client, token::token,
    };
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_authorization_code_flow() {
        // Create the shared state
        let state: SharedAppState = Arc::new(Mutex::new(AppState {
            authorization_state: HashMap::new(),
            client_registry: HashMap::new(),
        }));

        // Build the application
        let app = Router::new()
            .route("/authorize", axum::routing::get(authorize))
            .route("/token", axum::routing::post(token))
            .route("/register", axum::routing::post(register_client))
            .with_state(state.clone());

        // Step 1: Register the client
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

        let client_id = registration_response["client_id"].as_str().unwrap();
        let client_secret = registration_response["client_secret"].as_str().unwrap();

        // Step 2: Simulate an /authorize request
        let authorize_request = Request::builder()
            .uri(format!(
                "/authorize?client_id={client_id}&response_type=code&state=xyz&redirect_uri=http://localhost/callback"
            ))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(authorize_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let redirect_location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        let redirect_uri = url::Url::parse(redirect_location).unwrap();
        let code = redirect_uri
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .to_string();
        let state = redirect_uri
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .to_string();
        assert_eq!(state, "xyz");

        // Step 3: Simulate a /token request
        let token_request_body = format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}&client_secret={client_secret}"
        );

        let token_request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(token_request_body))
            .unwrap();

        let response = app.clone().oneshot(token_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_response: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(token_response["token_type"], "Bearer");
        assert_eq!(token_response["expires_in"], 3600);
        assert!(token_response["access_token"].as_str().is_some());

        println!("Token response: {:?}", token_response);
    }
}
