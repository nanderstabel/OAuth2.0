use axum::extract::Query;
use axum::routing::get;
use axum::{Router, response::IntoResponse};
use reqwest::{Client, redirect::Policy};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use tokio::net::TcpListener;
use tokio::task;
use tokio::time::{Duration, sleep};
use tracing_subscriber;

static INIT: std::sync::Once = std::sync::Once::new();

#[tokio::test]
async fn test_complete_authorization_code_flow() {
    // Initialize tracing (only once)
    INIT.call_once(|| {
        tracing_subscriber::fmt::init();
    });

    // Step 1: Set up the Authorization Server
    let auth_server = authorization_server::router::router();

    // Step 2: Start the Authorization Server
    // Bind the Authorization Server to a random port and start it
    let auth_listener = TcpListener::bind("localhost:0").await.unwrap();
    let auth_server_addr = auth_listener.local_addr().unwrap();
    let auth_server_url = format!("http://{}", auth_server_addr);
    let auth_server_handle = task::spawn(async move {
        axum::serve(auth_listener, auth_server).await.unwrap();
    });

    unsafe {
        // Set the AUTHORIZATION_SERVER_URL environment variable
        env::set_var("AUTHORIZATION_SERVER_URL", &auth_server_url);
    }

    let resource_server = resource_server::router::router();

    // Step 3: Set up the Mock Redirect URI Server
    let redirect_server = Router::new().route(
        "/callback",
        get(|query: Query<HashMap<String, String>>| async move {
            println!("Callback received with query: {:?}", query);
            "Callback handled".into_response()
        }),
    );

    // Step 4: Start the Resource Server
    // Bind the Resource Server to a random port and start it
    let resource_listener = TcpListener::bind("localhost:0").await.unwrap();
    let resource_server_addr = resource_listener.local_addr().unwrap();
    let resource_server_url = format!("http://{}", resource_server_addr);
    let resource_server_handle = task::spawn(async move {
        axum::serve(resource_listener, resource_server)
            .await
            .unwrap();
    });

    // Step 6: Start the Mock Redirect URI Server
    // Bind the mock server to a random port and start it
    let redirect_listener = TcpListener::bind("localhost:0").await.unwrap();
    let redirect_server_addr = redirect_listener.local_addr().unwrap();
    let redirect_server_url = format!("http://{}", redirect_server_addr);
    let redirect_server_handle = task::spawn(async move {
        axum::serve(redirect_listener, redirect_server)
            .await
            .unwrap();
    });

    // Wait for the servers to start
    sleep(Duration::from_secs(1)).await;

    // Step 7: Simulate the Client
    // Create an HTTP client with redirect following disabled
    let client = Client::builder().redirect(Policy::none()).build().unwrap();

    // Step 8: Register the client
    // Send a registration request to the Authorization Server
    let registration_request_body = format!(
        r#"
        {{
            "client_name": "Test Client",
            "redirect_uris": ["{redirect_server_url}/callback"]
        }}
    "#
    );

    let registration_response = client
        .post(format!("{auth_server_url}/register"))
        .header("Content-Type", "application/json")
        .body(registration_request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(registration_response.status(), 200);

    let registration_response_json: Value = registration_response.json().await.unwrap();
    let client_id = registration_response_json["client_id"].as_str().unwrap();
    let client_secret = registration_response_json["client_secret"]
        .as_str()
        .unwrap();

    // Step 9: Simulate an /authorize request
    // Send an authorization request to the Authorization Server
    let authorize_response = client
        .get(&format!(
            "{auth_server_url}/authorize?client_id={client_id}&response_type=code&state=xyz&redirect_uri={redirect_server_url}/callback"
        ))
        .send()
        .await
        .unwrap();

    // Verify the 303 See Other response
    assert_eq!(authorize_response.status(), 303);

    let redirect_location = authorize_response
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

    // Step 10: Simulate a /token request
    // Exchange the authorization code for an access token
    let token_response = client
        .post(format!("{auth_server_url}/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}&client_secret={client_secret}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), 200);

    let token_response_json: Value = token_response.json().await.unwrap();
    let access_token = token_response_json["access_token"].as_str().unwrap();
    assert_eq!(token_response_json["token_type"], "Bearer");
    assert_eq!(token_response_json["expires_in"], 3600);

    // Step 11: Fetch the public key for the Resource Server
    // Trigger the Resource Server to fetch the public key from the Authorization Server
    let fetch_public_key_response = client
        .get(format!("{resource_server_url}/fetch-public-key"))
        .send()
        .await
        .unwrap();

    assert_eq!(fetch_public_key_response.status(), 200);

    // Step 12: Simulate a request to the protected resource
    // Access the protected resource using the access token
    let resource_response = client
        .get(format!("{resource_server_url}/resource"))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(resource_response.status(), 200);

    let resource_response_json: Value = resource_response.json().await.unwrap();
    assert_eq!(
        resource_response_json["message"],
        format!("Access granted to user: {}", client_id)
    );

    println!("Integration test passed!");

    // Step 13: Stop the servers
    // Abort all server tasks
    auth_server_handle.abort();
    resource_server_handle.abort();
    redirect_server_handle.abort();
}
