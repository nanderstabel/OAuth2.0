use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use url::Url;

#[tokio::main]
async fn main() {
    // Create an HTTP client with redirect following disabled
    let client = Client::builder()
        .redirect(Policy::none()) // Disable automatic redirect following
        .build()
        .unwrap();

    // Step 1: Register the client
    let registration_response = register_client(&client).await.unwrap();
    let client_id = registration_response.client_id;
    let client_secret = registration_response.client_secret;

    println!("Registered Client ID: {}", client_id);
    println!("Registered Client Secret: {}", client_secret);

    // Step 2: Authorize the client
    let authorization_code = authorize_client(&client, &client_id).await.unwrap();
    println!("Authorization Code: {}", authorization_code);

    // Step 3: Exchange the authorization code for an access token
    let access_token =
        exchange_code_for_token(&client, &client_id, &client_secret, &authorization_code)
            .await
            .unwrap();
    println!("Access Token: {}", access_token);

    // Step 4: Access a protected resource
    let resource = access_protected_resource(&client, &access_token)
        .await
        .unwrap();
    println!("Protected Resource: {}", resource);
}

#[derive(Serialize, Deserialize)]
struct ClientRegistrationResponse {
    client_id: String,
    client_secret: String,
}

async fn register_client(client: &Client) -> Result<ClientRegistrationResponse, reqwest::Error> {
    let response = client
        .post("http://localhost:3033/register")
        .json(&serde_json::json!({
            "client_name": "Test Client",
            "redirect_uris": ["http://localhost/callback"]
        }))
        .send()
        .await?
        .json::<ClientRegistrationResponse>()
        .await?;

    Ok(response)
}

async fn authorize_client(client: &Client, client_id: &str) -> Result<String, reqwest::Error> {
    let response = client
        .get("http://localhost:3033/authorize")
        .query(&[
            ("client_id", client_id),
            ("response_type", "code"),
            ("state", "xyz"),
            ("redirect_uri", "http://localhost/callback"),
        ])
        .send()
        .await?;

    // Extract the redirect URL from the response
    let redirect_url = response.url().clone();

    println!("Status Code: {}", response.status());
    println!("Redirect URL: {}", redirect_url);

    let redirect_url = response.headers().get("location").unwrap();
    let redirect_url: Url = redirect_url.to_str().unwrap().parse().unwrap();
    println!("Location: {}", redirect_url);

    // Extract the authorization code from the redirect URL
    let code = redirect_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .unwrap();

    Ok(code)
}

#[derive(Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

async fn exchange_code_for_token(
    client: &Client,
    client_id: &str,
    client_secret: &str,
    code: &str,
) -> Result<String, reqwest::Error> {
    let response = client
        .post("http://localhost:3033/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await?
        .json::<TokenResponse>()
        .await?;

    Ok(response.access_token)
}

async fn access_protected_resource(
    client: &Client,
    access_token: &str,
) -> Result<String, reqwest::Error> {
    let response = client
        .get("http://localhost:3034/resource")
        .bearer_auth(access_token)
        .send()
        .await?
        .text()
        .await?;

    Ok(response)
}
