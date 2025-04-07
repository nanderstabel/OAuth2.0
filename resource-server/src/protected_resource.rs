use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::Json};
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, Validation, decode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing;

use crate::AppState;

#[derive(Serialize)]
pub struct ProtectedResource {
    pub message: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

/// Handles requests to the `/resource` endpoint.
///
/// Validates the JWT in the `Authorization` header and grants access to the protected resource.
#[axum_macros::debug_handler]
pub async fn protected_resource(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ProtectedResource>, StatusCode> {
    dotenv().ok(); // Load environment variables from .env

    tracing::info!("Received request for protected resource");

    fetch_public_key_handler(State(state.clone())).await?;

    // Extract the Authorization header
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            tracing::info!("Validating JWT: {token}");

            let public_key = {
                let key_guard = state.public_key.lock().unwrap();
                key_guard.clone()
            };

            if public_key.is_none() {
                tracing::error!("Public key not available");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            // Validate the JWT
            let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256); // Explicitly require RS256
            validation.validate_exp = true; // Ensure token expiration is validated

            match decode::<Claims>(token, public_key.as_ref().unwrap(), &validation) {
                Ok(token_data) => {
                    let claims = token_data.claims;

                    // Check token expiration
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    if claims.exp < now {
                        tracing::warn!("JWT has expired");
                        return Err(StatusCode::UNAUTHORIZED);
                    }

                    tracing::info!("JWT validated successfully for user: {}", claims.sub);
                    return Ok(Json(ProtectedResource {
                        message: format!("Access granted to user: {}", claims.sub),
                    }));
                }
                Err(err) => {
                    tracing::warn!("JWT validation failed: {}", err);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        }
    }

    tracing::warn!("Authorization header missing or invalid");
    Err(StatusCode::UNAUTHORIZED)
}

/// Handles requests to the `/fetch-public-key` endpoint.
///
/// Fetches the public key from the Authorization Server and updates the shared application state.
#[axum_macros::debug_handler]
pub async fn fetch_public_key_handler(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, StatusCode> {
    let jwks_url = format!("{}/jwks.json", state.authorization_server_url);
    tracing::info!("Fetching public key from JWKS endpoint: {}", jwks_url);

    let client = Client::new();
    let response = client
        .get(&jwks_url)
        .send()
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch JWKS: {}", err);
            StatusCode::BAD_GATEWAY
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|err| {
            tracing::error!("Failed to parse JWKS response: {}", err);
            StatusCode::BAD_GATEWAY
        })?;

    tracing::info!("Public key fetched successfully");

    let jwk = response["keys"][0].clone();
    let n = jwk["n"].as_str().ok_or_else(|| {
        tracing::error!("Missing 'n' field in JWKS");
        StatusCode::BAD_GATEWAY
    })?;
    let e = jwk["e"].as_str().ok_or_else(|| {
        tracing::error!("Missing 'e' field in JWKS");
        StatusCode::BAD_GATEWAY
    })?;

    tracing::info!("Modulus (n): {}", n);
    tracing::info!("Exponent (e): {}", e);

    // Use the Base64URL-encoded modulus and exponent to create the DecodingKey
    let decoding_key = DecodingKey::from_rsa_components(n, e).map_err(|err| {
        tracing::error!("Failed to create DecodingKey: {}", err);
        StatusCode::BAD_GATEWAY
    })?;

    tracing::info!("Decoding key created successfully");

    let mut key_guard = state.public_key.lock().unwrap();
    *key_guard = Some(decoding_key);

    tracing::info!("Public key fetched and stored successfully");
    Ok(StatusCode::OK)
}
