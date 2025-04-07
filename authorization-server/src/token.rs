/// The `token` module handles the `/token` endpoint of the Authorization Server.
/// This endpoint is responsible for exchanging authorization codes for access tokens.
use crate::SharedAppState;
use axum::{
    extract::{Form, State},
    response::Json,
};
use dotenvy::dotenv;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing;

/// Represents the request body for the `/token` endpoint.
#[derive(Deserialize, Debug)]
pub struct TokenRequest {
    /// The grant type (e.g., "authorization_code").
    pub grant_type: String,
    /// The authorization code issued by the `/authorize` endpoint.
    pub code: Option<String>,
    /// The client ID of the requesting client.
    pub client_id: String,
    /// The client secret (optional for public clients).
    pub client_secret: Option<String>,
}

/// Represents a successful token response.
#[derive(Serialize)]
pub struct TokenResponse {
    /// The access token issued to the client.
    pub access_token: String,
    /// The type of token (e.g., "Bearer").
    pub token_type: String,
    /// The expiration time of the token in seconds.
    pub expires_in: u64,
}

/// Represents an error response for the `/token` endpoint.
#[derive(Serialize)]
pub struct TokenErrorResponse {
    /// The error message.
    pub error: String,
}

/// Represents the claims included in the JWT access token.
#[derive(Serialize)]
struct Claims {
    /// The subject (e.g., client ID).
    sub: String,
    /// The expiration time of the token (UNIX timestamp).
    exp: u64,
    /// The scope of the token.
    scope: String,
}

/// Handles the `/token` endpoint.
///
/// This function validates the authorization code, client credentials, and grant type,
/// and issues a signed JWT as the access token.
///
/// # Arguments
/// - `State(app_state)`: Shared application state.
/// - `Form(payload)`: The request body containing the token request parameters.
///
/// # Returns
/// - `Json<TokenResponse>`: A successful token response with the access token.
/// - `(StatusCode, Json<TokenErrorResponse>)`: An error response if validation fails.
#[axum_macros::debug_handler]
pub async fn token(
    State(app_state): State<SharedAppState>,
    Form(payload): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, Json<TokenErrorResponse>> {
    tracing::info!("Received token request: {:?}", payload);

    dotenv().ok(); // Load environment variables from .env

    // Load the private key from the `unsafe-private.pem` file
    let private_key =
        fs::read_to_string("unsafe-private.pem").expect("Failed to read unsafe-private.pem");
    let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes())
        .expect("Failed to create encoding key from private key");

    if payload.grant_type != "authorization_code" {
        tracing::warn!("Unsupported grant_type: {}", payload.grant_type);
        return Err(Json(TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
        }));
    }

    let mut state = app_state.lock().unwrap();

    // Check if the authorization code exists in the state
    if let Some(client_id) = state
        .authorization_state
        .remove(&payload.code.clone().unwrap_or_default())
    {
        tracing::info!("Authorization code validated for client_id: {}", client_id);

        // Validate the client_id
        if let Some((stored_client_secret, _)) = state.client_registry.get(&client_id) {
            // If the client is confidential, validate the client_secret
            if let Some(client_secret) = &payload.client_secret {
                if client_secret != stored_client_secret {
                    tracing::warn!("Invalid client_secret for client_id: {}", client_id);
                    return Err(Json(TokenErrorResponse {
                        error: "invalid_client".to_string(),
                    }));
                }
            } else if !stored_client_secret.is_empty() {
                // Confidential client must provide a client_secret
                tracing::warn!(
                    "Missing client_secret for confidential client_id: {}",
                    client_id
                );
                return Err(Json(TokenErrorResponse {
                    error: "invalid_client".to_string(),
                }));
            }

            // Generate a signed JWT as the access token
            let expiration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600; // Token expires in 1 hour

            let claims = Claims {
                sub: client_id.clone(),
                exp: expiration,
                scope: "read".to_string(), // Example scope
            };

            // Explicitly set the algorithm to RS256
            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.typ = Some("JWT".to_string());

            let token = encode(&header, &claims, &encoding_key).unwrap();

            tracing::info!("Generated access token for client_id: {}", client_id);

            return Ok(Json(TokenResponse {
                access_token: token,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            }));
        }
    }

    tracing::warn!("Invalid authorization code or client_id");
    Err(Json(TokenErrorResponse {
        error: "invalid_grant".to_string(),
    }))
}
