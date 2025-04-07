/// The `register` module handles the `/register` endpoint of the Authorization Server.
/// This endpoint allows clients to register and obtain a `client_id` and `client_secret`.
use crate::SharedAppState;
use axum::{
    extract::{Json, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tracing;
use uuid::Uuid;

/// Represents the request body for the `/register` endpoint.
#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    /// The name of the client.
    pub client_name: String,
    /// The list of redirect URIs for the client.
    pub redirect_uris: Vec<String>,
}

/// Represents a successful registration response.
#[derive(Serialize)]
pub struct RegisterResponse {
    /// The client ID issued to the client.
    pub client_id: String,
    /// The client secret issued to the client.
    pub client_secret: String,
}

/// Handles the `/register` endpoint.
///
/// This function registers a new client, generates a `client_id` and `client_secret`,
/// and stores the client information in the shared application state.
///
/// # Arguments
/// - `State(app_state)`: Shared application state.
/// - `Json(payload)`: The request body containing the registration parameters.
///
/// # Returns
/// - `Json<RegisterResponse>`: A successful registration response with the `client_id` and `client_secret`.
/// - `(StatusCode, String)`: An error response if validation fails.
#[axum_macros::debug_handler]
pub async fn register_client(
    State(app_state): State<SharedAppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    tracing::info!("Received client registration request: {:?}", payload);

    let mut state = app_state.lock().unwrap();

    // Generate a unique client_id and client_secret
    let client_id = Uuid::new_v4().to_string();
    let client_secret = Uuid::new_v4().to_string();

    // Store the client information in the state
    state.client_registry.insert(
        client_id.clone(),
        (client_secret.clone(), payload.redirect_uris.clone()),
    );

    tracing::info!("Registered new client with client_id: {}", client_id);

    Ok(Json(RegisterResponse {
        client_id,
        client_secret,
    }))
}
