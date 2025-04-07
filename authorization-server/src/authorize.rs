/// The `authorize` module handles the `/authorize` endpoint of the Authorization Server.
/// This endpoint is responsible for generating authorization codes for clients.
use crate::SharedAppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Json, Redirect},
};
use serde::{Deserialize, Serialize};
use tracing;
use uuid::Uuid;

/// Represents the query parameters for the `/authorize` endpoint.
#[derive(Deserialize, Debug)]
pub struct AuthorizationRequest {
    /// The client ID of the requesting client.
    pub client_id: String,
    /// The response type (e.g., "code").
    pub response_type: String,
    /// The redirect URI to which the authorization code will be sent.
    pub redirect_uri: Option<String>,
    /// The requested scope (optional).
    pub scope: Option<String>,
    /// The state parameter to prevent CSRF attacks.
    pub state: Option<String>,
}

/// Represents a successful authorization response.
#[derive(Serialize)]
pub struct AuthorizationResponse {
    /// The authorization code issued to the client.
    pub code: String,
    /// The state parameter returned to the client.
    pub state: Option<String>,
}

/// Represents an error response for the `/authorize` endpoint.
#[derive(Serialize)]
pub struct AuthorizationErrorResponse {
    /// The error message.
    pub error: String,
    /// The state parameter returned to the client.
    pub state: Option<String>,
}

/// Handles the `/authorize` endpoint.
///
/// This function validates the client request, generates an authorization code,
/// and redirects the client to the specified redirect URI with the code and state.
///
/// # Arguments
/// - `State(app_state)`: Shared application state.
/// - `Query(params)`: Query parameters from the client request.
///
/// # Returns
/// - `Redirect`: Redirects the client to the specified redirect URI with the authorization code.
/// - `(StatusCode, Json<AuthorizationErrorResponse>)`: Returns an error response if validation fails.
#[axum_macros::debug_handler]
pub async fn authorize(
    State(app_state): State<SharedAppState>,
    Query(params): Query<AuthorizationRequest>,
) -> Result<Redirect, (StatusCode, Json<AuthorizationErrorResponse>)> {
    tracing::info!("Received authorization request: {:?}", params);

    let mut state = app_state.lock().unwrap();

    // 1. Validate `client_id`
    let client_data = state.client_registry.get(&params.client_id);
    if client_data.is_none() {
        tracing::warn!("Invalid client_id: {}", params.client_id);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthorizationErrorResponse {
                error: "invalid_client".to_string(),
                state: params.state.clone(),
            }),
        ));
    }
    let (_, registered_redirect_uris) = client_data.unwrap();

    // 2. Validate `response_type`
    if params.response_type != "code" {
        tracing::warn!("Unsupported response_type: {}", params.response_type);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthorizationErrorResponse {
                error: "unsupported_response_type".to_string(),
                state: params.state.clone(),
            }),
        ));
    }

    // 3. Validate `redirect_uri`
    let redirect_uri = match &params.redirect_uri {
        Some(uri) if registered_redirect_uris.contains(uri) => uri.clone(),
        None if !registered_redirect_uris.is_empty() => registered_redirect_uris[0].clone(),
        _ => {
            tracing::warn!("Invalid redirect_uri: {:?}", params.redirect_uri);
            return Err((
                StatusCode::FORBIDDEN,
                Json(AuthorizationErrorResponse {
                    error: "invalid_redirect_uri".to_string(),
                    state: params.state.clone(),
                }),
            ));
        }
    };

    // 4. Validate `scope` (optional, for now we assume all scopes are valid)
    if let Some(scope) = &params.scope {
        tracing::info!("Requested scope: {}", scope);
    }

    // 5. Generate and store the authorization code
    let code = Uuid::new_v4().to_string();
    state
        .authorization_state
        .insert(code.clone(), params.client_id.clone());

    tracing::info!("Generated authorization code: {}", code);

    // 6. Redirect to the `redirect_uri` with the authorization code and `state`
    let mut redirect_url = format!("{redirect_uri}?code={code}");
    if let Some(state_param) = &params.state {
        redirect_url.push_str(&format!("&state={}", state_param));
    }

    tracing::info!("Redirecting to: {}", redirect_url);

    // Ensure the redirect is returned correctly
    Ok(Redirect::to(&redirect_url))
}
