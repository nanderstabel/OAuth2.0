use crate::{AppState, SharedAppState, authorize, jwks, register, token};
use axum::{
    Router,
    routing::{get, post},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub fn router() -> Router {
    // Create the shared application state
    let app_state: SharedAppState = Arc::new(Mutex::new(AppState {
        authorization_state: HashMap::new(),
        client_registry: HashMap::new(),
    }));

    // Build the application with routes for OAuth 2.0
    let app = Router::new()
        .route("/authorize", get(authorize::authorize))
        .route("/token", post(token::token))
        .route("/register", post(register::register_client))
        .route("/jwks.json", get(jwks::jwks)) // Add the JWKS route
        .with_state(app_state); // Use the unified state

    app
}
