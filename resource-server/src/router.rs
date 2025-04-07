use crate::{
    AppState,
    protected_resource::{fetch_public_key_handler, protected_resource},
};
use axum::{Router, routing::get};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};

pub fn router() -> Router {
    // Read the AUTHORIZATION_SERVER_URL environment variable
    let authorization_server_url = env::var("AUTHORIZATION_SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:3033".to_string()); // Default to localhost if not set

    // Create the shared application state
    let state = AppState {
        tokens: Arc::new(Mutex::new(HashMap::new())),
        public_key: Arc::new(Mutex::new(None)),
        authorization_server_url,
    };

    // Build the application
    let app = Router::new()
        .route("/resource", get(protected_resource))
        .route("/fetch-public-key", get(fetch_public_key_handler)) // Add the fetch-public-key route
        .with_state(Arc::new(state));

    app
}
