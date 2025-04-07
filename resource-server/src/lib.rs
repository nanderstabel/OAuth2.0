pub mod protected_resource;
pub mod router;

use jsonwebtoken::DecodingKey;
use std::sync::Arc;

/// Application state for the Resource Server.
#[derive(Clone)]
pub struct AppState {
    pub tokens: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    pub public_key: Arc<std::sync::Mutex<Option<DecodingKey>>>,
    pub authorization_server_url: String, // Add the Authorization Server URL to the state
}
