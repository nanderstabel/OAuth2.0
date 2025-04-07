pub mod authorize;
pub mod jwks;
pub mod register;
pub mod router;
pub mod token;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct AppState {
    pub authorization_state: HashMap<String, String>,
    pub client_registry: HashMap<String, (String, Vec<String>)>,
}

pub type SharedAppState = Arc<Mutex<AppState>>;
