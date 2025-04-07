use tokio::net::TcpListener;
use tracing_subscriber;

mod authorize;
mod jwks;
mod register;
mod token;

use authorization_server::{SharedAppState, router::router};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let app = router();

    // Define the address to run the server on
    let listener = TcpListener::bind("0.0.0.0:3033").await.unwrap();

    tracing::info!(
        "OAuth 2.0 Authorization Server running on http://{}",
        listener.local_addr().unwrap()
    );

    // Run the server
    axum::serve(listener, app).await.unwrap();
}
