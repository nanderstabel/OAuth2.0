use resource_server::{AppState, router::router};
use tokio::net::TcpListener;
use tracing_subscriber;

mod protected_resource;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let app = router();

    // Define the address to run the server on
    let listener = TcpListener::bind("0.0.0.0:3034").await.unwrap();

    tracing::info!(
        "Resource Server running on http://{}",
        listener.local_addr().unwrap()
    );

    // Start the server
    axum::serve(listener, app).await.unwrap();
}
