use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    routing, Router,
};
use tokio::{net::TcpListener, sync::oneshot};

/// Channel senders to send the response and shutdown signals.
struct ServerState {
    shutdown_tx: oneshot::Sender<()>,
    response_tx: oneshot::Sender<crate::AuthResponse>,
}

/// Start a server and listen for a connection.
pub async fn serve_async(listen_port: u16) -> anyhow::Result<crate::AuthResponse> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (response_tx, response_rx) = oneshot::channel();
    let state = ServerState {
        shutdown_tx,
        response_tx,
    };

    let app = Router::new()
        .route("/", routing::get(handle))
        .with_state(Arc::new(Mutex::new(Some(state))));

    let listener = TcpListener::bind(format!("localhost:{}", listen_port)).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown((async move || {
            shutdown_rx.await.expect("error awaiting shutdown_rx")
        })())
        .await?;

    Ok(response_rx.await?)
}

/// Request handler - gets called when a request is received. Sends the query back through the
/// `response_tx` channel, initiates a graceful shutdown via the `shutdown_tx` channel, and
/// displays a message to the user.
async fn handle(
    Query(response): Query<crate::AuthResponse>,
    State(state): State<Arc<Mutex<Option<ServerState>>>>,
) -> &'static str {
    let mut data = state.lock().unwrap();
    let m_data = data.take().expect("state is None?");
    m_data.shutdown_tx.send(()).expect("shutdown send failed");
    m_data
        .response_tx
        .send(response)
        .expect("response send failed");
    "go back to the terminal"
}
