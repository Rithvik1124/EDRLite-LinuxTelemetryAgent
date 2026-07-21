use axum::{
    extract::State,
    routing::post,
    Json,
    Router,
};

use serde::{Deserialize, Serialize};

use tokio::sync::{
    mpsc,
    Mutex,
};

use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct TelemetryEvent {
    event_type: u8,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,

    tgid: u64,

    comm: String,
    filename: String,

    dst_ip: u32,
    dst_port: u16,

    time_stamp: u64,
}

#[derive(Clone)]
struct AppState {
    sender: mpsc::Sender<TelemetryEvent>,
}

async fn publish(
    State(state): State<AppState>,
    Json(event): Json<TelemetryEvent>,
) -> &'static str {
    if let Err(_) = state.sender.send(event).await {
        return "Queue is closed";
    }

    "Event queued successfully"
}

#[tokio::main]
async fn main() {
    // Queue capable of holding 100,000 events
    let (tx, rx) = mpsc::channel::<TelemetryEvent>(100_000);

    // Receiver must be shared safely
    let rx = Arc::new(Mutex::new(rx));

    // Spawn two worker tasks
    for worker_id in 0..2 {
        let rx = rx.clone();

        tokio::spawn(async move {
            loop {
                let event = {
                    let mut receiver = rx.lock().await;
                    receiver.recv().await
                };

                match event {
                    Some(event) => {
                        println!(
                            "[Worker {}] Processing: {:?}",
                            worker_id,
                            event
                        );

                        // Simulate Sigma processing
                        // run_sigma(event).await;
                    }

                    None => break,
                }
            }
        });
    }

    let state = AppState { sender: tx };

    let app = Router::new()
        .route("/publish", post(publish))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    println!("Server running on http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}