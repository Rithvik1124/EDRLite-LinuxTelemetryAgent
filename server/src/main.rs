use axum::{
    extract::State,
    routing::post,
    Json,
    Router,
};
mod db;
mod telemetry;
use crate::telemetry::TelemetryEvent;
mod detect;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

// #[derive(Debug, Default, Clone, Serialize, Deserialize)]
// pub struct TelemetryEvent {
//     pub event_type: String,
//     pub pid: u32,
//     pub ppid: u32,
//     pub uid: u32,
//     pub gid: u32,
//     pub tgid: u64,

//     pub comm: String,
//     pub filename: String,

//     pub dst_ip: String,
//     pub dst_port: String,

//     pub time_stamp: String,
// }

#[derive(Clone)]
struct AppState {
    sender: mpsc::Sender<TelemetryEvent>,
}

async fn publish(
    State(state): State<AppState>,
    Json(event): Json<TelemetryEvent>,
) -> &'static str {
    if state.sender.send(event).await.is_err() {
        return "Queue is closed";
    }

    "Event queued successfully"
}

#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel::<TelemetryEvent>(100_000);

    let rx = Arc::new(Mutex::new(rx));

    for worker_id in 0..2 {
        let rx = rx.clone();

        tokio::spawn(async move {
            loop {
                let event = {
                    let mut rx = rx.lock().await;
                    rx.recv().await
                };

                match event {
                    Some(event) => {
                        crate::db::events_in::write_event(event);
                    }
                    None => break,
                }
            }
        });
    }

    let app = Router::new()
        .route("/publish", post(publish))
        .with_state(AppState { sender: tx });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    println!("Listening on http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}