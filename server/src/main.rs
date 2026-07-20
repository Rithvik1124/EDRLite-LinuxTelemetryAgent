use axum::{
    extract::Json,
    routing::post,
    Router,
};
use serde_json::Value;
use std::net::SocketAddr;

async fn receive(Json(payload): Json<Value>) {
    println!("Received JSON:");
    println!("{}", serde_json::to_string_pretty(&payload).unwrap());
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", post(receive));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    println!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}