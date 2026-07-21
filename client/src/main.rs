use reqwest::Client;
use serde::Serialize;

#[derive(Serialize)]
struct Event {
    id: u32,
    name: String,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let event = Event {
        id: 1,
        name: "Alice".to_string(),
        message: "Hello mpsc!".to_string(),
    };

    let response = client
        .post("http://localhost:3000/publish")
        .json(&event)
        .send()
        .await?;

    println!("{}", response.text().await?);

    Ok(())
}