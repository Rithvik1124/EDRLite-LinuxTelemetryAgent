
use crate::config::KafkaConfig;
use crate::error::KafkaResult;
use crate::kafka::consumer::MessageHandler;
use crate::kafka::{EventConsumer, EventProducer};
use async_trait::async_trait;
use std::time::Duration;
use chrono::Utc;

mod config;
mod error;
mod kafka;

struct MessagePrinter {}

impl MessagePrinter {
    fn new() -> Box<Self> {
        Box::new(MessagePrinter {})
    }
}

#[async_trait]
impl MessageHandler for MessagePrinter {
    async fn handle(&self, key: &[u8], payload: &[u8]) -> KafkaResult<()> {
        println!("Key: {}", String::from_utf8_lossy(key));
        println!("Payload: {}", String::from_utf8_lossy(payload));

        Ok(())
    }
}

#[tokio::main]
async fn main() -> KafkaResult<()> {
    tracing_subscriber::fmt::init();
    
    let config = KafkaConfig::default();

    let producer = EventProducer::new(config.clone())?;
    let consumer = EventConsumer::new(config, MessagePrinter::new())?;

    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let key = Utc::now().timestamp().to_string();
                    match producer.send_event(&key, "I'm a payload").await {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!("{:?}", e);
                        }
                    }
                }
            }
        }
    });

    consumer.start().await?;
    Ok(())
}