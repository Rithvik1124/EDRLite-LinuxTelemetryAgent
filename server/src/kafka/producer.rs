use crate::config::KafkaConfig;
use crate::error::{KafkaError, KafkaResult};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

pub struct EventProducer {
    producer: FutureProducer,
    topic: String,
    timeout: Duration,
}

impl EventProducer {
    pub fn new(config: KafkaConfig) -> KafkaResult<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.brokers)
            .set("message.timeout.ms", config.timeout_ms.to_string())
            .set("compression.type", "gzip")
            .set("retry.backoff.ms", "500")
            .set("request.required.acks", "all")
            .set("queue.buffering.max.messages", "100000")
            .create()
            .map_err(|e| KafkaError::ClientCreation(e.to_string()))?;

        Ok(EventProducer {
            producer,
            topic: config.topic,
            timeout: Duration::from_secs(config.timeout_ms / 1000),
        })
    }

    pub async fn send_event<K, V>(&self, key: K, payload: V) -> KafkaResult<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let record = FutureRecord::to(&self.topic)
            .payload(payload.as_ref())
            .key(key.as_ref());

        self.producer
            .send(record, self.timeout)
            .await
            .map_err(|(err, _)| KafkaError::MessageSend(err.to_string()))?;

        Ok(())
    }
}