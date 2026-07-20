#[derive(Debug, Clone)]
pub struct KafkaConfig {
    pub brokers: String,
    pub topic: String,
    pub group_id: String,
    pub timeout_ms: u64,
    pub max_retries: u32,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: "localhost:9092".to_string(),
            topic: "events".to_string(),
            group_id: "kafka-streaming-group".to_string(),
            timeout_ms: 5000,
            max_retries: 5,
        }
    }
}