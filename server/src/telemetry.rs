//because using TelemetryEvent separately in both main.rs and events.rs gave error
use std::hash::{DefaultHasher, Hash, Hasher};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Hash, Debug)]
pub struct TelemetryEvent {     
    pub event_type: String,         
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u64,

    pub comm: String,
    pub filename: String,

    pub dst_ip: String, //max 15 bytes
    pub dst_port: String, //max 5 bytes

    pub time_stamp: String,
}