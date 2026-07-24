use redb::{Database, TableDefinition, ReadableTable, ReadableDatabase};
use serde::{Deserialize, Serialize};
//mod initialize_db;
use crate::telemetry::TelemetryEvent;
use std::hash::{DefaultHasher, Hash, Hasher};
const EVENTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events_in");


// #[derive(Serialize, Deserialize, Hash, Debug)]
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
// impl Hash for GenEvent {
//     fn hash<H: Hasher>(&self, state: &mut H) {
//         self.pid.hash(state);
//         self.time_stamp.hash(state);
//         self.filename.hash(state);
//     }
// }

// fn calculate_hash<T: Hash>(t: &T) -> u64 {
//     let mut s = DefaultHasher::new();
//     t.hash(&mut s);
//     s.finish()
// }

fn calculate_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}




pub fn write_event(event: TelemetryEvent) -> Result<(), Box<dyn std::error::Error>>{
    let db = crate::db::initialize_db::set_db()?;
    println!("Starting write");
    let event_id = calculate_hash(&event);
    let write_txn = db.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(EVENTS_TABLE)?;
        
        //event.insert("event_id",calculate_hash(&event));
        // Serialize to bytes before inserting.
        // bincode is faster and smaller than JSON for internal storage.
        let bytes = bincode::serde::encode_to_vec(
            &event,
            bincode::config::standard(),
        )?;
        table.insert(event_id, &bytes.as_slice())?;
    }
    write_txn.commit()?;
    // Ok(())

    let read_txn = db.begin_read()?;
    println!("Opened DB");
    let table = read_txn.open_table(EVENTS_TABLE)?;
    // // Clone the bytes to own them outside the transaction scope.
    // // redb values borrow from the transaction and cannot outlive it.
    let stored_bytes = table.get(event_id)?.map(|v| v.value().to_vec());

    if let Some(bytes) = stored_bytes {
        let (coffee, _): (TelemetryEvent, usize) =
        bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard(),
        )?;
        println!("Loaded: {:?}", coffee);
    }
    Ok(())

}

