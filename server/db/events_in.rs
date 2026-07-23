use redb::{Database, TableDefinition, ReadableTable, ReadableDatabase};
use serde::{Deserialize, Serialize};
mod initialize_db;
use std::{collections::HashMap, hash::{DefaultHasher, Hash, Hasher}};
const EVENTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events_in");

// event.insert("Mode".to_string(), mode);
// event.insert("PID".to_string(), buff_event.pid.to_string());
// event.insert("PPID".to_string(), buff_event.ppid.to_string());
// event.insert("UID".to_string(), buff_event.uid.to_string());
// event.insert("GID".to_string(), buff_event.gid.to_string());
// event.insert("TGID".to_string(), buff_event.tgid.to_string());
// event.insert("Image".to_string(), convert_result_to_string(&buff_event.filename));
// event.insert("TimeStamp".to_string(), nanosec_to_24_hr(buff_event.time_stamp));
// event.insert("CommandLine".to_string(), cmdline);

#[derive(Serialize, Deserialize, Hash, Debug)]
pub struct GenEvent {
    pub event_id: String,
    pub event_type: u8,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u64,
    pub comm: String,
    pub filename: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub time_stamp: String,
}

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




fn write_event(event: GenEvent) -> Result<(), Box<dyn std::error::Error>>{
    let db = crate::initialize_db::set_db()?;
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

    let read_txn = db.begin_read()?;
    println!("Opened DB");
    let table = read_txn.open_table(EVENTS_TABLE)?;
    // // Clone the bytes to own them outside the transaction scope.
    // // redb values borrow from the transaction and cannot outlive it.
    let stored_bytes = table.get(event_id)?.map(|v| v.value().to_vec());

    if let Some(bytes) = stored_bytes {
        let (coffee, _): (HashMap<String, String>, usize) =
        bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard(),
        )?;
        println!("Loaded: {:?}", coffee);
    }
    Ok(())

}

fn main(){
    let mut x:HashMap<String, String> = HashMap::new();

    x.insert("UID".into(), "1000".into());
    x.insert("Image".into(), "/usr/bin/cat".into());
    x.insert("TGID".into(), "112794431153814".into());
    x.insert("CommandLine".into(), "cat".into());
    x.insert("PID".into(), "26262".into());
    x.insert("PPID".into(), "26239".into());
    x.insert("GID".into(), "1000".into());
    x.insert("Mode".into(), "Fork".into());
    x.insert("TimeStamp".into(), "3ms".into());
    if let Err(e) = write_event(x) {
    eprintln!("Error: {e}");
    print!("Done");
}

}