use redb::{Database, TableDefinition, ReadableTable, WritableTable};
use serde::{Deserialize, Serialize};

const COFFEE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("coffee");

#[derive(Serialize, Deserialize)]

pub struct GenEvent {
    pub event_type: u8,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,

    pub tgid: u64,

    pub comm: [u8; 16],
    pub filename: [u8; 512],

    pub dst_ip: u32,
    pub dst_port: u16,

    pub time_stamp: u64,
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::create("coffee.redb")?;
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(COFFEE_TABLE)?;
        let coffee = GenEvent { beans: "arabica".into(), roast: "medium".into() };
        // Serialize to bytes before inserting.
        // bincode is faster and smaller than JSON for internal storage.
        let bytes = bincode::serialize(&coffee)?;
        table.insert("favorite", &bytes)?;
    }
    write_txn.commit()?;

    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(COFFEE_TABLE)?;
    // Clone the bytes to own them outside the transaction scope.
    // redb values borrow from the transaction and cannot outlive it.
    let stored_bytes = table.get("favorite")?.map(|v| v.value().to_vec());

    if let Some(bytes) = stored_bytes {
        let coffee: Coffee = bincode::deserialize(&bytes)?;
        println!("Loaded: {} {}", coffee.beans, coffee.roast);
    }

    Ok(())
}