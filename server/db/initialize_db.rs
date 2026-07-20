use redb::{Database, TableDefinition, ReadableTable, WritableTable};
use serde::{Deserialize, Serialize};

const EVENTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("events_in");


fn initialize_events_db() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::create("coffee.redb")?;
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(EVENTS_TABLE)?;
        /*
        let coffee = Coffee { beans: "arabica".into(), roast: "medium".into() };
        // Serialize to bytes before inserting.
        // bincode is faster and smaller than JSON for internal storage.
        let bytes = bincode::serialize(&coffee)?;
        table.insert("favorite", &bytes)?;*/
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