use redb::{Database, TableDefinition, ReadableTable,};
use std::path::Path;
const EVENTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events_in");

const PATH: &str = "events_in.redb";
pub fn set_db() -> Result<Database, Box<dyn std::error::Error>> {
    Ok(Database::create(PATH)?)
}