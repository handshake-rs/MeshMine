use std::env;
use std::path::Path;
use std::sync::Arc;

use meshmine_storage::{DurableStore, RedbStore, ScanLimits};
use meshmine_work::{
    ACTIVE_LEASE_NAMESPACE, CAPTURE_NAMESPACE, DEVICE_NAMESPACE, LEASE_NAMESPACE, PlannerLimits,
    WorkPlanner,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("meshmine-workd: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    let path = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    match command.as_str() {
        "init" => {
            let store: Arc<dyn DurableStore> = if Path::new(&path).exists() {
                Arc::new(RedbStore::open_existing(&path).map_err(|error| error.to_string())?)
            } else {
                Arc::new(RedbStore::create(&path).map_err(|error| error.to_string())?)
            };
            WorkPlanner::open(store, PlannerLimits::default())
                .map_err(|error| error.to_string())?;
            println!("initialized portable MeshMine work database at {path}");
            Ok(())
        }
        "status" => {
            let store: Arc<dyn DurableStore> =
                Arc::new(RedbStore::open_existing(&path).map_err(|error| error.to_string())?);
            WorkPlanner::open(store.clone(), PlannerLimits::default())
                .map_err(|error| error.to_string())?;
            let limits = ScanLimits {
                maximum_records: 100_000,
                maximum_value_bytes: 64 * 1024,
                maximum_total_bytes: 128 * 1024 * 1024,
            };
            let devices = store
                .scan_namespace(DEVICE_NAMESPACE, limits)
                .map_err(|error| error.to_string())?;
            let leases = store
                .scan_namespace(LEASE_NAMESPACE, limits)
                .map_err(|error| error.to_string())?;
            let active = store
                .scan_namespace(ACTIVE_LEASE_NAMESPACE, limits)
                .map_err(|error| error.to_string())?;
            let pending = store
                .scan_namespace(CAPTURE_NAMESPACE, limits)
                .map_err(|error| error.to_string())?;
            println!("{{");
            println!("  \"registered_devices\": {},", devices.len());
            println!("  \"durable_leases\": {},", leases.len());
            println!("  \"active_leases\": {},", active.len());
            println!("  \"pending_captures\": {}", pending.len());
            println!("}}");
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: meshmine-workd <init|status> <database.redb>".to_owned()
}
