use std::{collections::HashMap, sync::OnceLock};

pub static UTILS_FILES: OnceLock<HashMap<String, &str>> = OnceLock::new();
const CORGO_TOML: &str = include_str!("../../rce-tester/Cargo.toml");
const MAIN_RS: &str = include_str!("../../rce-tester/src/main.rs");

pub fn init_utils_files() -> Result<(), String> {
    let mut map: HashMap<String, &str> = HashMap::<String, &str>::new();
    map.insert("Cargo.toml".into(), CORGO_TOML);
    map.insert("main.rs".into(), MAIN_RS);
    UTILS_FILES
        .set(map)
        .map_err(|_| "Error initializing UTILS_FILES")?;
    Ok(())
}
