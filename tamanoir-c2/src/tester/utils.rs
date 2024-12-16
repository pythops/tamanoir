//pub static UTILS_FILES: OnceLock<HashMap<String, &str>> = OnceLock::new();

use walkdir::WalkDir;

pub fn init_utils_files() -> Result<(), String> {
    for entry in WalkDir::new("../../rce-tester") {
        println!("{}", entry.map_err(|_| "error")?.path().display());
    }
    Ok(())
}
