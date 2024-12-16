pub mod utils;
use utils::init_utils_files;

use crate::{Cmd, Engine, TargetArch};
pub fn test_bin() -> Result<(), String> {
    init_utils_files()
}
