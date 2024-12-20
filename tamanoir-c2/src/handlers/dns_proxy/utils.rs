use std::{collections::HashMap, sync::OnceLock};

use crate::{KeyMap, Layout};

pub static KEYMAPS: OnceLock<HashMap<u8, KeyMap>> = OnceLock::new();
const AZERTY: &str = include_str!("../../../../assets/layouts/azerty.yml");
const QWERTY: &str = include_str!("../../../../assets/layouts/qwerty.yml");

pub fn init_keymaps() {
    let mut map = HashMap::<u8, KeyMap>::new();
    map.insert(
        Layout::Azerty as u8,
        serde_yaml::from_str::<KeyMap>(AZERTY).unwrap(),
    );
    map.insert(
        Layout::Qwerty as u8,
        serde_yaml::from_str::<KeyMap>(QWERTY).unwrap(),
    );
    KEYMAPS.set(map).expect("Error initializing KEYMAPS");
}
