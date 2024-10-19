use std::{
    error,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::channel,
        Arc, Mutex,
    },
    thread::{self, sleep},
    time::Duration,
};

use crate::ebpf;

pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

pub const TICK_RATE: u64 = 100;

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub terminate_signal: Arc<AtomicBool>,
    pub keys: Arc<Mutex<Vec<u32>>>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let (data_sender, data_receiver) = channel();
        let terminate_signal = Arc::new(AtomicBool::new(false));
        ebpf::load(data_sender, terminate_signal.clone());

        let keys = Arc::new(Mutex::new(Vec::new()));

        thread::spawn({
            let keys = keys.clone();
            move || loop {
                if let Ok(key) = data_receiver.recv() {
                    let mut keys = keys.lock().unwrap();
                    if keys.len() == keys.capacity() {
                        keys.reserve(4096);
                    }
                    keys.push(key);
                }
            }
        });

        Self {
            running: true,
            terminate_signal,
            keys,
        }
    }

    pub fn quit(&mut self) {
        self.terminate_signal.store(true, Ordering::Relaxed);
        sleep(Duration::from_millis(160));
        self.running = false;
    }
}
