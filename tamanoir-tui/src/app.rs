use std::error;

use anyhow::Result;
use ratatui::Frame;

use crate::notifications::Notification;

pub type AppResult<T> = Result<T, Box<dyn error::Error>>;

#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub notifications: Vec<Notification>,
}

impl App {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            running: true,
            notifications: Vec::new(),
        })
    }

    pub fn render(&mut self, frame: &mut Frame) {
        todo!()
    }

    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn tick(&mut self) {
        self.notifications.retain(|n| n.ttl > 0);
        self.notifications.iter_mut().for_each(|n| n.ttl -= 1);
    }
}
