use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

use crate::{
    app::{App, AppResult},
    event::Event,
    notifications::{Notification, NotificationLevel},
};

pub async fn handle_key_events(
    key_event: KeyEvent,
    app: &mut App,
    sender: mpsc::UnboundedSender<Event>,
) -> AppResult<()> {
    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.quit();
        }

        KeyCode::Char('c') | KeyCode::Char('C') => {
            if key_event.modifiers == KeyModifiers::CONTROL {
                app.quit();
            }
        }
        _ => {}
    }

    Ok(())
}
