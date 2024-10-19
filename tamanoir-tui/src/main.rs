use std::io;

use clap::{crate_description, crate_version, Command};
use ratatui::{backend::CrosstermBackend, Terminal};
use tamanoir_tui::{
    app::{App, AppResult, TICK_RATE},
    events::{Event, EventHandler},
    handlers::handle_key_events,
    tui::Tui,
};

fn main() -> AppResult<()> {
    Command::new("tamanoir")
        .about(crate_description!())
        .version(crate_version!())
        .get_matches();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This program must be run as root");
        std::process::exit(1);
    }

    let mut app = App::new();

    let backend = CrosstermBackend::new(io::stdout());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(TICK_RATE);
    let mut tui = Tui::new(terminal, events);
    tui.init()?;

    while app.running {
        tui.draw(&mut app)?;
        if let Event::Key(key_event) = tui.events.next()? {
            handle_key_events(key_event, &mut app)?
        }
    }

    tui.exit()?;
    Ok(())
}
