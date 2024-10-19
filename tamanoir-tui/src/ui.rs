use ratatui::{
    widgets::{Block, Borders, Padding, Paragraph, Wrap},
    Frame,
};

use crate::app::App;

pub fn render(app: &mut App, frame: &mut Frame) {
    let keys = { app.keys.lock().unwrap().clone() };
    let keys = keys.iter().map(|k| k.to_string()).collect::<Vec<String>>();
    let text = Paragraph::new(keys.join(" "))
        .block(
            Block::new()
                .borders(Borders::all())
                .padding(Padding::uniform(2)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(text, frame.area());
}
