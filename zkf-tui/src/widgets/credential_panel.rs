use crate::dashboard::VaultEntry;
use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, entry: Option<&VaultEntry>) {
    let lines = if let Some(entry) = entry {
        vec![
            Line::from(format!("Site: {}", entry.site)),
            Line::from(format!("Username: {}", entry.username)),
            Line::from(format!("Category: {}", entry.category)),
            Line::from(format!("Strength: {}%", entry.strength)),
            Line::from(format!("Status: {}", entry.proof_status)),
            Line::from(""),
            Line::from("Press P to prove the selected credential."),
        ]
    } else {
        vec![Line::from("No credential selected.")]
    };

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Credential").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}
