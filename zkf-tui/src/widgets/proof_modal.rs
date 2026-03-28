use crate::dashboard::ProofModalState;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, state: &ProofModalState) {
    if !state.open {
        return;
    }
    frame.render_widget(Clear, area);
    let paragraph = Paragraph::new(
        state
            .lines
            .iter()
            .cloned()
            .map(Line::from)
            .collect::<Vec<_>>(),
    )
    .alignment(Alignment::Left)
    .block(
        Block::default()
            .title(state.title.clone())
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}
