use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, lines: &[String]) {
    let paragraph = Paragraph::new(if lines.is_empty() {
        vec![Line::from("Audit surface is clean.")]
    } else {
        lines.iter().cloned().map(Line::from).collect()
    })
    .block(Block::default().title("Audit").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}
