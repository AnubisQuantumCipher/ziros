use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, commands: &[&str]) {
    let paragraph = Paragraph::new(commands.join("  "))
        .block(Block::default().title("Commands").borders(Borders::ALL));
    frame.render_widget(paragraph, area);
}
