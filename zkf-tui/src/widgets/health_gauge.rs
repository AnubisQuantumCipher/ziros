use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Gauge},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, health_score: u16) {
    let color = if health_score >= 80 {
        Color::Green
    } else if health_score >= 50 {
        Color::Yellow
    } else {
        Color::Red
    };
    let gauge = Gauge::default()
        .block(Block::default().title("Health").borders(Borders::ALL))
        .gauge_style(Style::default().fg(color))
        .label(format!("{health_score}/100"))
        .percent(health_score.min(100));
    frame.render_widget(gauge, area);
}
