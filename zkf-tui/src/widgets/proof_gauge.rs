use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Gauge},
};

pub fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    proof_percent: u16,
    stage_label: &str,
    proof_running: bool,
) {
    let color = if proof_percent >= 100 {
        Color::Green
    } else if proof_running {
        Color::Cyan
    } else {
        Color::Yellow
    };
    let gauge = Gauge::default()
        .block(Block::default().title("Proof").borders(Borders::ALL))
        .gauge_style(Style::default().fg(color))
        .label(format!("{stage_label} · {}%", proof_percent.min(100)))
        .percent(proof_percent.min(100));
    frame.render_widget(gauge, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn proof_gauge_renders_title_and_stage() {
        let backend = TestBackend::new(60, 6);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render(frame, frame.area(), 65, "Constraint check running", true))
            .expect("draw should work");

        let buffer = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(buffer.contains("Proof"));
        assert!(buffer.contains("Constraint"));
    }
}
