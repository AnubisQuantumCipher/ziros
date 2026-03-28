use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Sparkline},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, samples: &[u64], proof_running: bool) {
    if samples.is_empty() {
        let paragraph = Paragraph::new(vec![Line::from("Awaiting proof telemetry.")])
            .block(Block::default().title("Activity").borders(Borders::ALL));
        frame.render_widget(paragraph, area);
        return;
    }

    let sparkline = Sparkline::default()
        .block(Block::default().title("Activity").borders(Borders::ALL))
        .style(Style::default().fg(if proof_running {
            Color::Cyan
        } else {
            Color::Green
        }))
        .data(samples);
    frame.render_widget(sparkline, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn proof_animation_renders_idle_message_without_samples() {
        let backend = TestBackend::new(60, 6);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render(frame, frame.area(), &[], false))
            .expect("draw should work");

        let buffer = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(buffer.contains("Activity"));
        assert!(buffer.contains("Awaiting"));
    }

    #[test]
    fn proof_animation_renders_sparkline_with_samples() {
        let backend = TestBackend::new(60, 6);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render(frame, frame.area(), &[9, 12, 7, 18], true))
            .expect("draw should work");

        let buffer = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(buffer.contains("Activity"));
    }
}
