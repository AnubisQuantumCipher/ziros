use crate::dashboard::VaultEntry;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

pub fn render(frame: &mut Frame<'_>, area: Rect, entries: &[VaultEntry], selected: usize) {
    let rows = entries.iter().map(|entry| {
        Row::new([
            Cell::from(entry.id.clone()),
            Cell::from(entry.site.clone()),
            Cell::from(entry.username.clone()),
            Cell::from(format!("{}%", entry.strength)),
            Cell::from(entry.proof_status.clone()),
        ])
    });
    let widths = [
        ratatui::layout::Constraint::Length(4),
        ratatui::layout::Constraint::Percentage(34),
        ratatui::layout::Constraint::Percentage(30),
        ratatui::layout::Constraint::Length(10),
        ratatui::layout::Constraint::Length(12),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(["ID", "Site", "Username", "Strength", "Proof"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().title("Vault").borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state =
        TableState::default().with_selected(Some(selected.min(entries.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut state);
}
