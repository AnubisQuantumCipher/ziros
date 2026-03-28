use std::sync::mpsc::Receiver;
use std::time::Duration;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use zkf_tui::{
    DashboardAction, ProofJobUpdate, ZkDashboard, aegisvault_state, aegisvault_template,
    apply_reference_proof_update, spawn_local_proof_job,
};
use zkf_ui::{ZkTheme, render_proof_banner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let theme = ZkTheme::default();
    let template = aegisvault_template().expect("template");
    println!(
        "{}",
        render_proof_banner(
            &template.program.name,
            template.program.signals.len(),
            template.program.constraints.len(),
            &theme
        )
    );

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let dashboard = ZkDashboard::new();
    let mut state = aegisvault_state();
    let mut receiver: Option<Receiver<ProofJobUpdate>> = None;

    let result = loop {
        terminal.draw(|frame| dashboard.draw(frame, &state))?;

        let mut clear_receiver = false;
        if let Some(active) = receiver.as_ref() {
            while let Ok(message) = active.try_recv() {
                clear_receiver = apply_reference_proof_update(&mut state, message);
            }
        }
        if clear_receiver {
            receiver = None;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match dashboard.handle_key(&mut state, key) {
                    DashboardAction::None => {}
                    DashboardAction::Quit => break Ok(()),
                    DashboardAction::TriggerProof => {
                        if receiver.is_none() {
                            state.begin_proof();
                            receiver = Some(spawn_local_proof_job(
                                template.program.clone(),
                                template.sample_inputs.clone(),
                            ));
                        }
                    }
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
