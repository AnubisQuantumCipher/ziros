use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use std::sync::mpsc::{self, Receiver};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardAction {
    None,
    Quit,
    TriggerProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    pub id: String,
    pub site: String,
    pub username: String,
    pub category: String,
    pub strength: u8,
    pub proof_status: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProofModal {
    pub title: String,
    pub lines: Vec<String>,
    pub open: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofProgressEvent {
    pub percent: u16,
    pub stage_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofJobResult {
    pub verified: bool,
    pub progress_lines: Vec<String>,
    pub proof_summary: String,
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofJobUpdate {
    Event(ProofProgressEvent),
    Finished(ProofJobResult),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardState {
    pub entries: Vec<VaultEntry>,
    pub selected: usize,
    pub health_score: u16,
    pub proof_percent: u16,
    pub proof_stage_label: String,
    pub proof_activity_samples: Vec<u16>,
    pub proof_running: bool,
    pub audit_lines: Vec<String>,
    pub status_line: String,
    pub proof_modal: ProofModal,
}

impl DashboardState {
    pub fn begin_proof(&mut self) {
        self.proof_running = true;
        self.proof_percent = 0;
        self.proof_stage_label = "Starting".to_string();
        self.status_line = "Proof job started.".to_string();
    }

    pub fn apply_proof_event(&mut self, event: &ProofProgressEvent) {
        self.proof_percent = event.percent.min(100);
        self.proof_stage_label = event.stage_label.clone();
        self.proof_activity_samples.push(self.proof_percent);
        if self.proof_activity_samples.len() > 32 {
            let keep_from = self.proof_activity_samples.len() - 32;
            self.proof_activity_samples.drain(0..keep_from);
        }
    }

    pub fn finish_proof(&mut self, verified: bool) {
        self.proof_running = false;
        self.proof_percent = 100;
        self.proof_stage_label = if verified {
            "Verified".to_string()
        } else {
            "Failed".to_string()
        };
        self.status_line = if verified {
            "Proof completed successfully.".to_string()
        } else {
            "Proof finished but verification failed.".to_string()
        };
    }

    pub fn fail_proof(&mut self, message: &str) {
        self.proof_running = false;
        self.proof_stage_label = "Failed".to_string();
        self.status_line = message.to_string();
    }

    pub fn open_modal(&mut self, title: impl Into<String>, lines: Vec<String>) {
        self.proof_modal = ProofModal {
            title: title.into(),
            lines,
            open: true,
        };
    }

    fn close_modal(&mut self) {
        self.proof_modal = ProofModal::default();
    }
}

#[derive(Debug, Default)]
pub struct ZkDashboard;

impl ZkDashboard {
    pub fn new() -> Self {
        Self
    }

    pub fn draw(&self, frame: &mut Frame<'_>, state: &DashboardState) {
        let area = frame.area();
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(5),
                Constraint::Length(3),
            ])
            .split(area);

        let header = Paragraph::new(format!(
            "Health {} | Proof {}% | Stage {}",
            state.health_score, state.proof_percent, state.proof_stage_label
        ))
        .block(Block::default().title("ZirOS TUI").borders(Borders::ALL));
        frame.render_widget(header, rows[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(rows[1]);

        let entries = state
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let marker = if index == state.selected { ">" } else { " " };
                ListItem::new(format!(
                    "{marker} {} ({}) [{}]",
                    entry.site, entry.username, entry.proof_status
                ))
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            List::new(entries).block(Block::default().title("Vault").borders(Borders::ALL)),
            body[0],
        );

        let audit = Paragraph::new(state.audit_lines.join("\n"))
            .block(Block::default().title("Audit").borders(Borders::ALL));
        frame.render_widget(audit, body[1]);

        let status = Paragraph::new(state.status_line.as_str())
            .block(Block::default().title("Status").borders(Borders::ALL));
        frame.render_widget(status, rows[2]);

        let footer = Paragraph::new("Keys: Up/Down select, P prove, Q quit, Esc close modal")
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, rows[3]);

        if state.proof_modal.open {
            let popup = centered_rect(80, 60, area);
            frame.render_widget(Clear, popup);
            let modal = Paragraph::new(state.proof_modal.lines.join("\n")).block(
                Block::default()
                    .title(state.proof_modal.title.as_str())
                    .borders(Borders::ALL),
            );
            frame.render_widget(modal, popup);
        }
    }

    pub fn handle_key(&self, state: &mut DashboardState, key: KeyEvent) -> DashboardAction {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => DashboardAction::Quit,
            KeyCode::Char('p') | KeyCode::Char('P') => DashboardAction::TriggerProof,
            KeyCode::Esc | KeyCode::Enter if state.proof_modal.open => {
                state.close_modal();
                DashboardAction::None
            }
            KeyCode::Up => {
                if state.selected > 0 {
                    state.selected -= 1;
                }
                DashboardAction::None
            }
            KeyCode::Down => {
                if state.selected + 1 < state.entries.len() {
                    state.selected += 1;
                }
                DashboardAction::None
            }
            _ => DashboardAction::None,
        }
    }
}

pub fn run_local_proof_demo_with_backend(
    program: &zkf_lib::Program,
    inputs: &zkf_lib::WitnessInputs,
    backend: &str,
) -> Result<ProofJobResult, String> {
    let embedded = zkf_lib::compile_and_prove_with_progress_backend(
        program,
        inputs,
        backend,
        None,
        None,
        |_| {},
    )
    .map_err(|error| error.to_string())?;
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)
        .map_err(|error| error.to_string())?;
    if !verified {
        return Err("proof verification failed".to_string());
    }

    let progress_lines = vec![
        format!("backend selected: {backend}"),
        format!(
            "constraint count: {}",
            embedded.compiled.program.constraints.len()
        ),
        format!("public inputs: {}", embedded.artifact.public_inputs.len()),
        "verification: ok".to_string(),
    ];

    Ok(ProofJobResult {
        verified,
        proof_summary: format!(
            "proof verified with backend {backend} and {} public inputs",
            embedded.artifact.public_inputs.len()
        ),
        credential: format!(
            "program={} public_inputs={:?}",
            embedded.compiled.program.name, embedded.artifact.public_inputs
        ),
        progress_lines,
    })
}

pub fn spawn_local_proof_job_with_backend(
    program: zkf_lib::Program,
    inputs: zkf_lib::WitnessInputs,
    backend: String,
) -> Receiver<ProofJobUpdate> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ProofJobUpdate::Event(ProofProgressEvent {
            percent: 5,
            stage_label: "Compile".to_string(),
        }));
        match run_local_proof_demo_with_backend(&program, &inputs, &backend) {
            Ok(result) => {
                let _ = tx.send(ProofJobUpdate::Event(ProofProgressEvent {
                    percent: 100,
                    stage_label: "Verified".to_string(),
                }));
                let _ = tx.send(ProofJobUpdate::Finished(result));
            }
            Err(error) => {
                let _ = tx.send(ProofJobUpdate::Failed(error));
            }
        }
    });
    rx
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
