use crate::widgets;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};
use zkf_lib::{ProofEvent, ProofStage};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VaultEntry {
    pub id: String,
    pub site: String,
    pub username: String,
    pub category: String,
    pub strength: u16,
    pub proof_status: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofModalState {
    pub open: bool,
    pub title: String,
    pub lines: Vec<String>,
}

impl Default for ProofModalState {
    fn default() -> Self {
        Self {
            open: false,
            title: "Proof".to_string(),
            lines: vec!["No proof has been requested yet.".to_string()],
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DashboardState {
    pub entries: Vec<VaultEntry>,
    pub selected: usize,
    pub health_score: u16,
    pub proof_percent: u16,
    pub proof_stage_label: String,
    pub proof_activity_samples: Vec<u64>,
    pub proof_running: bool,
    pub audit_lines: Vec<String>,
    pub status_line: String,
    pub proof_modal: ProofModalState,
}

impl DashboardState {
    const PROOF_SAMPLE_LIMIT: usize = 12;

    pub fn selected_entry(&self) -> Option<&VaultEntry> {
        self.entries.get(self.selected)
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1).min(self.entries.len() - 1);
        }
    }

    pub fn open_modal(&mut self, title: impl Into<String>, lines: Vec<String>) {
        self.proof_modal.open = true;
        self.proof_modal.title = title.into();
        self.proof_modal.lines = lines;
    }

    pub fn close_modal(&mut self) {
        self.proof_modal.open = false;
    }

    pub fn begin_proof(&mut self) {
        self.proof_percent = 0;
        self.proof_stage_label = "Queued".to_string();
        self.proof_activity_samples.clear();
        self.proof_running = true;
        self.status_line = "Proof running...".to_string();
        self.open_proof_progress_modal();
    }

    pub fn finish_proof(&mut self, verified: bool) {
        self.proof_running = false;
        self.proof_percent = 100;
        self.proof_stage_label = if verified {
            "Verification passed".to_string()
        } else {
            "Verification failed".to_string()
        };
    }

    pub fn fail_proof(&mut self, message: &str) {
        self.proof_running = false;
        self.proof_stage_label = "Proof failed".to_string();
        self.status_line = format!("Proof failed: {message}");
    }

    pub fn open_proof_progress_modal(&mut self) {
        self.open_modal("Proof Progress", self.proof_progress_lines());
    }

    pub fn proof_progress_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Stage: {}", self.proof_stage_label),
            format!("Progress: {}%", self.proof_percent),
            format!(
                "State: {}",
                if self.proof_running {
                    "running"
                } else {
                    "idle"
                }
            ),
        ];
        if !self.proof_activity_samples.is_empty() {
            let recent = self
                .proof_activity_samples
                .iter()
                .rev()
                .take(6)
                .copied()
                .collect::<Vec<_>>();
            let recent = recent
                .iter()
                .rev()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("Recent stage durations (ms): {recent}"));
        }
        lines
    }

    pub fn apply_proof_event(&mut self, event: &ProofEvent) {
        match event {
            ProofEvent::StageStarted { stage } => {
                self.proof_percent = stage_started_percent(*stage);
                self.proof_stage_label = format!("{} running", stage.label());
                self.proof_running = true;
            }
            ProofEvent::CompileCompleted { duration_ms, .. } => {
                self.push_proof_sample(*duration_ms);
                self.proof_percent = 25;
                self.proof_stage_label = "Compile complete".to_string();
                self.proof_running = true;
            }
            ProofEvent::WitnessCompleted { duration_ms, .. } => {
                self.push_proof_sample(*duration_ms);
                self.proof_percent = 50;
                self.proof_stage_label = "Witness built".to_string();
                self.proof_running = true;
            }
            ProofEvent::PrepareWitnessCompleted {
                duration_ms,
                public_inputs,
                ..
            } => {
                self.push_proof_sample(*duration_ms);
                self.proof_percent = 75;
                self.proof_stage_label =
                    format!("Constraint check passed ({public_inputs} public inputs)");
                self.proof_running = true;
            }
            ProofEvent::ProveCompleted {
                duration_ms,
                proof_size_bytes,
                ..
            } => {
                self.push_proof_sample(*duration_ms);
                self.proof_percent = 100;
                self.proof_stage_label = format!("Proof sealed ({proof_size_bytes} bytes)");
                self.proof_running = false;
            }
        }

        if self.proof_modal.open && self.proof_modal.title == "Proof Progress" {
            self.proof_modal.lines = self.proof_progress_lines();
        }
    }

    fn push_proof_sample(&mut self, duration_ms: u128) {
        let sample = u64::try_from(duration_ms).unwrap_or(u64::MAX);
        self.proof_activity_samples.push(sample);
        if self.proof_activity_samples.len() > Self::PROOF_SAMPLE_LIMIT {
            let overflow = self.proof_activity_samples.len() - Self::PROOF_SAMPLE_LIMIT;
            self.proof_activity_samples.drain(0..overflow);
        }
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            selected: 0,
            health_score: 0,
            proof_percent: 0,
            proof_stage_label: "Idle".to_string(),
            proof_activity_samples: Vec::new(),
            proof_running: false,
            audit_lines: Vec::new(),
            status_line: "Ready".to_string(),
            proof_modal: ProofModalState::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DashboardAction {
    None,
    Quit,
    TriggerProof,
}

pub struct ZkDashboard {
    commands: [&'static str; 5],
}

impl Default for ZkDashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkDashboard {
    pub fn new() -> Self {
        Self {
            commands: [
                "↑/↓ Move",
                "Enter Details",
                "P Prove",
                "Esc Close",
                "Q Quit",
            ],
        }
    }

    pub fn handle_key(&self, state: &mut DashboardState, key: KeyEvent) -> DashboardAction {
        match key.code {
            KeyCode::Char('q') => DashboardAction::Quit,
            KeyCode::Up => {
                state.move_up();
                DashboardAction::None
            }
            KeyCode::Down => {
                state.move_down();
                DashboardAction::None
            }
            KeyCode::Esc => {
                state.close_modal();
                DashboardAction::None
            }
            KeyCode::Enter => {
                if let Some(entry) = state.selected_entry() {
                    state.open_modal(
                        format!("Credential {}", entry.id),
                        vec![
                            format!("Site: {}", entry.site),
                            format!("Username: {}", entry.username),
                            format!("Category: {}", entry.category),
                            format!("Strength: {}%", entry.strength),
                            format!("Status: {}", entry.proof_status),
                        ],
                    );
                }
                DashboardAction::None
            }
            KeyCode::Char('p') => DashboardAction::TriggerProof,
            _ => DashboardAction::None,
        }
    }

    pub fn draw(&self, frame: &mut Frame<'_>, state: &DashboardState) {
        if frame.area().width >= 110 && frame.area().height >= 28 {
            self.draw_wide(frame, state);
        } else {
            self.draw_compact(frame, state);
        }

        if state.proof_modal.open {
            widgets::proof_modal::render(
                frame,
                centered_rect(frame.area(), 72, 60),
                &state.proof_modal,
            );
        }
    }

    fn draw_wide(&self, frame: &mut Frame<'_>, state: &DashboardState) {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(12),
                Constraint::Length(5),
                Constraint::Length(3),
            ])
            .split(frame.area());
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(38),
                Constraint::Percentage(34),
                Constraint::Percentage(28),
            ])
            .split(root[0]);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(5),
                Constraint::Min(6),
            ])
            .split(body[2]);
        let lower = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(root[1]);

        widgets::vault_table::render(frame, body[0], &state.entries, state.selected);
        widgets::credential_panel::render(frame, body[1], state.selected_entry());
        widgets::health_gauge::render(frame, right[0], state.health_score);
        widgets::proof_gauge::render(
            frame,
            right[1],
            state.proof_percent,
            &state.proof_stage_label,
            state.proof_running,
        );
        widgets::audit_panel::render(frame, right[2], &state.audit_lines);
        widgets::proof_animation::render(
            frame,
            lower[1],
            &state.proof_activity_samples,
            state.proof_running,
        );
        widgets::command_bar::render(frame, root[2], &self.commands);
        widgets::status_panel::render(frame, lower[0], &state.status_line);
    }

    fn draw_compact(&self, frame: &mut Frame<'_>, state: &DashboardState) {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Min(6),
                Constraint::Min(4),
                Constraint::Length(5),
                Constraint::Length(4),
                Constraint::Length(3),
            ])
            .split(frame.area());
        let metrics = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(36),
                Constraint::Percentage(36),
            ])
            .split(root[3]);

        widgets::vault_table::render(frame, root[0], &state.entries, state.selected);
        widgets::credential_panel::render(frame, root[1], state.selected_entry());
        widgets::audit_panel::render(frame, root[2], &state.audit_lines);
        widgets::health_gauge::render(frame, metrics[0], state.health_score);
        widgets::proof_gauge::render(
            frame,
            metrics[1],
            state.proof_percent,
            &state.proof_stage_label,
            state.proof_running,
        );
        widgets::proof_animation::render(
            frame,
            metrics[2],
            &state.proof_activity_samples,
            state.proof_running,
        );
        widgets::status_panel::render(frame, root[4], &state.status_line);
        widgets::command_bar::render(frame, root[5], &self.commands);
    }
}

fn centered_rect(area: Rect, width_pct: u16, height_pct: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height_pct) / 2),
            Constraint::Percentage(height_pct),
            Constraint::Percentage((100 - height_pct) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_pct) / 2),
            Constraint::Percentage(width_pct),
            Constraint::Percentage((100 - width_pct) / 2),
        ])
        .split(vertical[1])[1]
}

fn stage_started_percent(stage: ProofStage) -> u16 {
    match stage {
        ProofStage::Compile => 10,
        ProofStage::Witness => 35,
        ProofStage::PrepareWitness => 65,
        ProofStage::Prove => 85,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn sample_state() -> DashboardState {
        DashboardState {
            entries: vec![
                VaultEntry {
                    id: "1".to_string(),
                    site: "mail.zir".to_string(),
                    username: "alice".to_string(),
                    category: "email".to_string(),
                    strength: 91,
                    proof_status: "Ready".to_string(),
                },
                VaultEntry {
                    id: "2".to_string(),
                    site: "bank.zir".to_string(),
                    username: "alice.reserve".to_string(),
                    category: "finance".to_string(),
                    strength: 84,
                    proof_status: "Pending".to_string(),
                },
            ],
            selected: 0,
            health_score: 88,
            proof_percent: 75,
            proof_stage_label: "Constraint check passed".to_string(),
            proof_activity_samples: vec![9, 12, 18],
            proof_running: true,
            audit_lines: vec!["Soundness checks passed.".to_string()],
            status_line: "AegisVault dashboard ready".to_string(),
            proof_modal: ProofModalState::default(),
        }
    }

    #[test]
    fn dashboard_navigation_and_modal_controls_work() {
        let dashboard = ZkDashboard::new();
        let mut state = sample_state();

        assert_eq!(
            dashboard.handle_key(&mut state, key(KeyCode::Down)),
            DashboardAction::None
        );
        assert_eq!(state.selected, 1);
        assert_eq!(
            dashboard.handle_key(&mut state, key(KeyCode::Enter)),
            DashboardAction::None
        );
        assert!(state.proof_modal.open);
        assert_eq!(
            dashboard.handle_key(&mut state, key(KeyCode::Esc)),
            DashboardAction::None
        );
        assert!(!state.proof_modal.open);
        assert_eq!(
            dashboard.handle_key(&mut state, key(KeyCode::Char('p'))),
            DashboardAction::TriggerProof
        );
        assert_eq!(
            dashboard.handle_key(&mut state, key(KeyCode::Char('q'))),
            DashboardAction::Quit
        );
    }

    #[test]
    fn dashboard_renders_key_panels() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let dashboard = ZkDashboard::new();
        let state = sample_state();

        terminal
            .draw(|frame| dashboard.draw(frame, &state))
            .expect("draw should work");

        let buffer = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(buffer.contains("Vault"));
        assert!(buffer.contains("Credential"));
        assert!(buffer.contains("Health"));
        assert!(buffer.contains("Proof"));
        assert!(buffer.contains("Audit"));
        assert!(buffer.contains("Activity"));
        assert!(buffer.contains("AegisVault dashboard ready"));
    }

    #[test]
    fn proof_event_mapping_updates_progress_state_and_modal_lines() {
        let mut state = DashboardState::default();

        state.begin_proof();
        assert!(state.proof_modal.open);
        assert_eq!(state.proof_percent, 0);
        assert_eq!(state.proof_stage_label, "Queued");

        state.apply_proof_event(&ProofEvent::StageStarted {
            stage: ProofStage::Compile,
        });
        assert_eq!(state.proof_percent, 10);
        assert!(state.proof_running);
        assert!(
            state
                .proof_modal
                .lines
                .iter()
                .any(|line| line.contains("10%"))
        );

        state.apply_proof_event(&ProofEvent::CompileCompleted {
            backend: zkf_lib::BackendKind::ArkworksGroth16,
            signal_count: 3,
            constraint_count: 2,
            duration_ms: 14,
        });
        state.apply_proof_event(&ProofEvent::WitnessCompleted {
            witness_values: 4,
            duration_ms: 21,
        });
        state.apply_proof_event(&ProofEvent::PrepareWitnessCompleted {
            witness_values: 4,
            public_inputs: 1,
            duration_ms: 8,
        });
        state.apply_proof_event(&ProofEvent::ProveCompleted {
            backend: zkf_lib::BackendKind::ArkworksGroth16,
            proof_size_bytes: 128,
            duration_ms: 33,
        });

        assert_eq!(state.proof_percent, 100);
        assert_eq!(state.proof_activity_samples, vec![14, 21, 8, 33]);
        assert!(!state.proof_running);
        assert!(state.proof_stage_label.contains("128 bytes"));
    }
}
