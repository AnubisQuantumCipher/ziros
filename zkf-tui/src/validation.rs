use crate::{
    DashboardState, ZkDashboard,
    reference_apps::{aegisvault_state, aegisvault_template},
    run_local_proof_demo,
};
use ratatui::{Terminal, backend::TestBackend};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TerminalProfile {
    pub name: &'static str,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TerminalValidationResult {
    pub profile: TerminalProfile,
    pub missing_markers: Vec<&'static str>,
}

impl TerminalValidationResult {
    pub fn passed(&self) -> bool {
        self.missing_markers.is_empty()
    }
}

const SUPPORTED_TERMINAL_PROFILES: [TerminalProfile; 4] = [
    TerminalProfile {
        name: "iTerm2",
        width: 140,
        height: 40,
    },
    TerminalProfile {
        name: "Terminal.app",
        width: 120,
        height: 36,
    },
    TerminalProfile {
        name: "VS Code Terminal",
        width: 120,
        height: 34,
    },
    TerminalProfile {
        name: "Windows Terminal",
        width: 132,
        height: 36,
    },
];

const RESIZE_SMOKE_PROFILES: [TerminalProfile; 2] = [
    TerminalProfile {
        name: "Compact",
        width: 84,
        height: 24,
    },
    TerminalProfile {
        name: "Tight",
        width: 72,
        height: 22,
    },
];

pub fn supported_terminal_profiles() -> &'static [TerminalProfile] {
    &SUPPORTED_TERMINAL_PROFILES
}

pub fn resize_smoke_profiles() -> &'static [TerminalProfile] {
    &RESIZE_SMOKE_PROFILES
}

pub fn render_dashboard_snapshot(
    state: &DashboardState,
    profile: TerminalProfile,
) -> Result<String, String> {
    let backend = TestBackend::new(profile.width, profile.height);
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    let dashboard = ZkDashboard::new();
    terminal
        .draw(|frame| dashboard.draw(frame, state))
        .map_err(|error| error.to_string())?;

    Ok(terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>())
}

pub fn validate_reference_dashboard(
    profile: TerminalProfile,
) -> Result<TerminalValidationResult, String> {
    let snapshot = render_dashboard_snapshot(&aegisvault_state(), profile)?;
    let mut missing_markers = Vec::new();
    for marker in [
        "Vault",
        "Credential",
        "Health",
        "Proof",
        "Audit",
        "Activity",
        "Status",
        "Commands",
    ] {
        if !snapshot.contains(marker) {
            missing_markers.push(marker);
        }
    }

    Ok(TerminalValidationResult {
        profile,
        missing_markers,
    })
}

pub fn validate_reference_proof_demo() -> Result<Vec<String>, String> {
    let template = aegisvault_template().map_err(|error| error.to_string())?;
    let result = run_local_proof_demo(&template.program, &template.sample_inputs)?;
    Ok(result.progress_lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_terminal_profiles_render_reference_dashboard() {
        for profile in supported_terminal_profiles() {
            let result = validate_reference_dashboard(*profile).expect("render should succeed");
            assert!(
                result.passed(),
                "profile {} missing {:?}",
                profile.name,
                result.missing_markers
            );
        }
    }

    #[test]
    fn resize_smoke_profiles_keep_key_sections_visible() {
        for profile in resize_smoke_profiles() {
            let result = validate_reference_dashboard(*profile).expect("render should succeed");
            assert!(
                result.passed(),
                "profile {} missing {:?}",
                profile.name,
                result.missing_markers
            );
        }
    }

    #[test]
    fn reference_proof_demo_reports_all_stages() {
        let lines = validate_reference_proof_demo().expect("proof demo should succeed");
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("Compile:"));
        assert!(lines[1].starts_with("Witness:"));
        assert!(lines[2].starts_with("Constraint Check:"));
        assert!(lines[3].starts_with("Prove:"));
    }
}
