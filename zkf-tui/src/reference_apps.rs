use crate::{DashboardState, ProofJobUpdate, VaultEntry};

pub fn aegisvault_state() -> DashboardState {
    DashboardState {
        entries: vec![
            VaultEntry {
                id: "1".to_string(),
                site: "mail.zir".to_string(),
                username: "alice".to_string(),
                category: "email".to_string(),
                strength: 94,
                proof_status: "Ready".to_string(),
            },
            VaultEntry {
                id: "2".to_string(),
                site: "bank.zir".to_string(),
                username: "alice.reserve".to_string(),
                category: "finance".to_string(),
                strength: 88,
                proof_status: "Ready".to_string(),
            },
            VaultEntry {
                id: "3".to_string(),
                site: "oracle.zir".to_string(),
                username: "alice.oracle".to_string(),
                category: "infrastructure".to_string(),
                strength: 82,
                proof_status: "Ready".to_string(),
            },
            VaultEntry {
                id: "4".to_string(),
                site: "diary.zir".to_string(),
                username: "alice.private".to_string(),
                category: "personal".to_string(),
                strength: 97,
                proof_status: "Sealed".to_string(),
            },
        ],
        selected: 0,
        health_score: 91,
        proof_percent: 0,
        proof_stage_label: "Idle".to_string(),
        proof_activity_samples: Vec::new(),
        proof_running: false,
        audit_lines: vec![
            "Vault root: sealed".to_string(),
            "Breach watch: synchronized".to_string(),
            "Swarm defense: active".to_string(),
        ],
        status_line: "Press P to prove the selected credential.".to_string(),
        proof_modal: Default::default(),
    }
}

pub fn aegisvault_template() -> zkf_lib::ZkfResult<zkf_lib::TemplateProgram> {
    zkf_lib::templates::poseidon_commitment()
}

pub fn apply_reference_proof_update(state: &mut DashboardState, update: ProofJobUpdate) -> bool {
    match update {
        ProofJobUpdate::Event(event) => {
            state.apply_proof_event(&event);
            false
        }
        ProofJobUpdate::Finished(result) => {
            if let Some(entry) = state.entries.get_mut(state.selected) {
                entry.proof_status = if result.verified {
                    "Verified".to_string()
                } else {
                    "Invalid".to_string()
                };
            }
            state.finish_proof(result.verified);
            state.open_modal(
                "Proof Result",
                result
                    .progress_lines
                    .into_iter()
                    .chain([
                        String::new(),
                        result.proof_summary,
                        String::new(),
                        result.credential,
                    ])
                    .collect(),
            );
            state.status_line = "Proof completed.".to_string();
            true
        }
        ProofJobUpdate::Failed(message) => {
            if let Some(entry) = state.entries.get_mut(state.selected) {
                entry.proof_status = "Failed".to_string();
            }
            state.fail_proof(&message);
            state.open_modal("Proof Failed", vec![message]);
            true
        }
    }
}
