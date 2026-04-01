// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::collections::BTreeMap;
use std::time::Duration;
use zkf_lib::{ProofEvent, ProofStage};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProgressStageSnapshot {
    pub label: String,
    pub started: bool,
    pub finished: bool,
    pub duration_ms: Option<u128>,
    pub detail: String,
}

impl ProgressStageSnapshot {
    fn new(stage: ProofStage) -> Self {
        Self {
            label: stage.label().to_string(),
            started: false,
            finished: false,
            duration_ms: None,
            detail: "pending".to_string(),
        }
    }
}

pub struct ProofProgressReporter {
    multi: MultiProgress,
    bars: BTreeMap<ProofStage, ProgressBar>,
    snapshots: BTreeMap<ProofStage, ProgressStageSnapshot>,
}

impl Default for ProofProgressReporter {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ProofProgressReporter {
    pub fn new(hidden: bool) -> Self {
        let multi = MultiProgress::new();
        if hidden {
            multi.set_draw_target(ProgressDrawTarget::hidden());
        }
        let style = match ProgressStyle::with_template("{spinner:.cyan} {msg}") {
            Ok(style) => style,
            Err(_) => ProgressStyle::default_spinner(),
        }
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");

        let mut bars = BTreeMap::new();
        let mut snapshots = BTreeMap::new();
        for stage in [
            ProofStage::Compile,
            ProofStage::Witness,
            ProofStage::PrepareWitness,
            ProofStage::Prove,
        ] {
            let bar = multi.add(ProgressBar::new_spinner());
            bar.set_style(style.clone());
            bar.enable_steady_tick(Duration::from_millis(80));
            bar.set_message(format!("{} pending", stage.label()));
            bars.insert(stage, bar);
            snapshots.insert(stage, ProgressStageSnapshot::new(stage));
        }

        Self {
            multi,
            bars,
            snapshots,
        }
    }

    pub fn observe(&mut self, event: ProofEvent) {
        let stage = event.stage();
        let Some(snapshot) = self.snapshots.get_mut(&stage) else {
            return;
        };
        let Some(bar) = self.bars.get(&stage) else {
            return;
        };

        match event {
            ProofEvent::StageStarted { .. } => {
                snapshot.started = true;
                snapshot.detail = "running".to_string();
                bar.set_message(format!("{} running", snapshot.label));
            }
            ProofEvent::CompileCompleted {
                signal_count,
                constraint_count,
                duration_ms,
                ..
            } => {
                snapshot.finished = true;
                snapshot.duration_ms = Some(duration_ms);
                snapshot.detail =
                    format!("{signal_count} signals / {constraint_count} constraints");
                bar.finish_with_message(format!(
                    "{} done in {} ms ({})",
                    snapshot.label, duration_ms, snapshot.detail
                ));
            }
            ProofEvent::WitnessCompleted {
                witness_values,
                duration_ms,
            } => {
                snapshot.finished = true;
                snapshot.duration_ms = Some(duration_ms);
                snapshot.detail = format!("{witness_values} values");
                bar.finish_with_message(format!(
                    "{} done in {} ms ({})",
                    snapshot.label, duration_ms, snapshot.detail
                ));
            }
            ProofEvent::PrepareWitnessCompleted {
                witness_values,
                public_inputs,
                duration_ms,
            } => {
                snapshot.finished = true;
                snapshot.duration_ms = Some(duration_ms);
                snapshot.detail =
                    format!("{witness_values} values / {public_inputs} public inputs");
                bar.finish_with_message(format!(
                    "{} done in {} ms ({})",
                    snapshot.label, duration_ms, snapshot.detail
                ));
            }
            ProofEvent::ProveCompleted {
                proof_size_bytes,
                duration_ms,
                ..
            } => {
                snapshot.finished = true;
                snapshot.duration_ms = Some(duration_ms);
                snapshot.detail = format!("{proof_size_bytes} proof bytes");
                bar.finish_with_message(format!(
                    "{} done in {} ms ({})",
                    snapshot.label, duration_ms, snapshot.detail
                ));
            }
        }
    }

    pub fn snapshot(&self) -> Vec<ProgressStageSnapshot> {
        [
            ProofStage::Compile,
            ProofStage::Witness,
            ProofStage::PrepareWitness,
            ProofStage::Prove,
        ]
        .into_iter()
        .filter_map(|stage| self.snapshots.get(&stage).cloned())
        .collect()
    }

    pub fn lines(&self) -> Vec<String> {
        self.snapshot()
            .into_iter()
            .map(|snapshot| {
                let status = if snapshot.finished {
                    "done"
                } else if snapshot.started {
                    "running"
                } else {
                    "pending"
                };
                let duration = snapshot
                    .duration_ms
                    .map(|value| format!("{} ms", value))
                    .unwrap_or_else(|| "-".to_string());
                format!(
                    "{}: {} | {} | {}",
                    snapshot.label, status, duration, snapshot.detail
                )
            })
            .collect()
    }

    pub fn clear(&self) {
        let _ = self.multi.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_lib::BackendKind;

    #[test]
    fn reporter_tracks_stage_progress() {
        let mut reporter = ProofProgressReporter::new(true);
        reporter.observe(ProofEvent::StageStarted {
            stage: ProofStage::Compile,
        });
        reporter.observe(ProofEvent::CompileCompleted {
            backend: BackendKind::ArkworksGroth16,
            signal_count: 4,
            constraint_count: 2,
            duration_ms: 11,
        });
        reporter.observe(ProofEvent::StageStarted {
            stage: ProofStage::Witness,
        });
        reporter.observe(ProofEvent::WitnessCompleted {
            witness_values: 3,
            duration_ms: 2,
        });

        let lines = reporter.lines();
        assert_eq!(
            lines[0],
            "Compile: done | 11 ms | 4 signals / 2 constraints"
        );
        assert_eq!(lines[1], "Witness: done | 2 ms | 3 values");
        assert_eq!(lines[2], "Constraint Check: pending | - | pending");
        assert_eq!(lines[3], "Prove: pending | - | pending");
    }
}
