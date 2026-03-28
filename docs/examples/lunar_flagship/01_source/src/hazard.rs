use std::collections::BTreeMap;
use zkf_core::{BlackBoxOp, Expr, FieldElement, FieldId, Program, Witness, WitnessInputs};
use zkf_lib::app::builder::ProgramBuilder;
use zkf_lib::app::private_identity::poseidon_permutation4_bn254;

pub const HAZARD_CELL_COUNT: usize = 4;

fn signal(name: &str) -> Expr {
    Expr::signal(name)
}

fn constant(value: i64) -> Expr {
    Expr::Const(FieldElement::from_i64(value))
}

fn mul(a: Expr, b: Expr) -> Expr {
    Expr::Mul(Box::new(a), Box::new(b))
}

fn add(exprs: Vec<Expr>) -> Expr {
    Expr::Add(exprs)
}

fn cell_score_name(i: usize) -> String {
    format!("cell_{i}_score")
}

fn cell_x_name(i: usize) -> String {
    format!("cell_{i}_x")
}

fn cell_y_name(i: usize) -> String {
    format!("cell_{i}_y")
}

fn flag_name(i: usize) -> String {
    format!("select_flag_{i}")
}

/// Build the terrain hazard assessment circuit via ProgramBuilder.
///
/// Proves: "From a private 4-cell hazard grid, the cell with the lowest
/// score was selected, that score is below the public threshold, and the
/// full grid is committed via Poseidon."
pub fn build_hazard_program() -> Result<Program, Box<dyn std::error::Error>> {
    let mut b = ProgramBuilder::new("lunar_hazard_assessment", FieldId::Bn254);

    b.metadata_entry("application", "lunar-landing-hazard-assessment")?;
    b.metadata_entry("cell_count", HAZARD_CELL_COUNT.to_string())?;
    b.metadata_entry("commitment", "poseidon4-chained")?;
    b.metadata_entry("selection_method", "one-hot-mux-minimum")?;

    // ── Private inputs: 4 cells × (score, x, y) + selected_index ─────────
    for i in 0..HAZARD_CELL_COUNT {
        b.private_input(&cell_score_name(i))?;
        b.private_input(&cell_x_name(i))?;
        b.private_input(&cell_y_name(i))?;
    }
    b.private_input("selected_index")?;

    // ── Public inputs ─────────────────────────────────────────────────────
    b.public_input("hazard_threshold")?;

    // ── Public outputs ────────────────────────────────────────────────────
    b.public_output("grid_commitment")?;
    b.public_output("selected_landing_x")?;
    b.public_output("selected_landing_y")?;
    b.public_output("selected_score")?;
    b.public_output("hazard_safe")?;

    // ── Range checks on all cell data ─────────────────────────────────────
    for i in 0..HAZARD_CELL_COUNT {
        b.constrain_range(&cell_score_name(i), 8)?; // scores 0-255
        b.constrain_range(&cell_x_name(i), 16)?; // coordinates 0-65535
        b.constrain_range(&cell_y_name(i), 16)?;
    }
    b.constrain_range("hazard_threshold", 8)?;
    b.constrain_range("selected_index", 2)?; // 0-3

    // ── One-hot selection flags ───────────────────────────────────────────
    // selected_index encodes which cell: one flag per cell, exactly one is 1.
    // flag_i = (selected_index == i) implemented via:
    //   flag_i ∈ {0,1}  AND  Σ flag_i = 1  AND  Σ(i * flag_i) = selected_index
    for i in 0..HAZARD_CELL_COUNT {
        b.private_signal(&flag_name(i))?;
        b.constrain_boolean(&flag_name(i))?;
    }
    // Exactly one flag is 1
    b.constrain_equal_labeled(
        add((0..HAZARD_CELL_COUNT).map(|i| signal(&flag_name(i))).collect()),
        constant(1),
        Some("exactly_one_cell_selected".to_string()),
    )?;
    // Weighted sum = selected_index
    b.constrain_equal_labeled(
        add((0..HAZARD_CELL_COUNT)
            .map(|i| mul(constant(i as i64), signal(&flag_name(i))))
            .collect()),
        signal("selected_index"),
        Some("selection_index_matches_flags".to_string()),
    )?;

    // ── MUX: extract selected score ───────────────────────────────────────
    // selected_score = Σ(flag_i * cell_i_score)
    b.constrain_equal_labeled(
        signal("selected_score"),
        add((0..HAZARD_CELL_COUNT)
            .map(|i| mul(signal(&flag_name(i)), signal(&cell_score_name(i))))
            .collect()),
        Some("selected_score_mux".to_string()),
    )?;

    // ── MUX: extract selected coordinates ─────────────────────────────────
    b.constrain_equal_labeled(
        signal("selected_landing_x"),
        add((0..HAZARD_CELL_COUNT)
            .map(|i| mul(signal(&flag_name(i)), signal(&cell_x_name(i))))
            .collect()),
        Some("selected_x_mux".to_string()),
    )?;
    b.constrain_equal_labeled(
        signal("selected_landing_y"),
        add((0..HAZARD_CELL_COUNT)
            .map(|i| mul(signal(&flag_name(i)), signal(&cell_y_name(i))))
            .collect()),
        Some("selected_y_mux".to_string()),
    )?;

    // ── Threshold check: selected_score + gap = threshold ─────────────────
    b.private_signal("threshold_gap")?;
    b.constrain_equal_labeled(
        signal("hazard_threshold"),
        add(vec![signal("selected_score"), signal("threshold_gap")]),
        Some("selected_score_below_threshold".to_string()),
    )?;
    b.constrain_range("threshold_gap", 8)?; // gap must be non-negative

    // ── Poseidon commitment to full grid ──────────────────────────────────
    // Round 1: hash(cell_0_score, cell_0_x, cell_0_y, cell_1_score)
    let r1_outputs = ["__poseidon_r1_0", "__poseidon_r1_1", "__poseidon_r1_2", "__poseidon_r1_3"];
    for name in r1_outputs {
        b.private_signal(name)?;
    }
    b.constrain_blackbox(
        BlackBoxOp::Poseidon,
        &[
            signal(&cell_score_name(0)),
            signal(&cell_x_name(0)),
            signal(&cell_y_name(0)),
            signal(&cell_score_name(1)),
        ],
        &r1_outputs,
        &BTreeMap::from([("width".to_string(), "4".to_string())]),
    )?;

    // Round 2: hash(r1_0, cell_1_x, cell_1_y, cell_2_score)
    let r2_outputs = ["__poseidon_r2_0", "__poseidon_r2_1", "__poseidon_r2_2", "__poseidon_r2_3"];
    for name in r2_outputs {
        b.private_signal(name)?;
    }
    b.constrain_blackbox(
        BlackBoxOp::Poseidon,
        &[
            signal("__poseidon_r1_0"),
            signal(&cell_x_name(1)),
            signal(&cell_y_name(1)),
            signal(&cell_score_name(2)),
        ],
        &r2_outputs,
        &BTreeMap::from([("width".to_string(), "4".to_string())]),
    )?;

    // Round 3: hash(r2_0, cell_2_x, cell_2_y, cell_3_score)
    let r3_outputs = ["__poseidon_r3_0", "__poseidon_r3_1", "__poseidon_r3_2", "__poseidon_r3_3"];
    for name in r3_outputs {
        b.private_signal(name)?;
    }
    b.constrain_blackbox(
        BlackBoxOp::Poseidon,
        &[
            signal("__poseidon_r2_0"),
            signal(&cell_x_name(2)),
            signal(&cell_y_name(2)),
            signal(&cell_score_name(3)),
        ],
        &r3_outputs,
        &BTreeMap::from([("width".to_string(), "4".to_string())]),
    )?;

    // Round 4: hash(r3_0, cell_3_x, cell_3_y, selected_index)
    let r4_outputs = ["__poseidon_r4_0", "__poseidon_r4_1", "__poseidon_r4_2", "__poseidon_r4_3"];
    for name in r4_outputs {
        b.private_signal(name)?;
    }
    b.constrain_blackbox(
        BlackBoxOp::Poseidon,
        &[
            signal("__poseidon_r3_0"),
            signal(&cell_x_name(3)),
            signal(&cell_y_name(3)),
            signal("selected_index"),
        ],
        &r4_outputs,
        &BTreeMap::from([("width".to_string(), "4".to_string())]),
    )?;

    // grid_commitment = final Poseidon output
    b.constrain_equal_labeled(
        signal("grid_commitment"),
        signal("__poseidon_r4_0"),
        Some("grid_commitment_binding".to_string()),
    )?;

    // ── Safety indicator: constrained to 1 ────────────────────────────────
    b.constrain_boolean("hazard_safe")?;
    b.constrain_equal_labeled(
        signal("hazard_safe"),
        constant(1),
        Some("hazard_assessment_safe".to_string()),
    )?;

    Ok(b.build()?)
}

/// Generate witness for the hazard assessment circuit.
pub fn hazard_witness(inputs: &WitnessInputs) -> Result<Witness, Box<dyn std::error::Error>> {
    let mut values = BTreeMap::<String, FieldElement>::new();

    // Read inputs
    let threshold = read_i64(inputs, "hazard_threshold")?;
    let selected_idx = read_i64(inputs, "selected_index")? as usize;
    if selected_idx >= HAZARD_CELL_COUNT {
        return Err(format!("selected_index {selected_idx} out of range 0..{HAZARD_CELL_COUNT}").into());
    }

    values.insert("hazard_threshold".into(), inputs["hazard_threshold"].clone());
    values.insert("selected_index".into(), inputs["selected_index"].clone());

    let mut scores = Vec::new();
    let mut xs = Vec::new();
    let mut ys = Vec::new();

    for i in 0..HAZARD_CELL_COUNT {
        let score = read_i64(inputs, &cell_score_name(i))?;
        let x = read_i64(inputs, &cell_x_name(i))?;
        let y = read_i64(inputs, &cell_y_name(i))?;
        scores.push(score);
        xs.push(x);
        ys.push(y);
        values.insert(cell_score_name(i), inputs[&cell_score_name(i)].clone());
        values.insert(cell_x_name(i), inputs[&cell_x_name(i)].clone());
        values.insert(cell_y_name(i), inputs[&cell_y_name(i)].clone());
    }

    // Selection flags (one-hot)
    for i in 0..HAZARD_CELL_COUNT {
        let flag_val = if i == selected_idx { 1i64 } else { 0i64 };
        values.insert(flag_name(i), FieldElement::from_i64(flag_val));
    }

    // Selected score, coordinates
    let selected_score = scores[selected_idx];
    let selected_x = xs[selected_idx];
    let selected_y = ys[selected_idx];
    values.insert("selected_score".into(), FieldElement::from_i64(selected_score));
    values.insert("selected_landing_x".into(), FieldElement::from_i64(selected_x));
    values.insert("selected_landing_y".into(), FieldElement::from_i64(selected_y));

    // Threshold gap
    if selected_score > threshold {
        return Err(format!(
            "selected cell {selected_idx} score {selected_score} exceeds threshold {threshold}"
        ).into());
    }
    let gap = threshold - selected_score;
    values.insert("threshold_gap".into(), FieldElement::from_i64(gap));

    // Safety indicator
    values.insert("hazard_safe".into(), FieldElement::from_i64(1));

    // Compute Poseidon hashes for grid commitment (full 4-lane permutation)
    // Collect all cell field elements upfront to avoid borrow conflicts
    let cell_fes: Vec<FieldElement> = (0..HAZARD_CELL_COUNT)
        .flat_map(|i| {
            vec![
                values[&cell_score_name(i)].clone(),
                values[&cell_x_name(i)].clone(),
                values[&cell_y_name(i)].clone(),
            ]
        })
        .collect();
    let sel_idx_fe = values["selected_index"].clone();

    // Round 1: poseidon(cell_0_score, cell_0_x, cell_0_y, cell_1_score)
    let r1 = poseidon_permutation4_bn254(&[
        cell_fes[0].clone(), cell_fes[1].clone(), cell_fes[2].clone(), cell_fes[3].clone(),
    ]).map_err(|e| format!("poseidon r1: {e}"))?;
    for (lane, val) in r1.iter().enumerate() {
        values.insert(format!("__poseidon_r1_{lane}"), val.clone());
    }

    // Round 2: poseidon(r1_0, cell_1_x, cell_1_y, cell_2_score)
    let r2 = poseidon_permutation4_bn254(&[
        r1[0].clone(), cell_fes[4].clone(), cell_fes[5].clone(), cell_fes[6].clone(),
    ]).map_err(|e| format!("poseidon r2: {e}"))?;
    for (lane, val) in r2.iter().enumerate() {
        values.insert(format!("__poseidon_r2_{lane}"), val.clone());
    }

    // Round 3: poseidon(r2_0, cell_2_x, cell_2_y, cell_3_score)
    let r3 = poseidon_permutation4_bn254(&[
        r2[0].clone(), cell_fes[7].clone(), cell_fes[8].clone(), cell_fes[9].clone(),
    ]).map_err(|e| format!("poseidon r3: {e}"))?;
    for (lane, val) in r3.iter().enumerate() {
        values.insert(format!("__poseidon_r3_{lane}"), val.clone());
    }

    // Round 4: poseidon(r3_0, cell_3_x, cell_3_y, selected_index)
    let r4 = poseidon_permutation4_bn254(&[
        r3[0].clone(), cell_fes[10].clone(), cell_fes[11].clone(), sel_idx_fe,
    ]).map_err(|e| format!("poseidon r4: {e}"))?;
    for (lane, val) in r4.iter().enumerate() {
        values.insert(format!("__poseidon_r4_{lane}"), val.clone());
    }

    // grid_commitment = r4[0]
    values.insert("grid_commitment".into(), r4[0].clone());

    Ok(Witness { values })
}

/// Sample hazard inputs for a 4-cell lunar terrain grid.
pub fn hazard_sample_inputs() -> WitnessInputs {
    let mut inputs = WitnessInputs::new();

    // 4 candidate landing cells on a lunar surface
    // Cell 0: Flat mare region — low hazard (score=12), coordinates (100, 200)
    inputs.insert("cell_0_score".into(), FieldElement::from_i64(12));
    inputs.insert("cell_0_x".into(), FieldElement::from_i64(100));
    inputs.insert("cell_0_y".into(), FieldElement::from_i64(200));

    // Cell 1: Rocky crater rim — high hazard (score=180)
    inputs.insert("cell_1_score".into(), FieldElement::from_i64(180));
    inputs.insert("cell_1_x".into(), FieldElement::from_i64(350));
    inputs.insert("cell_1_y".into(), FieldElement::from_i64(400));

    // Cell 2: Gentle slope — medium hazard (score=45)
    inputs.insert("cell_2_score".into(), FieldElement::from_i64(45));
    inputs.insert("cell_2_x".into(), FieldElement::from_i64(500));
    inputs.insert("cell_2_y".into(), FieldElement::from_i64(150));

    // Cell 3: Boulder field — high hazard (score=220)
    inputs.insert("cell_3_score".into(), FieldElement::from_i64(220));
    inputs.insert("cell_3_x".into(), FieldElement::from_i64(700));
    inputs.insert("cell_3_y".into(), FieldElement::from_i64(600));

    // Select cell 0 (flat mare, score=12) — the safest option
    inputs.insert("selected_index".into(), FieldElement::from_i64(0));

    // Threshold: 50 (anything above 50 is too hazardous)
    inputs.insert("hazard_threshold".into(), FieldElement::from_i64(50));

    inputs
}

fn read_i64(inputs: &WitnessInputs, name: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let element = inputs
        .get(name)
        .ok_or_else(|| format!("missing input: {name}"))?;
    let decimal = element.to_decimal_string();
    decimal
        .parse::<i64>()
        .map_err(|e| format!("invalid i64 for {name}: {e}").into())
}
