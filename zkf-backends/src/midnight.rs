use zkf_core::{Constraint, Expr, Program, Visibility};

/// Emit a Midnight Compact program from ZKF IR.
///
/// Generates valid Compact syntax following the Midnight DSL specification:
/// - `pragma language_version 0.21;`
/// - `witness name(): Type;` for private inputs
/// - `export circuit name(params): ReturnType { ... }` with colon return syntax
/// - `assert(expr, "label");` for constraints
/// - `Field` type for all signals (ZKF IR signals are field elements)
pub fn emit_compact(program: &Program) -> String {
    let mut out = String::new();

    // Pragma and header comment.
    out.push_str("pragma language_version 0.21;\n\n");
    out.push_str(&format!("// ZKF program: {}\n", program.name));
    out.push_str(&format!("// Field: {:?}\n\n", program.field));

    // Collect private signals for witness declarations.
    let private_signals: Vec<_> = program
        .signals
        .iter()
        .filter(|s| s.visibility == Visibility::Private)
        .collect();

    // Collect public signals for circuit parameters/outputs (exclude constants).
    let public_signals: Vec<_> = program
        .signals
        .iter()
        .filter(|s| s.visibility == Visibility::Public && s.constant.is_none())
        .collect();

    // Witness declarations — private inputs provided off-chain.
    // Witness functions are named with a `get_` prefix to avoid shadowing
    // the local const that stores the fetched value.
    if !private_signals.is_empty() {
        for s in &private_signals {
            out.push_str(&format!("witness get_{}(): Field;\n", s.name));
        }
        out.push('\n');
    }

    // Build return type — Compact uses `: ReturnType` syntax.
    let return_type = if public_signals.is_empty() {
        "[]".to_string()
    } else if public_signals.len() == 1 {
        "Field".to_string()
    } else {
        let fields: Vec<&str> = public_signals.iter().map(|_| "Field").collect();
        format!("[{}]", fields.join(", "))
    };

    // Export circuit declaration with input params.
    let input_params: Vec<String> = public_signals
        .iter()
        .map(|s| format!("{}: Field", s.name))
        .collect();

    out.push_str(&format!(
        "export circuit {}({}): {} {{\n",
        program.name,
        input_params.join(", "),
        return_type
    ));

    // Fetch private witness values inside the circuit body.
    for s in &private_signals {
        out.push_str(&format!("  const {} = get_{}();\n", s.name, s.name));
    }

    if !private_signals.is_empty() {
        out.push('\n');
    }

    // Constants.
    for s in &program.signals {
        if let Some(value) = &s.constant {
            out.push_str(&format!("  const {} = {};\n", s.name, value));
        }
    }

    let has_constants = program.signals.iter().any(|s| s.constant.is_some());
    if has_constants {
        out.push('\n');
    }

    // Constraint assertions — Compact uses assert(expr, "label") syntax.
    for (idx, constraint) in program.constraints.iter().enumerate() {
        match constraint {
            Constraint::Equal { lhs, rhs, label } => {
                let label_str = label.clone().unwrap_or_else(|| format!("c{idx}"));
                out.push_str(&format!(
                    "  assert({} == {}, \"{}\");\n",
                    render_expr(lhs),
                    render_expr(rhs),
                    label_str
                ));
            }
            Constraint::Boolean { signal, label } => {
                let label_str = label.clone().unwrap_or_else(|| format!("c{idx}"));
                out.push_str(&format!(
                    "  assert({} * (1 - {}) == 0, \"{}\");\n",
                    signal, signal, label_str
                ));
            }
            Constraint::Range {
                signal,
                bits,
                label,
            } => {
                let label_str = label.clone().unwrap_or_else(|| format!("c{idx}"));
                // Cast Field to Uint<N> for range check — Compact requires matching types.
                out.push_str(&format!(
                    "  const {signal}_uint = {signal} as Uint<{bits}>; // {label_str}\n",
                ));
            }
            Constraint::BlackBox {
                op,
                inputs,
                outputs,
                label,
                ..
            } => {
                let label_str = label.clone().unwrap_or_else(|| format!("c{idx}"));
                let rendered_inputs = inputs.iter().map(render_expr).collect::<Vec<_>>();
                out.push_str(&format!(
                    "  // {}: {}([{}]) -> [{}]\n",
                    label_str,
                    op.as_str(),
                    rendered_inputs.join(", "),
                    outputs.join(", ")
                ));
            }
            Constraint::Lookup { .. } => { /* Lookup constraints not exportable; must be lowered first */
            }
        }
    }

    // Return public outputs.
    if public_signals.len() == 1 {
        out.push_str(&format!("\n  return {};\n", public_signals[0].name));
    } else if public_signals.len() > 1 {
        let return_fields: Vec<String> = public_signals.iter().map(|s| s.name.clone()).collect();
        out.push_str(&format!("\n  return [{}];\n", return_fields.join(", ")));
    }

    out.push_str("}\n");
    out
}

fn render_expr(expr: &Expr) -> String {
    match expr {
        Expr::Const(value) => value.to_decimal_string(),
        Expr::Signal(name) => name.clone(),
        Expr::Add(values) => {
            let parts = values.iter().map(render_expr).collect::<Vec<_>>();
            format!("({})", parts.join(" + "))
        }
        Expr::Sub(a, b) => format!("({} - {})", render_expr(a), render_expr(b)),
        Expr::Mul(a, b) => format!("({} * {})", render_expr(a), render_expr(b)),
        Expr::Div(a, b) => format!("({} / {})", render_expr(a), render_expr(b)),
    }
}
