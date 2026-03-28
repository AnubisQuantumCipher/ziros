use crate::builtins;
use crate::parse::{self, CircuitAttrs, ParamVisibility};
use crate::types::{self, InferredType, TypeEnv};
use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use std::collections::BTreeMap;

fn compile_error_tokens(tokens: impl ToTokens, message: impl Into<String>) -> TokenStream {
    syn::Error::new_spanned(tokens, message.into()).to_compile_error()
}

/// Generate the circuit program constructor and input builder from a parsed function.
pub fn generate_circuit(attrs: &CircuitAttrs, func: &syn::ItemFn) -> syn::Result<TokenStream> {
    let func_name = &func.sig.ident;
    let program_fn_name = quote::format_ident!("{}_program", func_name);
    let inputs_fn_name = quote::format_ident!("{}_inputs", func_name);

    let params = parse::extract_params(func)?;
    let field_str = &attrs.field;

    // Generate signal declarations.
    let mut signal_tokens = Vec::new();
    for param in &params {
        let name = &param.name;
        let vis = match param.visibility {
            ParamVisibility::Public => quote! { zkf_core::Visibility::Public },
            ParamVisibility::Private => quote! { zkf_core::Visibility::Private },
        };
        let signal_type = match types::rust_type_to_signal_type(&param.inner_type) {
            "Bool" => quote! { zkf_core::zir::SignalType::Bool },
            "UInt8" => quote! { zkf_core::zir::SignalType::UInt { bits: 8 } },
            "UInt16" => quote! { zkf_core::zir::SignalType::UInt { bits: 16 } },
            "UInt32" => quote! { zkf_core::zir::SignalType::UInt { bits: 32 } },
            "UInt64" => quote! { zkf_core::zir::SignalType::UInt { bits: 64 } },
            _ => quote! { zkf_core::zir::SignalType::Field },
        };

        signal_tokens.push(quote! {
            zkf_core::zir::Signal {
                name: #name.to_string(),
                visibility: #vis,
                ty: #signal_type,
                constant: None,
            }
        });
    }

    // Generate field ID.
    let field_id = match field_str.as_str() {
        "bn254" => quote! { zkf_core::FieldId::Bn254 },
        "bls12_381" => quote! { zkf_core::FieldId::Bls12_381 },
        "pasta_fp" => quote! { zkf_core::FieldId::PastaFp },
        "pasta_fq" => quote! { zkf_core::FieldId::PastaFq },
        "goldilocks" => quote! { zkf_core::FieldId::Goldilocks },
        "baby_bear" => quote! { zkf_core::FieldId::BabyBear },
        "mersenne31" => quote! { zkf_core::FieldId::Mersenne31 },
        _ => {
            return Err(syn::Error::new_spanned(
                func,
                format!("unknown field: {}", field_str),
            ));
        }
    };

    let func_name_str = func_name.to_string();

    // Extract constraints and intermediate signals from the function body.
    let mut extra_signals = Vec::new();
    let mut constraint_tokens = Vec::new();
    let mut aux_counter = 0usize;
    // 7A: constant map for dynamic loop bounds.
    let mut consts: BTreeMap<String, i64> = BTreeMap::new();
    // 7B: struct definition registry: name → Vec<(field_name, field_type)>.
    let mut struct_defs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    // 7C: type inference environment.
    let mut type_env = TypeEnv::new();

    for stmt in &func.block.stmts {
        extract_constraints_from_stmt(
            stmt,
            &mut extra_signals,
            &mut constraint_tokens,
            &mut aux_counter,
            &mut consts,
            &mut struct_defs,
            &mut type_env,
        );
    }

    // Collect witness assignments from top-level `let` bindings.
    let mut witness_assignment_tokens = Vec::new();
    for stmt in &func.block.stmts {
        if let syn::Stmt::Local(local) = stmt
            && let Some(init) = &local.init
        {
            let name_opt = match &local.pat {
                syn::Pat::Ident(pi) => Some(pi.ident.to_string()),
                syn::Pat::Type(pt) => {
                    if let syn::Pat::Ident(pi) = &*pt.pat {
                        Some(pi.ident.to_string())
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(name_str) = name_opt {
                let rhs = expr_to_zir_tokens(&init.expr, &mut aux_counter);
                witness_assignment_tokens.push(quote! {
                    zkf_core::zir::WitnessAssignment {
                        target: #name_str.to_string(),
                        expr: #rhs,
                    }
                });
            }
        }
    }

    // Generate input builder function parameters.
    let mut input_params = Vec::new();
    let mut input_inserts = Vec::new();
    for param in &params {
        let name = syn::Ident::new(&param.name, proc_macro2::Span::call_site());
        let name_str = &param.name;

        // All inputs are passed as strings for FieldElement construction.
        input_params.push(quote! { #name: &str });
        input_inserts.push(quote! {
            inputs.insert(#name_str.to_string(), zkf_core::FieldElement::new(#name));
        });
    }

    let output = quote! {
        /// Constructs the ZIR program for this circuit.
        pub fn #program_fn_name() -> zkf_core::zir::Program {
            let mut signals = vec![
                #(#signal_tokens),*
            ];
            // Intermediate signals generated from body analysis.
            #(#extra_signals)*

            zkf_core::zir::Program {
                name: #func_name_str.to_string(),
                field: #field_id,
                signals,
                constraints: vec![#(#constraint_tokens),*],
                witness_plan: zkf_core::zir::WitnessPlan {
                    assignments: vec![#(#witness_assignment_tokens),*],
                    hints: vec![],
                    acir_program_bytes: None,
                },
                lookup_tables: Vec::new(),
                memory_regions: Vec::new(),
                custom_gates: Vec::new(),
                metadata: std::collections::BTreeMap::new(),
            }
        }

        /// Constructs witness inputs for this circuit.
        pub fn #inputs_fn_name(#(#input_params),*) -> zkf_core::WitnessInputs {
            let mut inputs = std::collections::BTreeMap::new();
            #(#input_inserts)*
            inputs
        }
    };

    Ok(output)
}

// ---------------------------------------------------------------------------
// 7A: Constant expression evaluator for dynamic loop bounds
// ---------------------------------------------------------------------------

/// Attempt to evaluate `expr` to an `i64` at DSL-compile time.
///
/// Handles:
/// - Integer literals
/// - Identifier lookup in `consts`
/// - Binary operations (+, -, *, /) with overflow-safe checked arithmetic
/// - Parenthesized sub-expressions
///
/// Returns `None` for any expression that cannot be fully evaluated.
fn try_const_eval(expr: &syn::Expr, consts: &BTreeMap<String, i64>) -> Option<i64> {
    match expr {
        syn::Expr::Lit(lit) => {
            if let syn::Lit::Int(int_lit) = &lit.lit {
                int_lit.base10_parse::<i64>().ok()
            } else {
                None
            }
        }
        syn::Expr::Path(path) => {
            let name = path.path.get_ident()?.to_string();
            consts.get(&name).copied()
        }
        syn::Expr::Binary(binary) => {
            let lhs = try_const_eval(&binary.left, consts)?;
            let rhs = try_const_eval(&binary.right, consts)?;
            match binary.op {
                syn::BinOp::Add(_) | syn::BinOp::AddAssign(_) => lhs.checked_add(rhs),
                syn::BinOp::Sub(_) | syn::BinOp::SubAssign(_) => lhs.checked_sub(rhs),
                syn::BinOp::Mul(_) | syn::BinOp::MulAssign(_) => lhs.checked_mul(rhs),
                syn::BinOp::Div(_) | syn::BinOp::DivAssign(_) => {
                    if rhs == 0 {
                        None
                    } else {
                        lhs.checked_div(rhs)
                    }
                }
                _ => None,
            }
        }
        syn::Expr::Paren(paren) => try_const_eval(&paren.expr, consts),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Core statement extraction
// ---------------------------------------------------------------------------

/// Walk a statement and emit constraint tokens + intermediate signal tokens.
///
/// Extra parameters vs the original:
/// - `consts`: constant map populated from literal `let` bindings; used for
///   dynamic loop bound evaluation (7A).
/// - `struct_defs`: registry of struct definitions encountered so far (7B).
/// - `type_env`: type inference environment (7C).
fn extract_constraints_from_stmt(
    stmt: &syn::Stmt,
    extra_signals: &mut Vec<TokenStream>,
    constraints: &mut Vec<TokenStream>,
    aux_counter: &mut usize,
    consts: &mut BTreeMap<String, i64>,
    struct_defs: &mut BTreeMap<String, Vec<(String, String)>>,
    type_env: &mut TypeEnv,
) {
    match stmt {
        // ---------------------------------------------------------------------------
        // 7B: Struct item definition — register field list.
        // ---------------------------------------------------------------------------
        syn::Stmt::Item(syn::Item::Struct(item_struct)) => {
            let struct_name = item_struct.ident.to_string();
            let mut fields: Vec<(String, String)> = Vec::new();
            if let syn::Fields::Named(named) = &item_struct.fields {
                for field in &named.named {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map(|id| id.to_string())
                        .unwrap_or_default();
                    let field_type = quote::quote!(#field.ty).to_string();
                    fields.push((field_name, field_type));
                }
            }
            struct_defs.insert(struct_name, fields);
        }

        // `let x = expr;`  or  `let p = Point { x: a, y: b };`
        syn::Stmt::Local(local) => {
            if let Some(init) = &local.init
                && let syn::Pat::Ident(pat_ident) = &local.pat
            {
                let var_name = pat_ident.ident.to_string();

                // ------------------------------------------------------------------
                // 7C: Extract type annotation if present.
                // `let x: u32 = expr` is represented as
                // `Pat::Type { pat: Pat::Ident, ty }` when parsed with full features.
                // ------------------------------------------------------------------
                let annotated_type = extract_pat_type_annotation(&local.pat);

                if let Some(ref inferred) = annotated_type {
                    type_env.insert(var_name.clone(), inferred.clone());
                }

                // ------------------------------------------------------------------
                // 7A: Populate consts map if RHS is a literal integer.
                // ------------------------------------------------------------------
                if let Some(lit_val) = try_const_eval(&init.expr, consts) {
                    consts.insert(var_name.clone(), lit_val);
                }

                // ------------------------------------------------------------------
                // 7B: Struct construction — `let p = Point { x: a, y: b }`
                // ------------------------------------------------------------------
                if let syn::Expr::Struct(struct_expr) = &*init.expr {
                    handle_struct_construction(
                        &var_name,
                        struct_expr,
                        extra_signals,
                        constraints,
                        aux_counter,
                        type_env,
                    );
                    return;
                }

                // ------------------------------------------------------------------
                // Standard `let x = expr` — determine signal type from type env.
                // ------------------------------------------------------------------
                let inferred = annotated_type.unwrap_or_else(|| {
                    type_env
                        .get(&var_name)
                        .cloned()
                        .unwrap_or(InferredType::Unknown)
                });
                let signal_type_tokens = inferred_type_to_signal_type_tokens(&inferred);

                let name_str = var_name.clone();
                extra_signals.push(quote! {
                    signals.push(zkf_core::zir::Signal {
                        name: #name_str.to_string(),
                        visibility: zkf_core::Visibility::Private,
                        ty: #signal_type_tokens,
                        constant: None,
                    });
                });

                // Generate an equality constraint: var_name = rhs_expr
                let rhs_expr = expr_to_zir_tokens(&init.expr, aux_counter);
                let lhs = quote! {
                    zkf_core::zir::Expr::Signal(#name_str.to_string())
                };
                constraints.push(quote! {
                    zkf_core::zir::Constraint::Equal {
                        lhs: #lhs,
                        rhs: #rhs_expr,
                        label: Some(format!("assign_{}", #name_str)),
                    }
                });
            } else if let syn::Pat::Type(pat_type) = &local.pat {
                // `let x: T = expr` — the pat is wrapped in Pat::Type.
                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    let var_name = pat_ident.ident.to_string();

                    if let Some(init) = &local.init {
                        // 7A: populate consts
                        if let Some(lit_val) = try_const_eval(&init.expr, consts) {
                            consts.insert(var_name.clone(), lit_val);
                        }

                        // 7C: record annotated type
                        let inferred = syn_type_to_inferred(&pat_type.ty);
                        type_env.insert(var_name.clone(), inferred.clone());

                        let signal_type_tokens = inferred_type_to_signal_type_tokens(&inferred);
                        let name_str = var_name.clone();

                        extra_signals.push(quote! {
                            signals.push(zkf_core::zir::Signal {
                                name: #name_str.to_string(),
                                visibility: zkf_core::Visibility::Private,
                                ty: #signal_type_tokens,
                                constant: None,
                            });
                        });

                        let rhs_expr = expr_to_zir_tokens(&init.expr, aux_counter);
                        let lhs = quote! {
                            zkf_core::zir::Expr::Signal(#name_str.to_string())
                        };
                        constraints.push(quote! {
                            zkf_core::zir::Constraint::Equal {
                                lhs: #lhs,
                                rhs: #rhs_expr,
                                label: Some(format!("assign_{}", #name_str)),
                            }
                        });
                    }
                }
            }
        }

        // Expression statements: function calls like assert_range(x, 8)
        syn::Stmt::Expr(expr, _) => {
            // Handle for loops via compile-time unrolling
            if let syn::Expr::ForLoop(for_loop) = expr {
                extract_constraints_from_for_loop(
                    for_loop,
                    extra_signals,
                    constraints,
                    aux_counter,
                    consts,
                    struct_defs,
                    type_env,
                );
            } else if let syn::Expr::If(if_expr) = expr {
                extract_constraints_from_if(
                    if_expr,
                    extra_signals,
                    constraints,
                    aux_counter,
                    consts,
                    struct_defs,
                    type_env,
                );
            } else if let syn::Expr::While(while_expr) = expr {
                extract_constraints_from_while(
                    while_expr,
                    extra_signals,
                    constraints,
                    aux_counter,
                    consts,
                    struct_defs,
                    type_env,
                );
            } else {
                extract_constraints_from_expr(expr, extra_signals, constraints, aux_counter);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// 7B: Struct construction helper
// ---------------------------------------------------------------------------

/// Handle `let var = StructName { field1: expr1, field2: expr2, ... }`.
///
/// Emits flattened signals `{var}_{field}` and equality constraints for each
/// field initialiser expression.
fn handle_struct_construction(
    var_name: &str,
    struct_expr: &syn::ExprStruct,
    extra_signals: &mut Vec<TokenStream>,
    constraints: &mut Vec<TokenStream>,
    aux_counter: &mut usize,
    type_env: &mut TypeEnv,
) {
    // Record the binding as a Struct type in the type environment.
    let struct_type_name = struct_expr
        .path
        .get_ident()
        .map(|id| id.to_string())
        .unwrap_or_else(|| {
            // Multi-segment path: use the last segment.
            struct_expr
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default()
        });
    type_env.insert(var_name.to_string(), InferredType::Struct(struct_type_name));

    for field in &struct_expr.fields {
        let field_name = match &field.member {
            syn::Member::Named(ident) => ident.to_string(),
            syn::Member::Unnamed(idx) => idx.index.to_string(),
        };

        let flat_name = format!("{}_{}", var_name, field_name);

        extra_signals.push(quote! {
            signals.push(zkf_core::zir::Signal {
                name: #flat_name.to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zkf_core::zir::SignalType::Field,
                constant: None,
            });
        });

        let rhs_tokens = expr_to_zir_tokens(&field.expr, aux_counter);
        constraints.push(quote! {
            zkf_core::zir::Constraint::Equal {
                lhs: zkf_core::zir::Expr::Signal(#flat_name.to_string()),
                rhs: #rhs_tokens,
                label: Some(format!("assign_{}", #flat_name)),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Extract constraints from a standalone expression
// ---------------------------------------------------------------------------

/// Extract constraints from a standalone expression (e.g., assert_range(x, 8)).
fn extract_constraints_from_expr(
    expr: &syn::Expr,
    _extra_signals: &mut Vec<TokenStream>,
    constraints: &mut Vec<TokenStream>,
    _aux_counter: &mut usize,
) {
    if let syn::Expr::Call(call) = expr
        && let syn::Expr::Path(path) = &*call.func
        && let Some(ident) = path.path.get_ident()
    {
        let fn_name = ident.to_string();
        if !builtins::is_builtin(&fn_name) {
            constraints.push(compile_error_tokens(
                call,
                format!(
                    "unsupported call `{fn_name}` in circuit body; only supported DSL builtins may appear as standalone statements"
                ),
            ));
            return;
        }

        if let Some(op_token) = builtin_blackbox_op_tokens(&fn_name) {
            let mut input_exprs = Vec::new();
            for arg in &call.args {
                let Some(sig_name) = expr_to_signal_name(arg) else {
                    constraints.push(compile_error_tokens(
                        arg,
                        format!(
                            "builtin `{fn_name}` only accepts named signal arguments; complex expressions must be bound to a local signal first"
                        ),
                    ));
                    return;
                };
                input_exprs.push(quote! { zkf_core::zir::Expr::Signal(#sig_name.to_string()) });
            }
            let label_str = fn_name.clone();
            constraints.push(quote! {
                zkf_core::zir::Constraint::BlackBox {
                    op: #op_token,
                    inputs: vec![#(#input_exprs),*],
                    outputs: Vec::new(),
                    params: std::collections::BTreeMap::new(),
                    label: Some(#label_str.to_string()),
                }
            });
            return;
        }

        match fn_name.as_str() {
            "assert_range" => {
                if call.args.len() != 2 {
                    constraints.push(compile_error_tokens(
                        call,
                        "assert_range(signal, bits) requires exactly two arguments",
                    ));
                    return;
                }
                let Some(sig) = expr_to_signal_name(&call.args[0]) else {
                    constraints.push(compile_error_tokens(
                        &call.args[0],
                        "assert_range requires a named signal as its first argument",
                    ));
                    return;
                };
                let Some(bits) = expr_to_u32_literal(&call.args[1]) else {
                    constraints.push(compile_error_tokens(
                        &call.args[1],
                        "assert_range requires a literal bit width as its second argument",
                    ));
                    return;
                };
                constraints.push(quote! {
                    zkf_core::zir::Constraint::Range {
                        signal: #sig.to_string(),
                        bits: #bits,
                        label: Some(format!("range_{}_{}", #sig, #bits)),
                    }
                });
            }
            "assert_bool" => {
                if call.args.len() != 1 {
                    constraints.push(compile_error_tokens(
                        call,
                        "assert_bool(signal) requires exactly one argument",
                    ));
                    return;
                }
                let Some(sig) = expr_to_signal_name(&call.args[0]) else {
                    constraints.push(compile_error_tokens(
                        &call.args[0],
                        "assert_bool requires a named signal argument",
                    ));
                    return;
                };
                constraints.push(quote! {
                    zkf_core::zir::Constraint::Boolean {
                        signal: #sig.to_string(),
                        label: Some(format!("bool_{}", #sig)),
                    }
                });
            }
            _ => constraints.push(compile_error_tokens(
                call,
                format!(
                    "builtin `{fn_name}` is declared in the DSL but does not have a lowering in statement position"
                ),
            )),
        }
    } else if let syn::Expr::Call(call) = expr {
        constraints.push(compile_error_tokens(
            call,
            "unsupported call in circuit body; only bare DSL builtin names are supported as standalone statements",
        ));
    }
}

fn builtin_blackbox_op_tokens(name: &str) -> Option<TokenStream> {
    let op = builtins::builtin_to_blackbox_op(name)?;

    Some(match op {
        "Poseidon" => quote! { zkf_core::zir::BlackBoxOp::Poseidon },
        "SHA256" => quote! { zkf_core::zir::BlackBoxOp::Sha256 },
        "Keccak256" => quote! { zkf_core::zir::BlackBoxOp::Keccak256 },
        "Blake2s" => quote! { zkf_core::zir::BlackBoxOp::Blake2s },
        "Pedersen" => quote! { zkf_core::zir::BlackBoxOp::Pedersen },
        "EcdsaSecp256k1" => quote! { zkf_core::zir::BlackBoxOp::EcdsaSecp256k1 },
        "SchnorrVerify" => quote! { zkf_core::zir::BlackBoxOp::SchnorrVerify },
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Expression → ZIR token conversion
// ---------------------------------------------------------------------------

/// Convert a Rust expression AST to ZIR Expr token stream.
fn expr_to_zir_tokens(expr: &syn::Expr, _aux_counter: &mut usize) -> TokenStream {
    match expr {
        syn::Expr::Path(path) => {
            if let Some(ident) = path.path.get_ident() {
                let name = ident.to_string();
                quote! { zkf_core::zir::Expr::Signal(#name.to_string()) }
            } else {
                compile_error_tokens(
                    path,
                    "qualified paths are not supported in circuit expressions; bind the value to a local signal first",
                )
            }
        }
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(int_lit) => match int_lit.base10_parse::<i64>() {
                Ok(value) => quote! {
                    zkf_core::zir::Expr::Const(zkf_core::FieldElement::from_i64(#value))
                },
                Err(_) => compile_error_tokens(
                    int_lit,
                    "integer literal could not be represented as an i64 field constant during DSL lowering",
                ),
            },
            _ => compile_error_tokens(
                lit,
                "only integer literals are supported in arithmetic circuit expressions",
            ),
        },
        syn::Expr::Binary(binary) => {
            let left = expr_to_zir_tokens(&binary.left, _aux_counter);
            let right = expr_to_zir_tokens(&binary.right, _aux_counter);
            match binary.op {
                syn::BinOp::Add(_) | syn::BinOp::AddAssign(_) => {
                    quote! {
                        zkf_core::zir::Expr::Add(vec![#left, #right])
                    }
                }
                syn::BinOp::Sub(_) | syn::BinOp::SubAssign(_) => {
                    quote! {
                        zkf_core::zir::Expr::Sub(
                            Box::new(#left),
                            Box::new(#right),
                        )
                    }
                }
                syn::BinOp::Mul(_) | syn::BinOp::MulAssign(_) => {
                    quote! {
                        zkf_core::zir::Expr::Mul(
                            Box::new(#left),
                            Box::new(#right),
                        )
                    }
                }
                syn::BinOp::Div(_) | syn::BinOp::DivAssign(_) => {
                    quote! {
                        zkf_core::zir::Expr::Div(
                            Box::new(#left),
                            Box::new(#right),
                        )
                    }
                }
                syn::BinOp::Eq(_)
                | syn::BinOp::Lt(_)
                | syn::BinOp::Le(_)
                | syn::BinOp::Ne(_)
                | syn::BinOp::Ge(_)
                | syn::BinOp::Gt(_) => compile_error_tokens(
                    binary,
                    "comparison operators are not supported in arithmetic circuit expressions; use a supported assertion builtin or explicit boolean lowering instead",
                ),
                _ => compile_error_tokens(
                    binary,
                    "unsupported binary operator in circuit expression",
                ),
            }
        }
        syn::Expr::Paren(paren) => expr_to_zir_tokens(&paren.expr, _aux_counter),
        syn::Expr::Call(call) => compile_error_tokens(
            call,
            "function calls are not supported in expression position; bind the result through a supported builtin statement or import path instead",
        ),
        syn::Expr::Index(index_expr) => {
            // Array indexing: arr[i] where i is a literal → Signal("arr_i")
            let base = expr_to_signal_name(&index_expr.expr);
            let idx = if let syn::Expr::Lit(lit) = &*index_expr.index
                && let syn::Lit::Int(int_lit) = &lit.lit
            {
                int_lit.base10_parse::<i64>().ok()
            } else {
                None
            };
            if let (Some(base_name), Some(i)) = (base, idx) {
                let name = format!("{}_{}", base_name, i);
                quote! { zkf_core::zir::Expr::Signal(#name.to_string()) }
            } else {
                compile_error_tokens(
                    index_expr,
                    "dynamic or non-identifier indexing is not supported in circuit expressions; use a literal index on a named array binding",
                )
            }
        }
        // 7B: Field access — `p.x` → Signal("p_x")
        syn::Expr::Field(field_expr) => {
            if let Some(base_name) = expr_to_signal_name(&field_expr.base) {
                let field_name = match &field_expr.member {
                    syn::Member::Named(ident) => ident.to_string(),
                    syn::Member::Unnamed(idx) => idx.index.to_string(),
                };
                let flat = format!("{}_{}", base_name, field_name);
                quote! { zkf_core::zir::Expr::Signal(#flat.to_string()) }
            } else {
                compile_error_tokens(
                    field_expr,
                    "field access requires a named local or struct binding in circuit expressions",
                )
            }
        }
        _ => compile_error_tokens(
            expr,
            "unsupported expression in circuit DSL lowering; rewrite it using literals, named signals, field access, or supported arithmetic operators",
        ),
    }
}

/// Try to extract a signal name from a simple identifier expression.
fn expr_to_signal_name(expr: &syn::Expr) -> Option<String> {
    if let syn::Expr::Path(path) = expr {
        path.path.get_ident().map(|id| id.to_string())
    } else {
        None
    }
}

/// Try to extract a u32 literal from an expression.
fn expr_to_u32_literal(expr: &syn::Expr) -> Option<u32> {
    if let syn::Expr::Lit(lit) = expr
        && let syn::Lit::Int(int_lit) = &lit.lit
    {
        return int_lit.base10_parse().ok();
    }
    None
}

/// Try to extract an i64 literal from an expression.
fn expr_to_i64_literal(expr: &syn::Expr) -> Option<i64> {
    if let syn::Expr::Lit(lit) = expr
        && let syn::Lit::Int(int_lit) = &lit.lit
    {
        return int_lit.base10_parse().ok();
    }
    None
}

// ---------------------------------------------------------------------------
// 7A: Dynamic loop unrolling
// ---------------------------------------------------------------------------

/// Compile-time unroll a for loop over a range whose bounds may reference
/// previously defined constants.
///
/// Supports `for i in START..END { body }` where START and END can be:
/// - integer literals
/// - identifiers bound earlier via `let n = <literal>;`
/// - binary expressions over the above (e.g. `n * 2`, `n + 1`)
///
/// Each iteration emits uniquely-named signals (suffixed with `_iter_N`) and
/// constraints with the loop variable substituted by its iteration value.
fn extract_constraints_from_for_loop(
    for_loop: &syn::ExprForLoop,
    extra_signals: &mut Vec<TokenStream>,
    constraints: &mut Vec<TokenStream>,
    aux_counter: &mut usize,
    consts: &mut BTreeMap<String, i64>,
    struct_defs: &mut BTreeMap<String, Vec<(String, String)>>,
    type_env: &mut TypeEnv,
) {
    // Extract loop variable name.
    let loop_var = if let syn::Pat::Ident(pat_ident) = &*for_loop.pat {
        pat_ident.ident.to_string()
    } else {
        constraints.push(compile_error_tokens(
            &for_loop.pat,
            "for-loop patterns must be simple identifiers in the circuit DSL",
        ));
        return;
    };

    // Extract range bounds — now uses try_const_eval for dynamic support (7A).
    let (start, end) = match &*for_loop.expr {
        syn::Expr::Range(range) => {
            let Some(s) = range
                .start
                .as_ref()
                .and_then(|e| try_const_eval(e, consts))
                .or_else(|| range.start.as_ref().and_then(|e| expr_to_i64_literal(e)))
            else {
                constraints.push(compile_error_tokens(
                    range.start.as_ref().unwrap_or(&for_loop.expr),
                    "for-loop start bounds must be compile-time constant integer expressions",
                ));
                return;
            };
            let Some(e) = range
                .end
                .as_ref()
                .and_then(|e| try_const_eval(e, consts))
                .or_else(|| range.end.as_ref().and_then(|e| expr_to_i64_literal(e)))
            else {
                constraints.push(compile_error_tokens(
                    range.end.as_ref().unwrap_or(&for_loop.expr),
                    "for-loop end bounds must be compile-time constant integer expressions",
                ));
                return;
            };
            (s, e)
        }
        _ => {
            constraints.push(compile_error_tokens(
                &for_loop.expr,
                "for loops in the circuit DSL must use a range with compile-time constant bounds",
            ));
            return;
        }
    };

    // Unroll each iteration.
    for i in start..end {
        // Make the loop variable available as a constant inside the body so
        // that nested loops / expressions can use it.
        consts.insert(loop_var.clone(), i);

        for stmt in &for_loop.body.stmts {
            match stmt {
                syn::Stmt::Local(local) => {
                    if let Some(init) = &local.init
                        && let syn::Pat::Ident(pat_ident) = &local.pat
                    {
                        let base_name = pat_ident.ident.to_string();
                        let iter_name = format!("{}_iter_{}", base_name, i);

                        extra_signals.push(quote! {
                            signals.push(zkf_core::zir::Signal {
                                name: #iter_name.to_string(),
                                visibility: zkf_core::Visibility::Private,
                                ty: zkf_core::zir::SignalType::Field,
                                constant: None,
                            });
                        });

                        let rhs =
                            expr_to_zir_tokens_with_subst(&init.expr, aux_counter, &loop_var, i);
                        constraints.push(quote! {
                            zkf_core::zir::Constraint::Equal {
                                lhs: zkf_core::zir::Expr::Signal(#iter_name.to_string()),
                                rhs: #rhs,
                                label: Some(format!("assign_{}", #iter_name)),
                            }
                        });
                    }
                }
                syn::Stmt::Expr(expr, _) => {
                    if let syn::Expr::ForLoop(nested) = expr {
                        extract_constraints_from_for_loop(
                            nested,
                            extra_signals,
                            constraints,
                            aux_counter,
                            consts,
                            struct_defs,
                            type_env,
                        );
                    } else if let syn::Expr::If(if_expr) = expr {
                        extract_constraints_from_if(
                            if_expr,
                            extra_signals,
                            constraints,
                            aux_counter,
                            consts,
                            struct_defs,
                            type_env,
                        );
                    } else {
                        extract_constraints_from_expr(
                            expr,
                            extra_signals,
                            constraints,
                            aux_counter,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // Remove the loop variable from consts after the loop so it doesn't
    // pollute the outer scope (unless it was already there).
    consts.remove(&loop_var);
}

// ---------------------------------------------------------------------------
// While loop lowering (compile-time unrolling with const bound)
// ---------------------------------------------------------------------------

/// Lower a `while` loop to unrolled constraints.
///
/// The condition must be evaluable at compile time (e.g., `while i < N` where
/// `i` is a mutable counter and `N` is a known constant). The loop body is
/// unrolled up to a maximum of 1024 iterations to prevent infinite expansion.
///
/// Supports patterns like:
/// ```ignore
/// let mut i = 0;
/// while i < 10 {
///     // body using i
///     i += 1;
/// }
/// ```
fn extract_constraints_from_while(
    while_expr: &syn::ExprWhile,
    extra_signals: &mut Vec<TokenStream>,
    constraints: &mut Vec<TokenStream>,
    aux_counter: &mut usize,
    consts: &mut BTreeMap<String, i64>,
    struct_defs: &mut BTreeMap<String, Vec<(String, String)>>,
    type_env: &mut TypeEnv,
) {
    const MAX_WHILE_ITERATIONS: usize = 1024;

    for iteration in 0..MAX_WHILE_ITERATIONS {
        // Evaluate the condition at compile time.
        match eval_while_condition(&while_expr.cond, consts) {
            Some(true) => {}
            Some(false) => break,
            None => {
                constraints.push(compile_error_tokens(
                    &while_expr.cond,
                    "while-loop conditions must be compile-time evaluable boolean comparisons over integer constants",
                ));
                return;
            }
        }

        // Process each statement in the body.
        for stmt in &while_expr.body.stmts {
            // Check for increment/assignment patterns like `i += 1` or `i = i + 1`
            if let syn::Stmt::Expr(expr, _) = stmt
                && try_apply_assign_op(expr, consts)
            {
                continue;
            }

            extract_constraints_from_stmt(
                stmt,
                extra_signals,
                constraints,
                aux_counter,
                consts,
                struct_defs,
                type_env,
            );
        }

        // Safety: prevent infinite unrolling
        if iteration == MAX_WHILE_ITERATIONS - 1 {
            break;
        }
    }
}

/// Evaluate a while-loop condition against the current const environment.
///
/// Supports: `expr < expr`, `expr <= expr`, `expr > expr`, `expr >= expr`,
/// `expr != expr`, `expr == expr`, and boolean literals.
fn eval_while_condition(cond: &syn::Expr, consts: &BTreeMap<String, i64>) -> Option<bool> {
    match cond {
        syn::Expr::Binary(bin) => {
            let lhs = try_const_eval(&bin.left, consts);
            let rhs = try_const_eval(&bin.right, consts);
            match (lhs, rhs) {
                (Some(l), Some(r)) => match bin.op {
                    syn::BinOp::Lt(_) => Some(l < r),
                    syn::BinOp::Le(_) => Some(l <= r),
                    syn::BinOp::Gt(_) => Some(l > r),
                    syn::BinOp::Ge(_) => Some(l >= r),
                    syn::BinOp::Ne(_) => Some(l != r),
                    syn::BinOp::Eq(_) => Some(l == r),
                    _ => None,
                },
                _ => None,
            }
        }
        syn::Expr::Lit(lit) => match lit.lit {
            syn::Lit::Bool(ref b) => Some(b.value()),
            _ => None,
        },
        syn::Expr::Paren(paren) => eval_while_condition(&paren.expr, consts),
        _ => None,
    }
}

/// Try to apply an assignment operator expression like `i += 1` to the const map.
/// Returns true if the expression was recognized and applied.
fn try_apply_assign_op(expr: &syn::Expr, consts: &mut BTreeMap<String, i64>) -> bool {
    if let syn::Expr::Assign(assign) = expr {
        // `i = expr` where expr uses consts
        if let syn::Expr::Path(path) = &*assign.left
            && let Some(name) = path.path.get_ident()
        {
            let name = name.to_string();
            if let Some(val) = try_const_eval(&assign.right, consts) {
                consts.insert(name, val);
                return true;
            }
        }
    }
    if let syn::Expr::Binary(bin) = expr
        && let syn::Expr::Path(path) = &*bin.left
        && let Some(name) = path.path.get_ident()
    {
        let name_str = name.to_string();
        if let Some(rhs_val) = try_const_eval(&bin.right, consts)
            && let Some(current) = consts.get(&name_str).copied()
        {
            let new_val = match bin.op {
                syn::BinOp::AddAssign(_) => current.checked_add(rhs_val),
                syn::BinOp::SubAssign(_) => current.checked_sub(rhs_val),
                syn::BinOp::MulAssign(_) => current.checked_mul(rhs_val),
                _ => None,
            };
            if let Some(v) = new_val {
                consts.insert(name_str, v);
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// If/else conditional lowering
// ---------------------------------------------------------------------------

/// Lower an if/else expression to conditional constraints.
///
/// Uses the selector pattern: for `if s { lhs == rhs }`, emits
/// `s * (lhs - rhs) == 0` which is trivially satisfied when s=0.
/// For else-branches, uses `(1 - s) * (lhs - rhs) == 0`.
fn extract_constraints_from_if(
    if_expr: &syn::ExprIf,
    extra_signals: &mut Vec<TokenStream>,
    constraints: &mut Vec<TokenStream>,
    aux_counter: &mut usize,
    consts: &mut BTreeMap<String, i64>,
    struct_defs: &mut BTreeMap<String, Vec<(String, String)>>,
    type_env: &mut TypeEnv,
) {
    // Extract selector signal name from the condition.
    let selector = if let syn::Expr::Path(path) = &*if_expr.cond {
        path.path.get_ident().map(|id| id.to_string())
    } else {
        None
    };

    let Some(selector_name) = selector else {
        constraints.push(compile_error_tokens(
            &if_expr.cond,
            "if conditions in the circuit DSL must be a named selector signal; computed boolean expressions are not lowered implicitly",
        ));
        return;
    };

    // Process then-branch: collect constraints, then wrap with selector.
    let mut then_constraints = Vec::new();
    let mut then_signals = Vec::new();
    for stmt in &if_expr.then_branch.stmts {
        extract_constraints_from_stmt(
            stmt,
            &mut then_signals,
            &mut then_constraints,
            aux_counter,
            consts,
            struct_defs,
            type_env,
        );
    }
    extra_signals.extend(then_signals);

    // Wrap each then-branch constraint: selector * (lhs - rhs) == 0
    for c in then_constraints {
        let sel = selector_name.clone();
        constraints.push(quote! {{
            let __inner = #c;
            if let zkf_core::zir::Constraint::Equal { lhs, rhs, label } = __inner {
                zkf_core::zir::Constraint::Equal {
                    lhs: zkf_core::zir::Expr::Mul(
                        Box::new(zkf_core::zir::Expr::Signal(#sel.to_string())),
                        Box::new(zkf_core::zir::Expr::Sub(
                            Box::new(lhs),
                            Box::new(rhs),
                        )),
                    ),
                    rhs: zkf_core::zir::Expr::Const(zkf_core::FieldElement::from_i64(0)),
                    label: label.map(|l| format!("if_{}_{}", #sel, l)),
                }
            } else {
                __inner
            }
        }});
    }

    // Process else-branch if present.
    if let Some((_, else_expr)) = &if_expr.else_branch {
        let mut else_constraints = Vec::new();
        let mut else_signals = Vec::new();

        match else_expr.as_ref() {
            syn::Expr::Block(block) => {
                for stmt in &block.block.stmts {
                    extract_constraints_from_stmt(
                        stmt,
                        &mut else_signals,
                        &mut else_constraints,
                        aux_counter,
                        consts,
                        struct_defs,
                        type_env,
                    );
                }
            }
            syn::Expr::If(nested_if) => {
                extract_constraints_from_if(
                    nested_if,
                    &mut else_signals,
                    &mut else_constraints,
                    aux_counter,
                    consts,
                    struct_defs,
                    type_env,
                );
            }
            _ => {
                else_constraints.push(compile_error_tokens(
                    else_expr,
                    "else branches in the circuit DSL must be blocks or nested if-expressions",
                ));
            }
        }

        extra_signals.extend(else_signals);

        // Wrap else-branch: (1 - selector) * (lhs - rhs) == 0
        for c in else_constraints {
            let sel = selector_name.clone();
            constraints.push(quote! {{
                let __inner = #c;
                if let zkf_core::zir::Constraint::Equal { lhs, rhs, label } = __inner {
                    zkf_core::zir::Constraint::Equal {
                        lhs: zkf_core::zir::Expr::Mul(
                            Box::new(zkf_core::zir::Expr::Sub(
                                Box::new(zkf_core::zir::Expr::Const(
                                    zkf_core::FieldElement::from_i64(1),
                                )),
                                Box::new(zkf_core::zir::Expr::Signal(#sel.to_string())),
                            )),
                            Box::new(zkf_core::zir::Expr::Sub(
                                Box::new(lhs),
                                Box::new(rhs),
                            )),
                        ),
                        rhs: zkf_core::zir::Expr::Const(zkf_core::FieldElement::from_i64(0)),
                        label: label.map(|l| format!("else_{}_{}", #sel, l)),
                    }
                } else {
                    __inner
                }
            }});
        }
    }
}

// ---------------------------------------------------------------------------
// Loop-variable substitution
// ---------------------------------------------------------------------------

/// Convert a Rust expression AST to ZIR Expr token stream, substituting
/// the loop variable with its current iteration value.
fn expr_to_zir_tokens_with_subst(
    expr: &syn::Expr,
    aux_counter: &mut usize,
    loop_var: &str,
    iter_val: i64,
) -> TokenStream {
    match expr {
        syn::Expr::Path(path) => {
            if let Some(ident) = path.path.get_ident() {
                let name = ident.to_string();
                if name == loop_var {
                    quote! { zkf_core::zir::Expr::Const(zkf_core::FieldElement::from_i64(#iter_val)) }
                } else {
                    quote! { zkf_core::zir::Expr::Signal(#name.to_string()) }
                }
            } else {
                compile_error_tokens(
                    path,
                    "qualified paths are not supported in loop-substituted circuit expressions",
                )
            }
        }
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(int_lit) => match int_lit.base10_parse::<i64>() {
                Ok(value) => {
                    quote! { zkf_core::zir::Expr::Const(zkf_core::FieldElement::from_i64(#value)) }
                }
                Err(_) => compile_error_tokens(
                    int_lit,
                    "integer literal could not be represented as an i64 field constant during loop lowering",
                ),
            },
            _ => compile_error_tokens(
                lit,
                "only integer literals are supported in loop-substituted arithmetic expressions",
            ),
        },
        syn::Expr::Binary(binary) => {
            let left = expr_to_zir_tokens_with_subst(&binary.left, aux_counter, loop_var, iter_val);
            let right =
                expr_to_zir_tokens_with_subst(&binary.right, aux_counter, loop_var, iter_val);
            match binary.op {
                syn::BinOp::Add(_) | syn::BinOp::AddAssign(_) => {
                    quote! { zkf_core::zir::Expr::Add(vec![#left, #right]) }
                }
                syn::BinOp::Sub(_) | syn::BinOp::SubAssign(_) => {
                    quote! { zkf_core::zir::Expr::Sub(Box::new(#left), Box::new(#right)) }
                }
                syn::BinOp::Mul(_) | syn::BinOp::MulAssign(_) => {
                    quote! { zkf_core::zir::Expr::Mul(Box::new(#left), Box::new(#right)) }
                }
                syn::BinOp::Div(_) | syn::BinOp::DivAssign(_) => {
                    quote! { zkf_core::zir::Expr::Div(Box::new(#left), Box::new(#right)) }
                }
                syn::BinOp::Eq(_)
                | syn::BinOp::Lt(_)
                | syn::BinOp::Le(_)
                | syn::BinOp::Ne(_)
                | syn::BinOp::Ge(_)
                | syn::BinOp::Gt(_) => compile_error_tokens(
                    binary,
                    "comparison operators are not supported in loop-substituted arithmetic expressions; use a supported assertion builtin instead",
                ),
                _ => compile_error_tokens(
                    binary,
                    "unsupported binary operator in loop-substituted circuit expression",
                ),
            }
        }
        syn::Expr::Paren(paren) => {
            expr_to_zir_tokens_with_subst(&paren.expr, aux_counter, loop_var, iter_val)
        }
        syn::Expr::Index(index_expr) => {
            // Array indexing with loop variable: arr[i] → Signal("arr_{iter_val}")
            let base = expr_to_signal_name(&index_expr.expr);
            let idx = if let syn::Expr::Path(p) = &*index_expr.index
                && let Some(id) = p.path.get_ident()
                && *id == loop_var
            {
                Some(iter_val)
            } else if let syn::Expr::Lit(lit) = &*index_expr.index
                && let syn::Lit::Int(int_lit) = &lit.lit
            {
                int_lit.base10_parse::<i64>().ok()
            } else {
                None
            };
            if let (Some(base_name), Some(i)) = (base, idx) {
                let name = format!("{}_{}", base_name, i);
                quote! { zkf_core::zir::Expr::Signal(#name.to_string()) }
            } else {
                expr_to_zir_tokens(expr, aux_counter)
            }
        }
        // 7B: Field access inside a loop body.
        syn::Expr::Field(field_expr) => {
            if let Some(base_name) = expr_to_signal_name(&field_expr.base) {
                let field_name = match &field_expr.member {
                    syn::Member::Named(ident) => ident.to_string(),
                    syn::Member::Unnamed(idx) => idx.index.to_string(),
                };
                let flat = format!("{}_{}", base_name, field_name);
                quote! { zkf_core::zir::Expr::Signal(#flat.to_string()) }
            } else {
                expr_to_zir_tokens(expr, aux_counter)
            }
        }
        _ => expr_to_zir_tokens(expr, aux_counter),
    }
}

// ---------------------------------------------------------------------------
// 7C: Type annotation helpers
// ---------------------------------------------------------------------------

/// Extract an `InferredType` from a `syn::Pat::Type` wrapper, if present.
///
/// For `let x: u32 = …`, syn parses the binding as `Pat::Type { pat: Pat::Ident("x"), ty: u32 }`.
/// This function handles that inner type annotation.
fn extract_pat_type_annotation(pat: &syn::Pat) -> Option<InferredType> {
    if let syn::Pat::Type(pat_type) = pat {
        Some(syn_type_to_inferred(&pat_type.ty))
    } else {
        None
    }
}

/// Convert a `syn::Type` to an `InferredType`.
fn syn_type_to_inferred(ty: &syn::Type) -> InferredType {
    if let syn::Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return match ident.to_string().as_str() {
            "bool" => InferredType::Bool,
            "u8" => InferredType::UInt(8),
            "u16" => InferredType::UInt(16),
            "u32" => InferredType::UInt(32),
            "u64" => InferredType::UInt(64),
            "u128" => InferredType::UInt(128),
            name => InferredType::Struct(name.to_string()),
        };
    }
    InferredType::Unknown
}

/// Convert an `InferredType` to the `zkf_core::zir::SignalType` token stream.
fn inferred_type_to_signal_type_tokens(ty: &InferredType) -> TokenStream {
    match ty {
        InferredType::Bool => quote! { zkf_core::zir::SignalType::Bool },
        InferredType::UInt(8) => quote! { zkf_core::zir::SignalType::UInt { bits: 8 } },
        InferredType::UInt(16) => quote! { zkf_core::zir::SignalType::UInt { bits: 16 } },
        InferredType::UInt(32) => quote! { zkf_core::zir::SignalType::UInt { bits: 32 } },
        InferredType::UInt(64) => quote! { zkf_core::zir::SignalType::UInt { bits: 64 } },
        _ => quote! { zkf_core::zir::SignalType::Field },
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // 7A: try_const_eval
    // -----------------------------------------------------------------------

    fn parse_expr(src: &str) -> syn::Expr {
        syn::parse_str(src).expect("parse_expr failed")
    }

    fn assert_compile_error(tokens: &TokenStream, expected_fragment: &str) {
        let rendered = tokens.to_string();
        assert!(
            rendered.contains("compile_error"),
            "expected compile_error! in: {rendered}"
        );
        assert!(
            rendered.contains(expected_fragment),
            "expected `{expected_fragment}` in: {rendered}"
        );
    }

    #[test]
    fn const_eval_integer_literal() {
        let expr = parse_expr("42");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), Some(42));
    }

    #[test]
    fn const_eval_identifier_lookup() {
        let expr = parse_expr("n");
        let mut consts = BTreeMap::new();
        consts.insert("n".to_string(), 10);
        assert_eq!(try_const_eval(&expr, &consts), Some(10));
    }

    #[test]
    fn const_eval_identifier_missing() {
        let expr = parse_expr("n");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), None);
    }

    #[test]
    fn const_eval_add() {
        let expr = parse_expr("3 + 4");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), Some(7));
    }

    #[test]
    fn const_eval_sub() {
        let expr = parse_expr("10 - 3");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), Some(7));
    }

    #[test]
    fn const_eval_mul() {
        let expr = parse_expr("3 * 4");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), Some(12));
    }

    #[test]
    fn const_eval_div() {
        let expr = parse_expr("12 / 4");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), Some(3));
    }

    #[test]
    fn const_eval_div_by_zero() {
        let expr = parse_expr("12 / 0");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), None);
    }

    #[test]
    fn const_eval_paren() {
        let expr = parse_expr("(3 + 4)");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), Some(7));
    }

    #[test]
    fn const_eval_ident_times_literal() {
        let expr = parse_expr("n * 2");
        let mut consts = BTreeMap::new();
        consts.insert("n".to_string(), 4);
        assert_eq!(try_const_eval(&expr, &consts), Some(8));
    }

    #[test]
    fn const_eval_complex_expr() {
        // (n * 2) + 1  where n = 3  → 7
        let expr = parse_expr("(n * 2) + 1");
        let mut consts = BTreeMap::new();
        consts.insert("n".to_string(), 3);
        assert_eq!(try_const_eval(&expr, &consts), Some(7));
    }

    #[test]
    fn const_eval_unsupported_expr_returns_none() {
        // A function call cannot be const-eval'd.
        let expr = parse_expr("foo()");
        let consts = BTreeMap::new();
        assert_eq!(try_const_eval(&expr, &consts), None);
    }

    #[test]
    fn const_eval_overflow_returns_none() {
        let expr = parse_expr("9223372036854775807 + 1"); // i64::MAX + 1
        let consts = BTreeMap::new();
        // checked_add should return None for overflow.
        assert_eq!(try_const_eval(&expr, &consts), None);
    }

    // -----------------------------------------------------------------------
    // 7B: Struct field flattening — via expr_to_zir_tokens (Field access)
    // -----------------------------------------------------------------------

    #[test]
    fn field_access_flattens_to_signal() {
        // `p.x` should produce Signal("p_x")
        let expr: syn::Expr = parse_expr("p.x");
        let mut aux = 0usize;
        let tokens = expr_to_zir_tokens(&expr, &mut aux);
        let s = tokens.to_string();
        // The generated token stream should reference "p_x"
        assert!(s.contains("p_x"), "expected p_x in: {}", s);
    }

    #[test]
    fn field_access_unnamed_flattens_to_index() {
        // `t.0` should produce Signal("t_0")
        let expr: syn::Expr = parse_expr("t.0");
        let mut aux = 0usize;
        let tokens = expr_to_zir_tokens(&expr, &mut aux);
        let s = tokens.to_string();
        assert!(s.contains("t_0"), "expected t_0 in: {}", s);
    }

    #[test]
    fn comparison_expression_emits_compile_error() {
        let expr: syn::Expr = parse_expr("a == b");
        let mut aux = 0usize;
        let tokens = expr_to_zir_tokens(&expr, &mut aux);
        assert_compile_error(&tokens, "comparison operators are not supported");
    }

    #[test]
    fn dynamic_index_expression_emits_compile_error() {
        let expr: syn::Expr = parse_expr("values[i]");
        let mut aux = 0usize;
        let tokens = expr_to_zir_tokens(&expr, &mut aux);
        assert_compile_error(
            &tokens,
            "dynamic or non-identifier indexing is not supported",
        );
    }

    #[test]
    fn call_expression_emits_compile_error() {
        let expr: syn::Expr = parse_expr("foo(x)");
        let mut aux = 0usize;
        let tokens = expr_to_zir_tokens(&expr, &mut aux);
        assert_compile_error(
            &tokens,
            "function calls are not supported in expression position",
        );
    }

    #[test]
    fn unsupported_builtin_statement_emits_compile_error() {
        let expr: syn::Expr = parse_expr("assert_eq(a, b)");
        let mut constraints = Vec::new();
        let mut extra_signals = Vec::new();
        let mut aux = 0usize;
        extract_constraints_from_expr(&expr, &mut extra_signals, &mut constraints, &mut aux);
        assert_eq!(constraints.len(), 1);
        assert_compile_error(
            &constraints[0],
            "does not have a lowering in statement position",
        );
    }

    #[test]
    fn if_condition_must_be_selector_signal() {
        let if_expr: syn::ExprIf = syn::parse_str("if a == b { assert_bool(flag); }").unwrap();
        let mut extra_signals = Vec::new();
        let mut constraints = Vec::new();
        let mut aux = 0usize;
        let mut consts = BTreeMap::new();
        let mut struct_defs = BTreeMap::new();
        let mut type_env = TypeEnv::new();
        extract_constraints_from_if(
            &if_expr,
            &mut extra_signals,
            &mut constraints,
            &mut aux,
            &mut consts,
            &mut struct_defs,
            &mut type_env,
        );
        assert_eq!(constraints.len(), 1);
        assert_compile_error(
            &constraints[0],
            "if conditions in the circuit DSL must be a named selector signal",
        );
    }

    #[test]
    fn while_condition_must_be_compile_time_evaluable() {
        let while_expr: syn::ExprWhile =
            syn::parse_str("while foo(x) { assert_bool(flag); }").unwrap();
        let mut extra_signals = Vec::new();
        let mut constraints = Vec::new();
        let mut aux = 0usize;
        let mut consts = BTreeMap::new();
        let mut struct_defs = BTreeMap::new();
        let mut type_env = TypeEnv::new();
        extract_constraints_from_while(
            &while_expr,
            &mut extra_signals,
            &mut constraints,
            &mut aux,
            &mut consts,
            &mut struct_defs,
            &mut type_env,
        );
        assert_eq!(constraints.len(), 1);
        assert_compile_error(
            &constraints[0],
            "while-loop conditions must be compile-time evaluable boolean comparisons",
        );
    }

    // -----------------------------------------------------------------------
    // 7C: Type helpers
    // -----------------------------------------------------------------------

    #[test]
    fn syn_type_to_inferred_bool() {
        let ty: syn::Type = syn::parse_str("bool").unwrap();
        assert_eq!(syn_type_to_inferred(&ty), InferredType::Bool);
    }

    #[test]
    fn syn_type_to_inferred_u32() {
        let ty: syn::Type = syn::parse_str("u32").unwrap();
        assert_eq!(syn_type_to_inferred(&ty), InferredType::UInt(32));
    }

    #[test]
    fn syn_type_to_inferred_u64() {
        let ty: syn::Type = syn::parse_str("u64").unwrap();
        assert_eq!(syn_type_to_inferred(&ty), InferredType::UInt(64));
    }

    #[test]
    fn syn_type_to_inferred_unknown() {
        let ty: syn::Type = syn::parse_str("Vec<u8>").unwrap();
        assert_eq!(syn_type_to_inferred(&ty), InferredType::Unknown);
    }

    #[test]
    fn inferred_type_signal_type_tokens_bool() {
        let tokens = inferred_type_to_signal_type_tokens(&InferredType::Bool);
        assert!(tokens.to_string().contains("Bool"));
    }

    #[test]
    fn inferred_type_signal_type_tokens_uint32() {
        let tokens = inferred_type_to_signal_type_tokens(&InferredType::UInt(32));
        let s = tokens.to_string();
        assert!(s.contains("UInt") && s.contains("32"));
    }

    #[test]
    fn inferred_type_signal_type_tokens_field_fallback() {
        let tokens = inferred_type_to_signal_type_tokens(&InferredType::Unknown);
        assert!(tokens.to_string().contains("Field"));
    }
}
