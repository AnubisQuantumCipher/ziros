mod wallet_ffi;

use once_cell::sync::Lazy;
use serde_json::Value;
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;
use std::str::FromStr;
use std::sync::Mutex;
use zkf_core::{CompiledProgram, Expr, FieldId, Program, ProofArtifact};
use zkf_lib::{
    ProgramBuilder, WitnessInputs, ZkfError, compile, compile_default, prove, verify,
    witness_from_inputs, witness_inputs_from_json_map,
};

pub use wallet_ffi::*;

pub(crate) static LAST_ERROR: Lazy<Mutex<Option<CString>>> = Lazy::new(|| Mutex::new(None));

#[repr(C)]
pub struct ZkfProgramBuilderHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZkfProgramHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZkfCompiledProgramHandle {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZkfProofArtifactHandle {
    _private: [u8; 0],
}

pub(crate) fn sanitize_cstring(message: String) -> CString {
    let filtered = message.replace('\0', " ");
    match CString::new(filtered) {
        Ok(value) => value,
        Err(_) => CString::new("ffi error").expect("ffi fallback error string"),
    }
}

pub(crate) fn set_last_error(message: impl Into<String>) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = Some(sanitize_cstring(message.into()));
    }
}

pub(crate) fn clear_last_error() {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = None;
    }
}

pub(crate) fn c_int_error(message: impl Into<String>) -> c_int {
    set_last_error(message);
    -1
}

pub(crate) fn null_error<T>(message: impl Into<String>) -> *mut T {
    set_last_error(message);
    ptr::null_mut()
}

pub(crate) fn false_error(message: impl Into<String>) -> bool {
    set_last_error(message);
    false
}

pub(crate) fn string_arg(ptr: *const c_char, label: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{label} pointer is null"));
    }

    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str()
        .map(|value| value.to_string())
        .map_err(|err| format!("invalid UTF-8 in {label}: {err}"))
}

fn field_arg(ptr: *const c_char) -> Result<FieldId, String> {
    let raw = string_arg(ptr, "field")?;
    FieldId::from_str(&raw).map_err(|err| format!("invalid field '{raw}': {err}"))
}

fn backend_arg(ptr: *const c_char) -> Result<Option<String>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    string_arg(ptr, "backend").map(Some)
}

fn parse_expr_json(ptr: *const c_char, label: &str) -> Result<Expr, String> {
    let raw = string_arg(ptr, label)?;
    serde_json::from_str(&raw).map_err(|err| format!("failed to parse {label}: {err}"))
}

fn parse_inputs_json(ptr: *const c_char) -> Result<WitnessInputs, String> {
    let raw = string_arg(ptr, "inputs_json")?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|err| format!("failed to parse inputs_json: {err}"))?;
    match value {
        Value::Object(map) => witness_inputs_from_json_map(&map).map_err(error_to_string),
        other => Err(format!(
            "inputs_json must be a JSON object, found {}",
            other
        )),
    }
}

fn compile_program(program: &Program, backend: Option<&str>) -> Result<CompiledProgram, String> {
    match backend {
        Some(value) => compile(program, value, None).map_err(error_to_string),
        None => compile_default(program, None).map_err(error_to_string),
    }
}

fn error_to_string(error: ZkfError) -> String {
    error.to_string()
}

fn with_builder_mut<T>(
    handle: *mut ZkfProgramBuilderHandle,
    f: impl FnOnce(&mut ProgramBuilder) -> Result<T, String>,
) -> Result<T, String> {
    if handle.is_null() {
        return Err("builder pointer is null".to_string());
    }

    let builder = unsafe { &mut *(handle as *mut ProgramBuilder) };
    f(builder)
}

fn with_program_ref<T>(
    handle: *mut ZkfProgramHandle,
    f: impl FnOnce(&Program) -> Result<T, String>,
) -> Result<T, String> {
    if handle.is_null() {
        return Err("program pointer is null".to_string());
    }

    let program = unsafe { &*(handle as *mut Program) };
    f(program)
}

fn with_artifact_ref<T>(
    handle: *mut ZkfProofArtifactHandle,
    f: impl FnOnce(&ProofArtifact) -> Result<T, String>,
) -> Result<T, String> {
    if handle.is_null() {
        return Err("artifact pointer is null".to_string());
    }

    let artifact = unsafe { &*(handle as *mut ProofArtifact) };
    f(artifact)
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_last_error_message() -> *const c_char {
    match LAST_ERROR.lock() {
        Ok(slot) => slot.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
        Err(_) => ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(value));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_program_builder_new(
    name: *const c_char,
    field: *const c_char,
) -> *mut ZkfProgramBuilderHandle {
    clear_last_error();
    let result: Result<*mut ZkfProgramBuilderHandle, String> = (|| {
        let name = string_arg(name, "name")?;
        let field = field_arg(field)?;
        Ok(Box::into_raw(Box::new(ProgramBuilder::new(name, field)))
            as *mut ZkfProgramBuilderHandle)
    })();

    match result {
        Ok(handle) => handle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_program_builder_private_input(
    builder: *mut ZkfProgramBuilderHandle,
    name: *const c_char,
) -> c_int {
    clear_last_error();
    match with_builder_mut(builder, |builder| {
        let name = string_arg(name, "name")?;
        builder.private_input(name).map_err(error_to_string)?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_program_builder_public_output(
    builder: *mut ZkfProgramBuilderHandle,
    name: *const c_char,
) -> c_int {
    clear_last_error();
    match with_builder_mut(builder, |builder| {
        let name = string_arg(name, "name")?;
        builder.public_output(name).map_err(error_to_string)?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_program_builder_add_assignment_json(
    builder: *mut ZkfProgramBuilderHandle,
    target: *const c_char,
    expr_json: *const c_char,
) -> c_int {
    clear_last_error();
    match with_builder_mut(builder, |builder| {
        let target = string_arg(target, "target")?;
        let expr = parse_expr_json(expr_json, "expr_json")?;
        builder
            .add_assignment(target, expr)
            .map_err(error_to_string)?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_program_builder_constrain_equal_json(
    builder: *mut ZkfProgramBuilderHandle,
    lhs_json: *const c_char,
    rhs_json: *const c_char,
) -> c_int {
    clear_last_error();
    match with_builder_mut(builder, |builder| {
        let lhs = parse_expr_json(lhs_json, "lhs_json")?;
        let rhs = parse_expr_json(rhs_json, "rhs_json")?;
        builder.constrain_equal(lhs, rhs).map_err(error_to_string)?;
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => c_int_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_program_builder_build(
    builder: *mut ZkfProgramBuilderHandle,
) -> *mut ZkfProgramHandle {
    clear_last_error();
    match with_builder_mut(builder, |builder| builder.build().map_err(error_to_string)) {
        Ok(program) => Box::into_raw(Box::new(program)) as *mut ZkfProgramHandle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_compile(
    program: *mut ZkfProgramHandle,
    backend: *const c_char,
) -> *mut ZkfCompiledProgramHandle {
    clear_last_error();
    let result = with_program_ref(program, |program| {
        let backend = backend_arg(backend)?;
        compile_program(program, backend.as_deref())
    });

    match result {
        Ok(compiled) => Box::into_raw(Box::new(compiled)) as *mut ZkfCompiledProgramHandle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_prove(
    program: *mut ZkfProgramHandle,
    inputs_json: *const c_char,
    backend: *const c_char,
) -> *mut ZkfProofArtifactHandle {
    clear_last_error();
    let result = with_program_ref(program, |program| {
        let inputs = parse_inputs_json(inputs_json)?;
        let backend = backend_arg(backend)?;
        let compiled = compile_program(program, backend.as_deref())?;
        let witness = witness_from_inputs(program, &inputs, None).map_err(error_to_string)?;
        prove(&compiled, &witness).map_err(error_to_string)
    });

    match result {
        Ok(artifact) => Box::into_raw(Box::new(artifact)) as *mut ZkfProofArtifactHandle,
        Err(err) => null_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_verify(
    program: *mut ZkfProgramHandle,
    artifact: *mut ZkfProofArtifactHandle,
    backend: *const c_char,
) -> bool {
    clear_last_error();
    let result = with_program_ref(program, |program| {
        with_artifact_ref(artifact, |artifact| {
            let backend = backend_arg(backend)?;
            let compiled = compile_program(program, backend.as_deref())?;
            verify(&compiled, artifact).map_err(error_to_string)
        })
    });

    match result {
        Ok(value) => value,
        Err(err) => false_error(err),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_free_program_builder(builder: *mut ZkfProgramBuilderHandle) {
    if builder.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(builder as *mut ProgramBuilder));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_free_program(program: *mut ZkfProgramHandle) {
    if program.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(program as *mut Program));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_free_compiled_program(compiled: *mut ZkfCompiledProgramHandle) {
    if compiled.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(compiled as *mut CompiledProgram));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn zkf_free_proof_artifact(artifact: *mut ZkfProofArtifactHandle) {
    if artifact.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(artifact as *mut ProofArtifact));
    }
}
