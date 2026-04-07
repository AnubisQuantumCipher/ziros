use std::ffi::{CStr, CString};

use zkf_ffi::{
    zkf_compile, zkf_free_compiled_program, zkf_free_program, zkf_free_program_builder,
    zkf_free_proof_artifact, zkf_last_error_message, zkf_program_builder_add_assignment_json,
    zkf_program_builder_build, zkf_program_builder_constrain_equal_json,
    zkf_program_builder_new, zkf_program_builder_private_input,
    zkf_program_builder_public_output, zkf_prove, zkf_verify,
};

fn last_error() -> String {
    let pointer = zkf_last_error_message();
    if pointer.is_null() {
        "(unknown ffi error)".to_string()
    } else {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

#[test]
fn ffi_surface_compiles_proves_and_verifies() {
    let name = CString::new("ffi_multiply").expect("name");
    let field = CString::new("goldilocks").expect("field");
    let x = CString::new("x").expect("x");
    let y = CString::new("y").expect("y");
    let product = CString::new("product").expect("product");
    let mul_expr = CString::new(
        "{\"op\":\"mul\",\"args\":[{\"op\":\"signal\",\"args\":\"x\"},{\"op\":\"signal\",\"args\":\"y\"}]}",
    )
    .expect("mul expr");
    let product_expr =
        CString::new("{\"op\":\"signal\",\"args\":\"product\"}").expect("product expr");
    let inputs_json = CString::new("{\"x\":\"3\",\"y\":\"7\"}").expect("inputs json");
    let backend = CString::new("plonky3").expect("backend");

    let builder = zkf_program_builder_new(name.as_ptr(), field.as_ptr());
    assert!(!builder.is_null(), "{}", last_error());
    assert_eq!(
        zkf_program_builder_private_input(builder, x.as_ptr()),
        0,
        "{}",
        last_error()
    );
    assert_eq!(
        zkf_program_builder_private_input(builder, y.as_ptr()),
        0,
        "{}",
        last_error()
    );
    assert_eq!(
        zkf_program_builder_public_output(builder, product.as_ptr()),
        0,
        "{}",
        last_error()
    );
    assert_eq!(
        zkf_program_builder_add_assignment_json(builder, product.as_ptr(), mul_expr.as_ptr()),
        0,
        "{}",
        last_error()
    );
    assert_eq!(
        zkf_program_builder_constrain_equal_json(builder, product_expr.as_ptr(), mul_expr.as_ptr()),
        0,
        "{}",
        last_error()
    );

    let program = zkf_program_builder_build(builder);
    assert!(!program.is_null(), "{}", last_error());

    let compiled = zkf_compile(program, backend.as_ptr());
    assert!(!compiled.is_null(), "{}", last_error());

    let artifact = zkf_prove(program, inputs_json.as_ptr(), backend.as_ptr());
    assert!(!artifact.is_null(), "{}", last_error());
    assert!(zkf_verify(program, artifact, backend.as_ptr()), "{}", last_error());

    zkf_free_proof_artifact(artifact);
    zkf_free_compiled_program(compiled);
    zkf_free_program(program);
    zkf_free_program_builder(builder);
}
