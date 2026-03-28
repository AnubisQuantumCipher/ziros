extern crate proc_macro;

mod builtins;
mod lower;
mod parse;
mod types;

use proc_macro::TokenStream;
use syn::parse_macro_input;

/// Attribute macro that transforms a Rust function into a ZK circuit.
///
/// # Usage
///
/// ```ignore
/// #[zkf::circuit(field = "bn254")]
/// fn verify_age(
///     birth_year: Private<u32>,
///     current_year: Public<u32>,
///     threshold: Public<u32>,
/// ) -> Public<bool> {
///     let age = current_year - birth_year;
///     assert_range(age, 8);
///     age >= threshold
/// }
/// ```
///
/// This generates:
/// - `fn verify_age_program() -> zkf_core::zir::Program`
/// - `fn verify_age_inputs(birth_year: u32, current_year: u32, threshold: u32) -> zkf_core::WitnessInputs`
#[proc_macro_attribute]
pub fn circuit(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as parse::CircuitAttrs);
    let func = parse_macro_input!(item as syn::ItemFn);

    match lower::generate_circuit(&attrs, &func) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
