use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitStr, Token};

/// Parsed attributes from `#[zkf::circuit(field = "bn254")]`.
pub struct CircuitAttrs {
    pub field: String,
}

impl Parse for CircuitAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut field = "bn254".to_string();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;

            match key.to_string().as_str() {
                "field" => {
                    let value: LitStr = input.parse()?;
                    field = value.value();
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown circuit attribute: {}", other),
                    ));
                }
            }

            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            }
        }

        Ok(CircuitAttrs { field })
    }
}

/// Parsed circuit parameter from the function signature.
///
/// For array types like `Public<[Field; 4]>`, the parameter is expanded into
/// individual element params (`name_0`, `name_1`, ...) during extraction.
pub struct CircuitParam {
    pub name: String,
    pub visibility: ParamVisibility,
    pub inner_type: String,
}

pub enum ParamVisibility {
    Public,
    Private,
}

/// Extract circuit parameters from function arguments.
pub fn extract_params(func: &syn::ItemFn) -> syn::Result<Vec<CircuitParam>> {
    let mut params = Vec::new();

    for arg in &func.sig.inputs {
        match arg {
            syn::FnArg::Typed(pat_type) => {
                let name = match pat_type.pat.as_ref() {
                    syn::Pat::Ident(ident) => ident.ident.to_string(),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            &pat_type.pat,
                            "circuit parameters must be simple identifiers",
                        ));
                    }
                };

                let (vis, inner) = parse_param_type(&pat_type.ty)?;

                // Expand array types into individual element parameters.
                if let Some((elem_type, len)) = crate::types::parse_array_type(&inner) {
                    for i in 0..len {
                        params.push(CircuitParam {
                            name: format!("{}_{}", name, i),
                            visibility: match vis {
                                ParamVisibility::Public => ParamVisibility::Public,
                                ParamVisibility::Private => ParamVisibility::Private,
                            },
                            inner_type: elem_type.to_string(),
                        });
                    }
                } else {
                    params.push(CircuitParam {
                        name,
                        visibility: vis,
                        inner_type: inner,
                    });
                }
            }
            syn::FnArg::Receiver(_) => {
                return Err(syn::Error::new_spanned(
                    arg,
                    "circuit functions cannot have a self parameter",
                ));
            }
        }
    }

    Ok(params)
}

fn parse_param_type(ty: &syn::Type) -> syn::Result<(ParamVisibility, String)> {
    match ty {
        syn::Type::Path(type_path) => {
            let segment = type_path
                .path
                .segments
                .last()
                .ok_or_else(|| syn::Error::new_spanned(ty, "expected type path"))?;

            let wrapper = segment.ident.to_string();
            let vis = match wrapper.as_str() {
                "Public" => ParamVisibility::Public,
                "Private" => ParamVisibility::Private,
                other => {
                    return Err(syn::Error::new_spanned(
                        &segment.ident,
                        format!(
                            "circuit parameters must be wrapped in Public<T> or Private<T>, got: {}",
                            other
                        ),
                    ));
                }
            };

            let inner = match &segment.arguments {
                syn::PathArguments::AngleBracketed(args) => {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        quote::quote!(#inner_ty).to_string()
                    } else {
                        "Field".to_string()
                    }
                }
                _ => "Field".to_string(),
            };

            Ok((vis, inner))
        }
        _ => Err(syn::Error::new_spanned(
            ty,
            "circuit parameters must use Public<T> or Private<T> types",
        )),
    }
}
