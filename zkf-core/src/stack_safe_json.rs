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

use serde::{Serialize, de::DeserializeOwned};
use std::io::Read;

const STACK_GROW_RED_ZONE: usize = 1024 * 1024;
const STACK_GROW_SIZE: usize = 64 * 1024 * 1024;

pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        serde_json::to_vec(value)
    })
}

pub fn to_vec_pretty<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        serde_json::to_vec_pretty(value)
    })
}

pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        deserializer.disable_recursion_limit();
        T::deserialize(serde_stacker::Deserializer::new(&mut deserializer))
    })
}

pub fn from_reader<R: Read, T: DeserializeOwned>(reader: R) -> serde_json::Result<T> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        deserializer.disable_recursion_limit();
        T::deserialize(serde_stacker::Deserializer::new(&mut deserializer))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BackendKind, CompiledProgram, Constraint, Expr, FieldElement, FieldId, Program, Signal,
        Visibility, WitnessPlan,
    };

    fn deep_expr(depth: usize) -> Expr {
        let mut expr = Expr::signal("in");
        for index in 0..depth {
            expr = Expr::Mul(
                Box::new(expr),
                Box::new(Expr::Const(FieldElement::from_u64((index % 11 + 2) as u64))),
            );
        }
        expr
    }

    fn deep_program(depth: usize) -> Program {
        Program {
            name: format!("deep-program-{depth}"),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "in".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: deep_expr(depth),
                label: Some("deep-recursive-constraint".to_string()),
            }],
            witness_plan: WitnessPlan::default(),
            ..Program::default()
        }
    }

    #[test]
    fn stack_safe_json_roundtrips_deep_program_and_compiled_program() {
        let program = deep_program(1_024);
        let program_bytes = to_vec_pretty(&program).expect("serialize deep program");
        let decoded_program: Program =
            from_slice(&program_bytes).expect("deserialize deep program");
        assert_eq!(decoded_program.digest_hex(), program.digest_hex());

        let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, program.clone());
        compiled.original_program = Some(program);
        let compiled_bytes = to_vec_pretty(&compiled).expect("serialize deep compiled program");
        let decoded_compiled: CompiledProgram =
            from_slice(&compiled_bytes).expect("deserialize deep compiled program");
        assert_eq!(decoded_compiled.program_digest, compiled.program_digest);
        assert_eq!(
            decoded_compiled
                .original_program
                .as_ref()
                .expect("original program")
                .digest_hex(),
            compiled
                .original_program
                .as_ref()
                .expect("original program")
                .digest_hex()
        );
    }

    #[test]
    fn deep_program_digest_remains_stable() {
        let program = deep_program(2_048);
        assert_eq!(
            program.digest_hex(),
            program.try_digest_hex().expect("try digest")
        );
    }

    #[cfg(feature = "full")]
    #[test]
    fn deep_zir_digest_remains_stable() {
        let program = deep_program(2_048);
        let zir = crate::program_v2_to_zir(&program);
        assert_eq!(zir.digest_hex(), zir.try_digest_hex().expect("try digest"));
    }
}
