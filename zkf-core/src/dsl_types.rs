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

//! Marker types for the `#[zkf::circuit]` DSL.
//!
//! These types exist so that user code written with the DSL proc macro compiles.
//! The macro parses `Public<T>` and `Private<T>` syntactically and generates
//! `zkf_core::Visibility::Public`/`Private` in the output — these structs are
//! never constructed at runtime. They only satisfy the compiler's name resolution.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zkf_core::dsl_types::*;
//! use zkf_dsl as zkf;
//!
//! #[zkf::circuit(field = "bn254")]
//! fn multiply(x: Private<Field>, y: Private<Field>) -> Public<Field> {
//!     x * y
//! }
//! ```

use core::marker::PhantomData;
use core::ops::{Add, Mul, Sub};

/// Marker for a public circuit signal.
///
/// The DSL proc macro parses this type syntactically. It is never constructed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Public<T>(PhantomData<T>);

/// Marker for a private circuit signal.
///
/// The DSL proc macro parses this type syntactically. It is never constructed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Private<T>(PhantomData<T>);

impl<T> Default for Public<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> Default for Private<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

// Arithmetic impls so that the original function body (kept by the proc macro for
// documentation/reference) type-checks. If these markers are evaluated
// accidentally, return another marker instead of panicking.
impl<T> Add for Private<T> {
    type Output = Private<T>;
    fn add(self, _rhs: Private<T>) -> Private<T> {
        Private::default()
    }
}
impl<T> Sub for Private<T> {
    type Output = Private<T>;
    fn sub(self, _rhs: Private<T>) -> Private<T> {
        Private::default()
    }
}
impl<T> Mul for Private<T> {
    type Output = Private<T>;
    fn mul(self, _rhs: Private<T>) -> Private<T> {
        Private::default()
    }
}
impl<T> Add for Public<T> {
    type Output = Public<T>;
    fn add(self, _rhs: Public<T>) -> Public<T> {
        Public::default()
    }
}
impl<T> Sub for Public<T> {
    type Output = Public<T>;
    fn sub(self, _rhs: Public<T>) -> Public<T> {
        Public::default()
    }
}
impl<T> Mul for Public<T> {
    type Output = Public<T>;
    fn mul(self, _rhs: Public<T>) -> Public<T> {
        Public::default()
    }
}

/// Marker for a prime-field element in DSL circuit signatures.
///
/// This type is parsed by the proc macro and mapped to `SignalType::Field`.
/// It does not carry a value at runtime.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash)]
pub struct Field;

#[cfg(test)]
mod tests {
    use super::{Field, Private, Public};

    #[test]
    fn private_marker_arithmetic_returns_marker_without_panicking() {
        let _ = Private::<Field>::default() + Private::<Field>::default();
        let _ = Private::<Field>::default() - Private::<Field>::default();
        let _ = Private::<Field>::default() * Private::<Field>::default();
    }

    #[test]
    fn public_marker_arithmetic_returns_marker_without_panicking() {
        let _ = Public::<Field>::default() + Public::<Field>::default();
        let _ = Public::<Field>::default() - Public::<Field>::default();
        let _ = Public::<Field>::default() * Public::<Field>::default();
    }
}
