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

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Seed(pub [u8; 32]);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87PrivateKey(pub Vec<u8>);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem1024DecapsulationKey(pub Vec<u8>);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(pub [u8; 32]);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_zeroize_on_drop_trait_bounds_compile() {
        fn assert_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize::<Ed25519Seed>();
        assert_zeroize::<MlDsa87PrivateKey>();
        assert_zeroize::<MlKem1024DecapsulationKey>();
        assert_zeroize::<X25519Secret>();
        assert_zeroize::<SymmetricKey>();
    }
}
