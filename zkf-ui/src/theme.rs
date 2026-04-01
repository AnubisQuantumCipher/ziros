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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZkTheme {
    pub colors_enabled: bool,
    pub unicode_enabled: bool,
    pub success_symbol: &'static str,
    pub failure_symbol: &'static str,
    pub warning_symbol: &'static str,
    pub info_symbol: &'static str,
    pub sealed_label: &'static str,
}

impl ZkTheme {
    pub fn plain() -> Self {
        Self {
            colors_enabled: false,
            unicode_enabled: false,
            success_symbol: "[ok]",
            failure_symbol: "[x]",
            warning_symbol: "[!]",
            info_symbol: "[i]",
            sealed_label: "SEALED",
        }
    }
}

impl Default for ZkTheme {
    fn default() -> Self {
        let colors_enabled = std::env::var_os("NO_COLOR").is_none();
        Self {
            colors_enabled,
            unicode_enabled: true,
            success_symbol: "✓",
            failure_symbol: "✕",
            warning_symbol: "!",
            info_symbol: "•",
            sealed_label: "SEALED",
        }
    }
}
