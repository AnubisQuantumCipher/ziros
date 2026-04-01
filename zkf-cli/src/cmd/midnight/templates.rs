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

use super::shared::midnight_template_catalog;

pub(crate) fn handle_templates(json: bool) -> Result<(), String> {
    let catalog = midnight_template_catalog()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&catalog).map_err(|error| error.to_string())?
        );
        return Ok(());
    }

    for entry in catalog {
        println!(
            "{}: {} [{}]",
            entry.template_id, entry.description, entry.backend_lane
        );
    }
    Ok(())
}
