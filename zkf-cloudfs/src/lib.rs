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

mod cloudfs;
mod config;
mod migrate;

pub use cloudfs::{
    CloudFS, ArtifactType, default_cache_root, default_cloud_docs_root, default_icloud_root,
    default_local_root,
};
pub use config::CloudFSConfig;
pub use migrate::{MigrationConflict, MigrationPlan, MigrationReport, migrate_to_icloud};
