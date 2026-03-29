        # ZirOS Public Open-Core Monorepo

        This repository is the first validated public-safe open-core cut for
        `AnubisQuantumCipher/ziros`.

        It is intentionally scoped to the open-core theorem-first stack needed
        for the reentry flagship and shared aerospace kit. The private staging
        workspace remains broader than this public cut, but public tags on this
        repository are the authoritative release surface for the included
        open-core tranche.

        ## Boundary

        - ground-side mission assurance
        - NASA Class D ground-support mission-ops assurance
        - normalized-export-based ingestion
        - no native replacement claim for GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime
        - Any mission that wants to place ZirOS outputs inside a NASA Class C or higher decision chain must perform an independent program assessment outside ZirOS.

        ## Included Open-Core Workspace Members

        - `zkf-core`
- `zkf-frontends`
- `zkf-backends`
- `zkf-gadgets`
- `zkf-registry`
- `zkf-ir-spec`
- `zkf-conformance`
- `zkf-cli`
- `zkf-lib`
- `zkf-examples`
- `zkf-runtime`
- `zkf-distributed`
- `zkf-ui`

        ## Excluded From The First Public Cut

        - `zkf-api`
        - `zkf-backends-pro`
        - `zkf-metal`
        - product-specific or private staging surfaces outside the open-core theorem-first tranche

        ## Release Surfaces

        - `release/sbom/open_core_workspace_sbom.json`
        - `release/provenance/public_mirror_provenance.json`
        - `release/theorem_coverage_status.json`
        - `release/public_bundle/`
        - `release/private_bundle/`
        - `report/REENTRY_MISSION_ASSURANCE_REPORT.md` when a candid flagship report is present at staging time
