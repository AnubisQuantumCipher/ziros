# zkf-python

`zkf-python` provides the Python packaging and binding surface for ZirOS. It is
the entrypoint for Python-based tooling that wants to import proof workflows
without shelling out to the CLI.

## Public API Surface

- Python package: `zkf`
- Build system: `maturin`
- Scope: Python bindings around compile/prove/verify and related helpers
