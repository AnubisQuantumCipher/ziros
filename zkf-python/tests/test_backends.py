from __future__ import annotations

import json
import unittest

from _import_helper import addition_program, import_zkf


class BackendRoundtripTests(unittest.TestCase):
    BACKENDS = {
        "arkworks-groth16": "bn254",
        "halo2": "pasta-fp",
        "plonky3": "goldilocks",
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.zkf = import_zkf()

    def test_compile_prove_verify_roundtrip(self) -> None:
        for backend, field in self.BACKENDS.items():
            with self.subTest(backend=backend):
                program_json = addition_program(field)
                compiled_json = self.zkf.compile(program_json, backend)
                proof_json = self.zkf.prove(
                    program_json,
                    compiled_json,
                    json.dumps({"x": "3", "y": "4"}),
                    backend,
                )
                verified = self.zkf.verify(compiled_json, proof_json, backend)

                self.assertTrue(verified, backend)


if __name__ == "__main__":
    unittest.main()
