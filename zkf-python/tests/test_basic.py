from __future__ import annotations

import json
import unittest

from _import_helper import addition_program, import_zkf


class BasicBindingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.zkf = import_zkf()

    def test_version_and_capability_matrix(self) -> None:
        version = self.zkf.version()
        matrix = json.loads(self.zkf.capability_matrix())

        self.assertIsInstance(version, str)
        self.assertTrue(version)
        self.assertIsInstance(matrix, dict)
        self.assertIn("entries", matrix)
        self.assertGreater(len(matrix["entries"]), 0)

    def test_inspect_reports_program_metadata(self) -> None:
        inspection = json.loads(self.zkf.inspect(addition_program("bn254")))
        self.assertEqual(inspection["program"]["constraints"], 1)
        self.assertEqual(inspection["program"]["signals"], 3)
        self.assertTrue(inspection["preferred_backend"])

    def test_import_circuit_accepts_descriptor_passthrough(self) -> None:
        descriptor = json.dumps({"program": json.loads(addition_program("bn254"))})
        imported = json.loads(self.zkf.import_circuit("circom", descriptor))
        self.assertEqual(imported["name"], "python_bn254_roundtrip")
        self.assertEqual(imported["field"], "bn254")


if __name__ == "__main__":
    unittest.main()
