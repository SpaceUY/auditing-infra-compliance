import json
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFS = ROOT / "auditing-infra-compliance" / "references"


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class FrameworkCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.iso = load(REFS / "frameworks" / "iso27001-2022.json")
        cls.tsc = load(REFS / "frameworks" / "tsc-2017.json")

    def test_iso_has_93_controls_by_theme(self):
        controls = self.iso["controls"]
        self.assertEqual(len(controls), 93)
        by_theme = Counter(c["theme"] for c in controls)
        self.assertEqual(
            dict(by_theme),
            {"organizational": 37, "people": 8, "physical": 14, "technological": 34},
        )

    def test_iso_new_2022_controls_present(self):
        ids = {c["id"] for c in self.iso["controls"]}
        for n in ["5.7", "5.23", "5.30", "7.4", "8.9", "8.10", "8.11", "8.12", "8.16", "8.23", "8.28"]:
            self.assertIn("A." + n, ids)

    def test_iso_clauses_cover_4_to_10(self):
        ids = [c["id"] for c in self.iso["clauses"]]
        self.assertIn("4.1", ids)
        self.assertIn("10.2", ids)
        self.assertEqual(len(ids), len(set(ids)))

    def test_tsc_has_61_criteria(self):
        criteria = self.tsc["criteria"]
        ids = [c["id"] for c in criteria]
        self.assertEqual(len(ids), 61)
        self.assertEqual(len(set(ids)), 61)
        self.assertEqual(sum(1 for i in ids if i.startswith("CC")), 33)
        for expected in ["A1.3", "C1.2", "PI1.5", "P8.1"]:
            self.assertIn(expected, ids)
        self.assertNotIn("C1.3", ids)

    def test_physical_controls_not_customer_only(self):
        physical = [c for c in self.iso["controls"] if c["id"].startswith("A.7.")]
        self.assertEqual(len(physical), 14)
        for c in physical:
            self.assertIn(c["responsibility"], {"inherited", "shared"}, c["id"])

    def test_drata_dcf_copied(self):
        copy = REFS / "mappings" / "drata-dcf.json"
        original = ROOT / "docs" / "research" / "drata-dcf-mapping.json"
        self.assertEqual(load(copy), load(original))
        self.assertEqual(len(load(copy)["tests"]), 130)


if __name__ == "__main__":
    unittest.main()
