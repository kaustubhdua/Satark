from __future__ import annotations

import unittest

from firstlight_rules import RULE_VERSION, _RULES, rule_metadata, validate_rule_registry


class FirstlightRuleRegistryTests(unittest.TestCase):
    def test_rule_ids_are_unique_and_technique_ids_are_well_formed(self):
        validate_rule_registry()
        self.assertEqual(RULE_VERSION, "1.0.0")
        self.assertEqual(len({rule["rule_id"] for rule in _RULES.values()}), len(_RULES))

    def test_known_rule_has_stable_id_version_and_cautious_mapping(self):
        metadata = rule_metadata("Unusual process ancestry")
        self.assertEqual(metadata["rule_id"], "FL-ENDPOINT-002")
        self.assertEqual(metadata["rule_version"], "1.0.0")
        self.assertEqual(metadata["attack_techniques"], ["T1059"])
        self.assertTrue(metadata["rule_limitations"])

    def test_unknown_title_does_not_claim_a_technique(self):
        metadata = rule_metadata("A future unknown finding")
        self.assertEqual(metadata["rule_id"], "FL-UNMAPPED-000")
        self.assertEqual(metadata["attack_techniques"], [])
        self.assertEqual(metadata["logic_type"], "unmapped")

    def test_returned_metadata_cannot_mutate_registry(self):
        metadata = rule_metadata("Unfamiliar successful login")
        metadata["attack_techniques"].append("T9999")
        self.assertEqual(rule_metadata("Unfamiliar successful login")["attack_techniques"], ["T1078"])


if __name__ == "__main__":
    unittest.main()
