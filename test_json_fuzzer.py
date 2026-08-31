"""
Unit tests for Deep JSON & Structured Body Fuzzer.
"""

import unittest
from core.fuzzer import (
    extract_json_leaf_paths,
    mutate_json_at_path,
    generate_json_fuzz_mutations,
)


class TestJSONFuzzer(unittest.TestCase):
    """Test suite for core.fuzzer."""

    def test_extract_json_leaf_paths(self):
        sample = {
            "customer": {
                "name": "Alice",
                "id": 101,
                "contacts": [{"type": "email", "value": "alice@example.com"}],
            },
            "active": True,
        }
        paths = extract_json_leaf_paths(sample)
        path_keys = [p[0] for p in paths]
        self.assertIn("customer.name", path_keys)
        self.assertIn("customer.id", path_keys)
        self.assertIn("customer.contacts.0.type", path_keys)
        self.assertIn("customer.contacts.0.value", path_keys)
        self.assertIn("active", path_keys)

    def test_mutate_json_at_path(self):
        sample = {
            "user": {
                "profile": {
                    "username": "admin",
                },
                "score": 50,
            }
        }
        mutated = mutate_json_at_path(sample, "user.profile.username", "' OR 1=1--")
        self.assertEqual(mutated["user"]["profile"]["username"], "' OR 1=1--")
        # Ensure original was untouched
        self.assertEqual(sample["user"]["profile"]["username"], "admin")
        self.assertEqual(mutated["user"]["score"], 50)

    def test_generate_json_fuzz_mutations(self):
        sample = {
            "order": {
                "id": 12,
                "item": "laptop",
            }
        }
        mutations = generate_json_fuzz_mutations(sample, "<payload>")
        self.assertEqual(len(mutations), 2)
        paths = [m[0] for m in mutations]
        self.assertIn("order.id", paths)
        self.assertIn("order.item", paths)


if __name__ == "__main__":
    unittest.main()
