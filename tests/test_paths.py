import unittest

import helpers  # noqa: F401  (sys.path setup)
import paths


class ExtractTests(unittest.TestCase):
    def test_flatten(self):
        self.assertEqual(paths.extract({"Buckets": [{"Name": "a"}, {"Name": "b"}]}, "Buckets[].Name"), ["a", "b"])

    def test_missing_key_returns_empty(self):
        self.assertEqual(paths.extract({"Buckets": []}, "Nope.Name"), [])
        self.assertEqual(paths.extract({"Buckets": [{"Name": "a"}]}, "Buckets[].Owner"), [])
        self.assertEqual(paths.extract(None, "a"), [])

    def test_nested_lists(self):
        data = {"a": [{"b": [1, 2]}, {"b": [3]}]}
        self.assertEqual(paths.extract(data, "a[].b[]"), [1, 2, 3])
        self.assertEqual(paths.extract(data, "a[].b"), [[1, 2], [3]])
        reservations = {"Reservations": [{"Instances": [{"Id": "i-1"}, {"Id": "i-2"}]}, {"Instances": [{"Id": "i-3"}]}]}
        self.assertEqual(paths.extract(reservations, "Reservations[].Instances[].Id"), ["i-1", "i-2", "i-3"])

    def test_star_alias(self):
        data = {"Buckets": [{"Name": "a"}]}
        self.assertEqual(paths.extract(data, "Buckets[*].Name"), paths.extract(data, "Buckets[].Name"))

    def test_dot_is_identity_and_empty_is_nothing(self):
        self.assertEqual(paths.extract("queue-url", "."), ["queue-url"])
        self.assertEqual(paths.extract({"a": 1}, ""), [])
        self.assertEqual(paths.extract({"Names": ["x", "y"]}, "Names[]"), ["x", "y"])

    def test_falsy_values_kept_none_dropped(self):
        self.assertEqual(paths.extract({"a": [{"v": 0}, {"v": False}, {"v": None}, {}]}, "a[].v"), [0, False])

    def test_malformed_path_raises(self):
        with self.assertRaises(ValueError):
            paths.extract({"a": [1]}, "a[0]")


if __name__ == "__main__":
    unittest.main()
