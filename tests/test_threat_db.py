import io
import tempfile
import unittest
from pathlib import Path

from threat_db import feed_status, lookup, url_digest
from update_threats import import_csv


class ThreatDatabaseTests(unittest.TestCase):
    def test_import_and_exact_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threats.sqlite3"
            csv_data = io.StringIO("url,verified\nhttps://Example.test/login,yes\nhttps://Example.test/login,yes\n")
            self.assertEqual(import_csv(csv_data, path, source="Test"), 1)
            self.assertTrue(lookup("https://example.test/login#section", path))
            self.assertFalse(lookup("https://example.test/other", path))
            self.assertEqual(feed_status(path)["count"], 1)

    def test_normalization_drops_default_port_and_fragment(self):
        self.assertEqual(url_digest("https://Example.test:443/path#x"), url_digest("https://example.test/path"))


if __name__ == "__main__":
    unittest.main()
