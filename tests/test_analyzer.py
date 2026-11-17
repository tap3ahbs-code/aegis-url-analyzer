import unittest

from analyzer import InvalidURL, analyze_url


class AnalyzerTests(unittest.TestCase):
    def test_rejects_incomplete_domain(self):
        with self.assertRaises(InvalidURL):
            analyze_url("https")

    def test_plain_address_is_normalized(self):
        result = analyze_url("www.wikipedia.org")
        self.assertEqual(result["host"], "www.wikipedia.org")
        self.assertEqual(result["level"], "low")
        self.assertFalse(result["checked_online"])

    def test_userinfo_points_to_real_host(self):
        result = analyze_url("https://trusted.example@192.0.2.5/login")
        self.assertEqual(result["host"], "192.0.2.5")
        self.assertIn("userinfo", {item["code"] for item in result["indicators"]})
        self.assertEqual(result["level"], "high")

    def test_demo_address_is_high_risk(self):
        result = analyze_url("http://192.0.2.5/login/verify?next=https%3A%2F%2Fexample.org")
        self.assertEqual(result["level"], "high")

    def test_rejects_non_web_schemes(self):
        with self.assertRaises(InvalidURL):
            analyze_url("javascript:alert(1)")

    def test_rejects_malformed_port(self):
        with self.assertRaises(InvalidURL):
            analyze_url("https://example.org:abc/")

    def test_bare_host_with_port(self):
        result = analyze_url("example.org:8443/path")
        self.assertEqual(result["host"], "example.org")
        self.assertIn("port", {item["code"] for item in result["indicators"]})


if __name__ == "__main__":
    unittest.main()
