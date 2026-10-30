import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fuzzy_engine import assess_risk
from message_analyzer import analyze_message
from url_analyzer import analyze_url

class PhishGuardTests(unittest.TestCase):
    def test_low_signal_score_is_bounded(self):
        features = {"url_suspicion": 0, "urgency": 0, "sensitive_request": 0, "deception": 0}
        result = assess_risk(features)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_otp_urgency_message_has_warnings(self):
        result = analyze_message("URGENT: send your OTP immediately or your account will be suspended")
        self.assertTrue(result["warnings"])
        self.assertGreater(result["urgency"], 0)
        self.assertGreater(result["sensitive_request"], 0)

    def test_ip_url_detected(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertTrue(any("IP address" in w for w in result["warnings"]))


    def test_domain_suffix_metadata_for_common_suffixes(self):
        indian = analyze_url("https://portal.example.co.in/login")
        self.assertEqual(indian["registrable_domain"], "example.co.in")
        self.assertEqual(indian["public_suffix"], "co.in")
        self.assertEqual(indian["tld"], "in")

    def test_common_tld_does_not_automatically_make_domain_safe(self):
        result = analyze_url("https://account-verify.example.com/login")
        self.assertEqual(result["tld"], "com")
        self.assertGreater(result["url_suspicion"], 0)
        self.assertIn("verdict_basis", result)

    def test_score_categories(self):
        for val in [0, 25, 50, 75, 100]:
            result = assess_risk({"url_suspicion":val,"urgency":val,"sensitive_request":val,"deception":val})
            self.assertTrue(0 <= result["score"] <= 100)
            self.assertIn(result["category"], ["Low","Medium","High","Critical"])

if __name__ == "__main__":
    unittest.main()
