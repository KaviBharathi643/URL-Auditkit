import unittest

from webapp.risk import compute_risk, risk_level_from_score


class RiskScoringTests(unittest.TestCase):
    def test_risk_level_thresholds(self) -> None:
        self.assertEqual(risk_level_from_score(0), "LOW")
        self.assertEqual(risk_level_from_score(24), "LOW")
        self.assertEqual(risk_level_from_score(25), "MEDIUM")
        self.assertEqual(risk_level_from_score(49), "MEDIUM")
        self.assertEqual(risk_level_from_score(50), "HIGH")
        self.assertEqual(risk_level_from_score(74), "HIGH")
        self.assertEqual(risk_level_from_score(75), "CRITICAL")

    def test_critical_check_failure_adds_bonus(self) -> None:
        checks = [
            {"name": "SSL/TLS Certificate Validity", "status": "FAIL"},
            {"name": "Domain Name Legitimacy", "status": "PASS"},
        ]
        result = compute_risk(checks)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertIn("SSL/TLS Certificate Validity", result["critical_failures"])


if __name__ == "__main__":
    unittest.main()
