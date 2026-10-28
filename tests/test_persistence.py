import os
import tempfile
import unittest

from webapp.persistence import get_scan, init_db, list_iocs, persist_scan


class PersistenceTests(unittest.TestCase):
    def test_persist_and_fetch_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["URL_AUDIT_DB_PATH"] = os.path.join(tmpdir, "test.db")
            init_db()

            scan_id, ioc_count = persist_scan(
                target_url="https://example.com",
                scan_mode="scan",
                prepared_results=[
                    {
                        "id": 1,
                        "name": "Domain Name Legitimacy",
                        "status": "PASS",
                        "risk_level": "LOW",
                        "section": "Domain Intelligence",
                        "evidence": "host=example.com",
                        "details": "",
                        "data": {},
                        "summary": "Looks normal",
                    },
                    {
                        "id": 9,
                        "name": "SSL/TLS Certificate Validity",
                        "status": "FAIL",
                        "risk_level": "HIGH",
                        "section": "Security Posture",
                        "evidence": "ip=1.2.3.4 country=US",
                        "details": "",
                        "data": {"country": "US"},
                        "summary": "Expired cert",
                    },
                ],
                counts={"PASS": 1, "WARN": 0, "FAIL": 1, "INFO": 0, "SKIP": 0},
                risk_score=60,
                risk_level="HIGH",
                verdict="MALICIOUS",
                threat_report={"verdict": "MALICIOUS", "executive_summary": "Risky"},
                duration_ms=1234,
            )

            self.assertGreater(scan_id, 0)
            self.assertGreaterEqual(ioc_count, 1)

            scan = get_scan(scan_id)
            self.assertIsNotNone(scan)
            assert scan is not None
            self.assertEqual(scan["target_url"], "https://example.com")
            self.assertEqual(len(scan["checks"]), 2)

            iocs = list_iocs(page=1, page_size=20)
            self.assertGreaterEqual(iocs["total"], 1)

            del os.environ["URL_AUDIT_DB_PATH"]


if __name__ == "__main__":
    unittest.main()
