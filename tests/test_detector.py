import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import detector  # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "sample_logs" / "sample.log"


class DetectorTests(unittest.TestCase):
    def setUp(self):
        with open(SAMPLE, encoding="utf-8") as handle:
            self.events = detector.parse_log(handle, 2026)

    def test_only_failed_passwords_are_parsed(self):
        self.assertEqual(len(self.events), 21)

    def test_invalid_user_flag(self):
        self.assertTrue(self.events[0].invalid_user)
        self.assertFalse([e for e in self.events if e.user == "root"][0].invalid_user)

    def test_bursts_are_split_by_silence(self):
        bursts = detector.group_bursts(self.events, window_minutes=5)
        self.assertEqual([b.attempts for b in bursts], [9, 12])

    def test_alerts_and_indicators(self):
        rows = detector.build_report(detector.group_bursts(self.events, 5), threshold=5)
        self.assertEqual(len(rows), 2)
        self.assertIn("username enumeration", rows[0]["indicators"])
        self.assertIn("root targeted", rows[1]["indicators"])

    def test_high_threshold_gives_no_alerts(self):
        rows = detector.build_report(detector.group_bursts(self.events, 5), threshold=50)
        self.assertEqual(rows, [])

    def test_iso_timestamp(self):
        line = "2026-10-06T16:09:30+0800 host sshd[1]: Failed password for bob from 1.2.3.4 port 22 ssh2"
        self.assertEqual(len(detector.parse_log([line], 2026)), 1)


if __name__ == "__main__":
    unittest.main()
