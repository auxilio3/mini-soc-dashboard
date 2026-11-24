"""Unit tests for the 8 detection rules. Run: python3 -m unittest discover tests -v"""

import random
import unittest
from datetime import timedelta

from soc import events as ev
from soc import rules
from soc.events import now


class RuleTests(unittest.TestCase):
    def setUp(self):
        random.seed(1)
        self.t = now()

    def fires(self, rule_name, evts):
        return rules.RULES[rule_name](evts)

    def test_each_attack_triggers_its_rule(self):
        for name, attack in ev.ATTACKS.items():
            with self.subTest(attack=name):
                alerts = self.fires(name, attack(self.t))
                self.assertTrue(alerts, f"{name} scenario did not trigger its rule")
                self.assertIn(name, alerts[0]["labels"]["ground_truth"])

    def test_benign_traffic_is_quiet(self):
        noise = ev.benign_events(self.t, 300)  # 5 minutes of normal activity
        self.assertEqual(rules.run_all(noise), [])

    def test_brute_force_threshold(self):
        attacker = "203.0.113.200"
        fails = [ev._auth(self.t + timedelta(seconds=i), "agarcia", attacker, "SRV-WEB01", "failure", "x")
                 for i in range(rules.BRUTE_FORCE_FAILURES - 1)]
        self.assertEqual(rules.brute_force(fails), [], "should not fire below threshold")
        fails.append(ev._auth(self.t, "agarcia", attacker, "SRV-WEB01", "failure", "x"))
        self.assertEqual(len(rules.brute_force(fails)), 1)

    def test_disabled_account_severity_tiers(self):
        one = ev._auth(self.t, "svc-legacy", "10.10.1.11", "SRV-DC01", "failure", "x", reason="account_disabled")
        self.assertEqual(rules.unauthorized_access([one])[0]["alert"]["severity"], "Low")
        three = [one] * rules.DISABLED_ACCOUNT_MEDIUM
        self.assertEqual(rules.unauthorized_access(three)[0]["alert"]["severity"], "Medium")

    def test_benign_powershell_not_flagged(self):
        e = ev._process(self.t, "WS-01", "hlee", "powershell.exe", "powershell.exe Get-Process", "benign")
        self.assertEqual(rules.suspicious_powershell([e]), [])

    def test_routine_group_change_not_flagged(self):
        e = ev._event(self.t, "iam", "added-member-to-group", "benign", user__name="it-admin1",
                      host__name="SRV-DC01", group__name="Marketing", user__target__name="hlee")
        self.assertEqual(rules.privilege_escalation([e]), [])

    def test_tuning_suppresses_known_good_lookalikes(self):
        evts = [e for make in ev.LOOKALIKES for e in make(self.t)]
        try:
            rules.TUNING = False
            self.assertTrue(rules.run_all(evts), "untuned rules should flag the look-alikes")
            rules.TUNING = True
            self.assertEqual(rules.run_all(evts), [], "tuned rules should ignore approved activity")
        finally:
            rules.TUNING = True


if __name__ == "__main__":
    unittest.main()
