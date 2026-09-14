import unittest

from trust_prediction.models import ChangeCategory, ChangeItem
from trust_prediction.substantiality import assess_change


class TestSubstantiality(unittest.TestCase):
    def test_code_change_with_high_impact_is_substantial(self):
        ch = ChangeItem(description="x", category=ChangeCategory.CODE, analyst_risk_impact=0.8)
        a = assess_change(ch)
        self.assertEqual(a.label.value, "substantial")
        self.assertFalse(a.prediction_generally_allowed)

    def test_configuration_change_with_low_impact_is_not_substantial(self):
        ch = ChangeItem(description="x", category=ChangeCategory.CONFIGURATION, analyst_risk_impact=0.1)
        a = assess_change(ch)
        self.assertEqual(a.label.value, "not_substantial")
        self.assertTrue(a.prediction_generally_allowed)

    def test_architecture_change_with_moderate_impact_is_borderline(self):
        ch = ChangeItem(description="x", category=ChangeCategory.ARCHITECTURE, analyst_risk_impact=0.3)
        a = assess_change(ch)
        self.assertEqual(a.label.value, "borderline")

    def test_thresholds_are_configurable(self):
        ch = ChangeItem(description="x", category=ChangeCategory.ARCHITECTURE, analyst_risk_impact=0.3)
        a = assess_change(ch, substantial_threshold=0.3, borderline_threshold=0.1)
        self.assertEqual(a.label.value, "substantial")


if __name__ == "__main__":
    unittest.main()
