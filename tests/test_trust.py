import unittest

from trust_prediction.models import (
    ApprovalDecision,
    ControlExecution,
    ControlOutcome,
    ControlStatus,
    PASR,
    SecurityControl,
    SubstantialityLabel,
    VerificationSample,
)
from trust_prediction.trust import compute_actual_trust, compute_expected_trust


class TestTrust(unittest.TestCase):
    def setUp(self):
        self.c1 = SecurityControl(name="A", weight=1.0)
        self.c2 = SecurityControl(name="B", weight=1.0, critical=True)
        self.controls = {self.c1.id: self.c1, self.c2.id: self.c2}

    def test_actual_trust_counts_only_executed_pass(self):
        execs = [
            ControlExecution(version_id="v1", control_id=self.c1.id, status=ControlStatus.EXECUTED, outcome=ControlOutcome.PASS_),
            ControlExecution(version_id="v1", control_id=self.c2.id, status=ControlStatus.EXECUTED, outcome=ControlOutcome.FAIL),
        ]
        t = compute_actual_trust("v1", self.controls, execs, target_threshold=0.9)
        self.assertAlmostEqual(t.fraction, 0.5)
        self.assertFalse(t.meets_target)

    def test_expected_trust_counts_approved_unblocked_pasr(self):
        pasr = PASR(
            version_id="v2", control_id=self.c1.id, identifiers="x",
            actors={"initiator": "a", "onf_group": "b", "app_owner": "c"},
            circumstances="c", rationale="r", original_execution_ref="ref", criteria="crit",
            onf_decision=ApprovalDecision.APPROVED, owner_decision=ApprovalDecision.APPROVED,
        )
        execs = [
            ControlExecution(version_id="v2", control_id=self.c1.id, status=ControlStatus.PREDICTED, pasr_id=pasr.id),
            ControlExecution(version_id="v2", control_id=self.c2.id, status=ControlStatus.EXECUTED, outcome=ControlOutcome.PASS_),
        ]
        t = compute_expected_trust("v2", self.controls, execs, {pasr.id: pasr}, target_threshold=0.9)
        self.assertAlmostEqual(t.fraction, 1.0)
        self.assertTrue(t.meets_target)

    def test_substantial_change_blocks_prediction_even_if_approved(self):
        pasr = PASR(
            version_id="v2", control_id=self.c1.id, identifiers="x",
            actors={"initiator": "a", "onf_group": "b", "app_owner": "c"},
            circumstances="c", rationale="r", original_execution_ref="ref", criteria="crit",
            onf_decision=ApprovalDecision.APPROVED, owner_decision=ApprovalDecision.APPROVED,
            substantiality_label=SubstantialityLabel.SUBSTANTIAL,
        )
        execs = [ControlExecution(version_id="v2", control_id=self.c1.id, status=ControlStatus.PREDICTED, pasr_id=pasr.id)]
        t = compute_expected_trust("v2", {self.c1.id: self.c1}, execs, {pasr.id: pasr}, target_threshold=0.5)
        self.assertAlmostEqual(t.fraction, 0.0)

    def test_critical_control_requires_verification(self):
        pasr = PASR(
            version_id="v2", control_id=self.c2.id, identifiers="x",
            actors={"initiator": "a", "onf_group": "b", "app_owner": "c"},
            circumstances="c", rationale="r", original_execution_ref="ref", criteria="crit",
            onf_decision=ApprovalDecision.APPROVED, owner_decision=ApprovalDecision.APPROVED,
        )
        execs = [ControlExecution(version_id="v2", control_id=self.c2.id, status=ControlStatus.PREDICTED, pasr_id=pasr.id)]

        # без верификации критическая мера не засчитывается
        t = compute_expected_trust("v2", {self.c2.id: self.c2}, execs, {pasr.id: pasr}, target_threshold=0.5)
        self.assertAlmostEqual(t.fraction, 0.0)

        # с верификацией, подтвердившей результат — засчитывается
        verif = [VerificationSample(version_id="v2", control_id=self.c2.id, pasr_id=pasr.id, reexecution_outcome=ControlOutcome.PASS_, matches_expected=True)]
        t2 = compute_expected_trust("v2", {self.c2.id: self.c2}, execs, {pasr.id: pasr}, target_threshold=0.5, verifications=verif)
        self.assertAlmostEqual(t2.fraction, 1.0)

        # с верификацией, НЕ подтвердившей результат — не засчитывается
        verif_fail = [VerificationSample(version_id="v2", control_id=self.c2.id, pasr_id=pasr.id, reexecution_outcome=ControlOutcome.FAIL, matches_expected=False)]
        t3 = compute_expected_trust("v2", {self.c2.id: self.c2}, execs, {pasr.id: pasr}, target_threshold=0.5, verifications=verif_fail)
        self.assertAlmostEqual(t3.fraction, 0.0)


if __name__ == "__main__":
    unittest.main()
