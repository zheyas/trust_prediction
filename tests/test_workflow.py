import tempfile
import unittest
from pathlib import Path

from trust_prediction.models import (
    ApprovalDecision,
    ChangeCategory,
    ControlOutcome,
    PredictionPolicy,
)
from trust_prediction.storage import Repository
from trust_prediction.workflow import TrustPredictionWorkflow, WorkflowError


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(Path(self.tmp.name) / "project.json")
        self.wf = TrustPredictionWorkflow(self.repo)
        self.wf.init_application("Test App", "Owner")
        self.ctrl = self.wf.add_control("Control A", weight=1.0)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_versions(self):
        v1 = self.wf.new_version("1.0", None, target_trust_threshold=0.9)
        self.wf.record_reference_execution(v1.id, self.ctrl.id, ControlOutcome.PASS_, "evidence", "team")
        v2 = self.wf.new_version("1.1", v1.id, target_trust_threshold=0.9)
        return v1, v2

    def test_forbidden_policy_blocks_initiation(self):
        v1, v2 = self._make_versions()
        self.wf.step1_set_policy(PredictionPolicy.FORBIDDEN, "ONF")
        with self.assertRaises(WorkflowError):
            self.wf.step2_initiate(v2.id, "team")

    def test_substantial_change_blocks_pasr_preparation(self):
        v1, v2 = self._make_versions()
        self.wf.step1_set_policy(PredictionPolicy.CONDITIONAL, "ONF")
        self.wf.add_change(v2.id, "big code change", ChangeCategory.CODE, [self.ctrl.id], analyst_risk_impact=0.9)
        with self.assertRaises(WorkflowError):
            self.wf.step4_prepare_pasr(v2.id, self.ctrl.id, "team", "onf", "owner", "circ", "rationale", "criteria")

    def test_dual_approval_required(self):
        v1, v2 = self._make_versions()
        self.wf.step1_set_policy(PredictionPolicy.UNRESTRICTED, "ONF")
        self.wf.add_change(v2.id, "small config change", ChangeCategory.CONFIGURATION, [self.ctrl.id], analyst_risk_impact=0.1)
        res = self.wf.step4_prepare_pasr(v2.id, self.ctrl.id, "team", "onf", "owner", "circ", "rationale", "criteria")
        pasr = res.payload["pasr"]

        # только одна сторона утвердила — прогноз ещё не утверждён
        self.wf.step6_approve(pasr.id, "onf", ApprovalDecision.APPROVED, "ONF")
        self.assertFalse(self.repo.pasrs[pasr.id].is_approved)

        # обе стороны утвердили — прогноз утверждён
        self.wf.step6_approve(pasr.id, "owner", ApprovalDecision.APPROVED, "Owner")
        self.assertTrue(self.repo.pasrs[pasr.id].is_approved)

    def test_rejection_by_either_party_blocks_approval(self):
        v1, v2 = self._make_versions()
        self.wf.step1_set_policy(PredictionPolicy.UNRESTRICTED, "ONF")
        self.wf.add_change(v2.id, "small config change", ChangeCategory.CONFIGURATION, [self.ctrl.id], analyst_risk_impact=0.1)
        res = self.wf.step4_prepare_pasr(v2.id, self.ctrl.id, "team", "onf", "owner", "circ", "rationale", "criteria")
        pasr = res.payload["pasr"]

        self.wf.step6_approve(pasr.id, "onf", ApprovalDecision.APPROVED, "ONF")
        self.wf.step6_approve(pasr.id, "owner", ApprovalDecision.REJECTED, "Owner", "не согласен")
        self.assertFalse(self.repo.pasrs[pasr.id].is_approved)
        self.assertTrue(self.repo.pasrs[pasr.id].is_rejected)

    def test_full_end_to_end_reaches_target(self):
        v1, v2 = self._make_versions()
        self.wf.step1_set_policy(PredictionPolicy.UNRESTRICTED, "ONF")
        self.wf.step2_initiate(v2.id, "team")
        self.wf.step3_risk_analysis(v2.id, "expert")
        res = self.wf.step4_prepare_pasr(v2.id, self.ctrl.id, "team", "onf", "owner", "circ", "rationale", "criteria")
        pasr = res.payload["pasr"]
        self.wf.step6_approve(pasr.id, "onf", ApprovalDecision.APPROVED, "ONF")
        self.wf.step6_approve(pasr.id, "owner", ApprovalDecision.APPROVED, "Owner")
        self.wf.step8_verify(v2.id, "auditor", sampling_rate=1.0)
        self.wf.step9_audit(v2.id, "auditor")
        result = self.wf.step10_assess(v2.id, "auditor")
        self.assertTrue(result.payload["expected"].meets_target)


if __name__ == "__main__":
    unittest.main()
