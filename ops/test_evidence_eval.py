import copy
import unittest
from evidence_eval import evaluate, digest


class EvidenceEvalTests(unittest.TestCase):
    def fixture(self):
        return {"schema": "cc.evidence-eval.v1", "manifest": {
            "as_of": "100", "filter_version": "pinned-rule", "ontology_sha256": "pinned-bundle",
            "source": "test fixture, never ledger content", "captured_at": "2026-09-07"},
            "cases": [{"id": "a", "response": {
                "filter_version": "pinned-rule", "corpus_digest": "pinned-input",
                "result": "Unsupported", "evidence_scope": "recorded_graph_feasibility",
                "verdict_policy": "first_zero_in_factor_order", "factual_verification": "not_assessed",
                "audit": {"schema": "cc.evidence-audit.v1", "absences": [{}], "contradictions": []}}}]}

    def test_empty_is_not_run(self):
        self.assertEqual(evaluate({"schema": "cc.evidence-eval.v1", "cases": []})["status"], "NOT RUN")

    def test_integrity_does_not_imply_quality(self):
        report = evaluate(self.fixture())
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["quality"]["status"], "NOT RUN")
        self.assertEqual(report["usefulness"]["status"], "NOT RUN")

    def test_old_response_and_version_drift_fail(self):
        for field in ("audit", "filter_version", "evidence_scope"):
            fixture = self.fixture()
            del fixture["cases"][0]["response"][field]
            self.assertEqual(evaluate(fixture)["status"], "FAIL")

    def test_duplicates_and_tampered_registration_are_rejected(self):
        fixture = self.fixture()
        fixture["cases"] *= 2
        with self.assertRaises(ValueError): evaluate(fixture)
        fixture = self.fixture()
        fixture["preregistration"] = {"specification": {}, "sha256": "wrong"}
        with self.assertRaises(ValueError): evaluate(fixture)

    def test_matched_arms_and_training_permission_are_required(self):
        fixture = self.fixture()
        spec = {"labels": {"a": {"expected_verdict": "Unsupported", "sources": ["external-fixture"], "reviewer": "fixture-author"}}}
        fixture["preregistration"] = {"specification": spec, "sha256": digest(spec)}
        fixture["model_policy"] = {"test-only": {"downstream_training_allowed": True,
            "license_url": "https://example.invalid/license", "terms_sha256": "test", "reviewed_by": "test", "reviewed_at": "2026-09-07"}}
        row = {"id": "a", "model": "test-only", "correct": True, "abstained": False, "latency_ms": 10, "cost_usd": 0}
        fixture["consumer_runs"] = {arm: [copy.deepcopy(row)] for arm in ("generation", "retrieval", "clockchain")}
        self.assertEqual(evaluate(fixture)["usefulness"]["arms"]["clockchain"]["correct_answers"], 1)
        fixture["model_policy"]["test-only"]["downstream_training_allowed"] = False
        with self.assertRaises(ValueError): evaluate(fixture)


if __name__ == "__main__":
    unittest.main()
