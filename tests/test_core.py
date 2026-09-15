from __future__ import annotations

import math
import unittest

from qdrant_client import QdrantClient

from agents import _heuristic_rca, heuristic_triage
from config import Settings
from eval_runner import GoldenCase, score_case
from tools import _simulated_output
from vector_rag import OfflineHashEmbeddingBackend, VectorRAGStore


class CoreRegressionTests(unittest.TestCase):
    def test_offline_embedding_is_finite_unit_vector(self) -> None:
        vector = OfflineHashEmbeddingBackend(256).embed(
            ["BGP session down interface eth1"]
        )[0]
        self.assertTrue(all(math.isfinite(value) for value in vector))
        self.assertAlmostEqual(sum(value * value for value in vector), 1.0)

    def test_qdrant_query_points_retrieves_sop(self) -> None:
        settings = Settings(_env_file=None, offline_mode=True, qdrant_vector_size=256)
        store = VectorRAGStore(settings)
        store._client = QdrantClient(":memory:")
        store._use_memory = False
        store.ingest_directory()

        result = store.retrieve("BGP neighbor session down and interface failure")

        self.assertGreater(len(result.documents), 0)

    def test_r2_simulation_uses_r2_identity(self) -> None:
        summary = _simulated_output("r2", "show ip bgp summary")
        interface = _simulated_output("r2", "show interface eth1")
        self.assertIn("10.0.0.2", summary)
        self.assertIn("65002", summary)
        self.assertIn("192.168.12.2/30", interface)

    def test_auth_failure_is_not_rewritten_as_physical_link_failure(self) -> None:
        triage = heuristic_triage(
            "r1 bgpd: authentication failure TCP MD5 mismatch"
        ).model_dump(mode="json")
        report = _heuristic_rca(
            triage,
            {
                "interface_status": "Interface eth1 state: DOWN",
                "bgp_summary": "Idle",
                "healthy": False,
            },
            {},
            "test-incident",
        )
        self.assertNotIn("Physical/data-link failure", report.root_cause)
        self.assertIn("authentication", report.root_cause.lower())

    def test_event_aware_probes_differ_by_alarm(self) -> None:
        from tools import _probes_for_event

        iface = set(_probes_for_event("interface_down"))
        auth = set(_probes_for_event("auth_failure"))
        bgp = set(_probes_for_event("bgp_session_down"))
        ospf = set(_probes_for_event("ospf_adjacency_down"))
        self.assertIn("show interface eth1", iface)
        self.assertNotIn("show ip route", iface)
        self.assertIn("show ip bgp summary", auth)
        self.assertIn("show ip route", bgp)
        self.assertIn("show ip route", ospf)
        self.assertNotIn("show ip bgp summary", ospf)

    def test_new_taxonomy_classifies_ospf_cpu_withdraw_bfd(self) -> None:
        ospf = heuristic_triage(
            "r1 ospfd: %OSPF-5-ADJCHG Neighbor 10.0.0.2 from FULL to DOWN"
        )
        cpu = heuristic_triage("r1 watchfrr: high cpu warning CPU utilization 97%")
        withdraw = heuristic_triage(
            "r1 bgpd: prefix 10.20.0.0/16 withdrawn by neighbor 192.168.12.2"
        )
        bfd = heuristic_triage("r1 bfdd: BFD session down with neighbor 192.168.12.2")
        self.assertEqual(ospf.event_type, "ospf_adjacency_down")
        self.assertEqual(cpu.event_type, "high_cpu")
        self.assertEqual(withdraw.event_type, "route_withdrawal")
        self.assertEqual(bfd.event_type, "link_failure")

    def test_llm_call_stats_survive_concurrent_increments(self) -> None:
        import threading

        from agents import _record_llm_call, llm_call_stats, reset_llm_call_stats

        reset_llm_call_stats()
        threads = [
            threading.Thread(
                target=lambda: [_record_llm_call("ok") for _ in range(500)]
            )
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(llm_call_stats()["ok"], 4000)
        reset_llm_call_stats()

    def test_triage_prompt_severity_matches_scored_labels(self) -> None:
        from agents import TRIAGE_SYSTEM
        from schema import EVENT_SEVERITY

        for event, severity in EVENT_SEVERITY.items():
            self.assertRegex(
                TRIAGE_SYSTEM,
                rf"{severity}\s+{event}\b",
                f"Triage prompt must state {event} as {severity}",
            )

    def test_device_names_are_canonicalized_across_spellings(self) -> None:
        from agents import canonicalize_device

        self.assertEqual(canonicalize_device("Leaf1"), "leaf-1")
        self.assertEqual(canonicalize_device("spine_2"), "spine-2")
        self.assertEqual(canonicalize_device("PE-3"), "pe3")
        self.assertEqual(canonicalize_device("router-1"), "r1")
        self.assertEqual(canonicalize_device("leaf-1"), "leaf-1")
        self.assertEqual(canonicalize_device(""), "unknown")

    def test_actionable_fault_mislabelled_info_is_not_aborted(self) -> None:
        from agents import triage_agent

        state = triage_agent(
            {
                "raw_syslog": "r1 bgpd: %BGP-5-ADJCHANGE: neighbor 192.168.12.2 Down",
                "messages": [],
                "errors": [],
            }
        )

        self.assertNotEqual(state["route_decision"], "abort")

    def test_full_score_requires_rag_documents(self) -> None:
        case = GoldenCase(
            id="score-test",
            category="test",
            syslog="r1 bgp down",
            expected_event_type="bgp_session_down",
            expected_severity="critical",
            expected_nodes_contains=["r1"],
        )
        triage = {
            "event_type": "bgp_session_down",
            "severity": "critical",
            "device_name": "r1",
        }
        rca = {
            "root_cause": "BGP peer is not established",
            "affected_nodes": ["r1"],
            "remediation_steps": [{"order": 1, "action": "Check peer"}],
        }

        result = score_case(case, triage=triage, rca=rca, rag={"documents": []})

        self.assertFalse(result.passed)
        self.assertFalse(
            next(
                field.correct
                for field in result.field_scores
                if field.field == "rag_documents"
            )
        )


if __name__ == "__main__":
    unittest.main()
