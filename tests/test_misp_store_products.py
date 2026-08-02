"""Tests for product_counts_by_threat_actor_type (dashboard / stats data).

Monkeypatches the briefing/FIA listers so the aggregation runs without MISP.

    python -m unittest tests.test_misp_store_products
"""

import unittest
from types import SimpleNamespace

from webapp import misp_store


class ProductCountsByThreatActorType(unittest.TestCase):
    def setUp(self):
        self._orig_briefings = misp_store.list_briefings
        self._orig_fias = misp_store.list_fias
        self._orig_taps = misp_store.list_threat_actor_profiles

    def tearDown(self):
        misp_store.list_briefings = self._orig_briefings
        misp_store.list_fias = self._orig_fias
        misp_store.list_threat_actor_profiles = self._orig_taps

    def _run(self, briefings, fias, taps=None):
        misp_store.list_briefings = lambda: briefings
        misp_store.list_fias = lambda: fias
        misp_store.list_threat_actor_profiles = lambda: taps or []
        return {r["actor_type"]: r for r in misp_store.product_counts_by_threat_actor_type()}

    def test_counts_briefings_and_fias_per_type(self):
        briefings = [
            SimpleNamespace(stories=[SimpleNamespace(threat_actor_types=["State-sponsored"])]),
            SimpleNamespace(stories=[SimpleNamespace(threat_actor_types=["State-sponsored", "Hacktivist"])]),
        ]
        fias = [SimpleNamespace(actor_types=["State-sponsored"])]
        rows = self._run(briefings, fias)
        self.assertEqual(rows["State-sponsored"]["daily_briefings"], 2)
        self.assertEqual(rows["State-sponsored"]["flash_intel_alerts"], 1)
        self.assertEqual(rows["State-sponsored"]["total"], 3)
        self.assertEqual(rows["Hacktivist"]["daily_briefings"], 1)

    def test_a_product_is_counted_once_per_type_not_per_story(self):
        # Same actor type across two stories in one briefing counts once.
        briefings = [
            SimpleNamespace(stories=[
                SimpleNamespace(threat_actor_types=["State-sponsored"]),
                SimpleNamespace(threat_actor_types=["State-sponsored"]),
            ]),
        ]
        rows = self._run(briefings, [])
        self.assertEqual(rows["State-sponsored"]["daily_briefings"], 1)

    def test_missing_type_falls_under_unspecified_sorted_last(self):
        briefings = [SimpleNamespace(stories=[SimpleNamespace(threat_actor_types=[])])]
        fias = [SimpleNamespace(actor_types=[])]
        misp_store.list_briefings = lambda: briefings
        misp_store.list_fias = lambda: fias
        misp_store.list_threat_actor_profiles = lambda: []
        rows = misp_store.product_counts_by_threat_actor_type()
        self.assertEqual(rows[-1]["actor_type"], "Unspecified")
        self.assertEqual(rows[-1]["total"], 2)


if __name__ == "__main__":
    unittest.main()
