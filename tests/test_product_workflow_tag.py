"""The workflow state of a product's event in MISP follows its review state.

An alert, an advisory or a detection engineering request was always created
with workflow:state="draft", and saving it never moved the tag: only approving,
rejecting or submitting it from a list did. One submitted for review as it was
written, or from its edit page, stayed a draft in MISP.

MISP is an autospec of PyMISP; nothing is written anywhere.

    python -m unittest tests.test_product_workflow_tag
"""

import unittest
from unittest import mock

from pymisp import MISPEvent, PyMISP

from webapp import misp_store

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
PRODUCTS = {
    "alert": (misp_store.create_fia, misp_store.update_fia, misp_store._fia_obj, misp_store.set_fia_review_state),
    "advisory": (misp_store.create_vea, misp_store.update_vea, misp_store._vea_obj, misp_store.set_vea_review_state),
    "request": (misp_store.create_der, misp_store.update_der, misp_store._der_obj, misp_store.set_der_review_state),
}


class WorkflowTag(unittest.TestCase):
    def misp(self, stored=None):
        """A specced PyMISP serving one product event, tagged as a draft, with
        the ``stored`` object on it when there is one."""
        event = MISPEvent()
        event.from_dict(uuid=UUID, id="42", info="product", date="2026-11-12")
        event.add_tag('workflow:state="draft"')
        if stored:
            event.Object.append(stored)
        misp = mock.create_autospec(PyMISP, instance=True)
        misp.add_event.return_value = misp.get_event.return_value = event
        for patcher in (mock.patch.object(misp_store, "_misp", return_value=misp),
                        mock.patch.object(misp_store, "_tag_local"),
                        mock.patch.object(misp_store.misp_session, "current_user_email",
                                          return_value="analyst@example.org")):
            patcher.start()
            self.addCleanup(patcher.stop)
        return misp

    def created_with(self, create, data):
        misp = self.misp()
        create(data)
        return [t.name for t in misp.add_event.call_args.args[0].tags]

    def test_one_created_for_review_is_ongoing(self):
        for name, (create, _update, _build, _review) in PRODUCTS.items():
            with self.subTest(name):
                tags = self.created_with(create, {"title": "New", "review_state": "pending-review"})
                self.assertIn('workflow:state="ongoing"', tags)
                self.assertNotIn('workflow:state="draft"', tags)

    def test_one_created_as_a_draft_is_a_draft(self):
        for name, (create, _update, _build, _review) in PRODUCTS.items():
            with self.subTest(name):
                self.assertIn('workflow:state="draft"', self.created_with(create, {"title": "New"}))

    def test_a_save_moves_the_tag(self):
        for name, (_create, update, build, _review) in PRODUCTS.items():
            with self.subTest(name):
                misp = self.misp(build({"title": "Stored", "review_state": "draft"}))
                update(UUID, {"title": "Stored", "review_state": "pending-review"})
                self.assertIn('workflow:state="ongoing"', [c.args[1] for c in misp.tag.call_args_list])
                self.assertIn('workflow:state="draft"', [c.args[1] for c in misp.untag.call_args_list])

    def test_approval_still_completes_it(self):
        for name, (_create, _update, build, review) in PRODUCTS.items():
            with self.subTest(name):
                misp = self.misp(build({"title": "Stored", "review_state": "pending-review"}))
                review(UUID, "approved")
                self.assertIn('workflow:state="complete"', [c.args[1] for c in misp.tag.call_args_list])


if __name__ == "__main__":
    unittest.main()
