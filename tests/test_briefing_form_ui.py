"""Browser checks for the daily briefing compose form.

The workbench layout lives almost entirely in the browser: which pane is on
screen, what the contents rail says about each story, and whether the summary
is still current. None of that is reachable from the other tests, and all of it
has broken at least once.

These drive a real Chromium against a real webapp, so they are opt-in and are
skipped by default. They only read and click; the form is never submitted, so
nothing is written to MISP.

    ZSAZSA_UI_TESTS=1 python -m unittest tests.test_briefing_form_ui
"""

import os
import threading
import unittest

UI_TESTS = os.environ.get("ZSAZSA_UI_TESTS") == "1"
# Playwright installs browsers outside the venv; point at one if it is not on
# the default search path.
CHROME = os.environ.get("ZSAZSA_UI_CHROME") or None


@unittest.skipUnless(UI_TESTS, "set ZSAZSA_UI_TESTS=1 to run the browser checks")
class BriefingComposeForm(unittest.TestCase):
    """One draft briefing, opened fresh for each check."""

    @classmethod
    def setUpClass(cls):
        from unittest import mock

        from playwright.sync_api import sync_playwright
        from werkzeug.serving import make_server

        import config
        from webapp import create_app, misp_store

        drafts = [b for b in misp_store.list_briefings()
                  if b.review_state == misp_store.BRIEFING_REVIEW_DRAFT and b.stories]
        if not drafts:
            raise unittest.SkipTest("no draft briefing with stories to open")
        cls.briefing = max(drafts, key=lambda b: len(b.stories))

        # The browser carries no MISP session, so the login redirect has to be off
        # or every page it opens is a 302 to MISP's login.
        sso = mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False)
        sso.start()
        cls.addClassCleanup(sso.stop)

        cls._server = make_server("127.0.0.1", 0, create_app(), threaded=True)
        cls.base_url = f"http://127.0.0.1:{cls._server.server_port}"
        threading.Thread(target=cls._server.serve_forever, daemon=True).start()

        cls._playwright = sync_playwright().start()
        cls.browser = cls._playwright.chromium.launch(executable_path=CHROME)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._playwright.stop()
        cls._server.shutdown()

    def setUp(self):
        self.errors = []
        self.page = self.browser.new_page(viewport={"width": 1500, "height": 950})
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        # Removing a story asks for confirmation in edit mode.
        self.page.on("dialog", lambda d: d.accept())
        self.page.goto(f"{self.base_url}/briefing/{self.briefing.uuid}/edit",
                       wait_until="networkidle", timeout=60000)
        self.page.wait_for_timeout(700)

    def tearDown(self):
        self.assertEqual(self.errors, [], "the page raised JavaScript errors")
        self.page.close()

    # ── helpers ──────────────────────────────────────────────────────────────

    def open_pane(self, name):
        self.page.locator(f'.wb-item[data-pane="{name}"]').click()
        self.page.wait_for_timeout(200)

    def visible_pane(self):
        return self.page.evaluate(
            "() => { const p = document.querySelector('.wb-pane.active'); return p && p.id; }")

    def story_count(self):
        return self.page.locator(".story-card").count()

    def remove_open_story(self):
        """The remove button lives inside its own pane, so only the open story
        can be deleted."""
        self.page.locator(".wb-pane.active .btn-remove-story").click()
        self.page.wait_for_timeout(500)

    # ── panes and the rail ───────────────────────────────────────────────────

    def test_the_rail_lists_every_story_and_opens_the_first(self):
        self.assertEqual(self.page.locator("#rail-stories .wb-item").count(),
                         self.story_count())
        self.assertEqual(self.visible_pane(), "pane-story-1")

    def test_only_one_pane_is_ever_on_screen(self):
        for pane in ("details", "summary", "story-1"):
            self.open_pane(pane)
            self.assertEqual(self.page.locator(".wb-pane.active").count(), 1)
            self.assertEqual(self.visible_pane(), f"pane-{pane}")

    def test_deleting_the_open_story_opens_the_one_that_took_its_place(self):
        self.open_pane("story-2")
        before = self.story_count()
        self.remove_open_story()
        self.assertEqual(self.story_count(), before - 1)
        self.assertEqual(self.visible_pane(), "pane-story-2")

    def test_deleting_the_last_story_falls_back_to_the_briefing_details(self):
        while self.story_count():
            self.page.locator("#rail-stories .wb-item").first.click()
            self.page.wait_for_timeout(150)
            self.remove_open_story()
        self.assertEqual(self.visible_pane(), "pane-details")
        self.assertEqual(self.page.locator("#count-stories").inner_text(), "0")

    def test_ticked_stories_are_deleted_together(self):
        """Thinning out a 73-story draft one story at a time took a click, a
        confirmation and a wait for each one. Shift-click ticks a range."""
        before = self.story_count()
        boxes = self.page.locator("#rail-stories .wb-story-check")
        boxes.nth(0).click()
        boxes.nth(1).click(modifiers=["Shift"])
        button = self.page.locator("#btn-delete-stories")
        self.assertEqual(button.inner_text().strip(), "Delete stories (2)")
        button.click()
        self.page.wait_for_timeout(300)
        self.assertEqual(self.story_count(), before - 2)
        self.assertTrue(button.is_disabled())

    def test_applying_exclusions_leaves_a_pane_open(self):
        """Exclusions can delete the story being edited. Before this was
        handled the editor was left blank with no pane at all."""
        self.open_pane("story-2")
        self.page.evaluate("""() => {
            const t = document.querySelectorAll('.story-title-input')[1];
            window.storyTitleExclusions = [t.value.slice(0, 12)];
        }""")
        self.page.locator("#btn-auto-delete-excluded").click()
        self.page.wait_for_timeout(500)
        self.assertIsNotNone(self.visible_pane())

    # ── story state ──────────────────────────────────────────────────────────

    def test_editing_a_drafted_story_marks_it_as_reworked(self):
        self.open_pane("story-1")
        self.page.evaluate(
            "() => document.querySelector('#pane-story-1 .story-drafted-by').value = 'ai'")
        self.page.locator("#pane-story-1 .story-content").first.type(" edit")
        self.page.wait_for_timeout(200)
        self.assertEqual(
            self.page.locator("#pane-story-1 .story-drafted-by").input_value(), "ai-edited")

    def test_picking_a_threat_actor_type_marks_a_drafted_story_as_reworked(self):
        self.open_pane("story-1")
        self.page.evaluate(
            "() => document.querySelector('#pane-story-1 .story-drafted-by').value = 'ai'")
        self.page.locator("#pane-story-1 .actor-type-pill").first.click()
        self.assertEqual(
            self.page.locator("#pane-story-1 .story-drafted-by").input_value(), "ai-edited")

    def test_the_threat_actor_type_the_model_picks_leaves_the_draft_as_drafted(self):
        self.open_pane("story-1")
        # The model only picks a type when the analyst has picked none.
        self.page.evaluate("""() => document.querySelectorAll('#pane-story-1 .actor-type-pill input')
            .forEach(cb => { cb.checked = false; cb.parentElement.classList.remove('selected'); })""")
        kind = self.page.locator("#pane-story-1 .actor-type-pill input").first.get_attribute("value")
        self.page.route("**/api/draft-story", lambda route: route.fulfill(
            json={"story": "Drafted.", "threat_actor_type": kind}))
        self.page.locator("#pane-story-1 .btn-draft-story").click()
        self.page.locator("#pane-story-1 .actor-type-pill.selected").first.wait_for()
        self.assertEqual(
            self.page.locator("#pane-story-1 .story-drafted-by").input_value(), "ai")

    # ── the summary and its staleness ────────────────────────────────────────

    def test_changing_a_story_marks_an_existing_summary_out_of_date(self):
        self.open_pane("summary")
        self.page.locator("#briefing-summary").fill("A summary written earlier.")
        self.open_pane("story-1")
        self.page.locator("#pane-story-1 .story-content").first.type(" x")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.locator("#summary-stale").input_value(), "true")

    def test_an_empty_summary_never_goes_out_of_date(self):
        self.open_pane("summary")
        self.page.locator("#briefing-summary").fill("")
        self.open_pane("story-1")
        self.page.locator("#pane-story-1 .story-content").first.type(" x")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.locator("#summary-stale").input_value(), "false")

    def test_rewriting_the_summary_clears_the_warning(self):
        self.page.evaluate("() => setSummaryStale(true)")
        self.open_pane("summary")
        self.assertTrue(self.page.locator("#summary-stale-warning").is_visible())
        self.page.locator("#briefing-summary").type(" reworded")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.locator("#summary-stale").input_value(), "false")
        self.assertFalse(self.page.locator("#summary-stale-warning").is_visible())

    def test_both_draft_buttons_go_quiet_while_one_is_running(self):
        """The action sits in the shell and on the pane. Leaving the other live
        starts a second model call over the same stories."""
        self.page.route("**/api/draft-briefing-summary", lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"ok": true, "job_id": "never-completes"}'))
        self.page.locator(".btn-draft-summary").first.click()
        self.page.wait_for_timeout(400)
        self.assertEqual(
            self.page.locator(".btn-draft-summary").evaluate_all("els => els.map(e => e.disabled)"),
            [True, True])

    # ── the overlap check ────────────────────────────────────────────────────

    def check_overlap(self, a, b):
        """Runs the check with the worker's answer that stories a and b cover
        the same event. The check refuses stories without text."""
        self.page.evaluate("() => document.querySelectorAll('.story-content').forEach(t => t.value = 'Text')")
        self.page.route("**/api/briefing-overlap-check",
                        lambda route: route.fulfill(json={"ok": True, "job_id": "overlap"}))
        self.page.route("**/pipeline/run/overlap", lambda route: route.fulfill(json={
            "ok": True, "job": {"status": "completed",
                                "result": {"overlaps": [{"a": a, "b": b, "score": 0.8, "reason": "Same event."}]}}}))
        self.page.locator("#btn-check-overlap").dispatch_event("click")
        self.page.locator("#overlap-results li").wait_for()

    def overlap_pairs(self):
        return self.page.locator("#overlap-results .fw-semibold").all_inner_texts()

    def test_deleting_a_story_keeps_the_overlap_overview_until_it_is_acknowledged(self):
        self.check_overlap(1, 2)
        self.open_pane("story-1")
        self.remove_open_story()
        self.assertEqual(self.overlap_pairs(), ["A deleted story and Story 1"])
        self.assertEqual(self.page.locator(".story-card.border-warning").count(), 0)
        self.page.locator("#btn-overlap-acknowledge").click()
        self.assertFalse(self.page.locator("#overlap-results").is_visible())

    def test_an_overlapping_pair_follows_its_stories_when_another_is_deleted(self):
        self.page.locator("#btn-add-story").click()
        self.check_overlap(2, 3)
        self.open_pane("story-1")
        self.remove_open_story()
        self.assertEqual(self.overlap_pairs(), ["Story 1 and Story 2"])
        self.assertEqual(self.page.locator(".story-card.border-warning").count(), 2)

    # ── keyboard and assistive technology ────────────────────────────────────

    def test_the_rail_is_wired_up_as_a_tablist(self):
        wiring = self.page.evaluate("""() => ({
            tablist: !!document.querySelector('[role=tablist]'),
            selected: [...document.querySelectorAll('.wb-item')]
                        .filter(t => t.getAttribute('aria-selected') === 'true').length,
            inTabOrder: [...document.querySelectorAll('.wb-item')]
                        .filter(t => t.tabIndex === 0).length,
            controlsResolve: [...document.querySelectorAll('.wb-item')]
                        .every(t => !!document.getElementById(t.getAttribute('aria-controls'))),
            labelsResolve: [...document.querySelectorAll('.wb-pane')]
                        .every(p => !!document.getElementById(p.getAttribute('aria-labelledby'))),
        })""")
        self.assertTrue(wiring["tablist"])
        self.assertEqual(wiring["selected"], 1)
        self.assertEqual(wiring["inTabOrder"], 1, "roving tabindex is broken")
        self.assertTrue(wiring["controlsResolve"], "a tab points at a pane that is gone")
        self.assertTrue(wiring["labelsResolve"], "a pane points at a tab that is gone")

    def test_the_wiring_survives_stories_being_renumbered(self):
        self.open_pane("story-1")
        self.remove_open_story()
        self.assertTrue(self.page.evaluate(
            """() => [...document.querySelectorAll('.wb-item')]
                  .every(t => !!document.getElementById(t.getAttribute('aria-controls')))"""))

    def test_arrow_keys_walk_the_rail(self):
        self.page.evaluate("() => document.querySelector('.wb-item[aria-selected=true]').focus()")
        self.page.keyboard.press("ArrowDown")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.visible_pane(), "pane-story-2")
        self.page.keyboard.press("Home")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.visible_pane(), "pane-details")

    def test_arrow_keys_inside_a_field_still_move_the_caret(self):
        """The tablist must not swallow arrows meant for the text being typed."""
        self.open_pane("story-1")
        self.page.locator("#pane-story-1 .story-content").first.click()
        self.page.evaluate(
            "() => document.querySelector('#pane-story-1 .story-content').setSelectionRange(0, 0)")
        self.page.keyboard.press("ArrowDown")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.visible_pane(), "pane-story-1")
        self.assertGreater(self.page.evaluate(
            "() => document.querySelector('#pane-story-1 .story-content').selectionStart"), 0)


if __name__ == "__main__":
    unittest.main()
