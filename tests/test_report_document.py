"""Reading a long report and drafting its stories (core/report_document.py).

Pins what the eight reports this was built against taught: running headers
and footers removed, the PDF's own text order kept across columns, outline
entries placed by their title and InDesign's anchors left out, headings found
by size when there is no outline, the TLP a document is marked with, scanned
and protected PDFs refused, and the drafts: contiguous, split where a section
is long or made of substantial parts, never merged across sections. The PDFs
are made in the test with PyMuPDF; the download is mocked.

    python -m unittest tests.test_report_document
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pymupdf

import config

from core import report_document as rd

BODY = ("Threat actors continued to exploit edge devices across the sector, and the "
        "campaigns grew in scale and in speed through the year. ")


def _pdf(pages, toc=None, metadata=None, password=None, width=595, height=842):
    """A PDF from [[(x, y, size, text), ...] per page]."""
    doc = pymupdf.open()
    for items in pages:
        page = doc.new_page(width=width, height=height)
        for x, y, size, text in items:
            page.insert_text((x, y), text, fontsize=size)
    if toc:
        doc.set_toc(toc)
    if metadata:
        doc.set_metadata(metadata)
    if password:
        return doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw=password, user_pw=password)
    return doc.tobytes()


def _paragraph(y, lines=4, x=60, size=10):
    return [(x, y + i * 13, size, BODY[:70]) for i in range(lines)]


def _page(heading=None, y=120, header="ACME THREAT REPORT", number=1):
    items = [(60, 30, 8, header), (500, 820, 8, str(number))]
    if heading:
        items.append((60, y - 40, 20, heading))
    return items + _paragraph(y) + _paragraph(y + 80)


def _read(data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "r.pdf"
        path.write_bytes(data)
        return rd.read_document(str(path))


def _blocks(sizes):
    """Body blocks of the given lengths, one page each."""
    return [{"id": i, "page": i + 1, "text": "x" * n, "size": 1.0, "kind": "p"} for i, n in enumerate(sizes)]


class Reading(unittest.TestCase):
    def test_running_headers_and_page_numbers_are_removed(self):
        reading = _read(_pdf([_page("Section %d" % n, number=n) for n in range(1, 6)]))
        texts = [b["text"] for b in reading["blocks"]]
        self.assertFalse([t for t in texts if "ACME" in t or t.isdigit()])
        self.assertIn("ACME THREAT REPORT", reading["running"])

    def test_a_heading_is_found_by_its_size_against_the_body_text(self):
        reading = _read(_pdf([_page("Ransomware", number=1), _page("Phishing", number=2), _page("Espionage", number=3)]))
        headings = [b["text"] for b in reading["blocks"] if b["kind"] == "h"]
        self.assertEqual(headings, ["Ransomware", "Phishing", "Espionage"])
        self.assertEqual({b["size"] for b in reading["blocks"] if b["kind"] == "p"}, {1.0})

    def test_sizes_are_compared_not_read_as_points(self):
        # ESET's pages are 3840 points wide, with 33 pt body text.
        page = [(100, 300, 110, "Lumma Stealer returns")] + [(100, 500 + i * 45, 33, BODY[:70]) for i in range(8)]
        reading = _read(_pdf([page, page], width=3840, height=2160))
        self.assertEqual(reading["blocks"][0]["kind"], "h")
        self.assertEqual(reading["blocks"][1]["kind"], "p")

    def test_columns_keep_the_order_the_pdf_has_them_in(self):
        left = [(60, 200 + i * 13, 10, "Left column line %d about intrusions." % i) for i in range(6)]
        right = [(320, 200 + i * 13, 10, "Right column line %d about phishing." % i) for i in range(6)]
        reading = _read(_pdf([left + right]))
        text = " ".join(b["text"] for b in reading["blocks"])
        self.assertLess(text.index("Left column line 5"), text.index("Right column line 0"))

    def test_a_compound_or_address_broken_over_two_lines_is_joined(self):
        page = [(60, 200, 10, "The actor used a state-"), (60, 213, 10, "sponsored loader, see https://example.org/a-"),
                (60, 226, 10, "report/today. Then it moved on.")]
        reading = _read(_pdf([page]))
        self.assertIn("a state-sponsored loader, see https://example.org/a-report/today. Then",
                      reading["blocks"][0]["text"])

    def test_outline_entries_are_placed_on_their_title_and_anchors_left_out(self):
        pages = [_page("Opening statement", number=1), _page("China", number=2), _page("Russia", number=3)]
        # The heading is lower on the page than a paragraph that also opens with
        # its words, as a chapter that starts mid page.
        pages[2] = _page(number=3)[:2] + [(60, 120, 10, "Russia and its neighbours were quieter.")] \
            + [(60, 400, 20, "Russia")] + _paragraph(440)
        toc = [[1, "_s3n6j2ho91kz", 1], [1, "Opening statement", 1], [1, "China", 2],
               [1, "Figure 7: Summary of activity", 2], [1, "Russia", 3]]
        with mock.patch.object(rd, "_SMALL_DOCUMENT_CHARS", 0):
            reading = _read(_pdf(pages, toc=toc))
        self.assertEqual([e["title"] for e in reading["outline"]], ["Opening statement", "China", "Russia"])
        self.assertEqual(reading["outline_skipped"], 2)
        russia = reading["blocks"][reading["outline"][2]["block"]]
        self.assertEqual((russia["text"], russia["kind"]), ("Russia", "h"))
        self.assertEqual(reading["structure"], "outline")

    def test_without_an_outline_the_headings_that_recur_split_the_document(self):
        pages = [[(60, 300, 40, "THREAT LANDSCAPE")]]
        for n, name in enumerate(["Key findings", "Threat actors", "Sectors"], start=2):
            pages.append(_page(name, number=n) + _paragraph(300) + _paragraph(400))
        # An infographic: large labels, many on one page.
        pages.append([(60, 100 + i * 40, 18, "LABEL %d" % i) for i in range(6)] + _paragraph(400))
        with mock.patch.object(rd, "_SMALL_DOCUMENT_CHARS", 0):
            reading = _read(_pdf(pages))
        self.assertEqual(reading["structure"], "headings")
        self.assertEqual([s["title"] for s in reading["drafts"]],
                         ["Opening pages", "Key findings", "Threat actors", "Sectors"])

    def test_the_tlp_a_document_is_marked_with(self):
        pages = [[(60, 30, 8, "TLP:CLEAR/PUBLIC")] + _paragraph(200) for _ in range(3)]
        self.assertEqual(_read(_pdf(pages))["tlp"], "clear")
        pages = [[(60, 830, 8, "TLP:WHITE")] + _paragraph(200)]
        self.assertEqual(_read(_pdf(pages))["tlp"], "clear")
        # A marking explained in the body is not the document's own.
        pages = [_paragraph(200), [(60, 300, 10, "TLP:RED means for the named recipients only.")] + _paragraph(400)]
        self.assertEqual(_read(_pdf(pages))["tlp"], "")

    def test_title_and_date_come_from_the_metadata_unless_it_is_a_file_name(self):
        meta = {"title": "ENISA_ETL26_BOOKLET_OUT_WEB", "creationDate": "D:20261030093741+01'00'"}
        pages = [[(60, 200, 35, "ENISA THREAT"), (60, 260, 51, "LANDSCAPE"), (60, 320, 17, "SEPTEMBER 2026")]
                 + _paragraph(400)]
        reading = _read(_pdf(pages, metadata=meta))
        self.assertEqual((reading["title"], reading["created"]), ("Enisa Threat Landscape", "2026-10-30"))
        reading = _read(_pdf(pages, metadata={"title": "2026 State of Security"}))
        self.assertEqual((reading["title"], reading["created"]), ("2026 State of Security", ""))

    def test_a_scanned_pdf_is_refused(self):
        with self.assertRaisesRegex(rd.ReportError, "scanned"):
            _read(_pdf([[(60, 100, 10, "p. 1")], [], []]))

    def test_a_protected_pdf_is_refused(self):
        with self.assertRaisesRegex(rd.ReportError, "password"):
            _read(_pdf([_paragraph(200)], password="secret"))

    def test_a_file_that_is_not_a_pdf_is_refused(self):
        with self.assertRaisesRegex(rd.ReportError, "not a PDF"):
            rd.read_pdf(b"<html><body>Download the report</body></html>")


class ChildProcess(unittest.TestCase):
    def test_the_pdf_is_read_in_a_child_process(self):
        data = _pdf([_page("Section %d" % n, number=n) for n in range(1, 4)])
        with mock.patch.object(rd, "read_document", side_effect=AssertionError("read in this process")):
            reading = rd.read_pdf(data)
        self.assertEqual(reading["pages"], 3)
        self.assertTrue(reading["drafts"])

    def test_the_childs_refusal_reaches_the_analyst(self):
        with self.assertRaisesRegex(rd.ReportError, "password"):
            rd.read_pdf(_pdf([_paragraph(200)], password="secret"))

    def test_a_child_that_takes_too_long_is_stopped(self):
        timeout = subprocess.TimeoutExpired(cmd="reader", timeout=180)
        with mock.patch.object(rd.subprocess, "run", side_effect=timeout), \
                self.assertRaisesRegex(rd.ReportError, "longer than 3 minutes"):
            rd.read_pdf(_pdf([_paragraph(200)]))

    def test_a_child_that_crashes_is_logged_and_reported(self):
        crashed = subprocess.CompletedProcess(args=[], returncode=-11, stdout=b"", stderr=b"Segmentation fault")
        with mock.patch.object(rd.subprocess, "run", return_value=crashed), \
                self.assertLogs("core.report_document", "ERROR") as logged, \
                self.assertRaisesRegex(rd.ReportError, "could not be read"):
            rd.read_pdf(_pdf([_paragraph(200)]))
        self.assertIn("Segmentation fault", logged.output[0])


class Drafts(unittest.TestCase):
    def assertContiguous(self, stories, blocks):
        self.assertEqual(stories[0]["start"], 0)
        self.assertEqual(stories[-1]["end"], len(blocks))
        for a, b in zip(stories, stories[1:]):
            self.assertEqual(a["end"], b["start"])

    def test_a_short_document_is_one_story(self):
        blocks = _blocks([800] * 6)
        stories = rd.draft_stories(blocks, [], "ENISA Threat Landscape")
        self.assertEqual([(s["title"], s["start"], s["end"]) for s in stories], [("ENISA Threat Landscape", 0, 6)])

    def test_themes_nested_under_the_first_still_become_stories_of_their_own(self):
        # CrowdStrike: the six themes are in the outline as one, then five under it.
        blocks = _blocks([100] + [6000] * 6)
        marks = [{"level": 1, "title": "Key Adversary Themes", "block": 0},
                 {"level": 2, "title": "AI", "block": 1}] + \
                [{"level": 3, "title": "Theme %d" % n, "block": n + 1} for n in range(1, 6)]
        stories = rd.draft_stories(blocks, marks)
        self.assertEqual([s["title"] for s in stories], ["AI"] + ["Theme %d" % n for n in range(1, 6)])
        self.assertContiguous(stories, blocks)

    def test_a_heading_on_its_own_joins_the_first_story_under_it(self):
        blocks = _blocks([100, 5000, 5000, 6000, 3000])
        marks = [{"level": 1, "title": "Section IV: Cybercrime", "block": 0},
                 {"level": 2, "title": "Ransomware", "block": 1},
                 {"level": 2, "title": "Fraud", "block": 2},
                 {"level": 2, "title": "Infostealers", "block": 3},
                 {"level": 1, "title": "Conclusion", "block": 4}]
        stories = rd.draft_stories(blocks, marks)
        self.assertEqual([(s["title"], s["start"]) for s in stories],
                         [("Ransomware", 0), ("Fraud", 2), ("Infostealers", 3), ("Conclusion", 4)])
        self.assertEqual(stories[0]["path"], ["Section IV: Cybercrime"])

    def test_a_small_story_is_not_folded_into_the_section_before(self):
        # The fold that pulled Recorded Future's Section IV opening into Section III.
        blocks = _blocks([3000, 900, 4000])
        marks = [{"level": 1, "title": "Section III", "block": 0},
                 {"level": 1, "title": "Section IV", "block": 1},
                 {"level": 1, "title": "Section V", "block": 2}]
        self.assertEqual([s["title"] for s in rd.draft_stories(blocks, marks)], ["Section III", "Section IV", "Section V"])

    def test_a_short_section_of_substantial_parts_is_split(self):
        # Recorded Future's Section III, 14,800 characters on four conflicts.
        blocks = _blocks([2500, 3100, 2400, 2400, 1700])
        marks = [{"level": 1, "title": "Section III", "block": 0}] + \
                [{"level": 2, "title": "Conflict %d" % n, "block": n} for n in range(1, 5)]
        self.assertEqual(len(rd.draft_stories(blocks, marks)), 5)

    def test_a_section_of_short_paragraphs_stays_one_story(self):
        # Microsoft's sections of a few paragraphs under a heading each.
        blocks = _blocks([700, 1200, 900, 1300, 1100, 800])
        marks = [{"level": 4, "title": "AI-augmented intrusions", "block": 0}] + \
                [{"level": 5, "title": "Part %d" % n, "block": n} for n in range(1, 6)]
        stories = rd.draft_stories(blocks, marks)
        self.assertEqual([(s["title"], s["start"], s["end"]) for s in stories], [("AI-augmented intrusions", 0, 6)])

    def test_text_before_the_first_section_is_its_own_story(self):
        blocks = _blocks([4000, 6000, 6000])
        marks = [{"level": 1, "title": "China", "block": 1}, {"level": 1, "title": "Russia", "block": 2}]
        self.assertEqual([s["title"] for s in rd.draft_stories(blocks, marks)], ["Opening pages", "China", "Russia"])

    def test_a_long_story_without_headings_is_cut_where_a_page_ends(self):
        blocks = _blocks([5000] * 8)
        stories = rd.draft_stories(blocks, [], "Telemetry")
        self.assertGreater(len(stories), 1)
        self.assertTrue(all(s["chars"] <= 30_000 for s in stories))
        self.assertEqual(stories[0]["title"], "Telemetry, pages 1 to 3")
        self.assertContiguous(stories, blocks)

    def test_a_piece_of_one_page_is_named_by_that_page(self):
        stories = rd.draft_stories(_blocks([20_000, 20_000]), [], "Telemetry")
        self.assertEqual([s["title"] for s in stories], ["Telemetry, page 1", "Telemetry, page 2"])

    def test_a_long_story_is_cut_at_its_own_headings(self):
        blocks = _blocks([300] + [9000] * 4)
        for i, name in ((1, "Rapid exploitation"), (3, "Edge devices")):
            blocks.insert(i, {"id": 0, "page": blocks[i]["page"], "text": name, "size": 1.6, "kind": "h"})
        for n, b in enumerate(blocks):
            b["id"], b["page"] = n, n + 2
        stories = rd.draft_stories(blocks, [], "China-Nexus")
        self.assertEqual([s["title"] for s in stories],
                         ["China-Nexus", "China-Nexus: Rapid exploitation", "China-Nexus: Edge devices"])
        self.assertContiguous(stories, blocks)


class Fetching(unittest.TestCase):
    def _session(self, *responses):
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = list(responses)
        return session

    def _response(self, status=200, body=b"", headers=None):
        response = mock.Mock(status_code=status, headers=headers or {})
        response.iter_content.return_value = [body[i:i + 1000] for i in range(0, len(body), 1000)] or [b""]
        return response

    def _fetch(self, url, *responses, resolve=("host", 443, ["93.184.216.34"])):
        session = self._session(*responses)
        resolver = resolve if callable(resolve) else (lambda u: resolve)
        with mock.patch("curl_cffi.requests.Session", return_value=session), \
                mock.patch.object(rd, "resolve_public_url", side_effect=resolver):
            return rd.fetch_pdf(url), session

    def test_a_pdf_is_downloaded_with_its_name(self):
        (data, name), _ = self._fetch("https://example.org/files/ENISA_ETL26.pdf",
                                      self._response(body=b"%PDF-1.7 report"))
        self.assertEqual((data, name), (b"%PDF-1.7 report", "ENISA_ETL26.pdf"))

    def test_an_address_without_an_extension_is_named_from_its_answer(self):
        response = self._response(body=b"%PDF-1.3", headers={"content-disposition": 'attachment; filename="tlr2025.pdf"'})
        (_, name), _ = self._fetch("https://cert.example.eu/tlr2025/pdf", response)
        self.assertEqual(name, "tlr2025.pdf")

    def test_a_web_page_is_refused_with_what_to_do(self):
        with self.assertRaisesRegex(rd.ReportError, "web page, not a PDF. Download"):
            self._fetch("https://example.com/explore/report", self._response(body=b"<!doctype html><html><body>"))

    def test_a_redirect_to_an_internal_address_is_refused(self):
        hops = {"https://example.org/r": ("example.org", 443, ["93.184.216.34"]), "http://10.0.0.5/r.pdf": None}
        with self.assertRaisesRegex(rd.ReportError, "public"):
            self._fetch("https://example.org/r", self._response(302, headers={"location": "http://10.0.0.5/r.pdf"}),
                        resolve=lambda u: hops[u])

    def test_a_pdf_over_the_limit_is_refused(self):
        # The limit Settings has, read when the download starts.
        with mock.patch.object(config, "REPORT_IMPORT_MAX_MB", 1, create=True), \
                self.assertRaisesRegex(rd.ReportError, "larger than 1 MB"):
            self._fetch("https://example.org/big.pdf", self._response(body=b"%PDF-" + b"0" * (1024 * 1024)))

    def test_the_connection_is_pinned_to_the_checked_address(self):
        with mock.patch("curl_cffi.requests.Session") as session_cls, \
                mock.patch.object(rd, "resolve_public_url", return_value=("example.org", 443, ["93.184.216.34"])):
            session = session_cls.return_value.__enter__.return_value
            session.get.return_value = self._response(body=b"%PDF-1.7")
            rd.fetch_pdf("https://example.org/r.pdf")
        options = session_cls.call_args.kwargs["curl_options"]
        self.assertEqual(list(options.values()), [["example.org:443:93.184.216.34"]])
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])


class Answer(unittest.TestCase):
    def test_the_child_writes_its_refusal_as_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            pdf, answer = Path(tmp) / "r.pdf", Path(tmp) / "a.json"
            pdf.write_bytes(_pdf([_paragraph(200)], password="secret"))
            with mock.patch("resource.setrlimit"):
                self.assertEqual(rd._main(str(pdf), str(answer)), 2)
            self.assertIn("password", json.loads(answer.read_text())["error"])


if __name__ == "__main__":
    unittest.main()
