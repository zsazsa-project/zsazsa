"""The vulnerability a Flowintel case gets from a vulnerability advisory.

Its CVSS score is the number the advisory's CVSS opens with, read as the rest
of zsazsa reads it: "9.8 CRITICAL" as the analyser writes it, "7.5 (HIGH)" as
the form suggests, and none when the field holds no score, rather than the
version out of a CVSS vector. Flowintel is not asked.

    python -m unittest tests.test_flowintel_vea_case
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from core import flowintel_client


def _vea(**fields):
    data = dict(vea_id="VEA-00007", title="FortiOS heap overflow", cve_id="CVE-2026-0001\nCVE-2026-0002",
                cvss="9.8 CRITICAL", cwe="CWE-787", summary="A heap overflow.", tlp="amber", references=[])
    data.update(fields)
    return SimpleNamespace(**data)


class Vulnerability(unittest.TestCase):
    def vulnerability(self, vea):
        with mock.patch.object(flowintel_client, "create_case_from_product", return_value={"ok": True}) as create:
            flowintel_client.send_vea_to_flowintel({"id": "flowintel"}, vea, "# Advisory")
        return create.call_args.kwargs["vulnerability"]

    def test_the_score_is_the_number_the_cvss_opens_with(self):
        for cvss, score in (("9.8 CRITICAL", "9.8"), ("7.5 (HIGH)", "7.5"), ("10", "10.0"), ("", None),
                            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", None)):
            with self.subTest(cvss=cvss):
                self.assertEqual(self.vulnerability(_vea(cvss=cvss))["cvss_score"], score)

    def test_it_names_each_cve_of_the_advisory(self):
        self.assertEqual(self.vulnerability(_vea())["cve_ids"], ["CVE-2026-0001", "CVE-2026-0002"])


if __name__ == "__main__":
    unittest.main()
