"""What the page marks as an indicator in a report, for a lookup.

core.indicators holds the patterns the browser marks with, so these pin what an
analyst sees underlined. The text is from real reports: CERT.be's copy of
SOCRadar's "INC and The Gentlemen Ransomware", CERT-EU's threat landscape,
ESET's and ENISA's reports. IPs, hashes and CVEs are marked; a domain or a URL
only when defanged, as written plainly it is a reference or the publisher's own
site; nothing inside a URL that is not marked, nor a private address. parse()
is what the lookup accepts. In the analyst's own text, the preview of a
product's Markdown field, a plain domain or URL is marked too, unless it is a
file name or not in lower case.

    python -m unittest tests.test_indicator_patterns
"""

import re
import unittest

from core import indicators

SHA256 = "ffca6aa96572743200f9f0040a3e435766f6d7c15d6a4c72045a0cbb4db72eb4"


def marked(text):
    return [(kind, value) for kind, _start, _end, value in indicators.find(text)]


class Marked(unittest.TestCase):
    def test_the_server_in_the_text_and_not_its_as_number(self):
        text = ("The investigation began with an exposed command-and-control server at 45.227.254[.]43, whose "
                "open directories held the operators' knowledge base, most hosted on AS267784 (Flyservers S.A.).")
        self.assertEqual(marked(text), [("ip", "45.227.254.43")])

    def test_defanged_domains_hostnames_and_onion_addresses(self):
        text = ("| Domain | iquickline[.]com | Phantom / Athena C2 zone |\n"
                "Its agent calls back to api.iquickline[.]com.\n"
                "| Onion | incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad[.]onion | INC leak site |")
        self.assertEqual(marked(text), [
            ("domain", "iquickline.com"), ("domain", "api.iquickline.com"),
            ("domain", "incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion")])

    def test_hashes_by_their_length(self):
        text = (f"| SHA-256 | {SHA256} | INC build A |\n"
                "md5 9e107d9d372bb6826bd81d3542a419d6, sha1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
        self.assertEqual(marked(text), [("sha256", SHA256), ("md5", "9e107d9d372bb6826bd81d3542a419d6"),
                                        ("sha1", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")])

    def test_cves_written_as_the_report_writes_them(self):
        text = "FortiClient EMS (CVE-2026-35616): 2,236 targets. | CVE-2021-42278/42287 (noPac) | Windows AD |"
        self.assertEqual(marked(text), [("cve", "CVE-2026-35616"), ("cve", "CVE-2021-42278")])

    def test_a_defanged_url_is_one_indicator(self):
        self.assertEqual(marked("Payload from hxxps://mgardownload[.]com/setup.exe."),
                         [("url", "https://mgardownload.com/setup.exe")])

    def test_the_end_of_a_sentence_is_not_part_of_it(self):
        self.assertEqual(marked("Ghost C2 on 89.185.83[.]8. A retired zone, driverupdate[.]app."),
                         [("ip", "89.185.83.8"), ("domain", "driverupdate.app")])

    def test_written_without_defanging_an_ip_is_still_one(self):
        self.assertEqual(marked("RevSocks host 77.110.109.248"), [("ip", "77.110.109.248")])


class LeftAsText(unittest.TestCase):
    def test_what_looks_like_an_indicator_in_the_report_and_is_not(self):
        for text in ("Lateral Movement | T1021.002 SMB/Windows Admin Shares",
                     "OpenRouter (anthropic/claude-opus-4.6, moonshotai/kimi-k3)",
                     "| URL / path | /assets/js/analytics.js | Disguised loader path |",
                     "Shadow-copy removal through IOCTL 0x0053C028",
                     "most active between 06:00 and 14:00 UTC", "AS267784 (Flyservers S.A.)",
                     "Windows 10.0.17763.1234", "an IPv4 at 1.2.3.4.5"):
            with self.subTest(text):
                self.assertEqual(marked(text), [])

    def test_a_plain_domain_or_url_is_a_reference(self):
        """Marked, the publisher's own site and every reference link were: 59 of
        them in CERT-EU's report alone."""
        for text in ("Visit www.eset.com for more", "enisa.europa.eu", "Read WeLiveSecurity.com",
                     "https://cert.europa.eu/publications/threat-intelligence/tlr2024/pdf"):
            with self.subTest(text):
                self.assertEqual(marked(text), [])

    def test_nothing_inside_a_reference_url(self):
        url = "https://apnews.com/article/nato-summit-cybersecurity-hack-russia-netherlands-fa97bbf8797a51c2885d47f5f83691be"
        self.assertEqual(marked(f"See {url} and https://nvd.nist.gov/vuln/detail/CVE-2026-35616"), [])

    def test_private_and_documentation_addresses(self):
        for ip in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "172.20.1.1", "169.254.3.3", "100.64.1.1",
                   "203.0.113.77", "198.51.100.1", "192.0.2.10", "224.0.0.251", "255.255.255.255", "0.0.0.0"):
            with self.subTest(ip):
                self.assertEqual(marked(f"host {ip} seen"), [])

    def test_an_address_in_an_e_mail_is_not_a_domain(self):
        self.assertEqual(marked("from billing@bossprotect[.]com"), [])


class OwnText(unittest.TestCase):
    def own(self, text):
        return [(kind, value) for kind, _start, _end, value in indicators.find(text, plain=True)]

    def test_a_plain_domain_or_url_the_analyst_wrote(self):
        """www.belnet.be in a briefing's text could not be looked up: it is
        neither defanged nor, once Markdown makes it a link, plain text."""
        self.assertEqual(self.own("Demo for www.belnet.be connecting to 193.2.4.2"),
                         [("domain", "www.belnet.be"), ("ip", "193.2.4.2")])
        self.assertEqual(self.own("Payload at https://www.belnet.be/x."), [("url", "https://www.belnet.be/x")])
        self.assertEqual(marked("Demo for www.belnet.be connecting to 193.2.4.2"), [("ip", "193.2.4.2")])

    def test_file_names_and_product_names_are_not_domains(self):
        for text in ("Run cmd.exe, then rundll32.exe loads payload.ps1", "the agent.jar and config.json",
                     "built on ASP.NET and Node.js", "e.g. the U.S. sector"):
            with self.subTest(text):
                self.assertEqual(self.own(text), [])

    def test_defanged_is_marked_as_in_a_report(self):
        self.assertEqual(self.own("C2 at Evil[.]COM"), [("domain", "Evil.COM")])


class Parse(unittest.TestCase):
    def test_what_the_lookup_accepts(self):
        self.assertEqual(indicators.parse("ip", "45.227.254[.]43"), "45.227.254.43")
        self.assertEqual(indicators.parse("domain", " evil.com "), "evil.com")
        self.assertEqual(indicators.parse("url", "hxxps[:]//a[.]b/c"), "https://a.b/c")
        self.assertEqual(indicators.parse("cve", "cve-2026-35616"), "CVE-2026-35616")
        self.assertEqual(indicators.parse("sha256", SHA256.upper()), SHA256.upper())

    def test_what_it_refuses(self):
        for kind, value in (("ip", "10.0.0.1"), ("ip", "1.2.3"), ("md5", "x" * 32), ("sha1", SHA256),
                            ("domain", "a" * 3000), ("domain", "evil.com/x"), ("shell", "evil.com"),
                            ("ip", 42), ("ip", None), ("url", "javascript:alert(1)")):
            with self.subTest((kind, value)):
                self.assertIsNone(indicators.parse(kind, value))

    def test_an_attribute_value_by_its_type(self):
        """Marked by its type alone, a URL without its scheme opened a card
        whose lookup was then refused."""
        self.assertEqual(indicators.kind_of("ip-dst", "45.227.254.43"), "ip")
        self.assertEqual(indicators.kind_of("vulnerability", "CVE-2026-35616"), "cve")
        for misp_type, value in (("url", "evil.example/gate.php"), ("ip-src", "10.0.0.1"),
                                 ("ip-dst", "45.227.254.0/24"), ("text", "45.227.254.43"), ("md5", "")):
            with self.subTest((misp_type, value)):
                self.assertIsNone(indicators.kind_of(misp_type, value))


class Browser(unittest.TestCase):
    def test_the_patterns_are_what_a_browser_can_compile(self):
        """The page builds them with new RegExp(source, 'gi'): no named groups,
        no inline flags, no Python-only syntax."""
        config = indicators.browser_config()
        for pattern in config["patterns"]:
            with self.subTest(pattern["kind"]):
                re.compile(pattern["source"])
                self.assertNotRegex(pattern["source"], r"\(\?P|\(\?[aiLmsux]|\\A|\\Z")
        self.assertEqual(set(config["labels"]), {p["kind"] for p in config["patterns"]})
        self.assertTrue(set(config["mispTypes"].values()) <= set(config["labels"]))
        self.assertIn("exe", config["fileExtensions"])


if __name__ == "__main__":
    unittest.main()
