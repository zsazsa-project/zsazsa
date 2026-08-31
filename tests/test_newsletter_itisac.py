"""Tests for the IT-ISAC Open Source News parser.

IT-ISAC lays each article out as labelled fields separated by a rule, and the
labels wrap: a title runs onto the next line, an excerpt runs to several
paragraphs, and a title can itself contain a colon. Those are the things that
break a line-anchored parser.

    python -m unittest tests.test_newsletter_itisac
"""

import unittest

from webapp import newsletter_parsers as parsers

SAMPLE = """\
IT-ISAC Public

TLP:CLEAR

[IT-ISAC] Open Source News August 14, 2026


Title: Fake Zoom Installer Uses .NET Downloader to Deliver Overlord RAT on
macOS



Date Published: August 6, 2026



https://www.jamf.com/blog/fake-zoom-installer-delivers-overlord-rat-macos/


Excerpt: “Jamf Threat Labs recently identified a campaign using a fake Zoom
installer to deliver a configured build of Overlord, an open-source remote
access framework, hosted on attacker-controlled infrastructure.”

------------------------------



Title: Warning: Actively Exploited DoS vulnerability in Cisco Secure
Firewall, Patch Immediately!



Date Published: August 13, 2026


https://ccb.belgium.be/advisories/warning-actively-exploited-dos-vulnerability-cisco-secure-firewall-patch-immediately


Excerpt: “An unauthenticated, remote attacker can force the affected
devices to reload, leading to a denial of service.”


------------------------------



Title: You're Invited to get Phished! Why Invitation-themed Emails Remain
Effective



Date Published: August 12, 2026



https://cofense.com/blog/you-re-invited-to-get-phished!-why-invitation-themed-emails-remain-effective


Excerpt: “Threat actors are using event invitation-themed emails to deliver
malware and credential phishing content.

Invitation-themed emails make up almost fifteen percent of malware
campaigns.”


------------------------------




--

Dylan Roth

Threat Intelligence Coordinator



E: dylan@it-isac.org

www.it-isac.org
"""


class Parse(unittest.TestCase):
    def setUp(self):
        self.parsed = parsers.parse("IT-ISAC Open Source News", SAMPLE)
        self.articles = self.parsed["articles"]

    def test_report_metadata(self):
        self.assertEqual(self.parsed["report_title"], "[IT-ISAC] Open Source News August 14, 2026")
        self.assertEqual(self.parsed["tlp"], "clear")

    def test_every_article_is_found(self):
        self.assertEqual(len(self.articles), 3)

    def test_a_wrapped_title_is_joined(self):
        self.assertEqual(self.articles[0]["title"],
                         "Fake Zoom Installer Uses .NET Downloader to Deliver Overlord RAT on macOS")

    def test_a_title_containing_a_colon_survives(self):
        """"Warning: Actively Exploited..." must not be read as a field label."""
        self.assertTrue(self.articles[1]["title"].startswith("Warning: Actively Exploited"))
        self.assertTrue(self.articles[1]["title"].endswith("Patch Immediately!"))

    def test_urls_are_captured_whole(self):
        self.assertEqual(self.articles[0]["primary_url"],
                         "https://www.jamf.com/blog/fake-zoom-installer-delivers-overlord-rat-macos/")
        # Trailing punctuation is stripped from URLs, but a '!' inside the path is not.
        self.assertTrue(self.articles[2]["primary_url"].endswith("invitation-themed-emails-remain-effective"))
        self.assertIn("get-phished!", self.articles[2]["primary_url"])

    def test_the_excerpt_becomes_the_intro_without_its_quotes(self):
        intro = self.articles[0]["intro"]
        self.assertTrue(intro.startswith("Jamf Threat Labs"), intro)
        self.assertNotIn("“", intro)

    def test_a_multi_paragraph_excerpt_is_kept_whole(self):
        intro = self.articles[2]["intro"]
        self.assertIn("event invitation-themed emails", intro)
        self.assertIn("almost fifteen percent", intro)

    def test_the_mail_signature_is_not_an_article(self):
        self.assertNotIn("Dylan Roth", [a["title"] for a in self.articles])
        self.assertTrue(all(a["primary_url"] for a in self.articles))

    def test_the_signature_stays_out_of_the_last_excerpt(self):
        """When an edition ends without a closing rule, the signature would
        otherwise be read as more of the last article's excerpt, putting the
        sender's contact details into the imported summary."""
        head, _, tail = SAMPLE.rpartition("------------------------------")
        unclosed = head + tail
        last = parsers.parse("IT-ISAC Open Source News", unclosed)["articles"][-1]
        self.assertIn("almost fifteen percent", last["intro"])
        self.assertNotIn("dylan@it-isac.org", last["intro"])
        self.assertNotIn("Threat Intelligence Coordinator", last["intro"])

    def test_fields_running_together_do_not_merge(self):
        """This edition separates its fields with blank lines, which alone would
        end the title. A copy that loses them, and the labels are all that is
        left, must not fold the date into the title."""
        tight = ("Title: Something happened\n"
                 "Date Published: August 6, 2026\n"
                 "https://example.org/report\n"
                 "Excerpt: “The quote.”\n\n" + "-" * 30 + "\n")
        article = parsers.parse("IT-ISAC Open Source News", tight)["articles"][0]
        self.assertEqual(article["title"], "Something happened")
        self.assertEqual(article["primary_url"], "https://example.org/report")
        self.assertEqual(article["intro"], "The quote.")

    def test_a_link_inside_an_excerpt_does_not_truncate_it(self):
        """Quoted prose can carry a link. Harvesting it as the article's own URL
        ended the excerpt there and dropped the rest of the quote."""
        sample = ("Title: Something happened\n\nhttps://example.org/report\n\n"
                  "Excerpt: “The vendor published an advisory\n"
                  "at https://vendor.example/adv and urged customers to patch.\n"
                  "A second wave followed.”\n\n" + "-" * 30 + "\n")
        article = parsers.parse("IT-ISAC Open Source News", sample)["articles"][0]
        self.assertEqual(article["primary_url"], "https://example.org/report")
        self.assertIn("urged customers to patch", article["intro"])
        self.assertIn("A second wave followed", article["intro"])

    def test_it_isac_grades_nothing_so_nothing_is_invented(self):
        for article in self.articles:
            self.assertEqual(article["priority_key"], "")
            self.assertEqual(article["section"], "")


class Boundaries(unittest.TestCase):
    """A title opens an article and a rule closes one. Lines outside both, the
    mail's own header above the first article, belong to no article and must not
    be attached to the nearest one."""

    def parse(self, text):
        return parsers.parse("IT-ISAC Open Source News", text)["articles"]

    def test_a_banner_link_above_the_first_article_is_not_its_url(self):
        """Splitting on the rule alone put the mail header in the same block as
        the first article, so a 'view this online' link was published as that
        article's URL and sent the scraper to the newsletter itself."""
        articles = self.parse(
            "IT-ISAC Public\n"
            "View this newsletter online: https://example.org/editions/2026-08-14\n\n"
            "[IT-ISAC] Open Source News August 14, 2026\n\n"
            "Title: Fake Zoom Installer Delivers Overlord RAT\n\n"
            "https://example.org/blog/fake-zoom\n\n"
            "Excerpt: “Jamf Threat Labs identified a campaign.”\n\n" + "-" * 30 + "\n")
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["primary_url"], "https://example.org/blog/fake-zoom")
        self.assertEqual(articles[0]["related_urls"], [])

    def test_a_lost_rule_does_not_fold_two_articles_into_one(self):
        """An edition that reaches us without a rule between two articles, one
        reflowed by a mail client, used to collect them as a single article
        carrying both titles, and the second link was never published."""
        articles = self.parse(
            "Title: First story\n\nhttps://example.org/one\n\nExcerpt: “One.”\n\n"
            "Title: Second story\n\nhttps://example.org/two\n\nExcerpt: “Two.”\n\n"
            + "-" * 30 + "\n")
        self.assertEqual([(a["title"], a["primary_url"]) for a in articles],
                         [("First story", "https://example.org/one"),
                          ("Second story", "https://example.org/two")])


class ForwardedCopy(unittest.TestCase):
    """The same mail forwarded, which arrives quoted with '> ' like the ETDA one."""

    def test_a_quoted_forward_parses_the_same(self):
        quoted = "\n".join("> " + line for line in SAMPLE.split("\n"))
        forwarded = "Begin forwarded message:\nFrom: Dylan Roth\nSubject: news\n\n" + quoted
        parsed = parsers.parse("IT-ISAC Open Source News", forwarded)
        self.assertEqual([a["title"] for a in parsed["articles"]],
                         [a["title"] for a in parsers.parse("IT-ISAC Open Source News", SAMPLE)["articles"]])


class Registration(unittest.TestCase):
    def test_the_source_is_selectable_in_the_importer(self):
        self.assertIn("IT-ISAC Open Source News", parsers.available_sources())

    def test_an_unknown_source_is_refused(self):
        with self.assertRaises(ValueError):
            parsers.parse("Nonexistent Newsletter", SAMPLE)

    def test_empty_input_does_not_raise(self):
        self.assertEqual(parsers.parse("IT-ISAC Open Source News", "")["articles"], [])


if __name__ == "__main__":
    unittest.main()
