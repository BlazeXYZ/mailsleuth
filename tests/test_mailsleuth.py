import json
import unittest
from pathlib import Path

from mailsleuth.analyzer import analyze
from mailsleuth.domains import brand_lookalike, cousin_domain, org_domain
from mailsleuth.parser import parse_authentication_results, parse_bytes
from mailsleuth.report import to_html, to_json
from mailsleuth.reputation import vt_url_id
from mailsleuth.urls import analyze_url, defang

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def run(name):
    return analyze((SAMPLES / name).read_bytes(), name)


def titles(report):
    return [f.title for f in report.findings]


class DomainTests(unittest.TestCase):
    def test_org_domain(self):
        self.assertEqual(org_domain("mail.paypal.com"), "paypal.com")
        self.assertEqual(org_domain("shop.example.co.uk"), "example.co.uk")

    def test_brand_lookalike(self):
        self.assertIsNotNone(brand_lookalike("paypa1-security.com"))
        self.assertIsNotNone(brand_lookalike("micros0ft-login.net"))
        self.assertIsNotNone(brand_lookalike("paypal.com.verify-account.top"))
        self.assertIsNone(brand_lookalike("www.paypal.com"))
        self.assertIsNone(brand_lookalike("northwind-outfitters.com"))

    def test_cousin_domain(self):
        self.assertTrue(cousin_domain("acmec0rp.com", "acmecorp.com"))
        self.assertTrue(cousin_domain("acme-corp.com", "acmecorp.com"))
        self.assertFalse(cousin_domain("mail.acmecorp.com", "acmecorp.com"))
        self.assertFalse(cousin_domain("example.org", "acmecorp.com"))


class ParserTests(unittest.TestCase):
    def test_authentication_results(self):
        server, results = parse_authentication_results(
            "mx.google.com; dkim=pass header.i=@x.com header.s=s1 header.b=abc; "
            "spf=softfail (google.com: domain of a@b.com) smtp.mailfrom=a@b.com; "
            "dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=x.com")
        self.assertEqual(server, "mx.google.com")
        by_method = {r.method: r for r in results}
        self.assertEqual(by_method["spf"].result, "softfail")
        self.assertEqual(by_method["spf"].props["smtp.mailfrom"], "a@b.com")
        self.assertEqual(by_method["dmarc"].props["header.from"], "x.com")

    def test_topmost_auth_header_wins(self):
        raw = (b"Authentication-Results: real.mx; spf=fail smtp.mailfrom=a@evil.test; dmarc=fail\n"
               b"Authentication-Results: forged; spf=pass; dkim=pass; dmarc=pass\n"
               b"From: a@evil.test\n\nhi\n")
        p = parse_bytes(raw)
        self.assertEqual(p.authserv_id, "real.mx")
        self.assertEqual(p.auth_status("dmarc"), "fail")

    def test_originating_ip_skips_private(self):
        p = parse_bytes((SAMPLES / "02_credential_phish.eml").read_bytes())
        self.assertEqual(p.hops[0].ip, "127.0.0.1")
        self.assertEqual(p.originating_ip, "198.51.100.66")

    def test_headers_only_input(self):
        r = analyze(b"From: Microsoft Support <help@m1crosoft-support.net>\nSubject: hi\n")
        self.assertIn("Display name impersonates Microsoft", titles(r))


class UrlTests(unittest.TestCase):
    def reasons(self, url, text=""):
        return " | ".join(reason for _, reason in analyze_url(url, text))

    def test_ip_and_userinfo(self):
        self.assertIn("raw IP", self.reasons("http://203.0.113.5/login"))
        self.assertIn("raw IP", self.reasons("http://3405803781/login"))
        self.assertIn("Userinfo", self.reasons("https://paypal.com@evil.test/"))

    def test_anchor_mismatch(self):
        self.assertIn("Link text shows", self.reasons("https://evil.test/x", "https://www.paypal.com"))
        self.assertEqual(self.reasons("https://www.paypal.com/x", "paypal.com"), "")

    def test_defang(self):
        self.assertEqual(defang("https://evil.test/a.b"), "hxxps://evil[.]test/a.b")

    def test_vt_url_id(self):
        self.assertEqual(vt_url_id("http://example.com"), "aHR0cDovL2V4YW1wbGUuY29t")


class SampleTests(unittest.TestCase):
    def test_legitimate_newsletter(self):
        r = run("01_legit_newsletter.eml")
        self.assertEqual(r.verdict, "LIKELY LEGITIMATE")
        self.assertFalse([f for f in r.findings if f.severity in ("high", "medium")])

    def test_credential_phish(self):
        r = run("02_credential_phish.eml")
        self.assertEqual(r.verdict, "LIKELY PHISHING")
        t = titles(r)
        for expected in ("DMARC fail", "SPF softfail", "Display name impersonates PayPal",
                         "Sender domain imitates PayPal", "Suspicious link: 198.51.100.23",
                         "Suspicious link: bit.ly"):
            self.assertIn(expected, t)

    def test_bec_passes_auth_but_is_caught(self):
        r = run("03_bec_invoice.eml")
        self.assertEqual(r.email.auth_status("dmarc"), "pass")
        self.assertEqual(r.verdict, "LIKELY PHISHING")
        t = titles(r)
        self.assertIn("Replies redirected to a free webmail account", t)
        self.assertIn("Sender domain imitates the recipient's organization", t)
        self.assertTrue(any(x.startswith("Double file extension") for x in t))

    def test_mitre_tags_present(self):
        tags = {t for f in run("02_credential_phish.eml").findings for t in f.mitre}
        self.assertTrue({"T1566", "T1566.002", "T1656"} <= tags)

    def test_outputs_render(self):
        r = run("02_credential_phish.eml")
        self.assertEqual(json.loads(to_json([r]))["verdict"], "LIKELY PHISHING")
        page = to_html(r)
        self.assertIn("LIKELY PHISHING", page)
        self.assertNotIn("<script", page.lower())


if __name__ == "__main__":
    unittest.main()
