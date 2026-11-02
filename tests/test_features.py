"""Tests for header anomalies, summaries, IOCs and the web UI."""

import hashlib
import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from mailsleuth import reputation
from mailsleuth.analyzer import analyze
from mailsleuth.domains import brand_lookalike, decode_idn
from mailsleuth.urls import ExtractedURL
from mailsleuth.parser import parse_authentication_results, parse_bytes
from mailsleuth.web import Handler

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

RECEIVED = (b"Received: from a.test (a.test [198.51.100.9]) by mx.example.org; "
            b"Mon, 02 Nov 2026 10:00:00 +0000\n")


def email(*headers, body=b"hello\n"):
    return b"".join(h if h.endswith(b"\n") else h + b"\n" for h in headers) + b"\n" + body


def titles(raw):
    return [f.title for f in analyze(raw).findings]


class RealWorldAuthTests(unittest.TestCase):
    def test_gmail_arc_comment_is_ignored(self):
        # Gmail nests other methods' results inside the arc= comment.
        _, results = parse_authentication_results(
            "mx.google.com; arc=pass (i=1 spf=pass spfdomain=x.com dkim=pass dkdomain=x.com "
            "dmarc=pass fromdomain=x.com); spf=fail (google.com: domain of a@evil.test) "
            "smtp.mailfrom=a@evil.test; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=x.com")
        self.assertEqual([(r.method, r.result) for r in results],
                         [("arc", "pass"), ("spf", "fail"), ("dmarc", "fail")])

    def test_microsoft_compauth(self):
        p = parse_bytes(email(
            b"Authentication-Results: spf=pass (sender IP is 203.0.113.4) smtp.mailfrom=x.test; "
            b"dkim=none (message not signed) header.d=none;dmarc=none action=none "
            b"header.from=x.test;compauth=fail reason=001",
            b"From: a@x.test", b"Subject: s"))
        self.assertEqual(p.auth_status("compauth"), "fail")
        self.assertIn("Microsoft composite authentication failed", titles(p.message.as_bytes()))

    def test_missing_auth_headers_are_not_penalized(self):
        r = analyze(email(b"From: Jo <jo@example.org>", b"Subject: lunch?",
                          b"Message-ID: <1@example.org>", b"Date: Mon, 02 Nov 2026 10:00:00 +0000"))
        self.assertEqual([f.title for f in r.findings], ["No authentication results recorded"])
        self.assertEqual(r.score, 0)

    def test_forwarded_mail_softens_spf_fail(self):
        r = analyze(email(b"Authentication-Results: mx; arc=pass; spf=fail; dkim=pass header.d=x.test; dmarc=pass",
                          b"From: a@x.test", b"Subject: s"))
        spf = next(f for f in r.findings if f.title == "SPF fail")
        self.assertEqual(spf.severity, "medium")


class EncodingTests(unittest.TestCase):
    def test_idn_homograph(self):
        self.assertEqual(decode_idn("xn--pypal-4ve.com"), "pаypal.com")  # Cyrillic a
        brand, reason = brand_lookalike("xn--pypal-4ve.com")
        self.assertEqual(brand, "paypal")
        self.assertIn("IDN homograph", reason)

    def test_rfc2047_encoded_display_name_is_decoded(self):
        # "=?utf-8?b?UGF5UGFsIFNlcnZpY2U=?=" is base64 for "PayPal Service".
        self.assertIn("Display name impersonates PayPal", titles(email(
            b"From: =?utf-8?b?UGF5UGFsIFNlcnZpY2U=?= <x@evil.test>", b"Subject: s")))


class HeaderAnomalyTests(unittest.TestCase):
    def test_future_date(self):
        raw = email(RECEIVED, b"From: a@x.test", b"Subject: s",
                    b"Date: Tue, 03 Nov 2026 10:00:00 +0000")
        self.assertIn("Date header is later than delivery", titles(raw))

    def test_backdated(self):
        raw = email(RECEIVED, b"From: a@x.test", b"Subject: s",
                    b"Date: Fri, 30 Oct 2026 10:00:00 +0000")
        self.assertIn("Date header is backdated", titles(raw))

    def test_gophish_and_phpmailer(self):
        self.assertIn("Sent with GoPhish", titles(email(
            b"From: a@x.test", b"Subject: s", b"X-Gophish-Contact: it@x.test")))
        self.assertIn("Sent with PHPMailer 6.9.1", titles(email(
            b"From: a@x.test", b"Subject: s", b"X-Mailer: PHPMailer 6.9.1")))

    def test_missing_message_id(self):
        self.assertIn("Missing Message-ID", titles(email(b"From: a@x.test", b"Subject: s")))

    def test_not_an_email(self):
        with self.assertRaises(ValueError):
            analyze(b"just some text")

    def test_urgency_matches_whole_words_only(self):
        self.assertIn("Urgency / pressure language",
                      titles(email(b"From: a@x.test", b"Subject: urgent: reply")))
        self.assertNotIn("Urgency / pressure language",
                         titles(email(b"From: a@x.test", b"Subject: insurgent history notes")))


class SourceHygieneTests(unittest.TestCase):
    def test_no_control_characters_in_source(self):
        # Regression guard: a shell heredoc once turned the regex "\b" into a literal
        # backspace byte, which silently disabled keyword matching.
        root = Path(__file__).resolve().parent.parent
        for path in list((root / "mailsleuth").glob("*.py")) + list((root / "tests").glob("*.py")):
            data = path.read_bytes()
            bad = [b for b in data if b < 32 and b not in (9, 10, 13)]
            self.assertFalse(bad, f"control character in {path.name}")


class ReportContentTests(unittest.TestCase):
    def setUp(self):
        self.phish = analyze((SAMPLES / "02_credential_phish.eml").read_bytes())
        self.bec = analyze((SAMPLES / "03_bec_invoice.eml").read_bytes())
        self.legit = analyze((SAMPLES / "01_legit_newsletter.eml").read_bytes())

    def test_summary(self):
        self.assertIn("claims to be from PayPal", self.phish.summary)
        self.assertIn("3 links are deceptive", self.phish.summary)
        self.assertIn("passes SPF, DKIM and DMARC", self.bec.summary)
        self.assertTrue(self.legit.summary.startswith("No significant"))

    def test_iocs(self):
        self.assertEqual(self.legit.iocs, {})
        self.assertIn("paypa1-security.com", self.phish.iocs["domains"])
        self.assertNotIn("bit.ly", self.phish.iocs["domains"])       # shorteners aren't blockable
        self.assertNotIn("gmail.com", self.bec.iocs.get("domains", []))  # neither is freemail
        self.assertIn("dana.whitfield.ceo@gmail.com", self.bec.iocs["emails"])

    def test_attachment_hash(self):
        att = self.bec.attachments[0]
        expected = hashlib.sha256(b"<html><body><h1>Invoice</h1></body></html>").hexdigest()
        self.assertEqual(att["sha256"], expected)
        self.assertEqual(self.bec.iocs["sha256"], [expected])

    def test_breakdown_sums_to_raw_score(self):
        self.assertEqual(sum(self.bec.breakdown.values()), self.bec.score)


class ReputationTests(unittest.TestCase):
    """Network lookups are mocked: tests must never call real APIs."""

    def test_rate_limit_stops_further_calls(self):
        urls = [ExtractedURL(f"https://evil{i}.test/") for i in range(6)]
        responses = [("malicious", "9 malicious / 0 suspicious of 90 engines")] * 4 + \
                    [("error", "HTTP 429")]
        with mock.patch.dict(os.environ, {"VT_API_KEY": "test-key"}, clear=False), \
                mock.patch.dict(os.environ, {"URLHAUS_AUTH_KEY": ""}), \
                mock.patch.object(reputation, "check_virustotal", side_effect=responses) as vt:
            reputation.enrich(urls)
        self.assertEqual(vt.call_count, 5)                    # 6th URL never sent
        self.assertEqual(urls[0].reputation[0][1], "malicious")
        self.assertEqual(urls[4].reputation[0][1], "skipped")
        self.assertEqual(urls[5].reputation[0][1], "skipped")

    def test_offline_by_default(self):
        with mock.patch.object(reputation, "enrich") as enrich:
            analyze((SAMPLES / "02_credential_phish.eml").read_bytes())
        enrich.assert_not_called()


class WebUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, path, data=b""):
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def test_index(self):
        with urllib.request.urlopen(self.base + "/") as resp:
            self.assertIn(b"Drop an email here", resp.read())

    def test_analyze_upload(self):
        status, data = self.post("/analyze?name=x.eml", (SAMPLES / "03_bec_invoice.eml").read_bytes())
        self.assertEqual((status, data["verdict"]), (200, "LIKELY PHISHING"))
        self.assertIn("<!doctype html>", data["html"])

    def test_sample_whitelist_blocks_traversal(self):
        self.assertEqual(self.post("/sample/..%2F..%2Fmailsleuth%2Fweb.py")[0], 404)
        self.assertEqual(self.post("/sample/01_legit_newsletter.eml")[0], 200)

    def test_bad_input(self):
        self.assertEqual(self.post("/analyze", b"not an email")[0], 422)


if __name__ == "__main__":
    unittest.main()
