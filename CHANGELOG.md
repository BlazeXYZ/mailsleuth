# Changelog

## 1.1.0

### Added
- **Plain-English verdict summary** at the top of every report.
- **IOC export:** defanged URLs, domains, IPs, email addresses and attachment SHA-256 hashes. Shorteners, free webmail and legitimate brand domains are left out.
- **Score breakdown** by category, shown as a stacked bar in the HTML report.
- **Header forensics:** forged or backdated Date headers, out-of-order Received timestamps, missing Message-ID or Date, phishing-kit mailers (PHPMailer, King Phisher), and GoPhish simulation markers.
- **IDN homograph detection:** punycode labels are decoded and Cyrillic/Greek look-alike letters mapped to Latin, so `xn--pypal-4ve.com` is identified as "pаypal" with a Cyrillic а.
- Tests for RFC 2047-encoded display names, mocked reputation lookups (rate limiting, offline default) and source hygiene.
- **Microsoft 365 `compauth`** parsing, and a softer SPF severity when a valid ARC chain shows the mail was forwarded.
- **Local drag-and-drop web UI** (`mailsleuth serve`), with built-in samples and `/?sample=` deep links for demos.
- Garbage input is rejected instead of being scored as "legitimate".
- VirusTotal rate-limit handling (HTTP 429).
- GitHub Actions CI on Linux and Windows with Python 3.9, 3.11 and 3.13.

### Fixed
- A shell edit turned the regex `\b` into a literal backspace byte, which silently disabled urgency matching. It's now covered by a positive/negative test and a control-character hygiene test.
- Comments in `Authentication-Results` (such as Gmail's `arc=pass (i=1 spf=pass …)`) were being read as real results.
- Urgency keywords matched inside longer words ("urgent" inside "insurgent").
- Low-contrast text on MEDIUM severity badges.

### Changed
- Removed the T1070.006 (Timestomp) tag from Date-header anomalies. That technique covers file timestamps, and an approximate tag is worse than no tag.

## 1.0.0

- First release: SPF/DKIM/DMARC parsing, sender-identity checks, brand lookalike and cousin-domain detection, URL heuristics, attachment checks, optional VirusTotal/URLhaus lookups, MITRE ATT&CK tags, and terminal, JSON and HTML reports.
