# MailSleuth Design Document

This document records **why** MailSleuth is built the way it is. Each decision follows the same format:

- **Context:** the problem or constraint
- **Decision:** what was chosen
- **Alternatives considered:** what else was reasonable, and why it lost
- **Trade-offs:** what this decision costs
- **Revisit when:** the conditions that would change the answer

The [README](../README.md) has the short version in one table.

---

## Contents

- [Goals and non-goals](#goals-and-non-goals)
- [Data model](#data-model)
- [Processing pipeline](#processing-pipeline)
- Decisions
  - [D1. Standard library only](#d1-standard-library-only)
  - [D2. Read the receiver's verdicts instead of re-verifying](#d2-read-the-receivers-verdicts-instead-of-re-verifying)
  - [D3. Trust only the topmost Authentication-Results header](#d3-trust-only-the-topmost-authentication-results-header)
  - [D4. Transparent weighted rules instead of machine learning](#d4-transparent-weighted-rules-instead-of-machine-learning)
  - [D5. Strip RFC 5322 comments before parsing](#d5-strip-rfc-5322-comments-before-parsing)
  - [D6. Context-aware severities to control false positives](#d6-context-aware-severities-to-control-false-positives)
  - [D7. Relaxed alignment through organizational domains](#d7-relaxed-alignment-through-organizational-domains)
  - [D8. Lookalike detection: normalization first, edit distance second](#d8-lookalike-detection-normalization-first-edit-distance-second)
  - [D9. Offline by default; reputation is opt-in](#d9-offline-by-default-reputation-is-opt-in)
  - [D10. Stop on rate limits instead of sleeping](#d10-stop-on-rate-limits-instead-of-sleeping)
  - [D11. Defang for humans, raw for machines](#d11-defang-for-humans-raw-for-machines)
  - [D12. Curated IOC export](#d12-curated-ioc-export)
  - [D13. Accurate MITRE tags only](#d13-accurate-mitre-tags-only)
  - [D14. A plain-English summary generated from findings](#d14-a-plain-english-summary-generated-from-findings)
  - [D15. Static, script-free HTML reports](#d15-static-script-free-html-reports)
  - [D16. Web UI on http.server, bound to localhost](#d16-web-ui-on-httpserver-bound-to-localhost)
  - [D17. A custom private-IP list](#d17-a-custom-private-ip-list)
  - [D18. Reject non-email input](#d18-reject-non-email-input)
  - [D19. Synthetic samples on documentation IP ranges](#d19-synthetic-samples-on-documentation-ip-ranges)
  - [D20. unittest, mocked network, CI matrix](#d20-unittest-mocked-network-ci-matrix)
- [Lessons learned](#lessons-learned)

---

## Goals and non-goals

**Goals**
1. Turn a raw email into a defensible triage verdict in under a second.
2. Explain every conclusion: no score without a named finding behind it.
3. Keep false positives on legitimate bulk mail low.
4. Be safe to run on hostile input and safe to hand to non-specialists.
5. Run anywhere Python 3.11+ runs, with nothing to install.

**Non-goals**
- Replacing a secure email gateway. This is a *post-delivery* analyst tool, not an inline filter.
- Detonating attachments or following links. That belongs in a sandbox, not on an analyst's laptop.
- Cryptographic DKIM verification (see D2).

## Data model

```
ParsedEmail                     ExtractedURL                Finding
├─ message (EmailMessage)       ├─ url                      ├─ severity  high|medium|low|info
├─ subject, date, date_dt       ├─ anchor_text              ├─ category  Authentication|Sender|Header|URL|...
├─ from_name, from_addr         ├─ source  text|html-link   ├─ title     short, stable string
├─ return_path, reply_to        │          |html-form       ├─ detail    evidence for the analyst
├─ sender, to[]                 ├─ flags[(sev, reason)]     ├─ mitre[]   ATT&CK IDs
├─ auth_results[AuthResult]     └─ reputation[(provider,    └─ why       clause for the summary
├─ authserv_id, received_spf                verdict, detail)]
├─ dkim_signatures[{d, s}]
├─ hops[Hop]  (oldest first)    Report
├─ originating_ip, mailer       ├─ findings[], urls[], attachments[]
└─ auth_status(method)          ├─ score, verdict, summary
                                └─ breakdown{category: points}, iocs{type: [values]}
```

`Finding.title` is kept stable and short on purpose. Tests and downstream automation match on it. `detail` holds the evidence that changes from email to email.

## Processing pipeline

```
raw bytes
  │  parse_bytes()             email.parser with policy.default (decodes RFC 2047 words,
  ▼                            gives EmailMessage.get_content())
ParsedEmail
  │  guard: From / Subject / Received present?   ── no → ValueError (D18)
  ▼
check_authentication()   check_sender_identity()   check_headers()
check_content()          check_attachments()       extract_urls() → [enrich()] → check_urls()
  │  each appends Finding objects to one list
  ▼
sort by severity → score_findings() → summarize() → score_breakdown() → extract_iocs()
  ▼
Report  →  to_terminal() | to_json() | to_html()  (CLI or web.py)
```

The checks are independent functions that share one `findings` list. That gives three properties:
- **Extensible:** a new detection is one function plus one call. Scoring, rendering and the summary pick it up automatically.
- **Testable:** each check can be exercised with a three-line synthetic email.
- **Explainable:** the score is a pure function of the findings, so the score can never "know" something the report doesn't show.

---

## D1. Standard library only

**Context.** Analysts often work on locked-down workstations or isolated incident-response laptops where `pip install` is blocked or needs approval. The tool also handles hostile input, and every dependency adds attack and supply-chain surface. Typosquatted and compromised PyPI packages are a real, recurring problem.

**Decision.** Use only the Python standard library: `email`, `html.parser`, `urllib`, `http.server`, `hashlib`, `ipaddress`, `unittest`.

**Alternatives considered.**
| Option | Would give | Why not |
|---|---|---|
| `dkimpy` | Real DKIM verification | Not useful after the fact (D2) |
| `tldextract` | Accurate organizational domains via the Public Suffix List | Needs a download or a bundled snapshot; the built-in table covers the common cases (trade-off below) |
| `beautifulsoup4` | Tolerant HTML parsing | `html.parser` handles anchors and forms well, which is all that's needed |
| `Flask` / `FastAPI` | A nicer web framework | The UI has 4 routes, and a framework is more weight than that justifies |
| `pytest` | Nicer test output | `unittest` is enough and keeps "clone and run" literally true |

**Trade-offs.** Organizational-domain logic is approximate. I wrote my own Levenshtein (about 10 lines) instead of using `python-Levenshtein`'s C implementation, which is fine for strings shorter than 64 characters.

**Revisit when.** The tool moves to a server deployment where dependencies are managed. Then `tldextract` (PSL) would be the first addition.

## D2. Read the receiver's verdicts instead of re-verifying

**Context.** SPF, DKIM and DMARC are checked by the receiving mail server at delivery, and it records the outcome in `Authentication-Results` (RFC 8601).

**Decision.** Report the receiver's recorded verdicts. Don't redo the checks.

**Alternatives considered.** Re-run SPF (DNS TXT lookup of the envelope domain plus the connecting IP) and DKIM (fetch `selector._domainkey.domain`, recompute body and header hashes).

**Why not.**
- **SPF depends on time and on the network path.** The check needs the IP that connected *at delivery*, and the SPF record *as it was then*. Days later the record may have changed. Re-checking answers a different question.
- **DKIM keys rotate.** Selectors are often retired. Attackers using throwaway domains delete their DNS entirely after a campaign, so re-verification would produce false "fail" results.
- **Network access** would break the offline guarantee (D9) and tell the attacker's DNS server that someone is investigating.

**Trade-offs.** We trust the receiver to have done the job correctly, and we depend on the header being authentic (D3).

**Revisit when.** The tool is integrated *inline* at delivery time, as a milter or gateway plugin. Then verifying directly is correct.

## D3. Trust only the topmost Authentication-Results header

**Context.** Anyone can write `Authentication-Results: dmarc=pass` into an email before sending it. Each server prepends headers as mail passes through, so the receiver's own header ends up *above* anything the sender wrote.

**Decision.** Parse only the first (topmost) `Authentication-Results` header. A test sends a forged `dmarc=pass` header below a real `dmarc=fail` and checks that `fail` wins.

**Alternatives considered.**
- *Merge all headers:* an attacker-supplied `pass` could outvote the real `fail`.
- *Match a configured `authserv-id`:* RFC 8601 says receivers should strip incoming headers that claim *their* authserv-id. A tool configured with "my server is `mx.mycompany.com`" could trust exactly the matching header. This is the **robust** approach.

**Why topmost for now.** It needs no configuration and works for any mailbox out of the box, which matters for a portfolio demo and for personal use.

**Trade-offs.** Some gateway setups (for example a cloud filter in front of Exchange) add several headers, and the topmost may come from an inner hop. The parser records `authserv_id` so an analyst can see which server it came from.

**Revisit when.** The tool is used inside one organization. Add a `--trusted-authserv` option.

## D4. Transparent weighted rules instead of machine learning

**Context.** The output has to be a verdict an analyst can **defend in a ticket** and a junior analyst can **learn from**.

**Decision.** Use additive severity weights (High 25, Medium 10, Low 4, Info 0), capped at 100, with fixed thresholds (≥60 phishing, ≥25 suspicious).

**Why these numbers.**
- One High alone gives 25, which is **suspicious**. A single strong signal deserves a human look, not an alarm.
- Three Highs give 75, which is **phishing**. Independent strong signals together are convincing.
- Lows are worth 4, so seven are needed to reach *suspicious*. Lows are often legitimate quirks and shouldn't stack up to an alarm easily.
- A gap of roughly 2.5× between levels keeps one severity from being cancelled out by a few of the level below.

**Alternatives considered.**
| Option | Strength | Why not (yet) |
|---|---|---|
| Logistic regression / gradient boosting on header features | Learns real-world weights | Needs a large *labeled* corpus I don't have, and labels drift as attackers adapt |
| LLM classification | Reads intent in the body text | Not deterministic, hard to audit, sends email content to a third party, and can be prompt-injected *by the phishing email itself* |
| Bayesian combination | Statistically grounded | Assumes the signals are independent, which they aren't (DMARC fail and SPF fail are correlated) |

**Trade-offs.** The weights are expert judgment, not fitted to data. Correlated findings can double-count. SPF fail and DMARC fail both add points, which slightly over-scores spoofing. The 100 cap keeps this bounded.

**Revisit when.** Analyst feedback is collected (the roadmap item). Then the rules become *features*, and a model learns weights over them. This hybrid of rules as features and ML as calibration is how mature detection platforms work.

## D5. Strip RFC 5322 comments before parsing

**Context.** Header values can contain parenthesized comments. Gmail's real format:
```
arc=pass (i=1 spf=pass spfdomain=x.com dkim=pass dkdomain=x.com dmarc=pass fromdomain=x.com);
spf=fail (google.com: domain of a@evil.test does not designate …) smtp.mailfrom=a@evil.test
```

**Decision.** Remove comments, handling nested parentheses, *before* applying the method regex. A lookbehind `(?<![.\w])` also stops `header.dkim=`-style properties from matching as methods.

**Alternative.** A regex over the raw value. It would see `spf=pass` *inside the ARC comment* and, depending on ordering, report SPF as **pass** when the real verdict is **fail**. That is a security-relevant parsing bug, and a test pins the correct behavior.

**Trade-offs.** Comments sometimes carry useful text, such as Microsoft's "sender IP is …". It's lost from the parsed result but kept in the raw header.

## D6. Context-aware severities to control false positives

**Context.** False positives are not harmless. A tool that flags every newsletter teaches analysts to ignore it, and **alert fatigue is how real phish gets through**.

**Decisions.**
| Signal | Naive severity | MailSleuth | Reason |
|---|---|---|---|
| Return-Path ≠ From | Medium | **Low if DMARC passes** | ESPs such as SendGrid and Mailchimp use their own bounce domains for legitimate bulk mail |
| Message-ID domain ≠ From | Low | **Silent if DMARC passes** | Same cause |
| SPF fail | High | **Medium if ARC passes** | Forwarding and mailing lists break SPF, and ARC (RFC 8617) exists to vouch for the original result |
| No auth headers | Several penalties | **One Info note** | The email was probably exported from the sender's side, so absence of evidence isn't evidence |
| Urgency words | Per word | **Whole words, Medium only at ≥3** | "Urgent" alone is common in real business mail |

**Trade-offs.** Each softening is a lever an attacker could try to pull. **ARC is the important one:** an attacker can run their own ARC sealer, and `arc=pass` only means the chain is cryptographically valid, not that the sealer is trustworthy. Mitigation: only SPF is softened, and DMARC failure stays High. Production systems keep a **trusted-sealer list**, which is on the roadmap.

## D7. Relaxed alignment through organizational domains

**Context.** DMARC (RFC 7489) defines *alignment*: the authenticated domain must match the From domain. *Relaxed* alignment, the default, compares **organizational domains**, so `mail.paypal.com` aligns with `paypal.com`.

**Decision.** Compare organizational domains everywhere (Return-Path, Reply-To, DKIM `d=`, Message-ID, links). Compute them as the last two labels, or three for a built-in list of multi-label suffixes (`co.uk`, `com.au`…).

**Alternative.** The full Public Suffix List, which is what DMARC implementations actually use.

**Trade-offs.** With no PSL, private suffixes such as `github.io` and `herokuapp.com` are treated as one organization. So `attacker.github.io` "aligns" with `victim.github.io`. That is acceptable for header triage, documented, and the first PSL improvement on the roadmap.

## D8. Lookalike detection: normalization first, edit distance second

**Context.** Attackers register domains that *look* like a brand: `paypa1.com`, `rnicrosoft.com`, `paypal-secure.com`, or IDN homographs such as `xn--pypal-4ve.com`, which renders as "pаypal" with a **Cyrillic а**.

**Decision.** A layered check, cheapest and most specific first:
1. **Decode punycode** to Unicode (`xn--pypal-4ve` → `pаypal`).
2. **Normalize confusables:** map Cyrillic and Greek look-alike letters to Latin (`а→a`, `ο→o`, `р→p`…) and ASCII tricks (`0→o`, `1→l`, `rn→m`, `vv→w`).
3. **Token match:** split the host on `.`, `-` and `_`, then check whether a token *equals* a brand (`paypal-security.com` → token `paypal`).
4. **Edit distance 1**, only for brands of **5 or more letters**.

The **cousin-domain** check (sender vs. *recipient's* domain) uses normalization plus edit distance ≤2, on second-level domains of at least 4 characters.

**Why this order and these limits.**
- Normalization catches the *intentional* tricks exactly, with no fuzziness and so no false positives.
- Edit distance catches typos (`paypl`), but on short strings it matches nearly anything. `dhl` is one edit away from `dhs`, `dal` and `ddl`. Hence the 5-letter floor.
- Tokens beat substrings. A plain substring search finds `apple` in `pineapple.com`, and splitting into tokens avoids that.

**Alternatives considered.** dnstwist-style permutation generation (generate every variant of a brand, then compare). It's thorough, but it needs a brand list *and* a variant explosion per brand, and it doesn't help with cousin domains of arbitrary recipients. The Unicode TR39 full confusables table would be more complete than a 17-entry map but is much larger, and the map covers the letters actually used in Latin-script brand attacks.

**Trade-offs.** The brand list is small (14 entries). A real deployment would load the organization's own brands and partner domains.

## D9. Offline by default; reputation is opt-in

**Context.** Reputation services (VirusTotal, URLhaus) are valuable, but a query *discloses* the URL. URLs in internal phishing can contain tokens, internal hostnames or victim identifiers. Some organizations forbid sending them to third parties. VirusTotal's public API is limited to a few requests per minute.

**Decision.** Run no network calls unless `--online` is given *and* an API key is present. Even then, send only URLs (never bodies or addresses), cap them with `--max-urls` (default 10), and use 10-second timeouts.

**Why heuristics first.** Reputation feeds lag behind. A domain registered this morning for today's campaign has no reputation yet, while heuristics (lookalike, IP host, mismatched anchor) catch it on first sight. The two are complementary.

**Implementation notes.** VirusTotal v3 identifies a URL by its **unpadded URL-safe base64**, which avoids a submission round-trip and is unit-tested. A 404 from VirusTotal means "never scanned", which counts as *unknown*, not *clean*.

## D10. Stop on rate limits instead of sleeping

**Context.** Free VirusTotal keys allow 4 requests per minute. An email with 10 links hits HTTP 429 on the 5th.

**Decision.** On the first 429, mark that provider exhausted for the rest of the run, record "skipped" for the remaining URLs, and carry on with the analysis.

**Alternatives considered.** `sleep(60)` and retry, which turns a sub-second tool into a multi-minute one with no explanation. Exponential backoff is right for a service but wrong for an interactive CLI.

**Trade-offs.** Some URLs go unchecked. The report says so explicitly, which is better than a silent hang or a silent "clean". A mocked test confirms the 6th URL is never sent.

## D11. Defang for humans, raw for machines

**Context.** Analysts paste indicators into tickets, chat and email, where clients turn URLs into live links. A misclick on a live phishing link is a real incident.

**Decision.** The terminal and HTML outputs show defanged indicators: `hxxps://evil[.]com/path`, `user[@]evil[.]com`, `198[.]51[.]100[.]23`. JSON carries **raw** values (plus a `defanged` copy for URLs).

**Why.** People read the terminal and HTML. Programs read JSON, and a blocklist API needs the real value. Making automation "un-defang" values would be fragile.

## D12. Curated IOC export

**Context.** IOCs feed blocklists. A bad entry causes an outage: block `bit.ly` or `gmail.com` and the business stops.

**Decision.** IOCs are produced only when the verdict isn't LIKELY LEGITIMATE, and the list **excludes** URL shorteners, free-webmail domains and legitimate brand domains. Individual *addresses* on free webmail (`dana.whitfield.ceo@gmail.com`) are kept, since blocking one address is safe. Only *flagged* URLs are included.

**Trade-off.** Shortened phishing URLs still appear in the URL list (they're specific), but their domain doesn't.

## D13. Accurate MITRE tags only

**Context.** ATT&CK tags feed metrics and threat reports. A wrong tag isn't harmless decoration, because it misinforms whoever aggregates them.

**Decision.** Tag a finding only when a technique clearly describes it. Forged Date headers originally carried **T1070.006 (Timestomp)**. That technique is about modifying *file* timestamps on a host, so the tag was **removed**, and header-forensics findings are now untagged.

**Mapping rationale.**
- T1566 (Phishing) is the parent for authentication and sender-mismatch findings. The sub-techniques are used when the *delivery mechanism* is known (.001 attachment, .002 link).
- T1656 (Impersonation) covers pretending to be a trusted party: brand display names, lookalikes.
- T1583.001 / T1585.002 are *Resource Development*. They describe the attacker's preparation (registering domains, creating webmail accounts), which the lookalike domain and the freemail Reply-To are evidence of.
- T1036.007 (Double File Extension) is an exact match.

## D14. A plain-English summary generated from findings

**Context.** The person who reported the email, or a manager, needs one sentence, not 13 rows.

**Decision.** High-severity findings carry an optional `why` clause, such as *"it claims to be from PayPal but was sent from paypa1-security.com"*. The summary takes the top three, folds all link findings into one ("3 links are deceptive"), and adds context sentences. One example is *"It passes SPF, DKIM and DMARC, which means the attacker controls the sending domain…"* when authentication passed on a phishing verdict.

**Alternative.** An LLM-written summary. It would read nicely, but it isn't deterministic, could invent findings, and would send email content to a third party. A summary built from templates can only say what the findings support.

## D15. Static, script-free HTML reports

**Context.** Reports get attached to tickets and opened in browsers. Every value in them is **attacker-controlled**: subject, display name, URLs, filenames.

**Decision.** One self-contained HTML file with inline CSS, **no JavaScript** and no external requests. Every value goes through `html.escape`. The IOC list is a `readonly <textarea>` (select-all and copy) rather than a JS copy button.

**Why.** A display name of `<img src=x onerror=…>` would be **stored XSS against the analyst** if it weren't escaped. With no scripts at all, the report has no execution surface even if an escape were ever missed. A test asserts that `<script` never appears. No external fonts or CDNs means opening a report never leaks a request to a third party.

## D16. Web UI on http.server, bound to localhost

**Context.** A drag-and-drop UI makes the tool usable by people who don't use a CLI, and makes for a good live demo.

**Decision.** Use `http.server.ThreadingHTTPServer` with four routes, **bound to 127.0.0.1**, a 10 MB request cap, a whitelist for sample names, and no logging of content. Reports render in `<iframe sandbox="allow-same-origin allow-popups …">`, which deliberately leaves out `allow-scripts`.

**Why these details.**
- Python's documentation warns that `http.server` isn't for production. Binding to localhost keeps it a personal tool and never a network service.
- **Sandbox subtlety:** `allow-same-origin` together with `allow-scripts` would let framed content remove its own sandbox. With scripts off, same-origin is safe, and it lets the frame render reliably in every browser.
- Samples are served by **name from a whitelist** (the names that exist in `samples/`), never by joining a user path, which rules out `../../` traversal. A test checks this.
- Malformed input returns **HTTP 422 with a message**, never a stack trace, and never kills the server.

**Alternative.** Flask (D1), or a fully client-side JavaScript port. The JS port would mean maintaining two detection engines. One engine, two front ends, is the right shape.

## D17. A custom private-IP list

**Context.** The originating IP is the first *public* IP in the Received chain. Python's `ipaddress.is_private` returns **True for the RFC 5737 documentation ranges** (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so the samples' "public" IPs would be skipped.

**Decision.** Use an explicit list: RFC 1918, loopback, link-local, CGNAT (100.64/10), IPv6 ULA and link-local.

**Trade-off and known weakness.** "Oldest public hop" can be fooled. A sender can add fake `Received` lines *below* the first trusted server. The robust rule is to take the IP recorded by **your own MX** (the first hop whose `by` is your infrastructure). That needs configuration, so it's on the roadmap next to D3's `authserv-id`.

## D18. Reject non-email input

**Context.** An early version scored the text `x` as "LIKELY LEGITIMATE (18)". A confident verdict on garbage is worse than an error.

**Decision.** If there's no From, no Subject and no Received header, raise `ValueError`. The CLI skips that input with a message, and the web UI returns 422.

## D19. Synthetic samples on documentation IP ranges

**Context.** A demo needs realistic phishing. Real phishing samples contain real victims' data and live malicious URLs.

**Decision.** Hand-built samples with **RFC 5737** IPs (which can never route on the internet), fictional companies (`northwind-outfitters.com`, `acmecorp.com`) and deliberately broken lookalikes (`paypa1-security.com`). Each sample tells one story: no false positives, classic spoofing, and authenticated BEC.

## D20. unittest, mocked network, CI matrix

**Decision.**
- **`unittest`**, to keep D1.
- **Synthetic, minimal emails built inside tests** (`email(b"From: …", b"Subject: …")`), so each test names exactly the headers it depends on.
- **Mocked HTTP** for reputation. Tests must be deterministic, free and offline, and must never send sample URLs to real services.
- **A real server on port 0** (an ephemeral port) for web tests, so they test the actual HTTP behavior and never clash with a running instance.
- **CI on Ubuntu + Windows × Python 3.11/3.13/3.14, with `fail-fast: false`.** The minimum is 3.11, the oldest version still getting security fixes. The first CI run failed because Python 3.9 doesn't exist on GitHub's Ubuntu 26.04 runner image, and fail-fast cancelled the other jobs, which hid the fact that the code itself was fine. Every combination now reports independently. Email parsing and path handling differ across platforms and versions (Windows path separators showed up in report output during development).
- **A source-hygiene test** that fails on control characters in `.py` files. See below.

---

## Lessons learned

**1. A shell heredoc silently disabled a detector.** While editing through a shell, the regex `r"\b" + word + r"\b"` was written to disk with `\b` turned into a literal **backspace byte (0x08)**. The code still ran, and the tests still passed, but the urgency check matched *nothing*. It was caught because a sample's score dropped from 79 to 75, which I noticed because I checked outputs against the documented numbers. **Fixes:** the line was corrected, a test now checks both *positive and negative* matching, and a hygiene test fails on any control character in the source. **Takeaway:** test that a detector *fires*, not only that it doesn't crash, and treat unexplained number changes as bugs.

**2. Parsing standards are adversarial.** Gmail's nested comments (D5) and injected auth headers (D3) show that "parse the header" is a security decision, not a formatting detail.

**3. A punycode sample was more real than I'd planned.** The sample domain `xn--pypal-4ve.com` was flagged at first only as "one character away from paypal". Decoding it showed that it renders as **pаypal with a Cyrillic а**, a true IDN homograph. That led to IDN decoding and the confusables map (D8).

**4. Precision matters as much as recall.** Several of the decisions (D6, D12, D13, D18) are about *not* saying things. In a SOC, a tool's credibility comes from its false-positive rate.
