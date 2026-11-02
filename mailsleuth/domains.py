"""Domain helpers: organizational domains, lookalike and brand detection."""

import re

# Common multi-label public suffixes. A full Public Suffix List would be more
# accurate; this covers the cases that show up most often in mail.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "co.in", "com.mx", "co.za", "com.sg",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com",
    "zoho.com", "tutanota.com",
}

# Frequently impersonated brands and the domains they really send from.
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com",
                  "microsoftonline.com", "sharepoint.com"},
    "office365": {"microsoft.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazonses.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "coinbase": {"coinbase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "linkedin": {"linkedin.com"},
}

BRAND_LABELS = {"paypal": "PayPal", "office365": "Office 365", "docusign": "DocuSign",
                "fedex": "FedEx", "dhl": "DHL", "wellsfargo": "Wells Fargo",
                "linkedin": "LinkedIn"}


def brand_label(brand):
    return BRAND_LABELS.get(brand, brand.title())


# Characters attackers swap in to make a domain look like a brand.
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
              ("5", "s"), ("@", "a"), ("$", "s")]

# Non-Latin letters that render (almost) identically to Latin ones. Used after
# decoding punycode, so "xn--pypal-4ve" -> "pаypal" (Cyrillic a) -> "paypal".
# Written as escapes so the source stays readable ASCII.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ο": "o", "α": "a", "ρ": "p",
    "ν": "v", "ɡ": "g",
}


def org_domain(domain):
    """Return the organizational (registrable) domain, e.g. mail.paypal.com -> paypal.com."""
    if not domain:
        return ""
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(address):
    """Domain part of an email address, lowercased."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def aligned(domain_a, domain_b):
    """DMARC-style relaxed alignment: same organizational domain."""
    return bool(domain_a) and bool(domain_b) and org_domain(domain_a) == org_domain(domain_b)


def levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_homoglyphs(token):
    token = "".join(CONFUSABLES.get(ch, ch) for ch in token.lower())
    for fake, real in HOMOGLYPHS:
        token = token.replace(fake, real)
    return token


def decode_idn(domain):
    """Turn punycode labels back into Unicode: xn--pypal-4ve.com -> pаypal.com."""
    labels = []
    for label in (domain or "").lower().split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass  # malformed punycode: keep the raw label
        labels.append(label)
    return ".".join(labels)


def _tokens(domain):
    """Split a host into words, ignoring the TLD: secure-paypa1.co.uk -> [secure, paypa1]."""
    org = org_domain(domain)
    suffix_len = len(org.split(".")) - 1
    labels = decode_idn(domain).strip(".").split(".")[:-suffix_len or None]
    return [t for label in labels for t in re.split(r"[-_]", label) if t]


def brand_lookalike(domain):
    """Return (brand, reason) if the domain imitates a known brand it doesn't belong to."""
    if not domain:
        return None
    org = org_domain(domain)
    for brand, legit in BRANDS.items():
        if org in legit:
            return None
    for token in _tokens(domain):
        norm = normalize_homoglyphs(token)
        for brand in BRANDS:
            if token == brand:
                return brand, f"contains the brand name '{brand}' but is not a {brand_label(brand)} domain"
            if norm == brand and not token.isascii():
                return brand, (f"punycode label decodes to '{brand}' spelled with non-Latin "
                               "look-alike letters (IDN homograph attack)")
            if norm == brand:
                return brand, f"'{token}' is a homoglyph of '{brand}'"
            if len(brand) >= 5 and levenshtein(norm, brand) == 1:
                return brand, f"'{token}' is one character away from '{brand}'"
    return None


def cousin_domain(sender_domain, target_domain):
    """True when the sender's domain is a near-copy of the target's (acmec0rp.com vs acmecorp.com)."""
    a, b = org_domain(sender_domain), org_domain(target_domain)
    if not a or not b or a == b:
        return False
    sld_a, sld_b = a.split(".")[0], b.split(".")[0]
    if len(sld_b) < 4:
        return False
    return (normalize_homoglyphs(sld_a) == normalize_homoglyphs(sld_b)
            or levenshtein(sld_a, sld_b) <= 2)


def is_punycode(domain):
    return any(label.startswith("xn--") for label in (domain or "").lower().split("."))
