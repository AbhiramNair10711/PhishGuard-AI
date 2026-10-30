
"""Explainable domain and URL risk analysis for PhishGuard AI."""

import ipaddress
import re
from urllib.parse import urlparse, unquote

try:
    import tldextract

    extract_domain = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True
    )
except ImportError:
    extract_domain = None


# A suffix is context, not proof that a domain is malicious.
# Scores are deliberately small so that the extension cannot dominate.
TLD_RISK = {
    # Common general-purpose domains
    "com": 0,
    "org": 0,
    "net": 0,
    "info": 2,
    "biz": 2,
    "name": 1,
    "pro": 1,
    "app": 0,
    "dev": 0,
    "site": 3,
    "online": 3,
    "website": 3,
    "click": 5,
    "top": 5,
    "xyz": 4,
    "work": 3,
    "fit": 3,
    "country": 5,
    "gq": 5,
    "tk": 5,
    "zip": 4,
    "mov": 4,

    # Country-code domains
    "in": 0,
    "uk": 0,
    "us": 0,
    "ca": 0,
    "au": 0,
    "nz": 0,
    "de": 0,
    "fr": 0,
    "jp": 0,
    "cn": 1,
    "ru": 2,
    "br": 0,
    "io": 1,
    "ai": 0,
    "me": 1,
    "co": 1,

    # Common Indian second-level categories are handled by PSL parsing.
    # They are not automatically suspicious.
}

SUSPICIOUS_TERMS = {
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "account", "update", "confirm", "password", "banking",
    "wallet", "claim", "gift", "prize", "otp", "payment", "billing",
    "recover", "unlock", "suspend", "support", "reset", "validate"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "cutt.ly", "rb.gy", "buff.ly", "rebrand.ly", "lnkd.in",
    "shorturl.at", "soo.gd"
}

BRAND_NAMES = {
    "google", "microsoft", "apple", "amazon", "paypal", "facebook",
    "instagram", "whatsapp", "netflix", "instagram", "sbi", "hdfc",
    "icici", "axisbank", "paypal", "telegram"
}

# Recognized public suffixes are handled by tldextract's bundled PSL.
# This fallback covers common multi-part suffixes if tldextract is missing.
COMMON_MULTI_SUFFIXES = {
    "co.in", "com.in", "net.in", "org.in", "gov.in", "ac.in",
    "edu.in", "res.in", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.nz", "com.sg", "com.my",
    "co.jp", "com.br", "com.cn", "co.za"
}


def get_domain_details(host):
    """Extract TLD, public suffix, registered domain and subdomain."""

    host = (host or "").lower().strip().rstrip(".")

    if not host:
        return {
            "registrable_domain": "",
            "public_suffix": "",
            "tld": "",
            "subdomain": "",
            "suffix_known": False
        }

    try:
        ipaddress.ip_address(host)
        return {
            "registrable_domain": host,
            "public_suffix": "IP address",
            "tld": "IP address",
            "subdomain": "",
            "suffix_known": False
        }
    except ValueError:
        pass

    if extract_domain:
        result = extract_domain(host)
        suffix = result.suffix or ""

        return {
            "registrable_domain": result.top_domain_under_public_suffix or "",
            "public_suffix": suffix,
            "tld": suffix.rsplit(".", 1)[-1] if suffix else "",
            "subdomain": result.subdomain or "",
            "suffix_known": bool(suffix)
        }

    labels = host.split(".")
    suffix = ""

    for candidate in sorted(COMMON_MULTI_SUFFIXES, key=len, reverse=True):
        if host == candidate or host.endswith("." + candidate):
            suffix = candidate
            break

    if not suffix and len(labels) >= 2:
        suffix = labels[-1]

    suffix_labels = suffix.split(".") if suffix else []
    registered_count = len(suffix_labels) + 1

    registered = (
        ".".join(labels[-registered_count:])
        if len(labels) >= registered_count else ""
    )

    subdomain = (
        ".".join(labels[:-registered_count])
        if registered and len(labels) > registered_count else ""
    )

    return {
        "registrable_domain": registered,
        "public_suffix": suffix,
        "tld": suffix_labels[-1] if suffix_labels else "",
        "subdomain": subdomain,
        "suffix_known": bool(suffix)
    }


def analyze_url(raw_url):
    """Analyze a URL and return explainable risk indicators."""

    text = (raw_url or "").strip()
    candidate = text if "://" in text else "http://" + text
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")

    warnings = []
    signals = []
    score = 0
    domain = get_domain_details(host)

    def add(points, explanation, signal):
        nonlocal score
        score += points
        warnings.append(explanation)
        signals.append(signal)

    # 1. Check whether the hostname is valid.
    if not host:
        add(35, "The URL could not be parsed as a valid hostname.",
            "Invalid hostname")
    else:
        try:
            ipaddress.ip_address(host)
            add(35, "The URL uses an IP address instead of a domain name.",
                "IP address")
        except ValueError:
            labels = host.split(".")

            if len(labels) < 2:
                add(25, "The hostname does not contain a normal public suffix.",
                    "Incomplete hostname")

            if not domain["suffix_known"]:
                add(8, "The suffix was not identified by the available suffix data.",
                    "Unknown suffix")

            # 2. Check domain label structure.
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
                for label in labels
            ):
                add(15, "The hostname contains unusual or invalid formatting.",
                    "Invalid label formatting")

            if "xn--" in host:
                add(12, "The domain contains punycode/IDN labels; check for look-alike characters.",
                    "Internationalized domain")

            registered = domain["registrable_domain"]
            registered_label = (
                registered.split(".")[0] if registered else labels[0]
            )

            if len(registered_label) >= 25:
                add(8, "The registered domain name is unusually long.",
                    "Long domain label")

            if sum(ch.isdigit() for ch in registered_label) >= 4:
                add(8, "The registered domain contains many digits.",
                    "Digit-heavy domain")

            if domain["subdomain"]:
                sub_labels = domain["subdomain"].split(".")

                if len(sub_labels) >= 3:
                    add(10, "The URL contains several subdomain levels.",
                        "Deep subdomain structure")

                # A brand name in a subdomain is not the same as owning the brand.
                if any(
                    brand in sub_labels
                    for brand in BRAND_NAMES
                ):
                    add(8, "A known brand name appears in the subdomain, but the registered domain is different.",
                        "Brand-like subdomain")

            # 3. Evaluate the extension as a weak contextual signal.
            tld = domain["tld"]
            tld_points = TLD_RISK.get(tld, 1 if tld else 0)

            if tld:
                if tld_points > 0:
                    add(
                        tld_points,
                        f"The .{tld} suffix has a small caution weight in this heuristic. "
                        "The suffix alone does not indicate phishing.",
                        f"TLD context: .{tld} (+{tld_points})"
                    )
                else:
                    signals.append(
                        f"TLD context: .{tld} (neutral; no risk points)"
                    )

            # 4. Detect a brand-like registered domain.
            normalized_label = re.sub(r"[^a-z0-9]", "", registered_label)

            for brand in BRAND_NAMES:
                if normalized_label.startswith(brand) and normalized_label != brand:
                    add(
                        8,
                        f"The registered domain resembles or extends the name '{brand}'. "
                        "Check whether it is the genuine organization.",
                        "Brand-like registered domain"
                    )
                    break

            # 5. Hyphens and URL encoding.
            if "-" in registered:
                add(5, "The registered domain contains hyphens.",
                    "Hyphenated domain")

    # 6. URL transport and structure checks.
    if parsed.scheme.lower() != "https":
        add(12, "The URL does not use HTTPS. HTTPS alone would not guarantee safety.",
            "No HTTPS")

    if len(text) > 100:
        add(12, "The URL is unusually long.", "Long URL")

    if "@" in parsed.netloc:
        add(25, "The URL contains an @ symbol in its authority section.",
            "At-sign in URL")

    if host in SHORTENERS:
        add(18, "The URL uses a link shortener that hides the final destination.",
            "URL shortener")

    if re.search(r"%[0-9a-fA-F]{2}", text):
        add(5, "The URL contains percent-encoded characters.",
            "Percent encoding")

    searchable = unquote(host + parsed.path + parsed.query).lower()
    found_terms = sorted(
        term for term in SUSPICIOUS_TERMS if term in searchable
    )

    if found_terms:
        points = min(20, len(found_terms) * 4)
        add(
            points,
            "The URL contains sensitive or persuasive terms: "
            + ", ".join(found_terms[:6]) + ".",
            "Suspicious URL terms"
        )

    # Avoid repeatedly adding the same brand signal if a label has many matches.
    score = max(0, min(100, score))

    return {
        "url_suspicion": score,
        "urgency": 0,
        "sensitive_request": (
            25 if any(
                term in text.lower()
                for term in ["password", "otp", "verify", "login", "bank"]
            ) else 0
        ),
        "deception": min(100, score // 2),
        "warnings": warnings,
        "host": host or "unrecognised",
        "registrable_domain": domain["registrable_domain"] or "unidentified",
        "public_suffix": domain["public_suffix"] or "unidentified",
        "tld": domain["tld"] or "unidentified",
        "subdomain": domain["subdomain"] or "none",
        "suffix_known": domain["suffix_known"],
        "domain_signals": signals,
        "verdict_basis": (
            "The URL score combines domain structure, TLD context, "
            "HTTPS, suspicious terms, and other URL indicators. "
            "The fuzzy inference engine then combines URL suspicion "
            "with urgency, sensitive-data requests, and deception. "
            "The TLD alone never determines the final verdict."
        )
    }
