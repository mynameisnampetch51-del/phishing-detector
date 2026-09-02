"""Feature extraction for the PhiUSIIL-style phishing model.

The trained model (see ../../phishing-ml-classifier/main.ipynb) was fit on the
PhiUSIIL Phishing URL dataset (UCI id 967). That dataset's exact feature
extractor was never published, so a handful of "derived" features
(CharContinuationRate, TLDLegitimateProb, URLCharProb, DomainTitleMatchScore,
URLTitleMatchScore) are reasonable approximations of what their names
describe, not bit-for-bit reproductions. Everything else (counts of tags,
URL character counts, etc.) is extracted directly and should match closely.
"""
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

from bs4 import BeautifulSoup

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
PERCENT_ENCODING_RE = re.compile(r"%[0-9A-Fa-f]{2}")
URL_SAFE_EXTRA = set(":/.?=&-_~")

COMMON_LEGITIMATE_TLDS = {
    "com": 0.9, "org": 0.85, "net": 0.8, "edu": 0.95, "gov": 0.95,
    "io": 0.7, "co": 0.6, "uk": 0.8, "de": 0.8, "jp": 0.8, "fr": 0.8,
    "ca": 0.8, "au": 0.8, "info": 0.4, "biz": 0.3, "th": 0.75,
}
DEFAULT_TLD_PROB = 0.2

# Rough English letter-frequency table (a-z), used to approximate
# "how normal do these characters look" for URLCharProb.
CHAR_FREQ = {
    'a': .082, 'b': .015, 'c': .028, 'd': .043, 'e': .127, 'f': .022,
    'g': .020, 'h': .061, 'i': .070, 'j': .002, 'k': .008, 'l': .040,
    'm': .024, 'n': .067, 'o': .075, 'p': .019, 'q': .001, 'r': .060,
    's': .063, 't': .091, 'u': .028, 'v': .010, 'w': .024, 'x': .002,
    'y': .020, 'z': .001,
}
DEFAULT_CHAR_PROB = 0.03

SOCIAL_DOMAINS = (
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "youtube.com", "tiktok.com", "line.me", "wa.me", "whatsapp.com",
)
BANK_KEYWORDS = ("bank", "ธนาคาร")
PAY_KEYWORDS = ("pay", "payment", "ชำระเงิน")
CRYPTO_KEYWORDS = ("crypto", "bitcoin", "ethereum", "wallet", "blockchain")


def registered_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return parts[-2] if len(parts) >= 2 else hostname


def char_continuation_rate(url: str) -> float:
    if len(url) < 2:
        return 0.0

    def char_class(c):
        if c.isalpha():
            return "alpha"
        if c.isdigit():
            return "digit"
        return "other"

    continuations = sum(
        1 for a, b in zip(url, url[1:]) if char_class(a) == char_class(b)
    )
    return continuations / (len(url) - 1)


def tld_legitimate_prob(tld: str) -> float:
    return COMMON_LEGITIMATE_TLDS.get(tld.lower(), DEFAULT_TLD_PROB)


def url_char_prob(url: str) -> float:
    letters = [c.lower() for c in url if c.isalpha()]
    if not letters:
        return DEFAULT_CHAR_PROB
    return sum(CHAR_FREQ.get(c, DEFAULT_CHAR_PROB) for c in letters) / len(letters)


def fuzzy_match_score(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    tld = hostname.split(".")[-1] if "." in hostname else ""

    letters = sum(1 for c in url if c.isalpha())
    digits = sum(1 for c in url if c.isdigit())
    obfuscated_chars = len(PERCENT_ENCODING_RE.findall(url)) * 3
    equals = url.count("=")
    qmarks = url.count("?")
    ampersands = url.count("&")
    other_special = sum(
        1 for c in url
        if not c.isalnum() and c not in URL_SAFE_EXTRA
    )
    total_special = other_special + equals + qmarks + ampersands

    subdomain_parts = hostname.split(".")
    no_of_subdomain = max(len(subdomain_parts) - 2, 0)

    return {
        "URLLength": len(url),
        "DomainLength": len(hostname),
        "IsDomainIP": 1 if IP_RE.match(hostname) else 0,
        "CharContinuationRate": char_continuation_rate(url),
        "TLDLegitimateProb": tld_legitimate_prob(tld),
        "URLCharProb": url_char_prob(url),
        "TLDLength": len(tld),
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": 1 if obfuscated_chars else 0,
        "NoOfObfuscatedChar": obfuscated_chars,
        "ObfuscationRatio": obfuscated_chars / len(url) if url else 0.0,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / len(url) if url else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / len(url) if url else 0.0,
        "NoOfEqualsInURL": equals,
        "NoOfQMarkInURL": qmarks,
        "NoOfAmpersandInURL": ampersands,
        "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": total_special / len(url) if url else 0.0,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
    }, hostname, tld


def _same_domain(href: str, page_domain: str) -> bool:
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
        return True
    parsed = urlparse(href)
    if not parsed.netloc:
        return True
    return registered_domain(parsed.hostname or "") == page_domain


def extract_content_features(html: str, url: str, hostname: str, redirect_hosts: list) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    lines = html.split("\n")
    page_domain = registered_domain(hostname)

    title_tag = soup.find("title")
    title_text = title_tag.get_text(strip=True) if title_tag else ""
    domain_name = hostname.split(".")[0] if hostname else ""

    anchors = soup.find_all("a")
    self_refs = empty_refs = external_refs = 0
    for a in anchors:
        href = (a.get("href") or "").strip()
        if href in ("", "#", "javascript:void(0)"):
            empty_refs += 1
        elif _same_domain(href, page_domain):
            self_refs += 1
        else:
            external_refs += 1

    forms = soup.find_all("form")
    has_external_form_submit = any(
        not _same_domain((f.get("action") or ""), page_domain) and (f.get("action") or "").strip()
        for f in forms
    )

    body_text = soup.get_text(" ", strip=True).lower()
    self_redirects = sum(1 for h in redirect_hosts if registered_domain(h) == page_domain)

    return {
        "LineOfCode": len(lines),
        "LargestLineLength": max((len(line) for line in lines), default=0),
        "HasTitle": 1 if title_text else 0,
        "DomainTitleMatchScore": fuzzy_match_score(domain_name, title_text),
        "URLTitleMatchScore": fuzzy_match_score(url, title_text),
        "HasFavicon": 1 if soup.find("link", rel=re.compile("icon", re.I)) else 0,
        "Robots": 1 if soup.find("meta", attrs={"name": re.compile("robots", re.I)}) else 0,
        "IsResponsive": 1 if soup.find("meta", attrs={"name": "viewport"}) else 0,
        "NoOfURLRedirect": len(redirect_hosts),
        "NoOfSelfRedirect": self_redirects,
        "HasDescription": 1 if soup.find("meta", attrs={"name": re.compile("description", re.I)}) else 0,
        "NoOfPopup": html.count("window.open("),
        "NoOfiFrame": len(soup.find_all("iframe")),
        "HasExternalFormSubmit": 1 if has_external_form_submit else 0,
        "HasSocialNet": 1 if any(
            d in (a.get("href") or "") for a in anchors for d in SOCIAL_DOMAINS
        ) else 0,
        "HasSubmitButton": 1 if soup.find(["button"], attrs={"type": "submit"}) or soup.find(
            "input", attrs={"type": "submit"}
        ) else 0,
        "HasHiddenFields": 1 if soup.find("input", attrs={"type": "hidden"}) else 0,
        "HasPasswordField": 1 if soup.find("input", attrs={"type": "password"}) else 0,
        "Bank": 1 if any(k in body_text for k in BANK_KEYWORDS) else 0,
        "Pay": 1 if any(k in body_text for k in PAY_KEYWORDS) else 0,
        "Crypto": 1 if any(k in body_text for k in CRYPTO_KEYWORDS) else 0,
        "HasCopyrightInfo": 1 if "©" in html or "copyright" in body_text else 0,
        "NoOfImage": len(soup.find_all("img")),
        "NoOfCSS": len(soup.find_all("link", rel="stylesheet")) + len(soup.find_all("style")),
        "NoOfJS": len(soup.find_all("script")),
        "NoOfSelfRef": self_refs,
        "NoOfEmptyRef": empty_refs,
        "NoOfExternalRef": external_refs,
    }
