import re
import ipaddress
from urllib.parse import urlsplit


URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}
SUSPICIOUS_KEYWORDS = {
    "account",
    "banking",
    "billing",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
    "webscr",
}


def normalize_url_for_model(url):
    """Align submitted URLs with the scheme-less URLs used by the dataset."""
    value = str(url).strip()
    return re.sub(r"^https?://", "", value, count=1, flags=re.IGNORECASE)


def restore_unweighted_prior(probability, negative_count, positive_count):
    """Undo the prior shift introduced by balanced class weights."""
    probability = min(max(float(probability), 1e-12), 1 - 1e-12)
    sample_count = negative_count + positive_count
    negative_weight = sample_count / (2 * negative_count)
    positive_weight = sample_count / (2 * positive_count)
    denominator = probability * negative_weight + (1 - probability) * positive_weight
    return probability * negative_weight / denominator


def analyze_url(url, phishing_probability):
    """Combine the model score with explainable URL-structure indicators."""
    candidate = url if re.match(r"^https?://", url, flags=re.IGNORECASE) else f"https://{url}"
    parsed = urlsplit(candidate)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path.lower()
    parts = hostname.split(".") if hostname else []
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    subdomain_count = max(0, len(parts) - 2) if not is_ip else 0
    searchable_url = f"{hostname}/{path}?{parsed.query}".lower()
    keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(rf"(?<![a-z]){keyword}(?![a-z])", searchable_url)
    )
    unusual = []
    if hostname.startswith("xn--") or ".xn--" in hostname:
        unusual.append("punycode hostname")
    if "\\" in url or any(ord(character) > 127 for character in url):
        unusual.append("non-standard URL characters")
    if re.search(r"%2f|%5c", path, flags=re.IGNORECASE):
        unusual.append("encoded path separators")

    reasons = []
    risk_score = float(phishing_probability) * 100
    if is_ip:
        reasons.append("The hostname is an IP address rather than a domain name.")
        risk_score = max(risk_score, 78)
    if hostname in URL_SHORTENERS:
        reasons.append("The hostname belongs to a URL-shortening service, which obscures the destination.")
        risk_score = max(risk_score, 65)
    if subdomain_count >= 4:
        reasons.append(f"The URL uses {subdomain_count} subdomain levels.")
        risk_score = max(risk_score, 72)
    if keywords:
        reasons.append("Credential or account-related terms appear in the hostname or path: " + ", ".join(keywords) + ".")
        risk_score = max(risk_score, 72 if len(keywords) > 1 else 55)
    if unusual:
        reasons.extend(unusual)
        risk_score = max(risk_score, 65)
    if float(phishing_probability) >= 0.5:
        reasons.append("The model found character patterns associated with phishing URLs.")
    if not reasons:
        reasons.append("No strong URL-structure warning was found; this is not a guarantee of safety.")

    risk_score = min(risk_score, 100)
    if risk_score >= 85:
        classification = "phishing"
    elif risk_score >= 45:
        classification = "suspicious"
    else:
        classification = "safe"

    model_confidence = max(float(phishing_probability), 1 - float(phishing_probability)) * 100
    return {
        "classification": classification,
        "risk_score": round(risk_score, 1),
        "confidence": round(model_confidence / 100, 4),
        "uncertain": classification == "suspicious" or model_confidence < 65,
        "reasons": reasons,
        "features": {
            "url_length": len(url),
            "subdomain_count": subdomain_count,
            "uses_ip_address": is_ip,
            "uses_url_shortener": hostname in URL_SHORTENERS,
            "suspicious_keywords": keywords,
            "unusual_indicators": unusual,
            "has_query_parameters": bool(parsed.query),
        },
    }