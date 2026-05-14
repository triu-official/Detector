import ipaddress
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import joblib
import requests
import whois
from bs4 import BeautifulSoup

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "bank", "update", "confirm", "account", "password"}


@dataclass
class AnalysisResult:
    url: str
    score: int
    verdict: str
    reasons: list[str]
    features: dict[str, float]
    redirect_chain: list[str]


def validate_url(raw_url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(raw_url.strip())
    except ValueError:
        return False, "Malformed URL"

    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https URLs are allowed"
    if not parsed.netloc:
        return False, "URL must include a valid domain"
    if not _is_safe_public_host(parsed.hostname):
        return False, "URL points to a private or local network address"
    return True, ""


def _is_safe_public_host(host: str | None) -> bool:
    if not host:
        return False
    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror:
        return True
    ip = ipaddress.ip_address(resolved)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


def extract_url_features(url: str) -> tuple[dict[str, float], list[str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    reasons: list[str] = []

    subdomain_count = max(host.count(".") - 1, 0)
    has_ip = 0.0
    try:
        ipaddress.ip_address(host)
        has_ip = 1.0
        reasons.append("URL uses IP address instead of domain")
    except ValueError:
        pass

    suspicious_char_count = sum(url.count(ch) for ch in ["@", "-", "%", "="])
    if suspicious_char_count:
        reasons.append("URL contains suspicious special characters")

    keyword_hits = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower())
    if keyword_hits:
        reasons.append("URL contains phishing-associated keywords")

    is_shortener = float(host in SHORTENERS)
    if is_shortener:
        reasons.append("URL uses a known shortening service")

    features = {
        "url_length": float(len(url)),
        "subdomain_count": float(subdomain_count),
        "has_ip": has_ip,
        "suspicious_chars": float(suspicious_char_count),
        "keyword_hits": float(keyword_hits),
        "is_shortener": is_shortener,
        "path_length": float(len(path)),
    }
    return features, reasons


def get_domain_intelligence(url: str) -> tuple[dict[str, Any], list[str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    info: dict[str, Any] = {"domain": host, "domain_age_days": 0, "registrar": "unknown"}
    reasons: list[str] = []

    try:
        data = whois.whois(host)
        creation = data.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation_utc = creation.replace(tzinfo=timezone.utc)
            else:
                creation_utc = creation.astimezone(timezone.utc)
            age_days = max((datetime.now(timezone.utc) - creation_utc).days, 0)
            info["domain_age_days"] = age_days
            if age_days < 90:
                reasons.append("Domain is very new")
        registrar = getattr(data, "registrar", None)
        if registrar:
            info["registrar"] = str(registrar)
    except Exception:
        reasons.append("WHOIS lookup unavailable")

    return info, reasons


def trace_redirect_chain(url: str, timeout: int, max_depth: int) -> tuple[list[str], list[str]]:
    current = url
    chain: list[str] = [url]
    reasons: list[str] = []
    seen = {url}

    for _ in range(max_depth):
        try:
            response = requests.get(current, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            break

        if response.is_redirect and response.headers.get("Location"):
            nxt = urljoin(current, response.headers["Location"])
            if not _is_safe_public_host(urlparse(nxt).hostname):
                reasons.append("Redirect targets a private or local address")
                break
            if nxt in seen:
                reasons.append("Redirect loop detected")
                break
            chain.append(nxt)
            seen.add(nxt)
            current = nxt
            continue
        break

    if len(chain) > 3:
        reasons.append("Long redirect chain")
    return chain, reasons


def analyze_page(url: str, timeout: int) -> tuple[dict[str, float], list[str]]:
    signals = {"form_count": 0.0, "iframe_count": 0.0, "external_form_action": 0.0}
    reasons: list[str] = []

    try:
        response = requests.get(url, timeout=timeout)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        iframes = soup.find_all("iframe")

        signals["form_count"] = float(len(forms))
        signals["iframe_count"] = float(len(iframes))

        external_action = False
        for form in forms:
            action = form.get("action") or ""
            if action.startswith("http") and urlparse(action).hostname != urlparse(url).hostname:
                external_action = True
                break
        if external_action:
            signals["external_form_action"] = 1.0
            reasons.append("Page contains external form action")

        if iframes:
            reasons.append("Page embeds iframe elements")
    except requests.RequestException:
        reasons.append("Page content could not be fetched")

    return signals, reasons


def is_blacklisted(url: str, blacklist_domains: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in blacklist_domains


def _load_model(path: str):
    if not path or not os.path.exists(path):
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None


def _model_prediction(model, features: dict[str, float]) -> tuple[float | None, str | None]:
    if model is None:
        return None, None
    ordered_values = [features[k] for k in sorted(features)]
    try:
        if hasattr(model, "predict_proba"):
            phishing_probability = float(model.predict_proba([ordered_values])[0][1])
            importance = getattr(model, "feature_importances_", None)
            if importance is not None:
                top_index = int(max(range(len(importance)), key=lambda i: importance[i]))
                feature_name = sorted(features)[top_index]
                return phishing_probability, f"Model highlighted {feature_name} as strongest signal"
            return phishing_probability, "Model-based risk estimation used"
    except Exception:
        return None, None
    return None, None


def analyze_url(url: str, timeout: int, max_redirect_depth: int, blacklist_domains: set[str], model_path: str = "") -> AnalysisResult:
    valid, message = validate_url(url)
    if not valid:
        raise ValueError(message)

    features, reasons = extract_url_features(url)
    domain_info, domain_reasons = get_domain_intelligence(url)
    page_signals, page_reasons = analyze_page(url, timeout)
    redirects, redirect_reasons = trace_redirect_chain(url, timeout, max_redirect_depth)

    features.update(page_signals)
    features["domain_age_days"] = float(domain_info.get("domain_age_days", 0))

    all_reasons = reasons + domain_reasons + page_reasons + redirect_reasons

    if is_blacklisted(url, blacklist_domains):
        all_reasons.append("Domain found in local blacklist")
        features["blacklisted"] = 1.0
    else:
        features["blacklisted"] = 0.0

    score = 0
    score += min(int(features["url_length"] / 8), 20)
    score += int(features["has_ip"] * 25)
    score += min(int(features["suspicious_chars"] * 3), 15)
    score += int(features["keyword_hits"] * 4)
    score += int(features["is_shortener"] * 15)
    score += int(features["external_form_action"] * 15)
    score += min(len(redirects) * 2, 12)
    if 0 < features["domain_age_days"] < 90:
        score += 20
    if features["blacklisted"]:
        score = max(score, 90)

    model = _load_model(model_path)
    ml_prob, explain = _model_prediction(model, features)
    if ml_prob is not None:
        score = int((score * 0.6) + (ml_prob * 100 * 0.4))
        if explain:
            all_reasons.append(explain)

    score = max(0, min(score, 100))
    verdict = "high-risk" if score >= 70 else "suspicious" if score >= 40 else "likely-safe"
    if not all_reasons:
        all_reasons.append("No major phishing indicators detected")

    return AnalysisResult(
        url=url,
        score=score,
        verdict=verdict,
        reasons=all_reasons,
        features=features,
        redirect_chain=redirects,
    )
