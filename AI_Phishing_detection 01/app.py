
import csv
import ipaddress
import io
import json
import logging
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

import joblib
from flask import Flask, jsonify, make_response, render_template, request, session

from database import (
    clear_scans,
    delete_scan,
    get_dashboard_stats,
    get_recent_scans,
    get_scans,
    init_db,
    record_scan,
    search_scans,
)
from url_utils import analyze_url, normalize_url_for_model, restore_unweighted_prior


BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)
APP_ENV = os.environ.get("APP_ENV", "development").lower()
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if APP_ENV == "production" and not SECRET_KEY:
    raise RuntimeError("Set FLASK_SECRET_KEY before running in production.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY or secrets.token_urlsafe(32),
    DATABASE_PATH=os.environ.get("SCAN_DATABASE_PATH", str(BASE_DIR / "scan_history.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=APP_ENV == "production",
)

try:
    model = joblib.load(BASE_DIR / "phishing_model.pkl")
    vectorizer = joblib.load(BASE_DIR / "vectorizer.pkl")
except Exception:
    logger.exception("Unable to load the phishing detection model artifacts")
    model = None
    vectorizer = None

try:
    with (BASE_DIR / "model_metadata.json").open(encoding="utf-8") as metadata_file:
        model_metadata = json.load(metadata_file)
    model_prior = (
        int(model_metadata["negative_training_count"]),
        int(model_metadata["positive_training_count"]),
    )
    if min(model_prior) <= 0:
        raise ValueError("Training class counts must be positive.")
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
    logger.warning("Model prior metadata is unavailable; using the raw model probability")
    model_prior = None

init_db(app.config["DATABASE_PATH"])


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_is_valid():
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


def validate_url(value):
    if not isinstance(value, str):
        return None, "Enter a valid HTTP or HTTPS URL."

    value = value.strip()
    if not value:
        return None, "Enter a URL to scan."
    if len(value) > 2048:
        return None, "URL must be 2,048 characters or fewer."
    if any(character.isspace() or ord(character) < 32 for character in value):
        return None, "URL cannot contain spaces or control characters."

    candidate = value if re.match(r"^https?://", value, flags=re.IGNORECASE) else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return None, "Enter a valid HTTP or HTTPS URL."

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return None, "Enter a valid HTTP or HTTPS URL with a hostname."
    if parsed.username is not None or parsed.password is not None:
        return None, "URLs containing embedded credentials are not accepted."

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None, "Enter a valid hostname."
        labels = ascii_hostname.split(".")
        label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if ascii_hostname != "localhost" and (
            len(labels) < 2 or any(not label_pattern.fullmatch(label) for label in labels)
        ):
            return None, "Enter a valid hostname."

    return normalize_url_for_model(value), None


def scan_url(raw_url):
    normalized_url, error = validate_url(raw_url)
    if error:
        return None, error, 400
    if model is None or vectorizer is None:
        return None, "The detection model is unavailable. Please contact the administrator.", 503

    try:
        features = vectorizer.transform([normalized_url])
        if not hasattr(model, "predict_proba"):
            return None, "The detection model cannot provide a reliable risk score.", 503
        class_probabilities = dict(zip(model.classes_, model.predict_proba(features)[0]))
        raw_phishing_probability = float(class_probabilities.get(1, 0))
        phishing_probability = (
            restore_unweighted_prior(raw_phishing_probability, *model_prior)
            if model_prior
            else raw_phishing_probability
        )
        analysis = analyze_url(normalized_url, phishing_probability)
        scan = record_scan(
            app.config["DATABASE_PATH"],
            raw_url.strip(),
            analysis["classification"],
            analysis["risk_score"],
            analysis["confidence"],
            analysis["reasons"],
        )
        scan.update(
            uncertain=analysis["uncertain"],
            features=analysis["features"],
            phishing_probability=round(phishing_probability, 4),
            raw_phishing_probability=round(raw_phishing_probability, 4),
        )
        return scan, None, 200
    except Exception:
        logger.exception("URL scan failed")
        return None, "The scan could not be completed. Please try again.", 500


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'",
    )
    return response


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "")
        if not csrf_is_valid():
            result = {"error": "Your session expired. Refresh the page and try again."}
        else:
            scan, error, _ = scan_url(url)
            result = {"error": error} if error else scan

    return render_template(
        "index.html",
        csrf_token=csrf_token(),
        model_available=model is not None and vectorizer is not None,
        result=result,
        url=url,
        stats=get_dashboard_stats(app.config["DATABASE_PATH"]),
        recent_scans=get_recent_scans(app.config["DATABASE_PATH"], 10),
    )


@app.post("/api/scan")
def api_scan():
    if not csrf_is_valid():
        return jsonify(error="Your session expired. Refresh the page and try again."), 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    scan, error, status = scan_url(payload.get("url"))
    if error:
        return jsonify(error=error), status
    return jsonify(scan=scan, stats=get_dashboard_stats(app.config["DATABASE_PATH"])), 200


@app.get("/api/stats")
def api_stats():
    return jsonify(
        stats=get_dashboard_stats(app.config["DATABASE_PATH"]),
        recent_scans=get_recent_scans(app.config["DATABASE_PATH"], 50),
    )


@app.get("/api/history")
def api_history():
    search = request.args.get("search", "").strip()[:200]
    classification = request.args.get("classification", "all").strip().lower()
    if classification not in {"all", "safe", "suspicious", "phishing"}:
        return jsonify(error="Unknown classification filter."), 400
    try:
        limit = int(request.args.get("limit", "50"))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        return jsonify(error="History pagination values must be integers."), 400
    scans, total = search_scans(
        app.config["DATABASE_PATH"],
        search=search,
        classification=None if classification == "all" else classification,
        limit=limit,
        offset=offset,
    )
    return jsonify(scans=scans, total=total)


@app.delete("/api/history/<int:scan_id>")
def api_delete_scan(scan_id):
    if not csrf_is_valid():
        return jsonify(error="Your session expired. Refresh the page and try again."), 403
    if not delete_scan(app.config["DATABASE_PATH"], scan_id):
        return jsonify(error="Scan record not found."), 404
    return jsonify(stats=get_dashboard_stats(app.config["DATABASE_PATH"]))


@app.post("/api/history/clear")
def api_clear_history():
    if not csrf_is_valid():
        return jsonify(error="Your session expired. Refresh the page and try again."), 403
    clear_scans(app.config["DATABASE_PATH"])
    return jsonify(stats=get_dashboard_stats(app.config["DATABASE_PATH"]), recent_scans=[])


@app.get("/report.csv")
def download_report():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["URL", "Classification", "Risk score", "Model confidence", "Reasons", "Scanned at (UTC)"])
    for scan in get_scans(app.config["DATABASE_PATH"]):
        url = scan["url"]
        if url.startswith(("=", "+", "-", "@", "\t", "\r")):
            url = "'" + url
        confidence = "" if scan["confidence"] is None else f"{scan['confidence'] * 100:.2f}%"
        writer.writerow([
            url,
            scan["prediction"],
            f"{scan['risk_score']:.1f}%",
            confidence,
            "; ".join(scan["reasons"]),
            scan["scanned_at"],
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=phishing-scan-report.csv"
    return response


if __name__ == "__main__":
    debug = APP_ENV != "production" and os.environ.get("FLASK_DEBUG", "").lower() == "true"
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=debug,
    )
