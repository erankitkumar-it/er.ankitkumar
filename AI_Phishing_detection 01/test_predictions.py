
import joblib
import pandas as pd
from pathlib import Path

from train_model import train_and_evaluate
from url_utils import analyze_url, normalize_url_for_model, restore_unweighted_prior


def main():
    metrics = train_and_evaluate(save_artifacts=False)
    print("\nHOLDOUT SUMMARY")
    print(f"Accuracy: {metrics['accuracy'] * 100:.2f}%")
    print(f"False positive rate: {metrics['false_positive_rate'] * 100:.2f}%")

    model = joblib.load("phishing_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    try:
        import json
        with open("model_metadata.json", encoding="utf-8") as metadata_file:
            metadata = json.load(metadata_file)
        prior = (metadata["negative_training_count"], metadata["positive_training_count"])
    except (OSError, KeyError, ValueError):
        prior = None
    popular_urls = [
        "https://google.com",
        "https://www.google.com",
        "https://youtube.com",
        "https://www.youtube.com",
        "https://microsoft.com",
        "https://www.microsoft.com",
        "https://amazon.in",
        "https://www.amazon.in",
        "https://wikipedia.org",
        "https://www.wikipedia.org",
    ]
    popular_features = vectorizer.transform([normalize_url_for_model(url) for url in popular_urls])
    popular_probabilities = model.predict_proba(popular_features)[:, 1]
    popular_results = []
    for url, probability in zip(popular_urls, popular_probabilities):
        corrected_probability = restore_unweighted_prior(probability, *prior) if prior else probability
        result = analyze_url(normalize_url_for_model(url), corrected_probability)
        print(f"{url}: {result['classification']} (risk {result['risk_score']:.1f}%, corrected score {corrected_probability * 100:.1f}%)")
        assert result["classification"] == "safe", f"Unexpected classification for {url}"
        popular_results.append((url, result, float(corrected_probability)))

    dataset = pd.read_csv("Data/phishing_site_urls.csv")
    phishing_samples = dataset.loc[
        dataset["Label"].astype(str).str.strip().str.lower().eq("bad"), "URL"
    ].dropna().head(8).astype(str).tolist()
    sample_features = vectorizer.transform([normalize_url_for_model(url) for url in phishing_samples])
    sample_probabilities = model.predict_proba(sample_features)[:, 1]
    phishing_results = []
    for url, probability in zip(phishing_samples, sample_probabilities):
        corrected_probability = restore_unweighted_prior(probability, *prior) if prior else probability
        result = analyze_url(normalize_url_for_model(url), corrected_probability)
        print(f"Dataset phishing sample: {result['classification']} (risk {result['risk_score']:.1f}%)")
        assert result["classification"] != "safe", f"Phishing sample classified safe: {url}"
        phishing_results.append(result["classification"])

    from app import validate_url

    for invalid_url in ["", "javascript:alert(1)", "https://", "x" * 2049, "https://user:pass@example.com"]:
        assert validate_url(invalid_url)[1], f"Invalid URL accepted: {invalid_url[:80]}"
    for valid_url in ["http://example.com", "https://example.com", "example.com"]:
        assert validate_url(valid_url)[1] is None, f"Valid URL rejected: {valid_url}"

    pattern_cases = {
        "ip": "https://127.0.0.1/login",
        "deep_subdomains": "https://a.b.c.d.example.com/path",
        "shortener": "https://bit.ly/abc123",
        "credential_keywords": "https://secure-account-login.example.com/verify",
        "query_only": "https://example.com/search?ref=123",
        "unusual_characters": "https://xn--80ak6aa92e.com/path",
    }
    pattern_results = []
    for name, url in pattern_cases.items():
        normalized = normalize_url_for_model(url)
        probability = model.predict_proba(vectorizer.transform([normalized]))[0, 1]
        corrected_probability = restore_unweighted_prior(probability, *prior) if prior else probability
        result = analyze_url(normalized, corrected_probability)
        print(f"Pattern {name}: {result['classification']} (risk {result['risk_score']:.1f}%)")
        if name == "ip":
            assert result["features"]["uses_ip_address"]
        elif name == "deep_subdomains":
            assert result["features"]["subdomain_count"] >= 4
        elif name == "shortener":
            assert result["features"]["uses_url_shortener"]
        elif name == "credential_keywords":
            assert result["features"]["suspicious_keywords"]
        elif name == "query_only":
            assert not result["features"]["suspicious_keywords"]
            assert result["features"]["has_query_parameters"]
        elif name == "unusual_characters":
            assert result["features"]["unusual_indicators"]
        pattern_results.append((name, result))

    plain_url = analyze_url("https://example.com/search", 0.2)
    parameter_url = analyze_url("https://example.com/search?ref=123", 0.2)
    assert plain_url["risk_score"] == parameter_url["risk_score"]

    report_lines = [
        "# PhishTower Testing Report",
        "",
        "## Evaluation Method",
        "- Dataset: `Data/phishing_site_urls.csv` (project-provided; no external dataset used).",
        "- Exact duplicate URLs were removed before splitting; contradictory labels were excluded.",
        "- Stratified holdout: 80/20, `random_state=42`; metrics below are held-out results, not a guarantee of future performance.",
        "- Existing pickle files were loaded for URL probes and were not overwritten by this evaluation.",
        "",
        "## Holdout Metrics",
        f"- Accuracy: {metrics['accuracy'] * 100:.2f}%",
        f"- Phishing precision: {metrics['phishing_precision'] * 100:.2f}%",
        f"- Phishing recall: {metrics['phishing_recall'] * 100:.2f}%",
        f"- Phishing F1-score: {metrics['phishing_f1'] * 100:.2f}%",
        f"- False-positive rate: {metrics['false_positive_rate'] * 100:.2f}%",
        f"- Brier score: {metrics['brier_score']:.4f} (lower is better)",
        f"- Expected calibration error (10 bins): {metrics['expected_calibration_error']:.4f} (lower is better)",
        f"- Prior-corrected Brier score: {metrics['prior_corrected_brier_score']:.4f} (lower is better)",
        f"- Prior-corrected expected calibration error (10 bins): {metrics['prior_corrected_expected_calibration_error']:.4f} (lower is better)",
        "- The dashboard applies the empirical-prior correction for this balanced-class model; it does not change the stored model artifacts.",
        "",
        "Confusion matrix (rows: actual legitimate/phishing; columns: predicted legitimate/phishing):",
        "",
        "```text",
        str(metrics["confusion_matrix"]),
        "```",
        "",
        "## Requested Popular Domains",
        "| URL | Result | Risk | Prior-corrected phishing probability |",
        "|---|---|---:|---:|",
    ]
    report_lines.extend(
        f"| `{url}` | {result['classification'].capitalize()} | {result['risk_score']:.1f}% | {probability * 100:.1f}% |"
        for url, result, probability in popular_results
    )
    report_lines.extend([
        "",
        f"## Labeled Phishing Sample Probe: {len(phishing_results)} rows",
        f"- Not classified Safe: {sum(classification != 'safe' for classification in phishing_results)}/{len(phishing_results)}",
        "",
        "## URL Feature Cases",
        "| Case | Classification | Risk |",
        "|---|---|---:|",
    ])
    report_lines.extend(
        f"| {name.replace('_', ' ').capitalize()} | {result['classification'].capitalize()} | {result['risk_score']:.1f}% |"
        for name, result in pattern_results
    )
    report_lines.extend([
        "",
        "Input-validation checks cover empty input, unsupported schemes, missing host, credential-bearing URLs, and URLs over 2,048 characters.",
        "Query parameters are recorded as a feature but are not independently treated as malicious.",
        "",
    ])
    Path("TESTING_REPORT.md").write_text("\n".join(report_lines), encoding="utf-8")
    print("\nTesting report written to TESTING_REPORT.md")
    print("PASS: held-out metrics, popular-domain regression, phishing samples, URL features, and input validation")


if __name__ == "__main__":
    main()
