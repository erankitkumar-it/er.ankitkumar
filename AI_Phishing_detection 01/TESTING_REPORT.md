# PhishTower Testing Report

## Evaluation Method
- Dataset: `Data/phishing_site_urls.csv` (project-provided; no external dataset used).
- Exact duplicate URLs were removed before splitting; contradictory labels were excluded.
- Stratified holdout: 80/20, `random_state=42`; metrics below are held-out results, not a guarantee of future performance.
- Existing pickle files were loaded for URL probes and were not overwritten by this evaluation.

## Holdout Metrics
- Accuracy: 96.40%
- Phishing precision: 89.81%
- Phishing recall: 94.79%
- Phishing F1-score: 92.23%
- False-positive rate: 3.13%
- Brier score: 0.0292 (lower is better)
- Expected calibration error (10 bins): 0.0423 (lower is better)
- Prior-corrected Brier score: 0.0256 (lower is better)
- Prior-corrected expected calibration error (10 bins): 0.0190 (lower is better)
- The dashboard applies the empirical-prior correction for this balanced-class model; it does not change the stored model artifacts.

Confusion matrix (rows: actual legitimate/phishing; columns: predicted legitimate/phishing):

```text
[[76121, 2459], [1190, 21669]]
```

## Requested Popular Domains
| URL | Result | Risk | Prior-corrected phishing probability |
|---|---|---:|---:|
| `https://google.com` | Safe | 22.5% | 22.5% |
| `https://www.google.com` | Safe | 13.0% | 13.0% |
| `https://youtube.com` | Safe | 0.2% | 0.2% |
| `https://www.youtube.com` | Safe | 0.9% | 0.9% |
| `https://microsoft.com` | Safe | 12.7% | 12.7% |
| `https://www.microsoft.com` | Safe | 4.5% | 4.5% |
| `https://amazon.in` | Safe | 10.6% | 10.6% |
| `https://www.amazon.in` | Safe | 14.8% | 14.8% |
| `https://wikipedia.org` | Safe | 0.1% | 0.1% |
| `https://www.wikipedia.org` | Safe | 0.0% | 0.0% |

## Labeled Phishing Sample Probe: 8 rows
- Not classified Safe: 8/8

## URL Feature Cases
| Case | Classification | Risk |
|---|---|---:|
| Ip | Phishing | 99.8% |
| Deep subdomains | Suspicious | 72.0% |
| Shortener | Phishing | 95.9% |
| Credential keywords | Phishing | 100.0% |
| Query only | Safe | 4.6% |
| Unusual characters | Suspicious | 65.0% |

Input-validation checks cover empty input, unsupported schemes, missing host, credential-bearing URLs, and URLs over 2,048 characters.
Query parameters are recorded as a feature but are not independently treated as malicious.
