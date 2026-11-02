
import pandas as pd
import joblib
import numpy as np
import json

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, brier_score_loss, classification_report, confusion_matrix
from url_utils import normalize_url_for_model


def expected_calibration_error(labels, probabilities):
    calibration_error = 0.0
    bin_edges = np.linspace(0, 1, 11)
    labels = np.asarray(labels)
    probabilities = np.asarray(probabilities)
    for lower, upper in zip(bin_edges[:-1], bin_edges[1:]):
        selected = (probabilities >= lower) & (probabilities < upper)
        if selected.any():
            calibration_error += selected.mean() * abs(
                probabilities[selected].mean() - labels[selected].mean()
            )
    return calibration_error


def restore_unweighted_prior(probabilities, training_labels):
    labels = np.asarray(training_labels)
    negative_count = np.count_nonzero(labels == 0)
    positive_count = np.count_nonzero(labels == 1)
    sample_count = len(labels)
    negative_weight = sample_count / (2 * negative_count)
    positive_weight = sample_count / (2 * positive_count)
    probabilities = np.asarray(probabilities)
    denominator = probabilities * negative_weight + (1 - probabilities) * positive_weight
    return probabilities * negative_weight / denominator


def prepare_dataset():
    print("Loading dataset...")
    df = pd.read_csv("Data/phishing_site_urls.csv")
    df = df.dropna(subset=["URL", "Label"])
    df["URL"] = df["URL"].astype(str).map(normalize_url_for_model)
    df["Label"] = df["Label"].astype(str).str.strip().str.lower().map({"good": 0, "bad": 1})
    df = df.dropna(subset=["Label"])

    conflicts = df.groupby("URL")["Label"].nunique()
    conflicting_urls = conflicts[conflicts > 1].index
    df = df[~df["URL"].isin(conflicting_urls)].drop_duplicates(subset=["URL"])
    print("Dataset prepared.")
    print("Unique URLs:", len(df))
    print("Conflicting URLs removed:", len(conflicting_urls))
    return df["URL"], df["Label"].astype(int)


def train_and_evaluate(save_artifacts=True):
    X, y = prepare_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print("Training data:", len(X_train))
    print("Testing data:", len(X_test))

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        max_features=50000,
        sublinear_tf=True,
    )
    X_train_vector = vectorizer.fit_transform(X_train)
    X_test_vector = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X_train_vector, y_train)
    predictions = model.predict(X_test_vector)
    phishing_probabilities = model.predict_proba(X_test_vector)[:, 1]

    accuracy = accuracy_score(y_test, predictions)
    report = classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        digits=4,
        output_dict=True,
    )
    matrix = confusion_matrix(y_test, predictions)
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    false_positive_rate = false_positive / (false_positive + true_negative)
    calibration_error = expected_calibration_error(y_test, phishing_probabilities)
    brier_score = brier_score_loss(y_test, phishing_probabilities)
    corrected_probabilities = restore_unweighted_prior(phishing_probabilities, y_train)
    corrected_brier_score = brier_score_loss(y_test, corrected_probabilities)
    corrected_calibration_error = expected_calibration_error(y_test, corrected_probabilities)

    print("\nMODEL ACCURACY:")
    print(f"{accuracy * 100:.2f}%")
    print("\nCLASSIFICATION REPORT:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        digits=4,
    ))
    print("CONFUSION MATRIX [legitimate, phishing]:")
    print(matrix)
    print(f"FALSE POSITIVE RATE: {false_positive_rate * 100:.2f}%")
    print(f"BRIER SCORE: {brier_score:.4f}")
    print(f"EXPECTED CALIBRATION ERROR (10 BINS): {calibration_error:.4f}")
    print(f"PRIOR-CORRECTED BRIER SCORE: {corrected_brier_score:.4f}")
    print(f"PRIOR-CORRECTED EXPECTED CALIBRATION ERROR: {corrected_calibration_error:.4f}")

    if save_artifacts:
        joblib.dump(model, "phishing_model.pkl")
        joblib.dump(vectorizer, "vectorizer.pkl")
        with open("model_metadata.json", "w", encoding="utf-8") as metadata_file:
            json.dump({
                "negative_training_count": int((y_train == 0).sum()),
                "positive_training_count": int((y_train == 1).sum()),
                "class_weighting": "balanced",
                "probability_correction": "restore empirical class prior",
            }, metadata_file, indent=2)
        print("\nModel and vectorizer saved successfully.")

    return {
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "false_positive_rate": false_positive_rate,
        "brier_score": brier_score,
        "expected_calibration_error": calibration_error,
        "prior_corrected_brier_score": corrected_brier_score,
        "prior_corrected_expected_calibration_error": corrected_calibration_error,
        "training_negative_count": int((y_train == 0).sum()),
        "training_positive_count": int((y_train == 1).sum()),
        "phishing_precision": report["Phishing"]["precision"],
        "phishing_recall": report["Phishing"]["recall"],
        "phishing_f1": report["Phishing"]["f1-score"],
        "legitimate_precision": report["Legitimate"]["precision"],
        "legitimate_recall": report["Legitimate"]["recall"],
        "legitimate_f1": report["Legitimate"]["f1-score"],
        "test_size": len(y_test),
    }


if __name__ == "__main__":
    train_and_evaluate()
