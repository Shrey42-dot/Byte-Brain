import sys
import joblib
import numpy as np
import pandas as pd
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from extractor.feature_extractor import extract_features

MODEL_PATH = "model/byte_brain_rf.joblib"
SELECTOR_PATH = "model/feature_selector.joblib"

def main():
    if len(sys.argv) != 2:
        print("Usage: python model/infer.py <pe_file>")
        sys.exit(1)

    pe_file = sys.argv[1]

    print("[*] Loading model artifacts...")
    model = joblib.load(MODEL_PATH)
    selector = joblib.load(SELECTOR_PATH)

    print("[*] Extracting features...")
    feats = extract_features(pe_file)

    # Convert dict → DataFrame
    X = pd.DataFrame([feats])

    # Align feature order with training
    X = X.reindex(columns=selector.feature_names_in_, fill_value=0)

    print("[*] Applying feature selector...")
    X_sel = selector.transform(X)

    print("[*] Running inference...")
    proba = model.predict_proba(X_sel)[0]
    pred = model.predict(X_sel)[0]

    malware_prob = proba[1] if len(proba) > 1 else proba[0]

    if malware_prob < 0.30:
       threat = "LOW"
    elif malware_prob < 0.60:
       threat = "MEDIUM"
    elif malware_prob < 0.80:
       threat = "HIGH"
    else:
       threat = "CRITICAL"

    label = "MALWARE" if malware_prob >= 0.5 else "BENIGN"

    print("\n=== RESULT ===")
    print(f"Prediction    : {label}")
    print(f"Malware Prob. : {malware_prob:.4f}")
    print(f"Threat Level  : {threat}")
    summary, reasons = explain_confidence(feats, malware_prob)

    print("\n=== CONFIDENCE EXPLANATION ===")
    print(summary)
    for r in reasons:
       print(f"- {r}")
    return {
    "path": pe_file,
    "label": label,
    "prob": float(max(proba))
     }

def explain_confidence(features: dict, malware_prob: float):
    reasons = []

    # Entropy-based reasoning
    if features.get("max_entropy", 0) > 7.2:
        reasons.append("High section entropy (possible packing/obfuscation)")

    if features.get("mean_entropy", 0) > 6.5:
        reasons.append("Overall entropy higher than typical benign binaries")

    # Structural indicators
    if features.get("num_sections", 0) > 7:
        reasons.append("Unusual number of PE sections")

    if features.get("has_rsrc", 0) == 0:
        reasons.append("Missing resource section (common in packed malware)")

    # Import indicators
    suspicious_imports = [
        k for k, v in features.items()
        if k.startswith("imports_") and v == 1
    ]

    if suspicious_imports:
        reasons.append(
            f"Suspicious imports detected ({len(suspicious_imports)})"
        )

    # Final explanation
    if malware_prob < 0.30:
        summary = "Low-risk profile with mostly benign characteristics"
    elif malware_prob < 0.60:
        summary = "Mixed characteristics: some suspicious indicators but insufficient for malware classification"
    else:
        summary = "Strong malicious indicators across multiple feature groups"

    return summary, reasons
def scan_folder(folder_path):
    folder = Path(folder_path)
    exe_files = list(folder.rglob("*.exe"))

    if not exe_files:
        print("No .exe files found.")
        return

    results = []

    print(f"\nScanning folder: {folder_path}\n")

    for exe in exe_files:
        print("=" * 50)
        print(f"Scanning: {exe}")

        feats = extract_features(str(exe))
        X = pd.DataFrame([feats])
        X = X.reindex(columns=selector.feature_names_in_, fill_value=0)
        X_sel = selector.transform(X)

        proba = model.predict_proba(X_sel)[0]
        malware_prob = proba[1]
        pred = model.predict(X_sel)[0]

        label = "MALWARE" if pred == 1 else "BENIGN"

        if malware_prob >= 0.75:
            threat = "HIGH"
            action = "QUARANTINE"
        elif malware_prob >= 0.40:
            threat = "MEDIUM"
            action = "REVIEW"
        else:
            threat = "LOW"
            action = "ALLOW"

        print(f"Prediction    : {label}")
        print(f"Malware Prob. : {malware_prob:.4f}")
        print(f"Threat Level : {threat}")
        print(f"Action       : {action}")

        results.append((exe, malware_prob, label))

    # ===== SUMMARY =====
    benign = sum(1 for _, _, l in results if l == "BENIGN")
    malware = sum(1 for _, _, l in results if l == "MALWARE")
    avg_prob = sum(p for _, p, _ in results) / len(results)
    highest = max(results, key=lambda x: x[1])

    print("\n=== BATCH SUMMARY ===")
    print(f"Total files scanned : {len(results)}")
    print(f"Benign              : {benign}")
    print(f"Malware             : {malware}")
    print(f"Average malware prob: {avg_prob:.4f}")
    print(f"Highest risk file   : {highest[0]} ({highest[1]:.4f})")

if __name__ == "__main__":
    main()
