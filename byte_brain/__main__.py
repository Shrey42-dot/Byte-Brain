import argparse
import os
import sys

# --- Ensure project root is on sys.path ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from model.infer import main as infer_main


# -------------------------------
# Confidence → Action mapping
# -------------------------------
def map_action(prob):
    if prob >= 0.80:
        return "QUARANTINE IMMEDIATELY"
    elif prob >= 0.60:
        return "BLOCK / INVESTIGATE"
    elif prob >= 0.40:
        return "REVIEW"
    else:
        return "ALLOW"


# -------------------------------
# Batch summary printer
# -------------------------------
def print_batch_summary(results):
    if not results:
        print("\nNo PE files found.")
        return

    total = len(results)
    benign = sum(1 for r in results if r["label"] == "BENIGN")
    malware = sum(1 for r in results if r["label"] == "MALWARE")

    avg_prob = sum(r["prob"] for r in results) / total
    highest = max(results, key=lambda r: r["prob"])

    print("\n=== BATCH SUMMARY ===")
    print(f"Total files scanned : {total}")
    print(f"Benign              : {benign}")
    print(f"Malware             : {malware}")
    print(f"Average malware prob: {avg_prob:.4f}")
    print(f"Highest risk file   : {highest['path']} ({highest['prob']:.4f})")

    print("\n=== ACTION RECOMMENDATIONS ===")
    for r in results:
        action = map_action(r["prob"])
        print(f"{r['path']} → {action}")


# -------------------------------
# Main CLI entry
# -------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="byte-brain",
        description="Byte-Brain – Static PE Malware Scanner"
    )
    parser.add_argument(
        "path",
        help="Path to a PE file or directory containing PE files"
    )

    args = parser.parse_args()
    results = []

    # ---- Directory scan ----
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.lower().endswith(".exe"):
                    full_path = os.path.join(root, f)
                    print("\n" + "=" * 40)
                    print(f"Scanning: {full_path}")

                    # Simulate CLI call for infer.py
                    sys.argv = ["infer.py", full_path]
                    result = infer_main()

                    if result:
                        results.append(result)

        print_batch_summary(results)

    # ---- Single file scan ----
    else:
        sys.argv = ["infer.py", args.path]
        infer_main()


if __name__ == "__main__":
    main()
