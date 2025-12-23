import pefile
import numpy as np
import os

SUSPICIOUS_DLLS = {
    "ws2_32.dll",
    "advapi32.dll",
    "wininet.dll",
    "urlmon.dll"
}

def extract_features(pe_path):
    pe = pefile.PE(pe_path)

    features = {}

    # === HEADER FEATURES ===
    features["machine"] = pe.FILE_HEADER.Machine
    features["num_sections"] = pe.FILE_HEADER.NumberOfSections
    features["timestamp"] = pe.FILE_HEADER.TimeDateStamp

    # === SECTION FEATURES ===
    entropies = {}
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00").lower()
        entropies[name] = section.get_entropy()

    features["text_entropy"] = entropies.get(".text", 0)
    features["data_entropy"] = entropies.get(".data", 0)
    features["rsrc_entropy"] = entropies.get(".rsrc", 0)

    entropy_values = list(entropies.values())
    features["mean_entropy"] = float(np.mean(entropy_values))
    features["max_entropy"] = float(np.max(entropy_values))

    # === STRUCTURAL FLAGS ===
    features["has_rsrc"] = int(".rsrc" in entropies)
    features["has_reloc"] = int(".reloc" in entropies)

    # === IMPORT FEATURES ===
    imports = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore").lower()
            imports.add(dll)

    features["num_imports"] = len(imports)

    for dll in SUSPICIOUS_DLLS:
        features[f"imports_{dll.replace('.', '_')}"] = int(dll in imports)

    return features


if __name__ == "__main__":
    test_file = "samples/benign/sigcheck64.exe"

    if not os.path.exists(test_file):
        print("Test file not found.")
        exit(1)

    feats = extract_features(test_file)

    print("=== EXTRACTED FEATURES ===")
    for k, v in feats.items():
        print(f"{k}: {v}")
