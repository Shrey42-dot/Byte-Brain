# Byte-Brain 🧠

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/Shrey42-dot/Byte-Brain)

## Offline Static PE Malware Scanner with Explainable ML
Byte-Brain is a local, privacy-first malware analysis tool that performs static analysis on Windows Portable Executable (PE) files. Unlike standard "black-box" scanners, Byte-Brain uses a Random Forest classifier trained on the EMBER 2018 dataset to provide probability-based risk assessments alongside human-readable explanations.

--- 

## 🚀 Key Features
* Zero-Cloud Dependency: Fully offline analysis; no data ever leaves your machine.

* Static PE Analysis: Extracts structural, entropy-based, and import signals using pefile.

* Explainable Predictions: Moves beyond binary "Malware/Benign" labels by providing threat levels (LOW/MEDIUM/HIGH) and specific reasoning for each decision.

* Batch Intelligence: Rapidly scan entire directories and generate a summary report including average risk and highest-threat files.

* Operational Security: Designed for safe analysis without dynamic execution, preventing accidental malware activation

---

## 🧠 How It Works

### 1. Feature Engineering

* Byte-Brain focuses on high-signal, interpretable features rather than opaque byte n-grams:

* Structural: Machine type, number of sections, and timestamp.

* Entropy: Section-level entropy (e.g., .text, .data, .rsrc) to detect packing or encryption.

* Import Signals: Monitoring suspicious DLLs such as ws2_32.dll (networking) and urlmon.dll (web interaction).

### 2. Machine Learning Pipeline

* Dataset: A balanced corpus of 10,000 samples (5k benign / 5k malware) derived from the EMBER-2018 JSONL files.

* Model: A Random Forest Classifier achieving ~97% Accuracy and 0.99 ROC-AUC.

* Resource-Aware Training: The model was trained on a Windows host to mitigate VM memory constraints, while inference is optimized for lightweight Linux environments.

--- 

## 📂 Project Structure

    byte-brain/
    ├── byte_brain/
    │   ├── __init__.py
    │   └── __main__.py        # CLI Entry Point
    ├── extractor/
    │   ├── __init__.py
    │   └── feature_extractor.py # Custom PE feature extraction logic
    ├── model/
    │   ├── byte_brain_rf.joblib    # Serialized Random Forest model
    │   ├── feature_selector.joblib # VarianceThreshold selector
    │   └── infer.py                # Inference engine
    ├── samples/                    # Safe PE samples for testing
    │   ├── benign/
    │   │   ├── sigcheck64.exe
    │   │   ├── strings64.exe        
    │   └── README.txt
    ├── README.md
    ├── byte-brain
    ├── .gitignore
    └── requirements.txt            # Project dependencies

---

## 🛠️ Installation & Usage

### Setup

    # Clone the repository
    git clone https://github.com/Shrey42-dot/Byte-Brain.git
    cd Byte-Brain
    
    # Setup environment
    python3 -m venv bb-env
    source bb-env/bin/activate
    pip install -r requirements.txt

### Single File Scan

    ./byte-brain samples/benign/strings64.exe

### Batch Directory Scan

    ./byte-brain samples/

---

## Images

### Output of Batch Directory Scan:

<img width="743" height="681" alt="folder procssing result png byte brain image" src="https://github.com/user-attachments/assets/97daa28d-fc33-43f0-bdc1-69b7e4f942b3" />

### Defined Map-Actions:

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/56e81a76-3ee9-4411-b1cf-75758982d281" />

--- 
## 🛡️ Safety & Ethics

Byte-Brain is intended for defensive research and educational purposes. It performs static analysis only and does not execute the files it scans. Users should still handle known malware samples within isolated sandbox environments.

--- 
## 📈 Current Limitations

* Static analysis only (no runtime behavior)

* Limited feature set (no byte-level n-grams)

* Confidence is probabilistic, not absolute truth

These are deliberate design choices for safety and explainability.

---

## 🛣️ Future Improvements

* Feature importance visualization

* JSON / CSV report export

* YARA-style rule hints

* Ensemble models

* Optional dynamic analysis integration

---

## 👤 Author

### Shrey Pandey

GitHub: @Shrey42-dot

Focus: Cybersecurity & Machine Learning Engineering
