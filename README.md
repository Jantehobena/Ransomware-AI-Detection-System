### Ransomware AI Detection System

![GitHub stars](https://img.shields.io/github/stars/Jantehobena/Ransomware-AI-Detection-System?style=social)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/github/license/Jantehobena/Ransomware-AI-Detection-System)

#### 🛡️ Description
A machine learning-powered ransomware scanner that analyzes Windows PE files (`.exe`, `.dll`) by extracting features like entropy, headers, and section patterns. Supports manual labeling and incremental retraining.

---

### 🚀 Features
- CLI-based folder scan for `.exe` files
- Detects: `Benign`, `Malware`, `Ransomware`
- Interactive manual labeling (with deduplication)
- Saves label history in `manual_labels.csv`
- Auto-retraining model with feedback data
- MD5 & SHA1 fingerprinting

---

### 📂 File Structure
```
Ransomware-AI-Detection-System/
├── model/                  # Contains rf_model.pkl
├── utils/                  # Feature extraction utils
├── Final_Dataset_without_duplicate.csv
├── manual_labels.csv       # Manually labeled file log
├── scanner.py              # Main terminal scanner tool
├── train_model.ipynb       # Training notebook
├── scan_report.txt         # Auto report output
├── README.md               # GitHub description
├── LICENSE                 # MIT
└── .gitignore
```

---

### 💻 Usage
```bash
python scanner.py
# or retrain directly
python scanner.py --retrain
```

---

### 🧪 Manual Labeling
For files that fail feature extraction, the system will ask:
```bash
Enter Class (Benign/Malware):  Benign
Enter Category (Benign/Ransomware/Malware):  Ransomware
Enter Family Name (e.g., NVIDIA, DarkSide):  Custom
```
This info is saved and used for future prediction + retraining.

---

### 📈 Model Training
Model automatically retrains when ≥10 new samples are labeled, or manually via `--retrain`.


---

### 🤝 Contributing
Pull requests are welcome. Please open an issue first to discuss what you would like to change.

---

### 📸 Screenshots
> *Coming soon: CLI output, report sample, feature examples.*
