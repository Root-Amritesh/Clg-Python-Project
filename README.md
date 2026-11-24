# Offline Scam Message Detector

Rule-based SMS / WhatsApp scam screening tool built in Python. Analyses messages locally (offline) for common scam patterns, gives a risk score with reasons, and stores results for later review.

**Course**: 2026CSAE100 — Computational Thinking and Programming  
**Institution**: Bennett University, School of CSET  
**Academic Year**: 2026-27

## Repository

- **GitHub**: https://github.com/Root-Amritesh/Clg-Python-Project

## Features

- Keyword and phrase matching across 7 scam categories
- Regex-based URL inspection (shortened links, raw IPs, suspicious TLDs, brand impersonation)
- Sensitive information request detection (OTP, PIN, CVV, password)
- Weighted 0–100 risk score with three-level verdict (Safe / Suspicious / Likely Scam)
- Explainable results — every score point traced to a rule
- CSV history of all checked messages
- Flagged message report generation (TXT)
- Statistics and optional Matplotlib charts
- 35 labelled sample messages with accuracy/precision/recall metrics
- 20+ automated test cases
- Fully offline — no internet, no API, no ML, no external packages required

## Installation & Run

```bash
# No installation needed — uses Python standard library only
python scam_detector.py

# Run automated tests
python scam_detector.py --test

# Run demo on labelled samples
python scam_detector.py --demo

# Optional: install matplotlib for charts
pip install matplotlib
```

## Folder Structure

```
scam/
├── scam_detector.py        # Main program (run this)
├── data/
│   └── samples.csv         # 35 labelled sample messages
├── docs/
│   └── (report, diagrams)
├── README.md
├── .gitignore
└── requirements.txt
```

## Team

| Name | Enrollment | Role |
|------|-----------|------|
| Amritesh Kumar | S26CSEU0943 | Lead: rule design, scoring, OOP, integration, testing |
| Naved Ali | S26CSEU0955 | CSV history, statistics, flagged report, charts |
| Tanishk Singh | S26CSEU0934 | Menu flow, demo samples, input handling |
| Aryan Chahal | S26CSEU0933 | Regex, URL checks, edge-case testing |
| Praval Verma | S26CSEU0935 | Documentation, presentation, viva prep |

## License

This project is an academic submission for Bennett University and is shared for educational purposes.

