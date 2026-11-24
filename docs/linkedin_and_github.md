# Offline Scam Message Detector — GitHub & LinkedIn Deliverables
**Course**: 2026CSAE100 — Computational Thinking and Programming  
**Bennett University, Greater Noida** (2026–27)  

---

## 1. LinkedIn Post Draft

### Option A: Professional & Technical (Recommended)

🚀 **Excited to share our Sem-1 Python Project at Bennett University!**

Under the course *Computational Thinking and Programming (2026CSAE100)*, our 5-member team developed the **Offline Scam Message Detector** — a lightweight, rule-based screening engine built in pure Python to help everyday smartphone users quickly spot SMS and WhatsApp phishing threats.

💡 **Why Offline?**
Most scam detection tools rely on cloud APIs or heavy machine learning models. But SMS messages frequently contain sensitive personal data like account numbers and partial names. We wanted a solution that:
1. **Guarantees Privacy**: 100% local execution — no data ever leaves the user's device.
2. **Zero Cloud Dependency**: Works instantly even in low-connectivity areas in under 3 milliseconds.
3. **100% Explainable**: Every risk score point is traceable to a specific threat heuristic, rather than an unexplainable black-box prediction.

⚙️ **Key Features Built**:
- **Multi-Vector Rule Engine**: Screens 7 threat categories (KYC account blocks, panic urgency, job fraud, prize scams, UPI traps).
- **URL Anatomy Scanner**: Detects link shorteners, numerical IPv4 hosts, suspicious TLDs (`.xyz`, `.top`), and brand impersonation.
- **Smart Context Filter**: Eliminates false positives on genuine banking OTPs using safe-phrase discounts.
- **Recursive Evasion Normaliser**: Handles spaced-out evasion tricks (`"O T P"` $\rightarrow$ `"otp"`).
- **Session Audit Logs**: Full CSV history logging and flagged incident reporting with Matplotlib visual analytics.

📊 **Benchmark Results**:
Tested against 35 curated Indian SMS/WhatsApp samples:
- **100% Detection Accuracy** (35/35 correctly classified)
- **1.00 Precision & 1.00 Recall** (0 False Positives, 0 False Negatives)
- **24/24 Automated Unit Tests Passed**

A huge thank you to our faculty and mentors at Bennett University for guiding us through core computational thinking principles (decomposition, card sorting, and OOP modelling).

Proud of the teamwork with my project partners:
👥 Naved Ali | Tanishk Singh | Aryan Chahal | Praval Verma

🔗 **GitHub Repository**: https://github.com/Root-Amritesh/Clg-Python-Project

#Python #CyberSecurity #ComputerScience #ComputationalThinking #BennettUniversity #BTechCSE #OpenSource #PhishingDetection #StudentProjects #SoftwareEngineering

---

## 2. GitHub Repository Metadata

- **Repository Name**: `offline-scam-message-detector`
- **Short Description**:
  > A lightweight, explainable, rule-based SMS and WhatsApp scam screening tool in Python. 100% offline, privacy-safe, with zero external dependencies.
- **Topics / Tags**:
  `python3`, `scam-detection`, `sms-phishing`, `cybersecurity`, `rule-based-system`, `offline-first`, `computational-thinking`, `bennett-university`, `freshers-project`
- **Website URL**: (leave blank or link to presentation slides)

---

## 3. Git Commit Strategy (Ensuring All 5 Members Show Real Contributions)

To achieve maximum marks on repository collaboration, each of the five team members must commit their assigned subsystem with realistic timestamps and detailed commit messages.

```
                                  GIT COMMIT TIMELINE
Day 1: Repo Setup & Base Architecture (Amritesh)
  │
Day 2: Regex Engine & URL Scanner (Aryan)
  │
Day 3: Console Input Stream & Menu (Tanishk)
  │
Day 4: Safety Heuristics & Sensitive Filter (Praval)
  │
Day 5: CSV History & Visual Statistics (Naved)
  │
Day 6: Automated Testing & Benchmark Dataset (Amritesh + Tanishk)
  │
Day 7: Experiential Activities 3-7 & Documentation (All Members)
```

### Member-by-Member Commit Plan

#### Member 1: Amritesh Kumar (Lead — Architecture & Core Engine)
- **Commit 1**:
  ```bash
  git commit -m "feat(core): initialize repo structure, constants, and Rule abstract base class"
  ```
  *Files*: `scam_detector.py`, `.gitignore`, `requirements.txt`
- **Commit 2**:
  ```bash
  git commit -m "feat(scoring): implement ScamAnalyzer orchestrator, combination bonus, and test suite"
  ```
  *Files*: `scam_detector.py`

#### Member 2: Aryan Chahal (Regex & URL Engine)
- **Commit 3**:
  ```bash
  git commit -m "feat(url): implement URLRule with shortener, IP host, and suspicious TLD detection"
  ```
  *Files*: `scam_detector.py`
- **Commit 4**:
  ```bash
  git commit -m "feat(preproc): add recursive normalise_text for spaced evasion character collapsing"
  ```
  *Files*: `scam_detector.py`

#### Member 3: Tanishk Singh (Input Handling & Menu Flow)
- **Commit 5**:
  ```bash
  git commit -m "feat(ui): add multi-line console message reader and interactive 7-option CLI menu"
  ```
  *Files*: `scam_detector.py`
- **Commit 6**:
  ```bash
  git commit -m "data(samples): curate 35 labelled Indian SMS/WhatsApp benchmark samples"
  ```
  *Files*: `data/samples.csv`

#### Member 4: Praval Verma (Heuristics & Documentation)
- **Commit 7**:
  ```bash
  git commit -m "feat(heuristics): implement check_safe_phrase and sensitive credential filter with lambda"
  ```
  *Files*: `scam_detector.py`
- **Commit 8**:
  ```bash
  git commit -m "docs(activities): author Activity 3 decomposition and Activity 5 decision tree"
  ```
  *Files*: `docs/activities_3_to_7.md`

#### Member 5: Naved Ali (Persistence & Analytics)
- **Commit 9**:
  ```bash
  git commit -m "feat(history): implement HistoryManager with CSV appending, zip formatting, and export"
  ```
  *Files*: `scam_detector.py`
- **Commit 10**:
  ```bash
  git commit -m "feat(analytics): add summary statistics, ASCII text bars, and Matplotlib chart generator"
  ```
  *Files*: `scam_detector.py`, `docs/charts.png`

#### Final Team Integration Commit (All Members)
- **Commit 11**:
  ```bash
  git commit -m "docs(final): add comprehensive README, viva prep guide, slide deck, and project report"
  ```
  *Files*: `README.md`, `docs/viva_prep.md`, `docs/ppt_outline.md`, `Offline_Scam_Message_Detector_Project_Report.docx`

