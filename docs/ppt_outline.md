# Offline Scam Message Detector — Presentation Slide Deck (15 Slides)
**Course**: 2026CSAE100 — Computational Thinking and Programming  
**School**: Computer Science Engineering and Technology, Bennett University  
**Academic Year**: 2026–27 | **Section**: B-27 / S14  

---

### Slide 1: Title & Team Introduction
- **Title**: Offline Scam Message Detector
- **Subtitle**: Rule-Based SMS and WhatsApp Threat Screening in Python
- **Institution**: Bennett University, Greater Noida
- **Team Members**:
  - Amritesh Kumar (S26CSEU0943) — Project Lead
  - Naved Ali (S26CSEU0955)
  - Tanishk Singh (S26CSEU0934)
  - Aryan Chahal (S26CSEU0933)
  - Praval Verma (S26CSEU0935)
- **Speaker Notes**:
  > "Good morning respected evaluators. Today, our group presents our Sem-1 Computational Thinking and Programming project: the Offline Scam Message Detector. Our goal was to build a reliable, explainable, and privacy-preserving tool to screen fraudulent SMS and WhatsApp communications on personal devices without relying on third-party cloud services."

---

### Slide 2: Problem Statement & Motivation
- **Context**: Rapid rise in mobile financial fraud in India (fake KYC expiry, lottery claims, UPI collect requests).
- **The Core Problem**: Smartphone users have only seconds to decide whether an urgent message is authentic before clicking a dangerous link.
- **Privacy & Connectivity Dilemma**: Cloud-based security tools leak personal SMS data and fail in low-connectivity areas.
- **Project Solution**: An offline screening tool that analyses message syntax, URLs, and sensitive demands locally in under 3 milliseconds.
- **Speaker Notes**:
  > "Mobile phishing causes significant financial losses daily. Everyday users need a fast first-pass check. We chose to build this strictly offline because text messages often contain private data like account numbers and personal names. Our program protects privacy while remaining lightweight and fast."

---

### Slide 3: Project Objectives
1. **Local Message Analysis**: Ingest multi-line text messages and evaluate them locally without internet access.
2. **Multi-Vector Detection**: Screen for panic keywords, banking threats, fee demands, and malicious link anatomy.
3. **Transparent Scoring**: Calculate a bounded 0–100 risk score and classify it into Safe, Suspicious, or Likely Scam.
4. **Explainable Findings**: Itemise each triggered warning sign so users understand the reasoning behind the verdict.
5. **Session Persistence**: Maintain audit logs in CSV, calculate summary metrics, and export flagged threat reports.
- **Speaker Notes**:
  > "We established five concrete objectives. The most critical is explainability: instead of showing an opaque label, the tool shows exactly which words, links, and patterns contributed points to the total score."

---

### Slide 4: System Architecture & Data Flow
- **Pipeline Stages**:
  1. *Input & Preprocessing*: Multi-line ingestion, non-ASCII stripping, recursive evasion normalization.
  2. *Threat Detection Engine*: Safe phrase check $\rightarrow$ Keyword rules $\rightarrow$ Sensitive data $\rightarrow$ URL analysis.
  3. *Scoring Engine*: Points sum + 10-point combination bonus (for $\ge 3$ findings) - safe discounts.
  4. *Classification & Advice*: Threshold mapping (0-24 Safe, 25-49 Suspicious, 50-100 Likely Scam) + tailored tips.
  5. *Persistence*: Append to `history.csv` and export `flagged_report.txt`.
- **Speaker Notes**:
  > "Here is our end-to-end data pipeline. It starts with text cleaning, moves through four parallel detection checks, aggregates the weighted points with a multi-finding combination bonus, and produces both user-facing advice and persistent CSV records."

---

### Slide 5: Activity 3 — Problem Decomposition
- **Computational Thinking Concept**: Breaking a monolithic challenge into modular sub-problems.
- **Sub-Problems to Modules**:
  - *SP1: Ingestion & Evasion* $\rightarrow$ `preprocess()` & recursive `normalise_text()`.
  - *SP2: Pattern Identification* $\rightarrow$ `KeywordRule.check()`, `URLRule.check_urls()`.
  - *SP3: Context Discrimination* $\rightarrow$ `check_safe_phrase()` & `check_sensitive_info()`.
  - *SP4: Decision & Classification* $\rightarrow$ `ScamAnalyzer.analyse()` & `classify_verdict()`.
  - *SP5: Persistence & Analytics* $\rightarrow$ `HistoryManager` (`save`, `load`, statistics).
- **Speaker Notes**:
  > "In Activity 3, we mapped the problem into distinct sub-problems, each handled by a dedicated Python function. This ensures single-responsibility design and makes the codebase straightforward to test and explain."

---

### Slide 6: Activity 4 — Card Sorting & Approach Comparison
- **Card Sorting**: Organised system inputs, rules, data stores, and processing routines into logical clusters.
- **Approach Evaluation**:
  - *Approach 1 (Simple Keyword Count)*: Low accuracy (50%), high false positives on genuine OTPs.
  - *Approach 2 (Weighted Rules + Regex Engine — CHOSEN)*: 100% explainable, deterministic, zero dependencies.
  - *Approach 3 (Machine Learning Classifier)*: Black-box nature, requires training data, complex for 1st-year scope.
- **Data Structures Chosen**:
  - `list` of `dict`s for extensible rule definitions.
  - `frozenset` for immutable $O(1)$ domain and shortener lookups.
- **Speaker Notes**:
  > "In Activity 4, we compared three algorithmic paradigms. We selected the weighted rule engine because it offers 100% explainability, zero dependency overhead, and full determinism: identical inputs always yield identical risk scores."

---

### Slide 7: Activity 5 — Decision Tree & Flowchart
- **Decision Logic**:
  - Empty message $\rightarrow$ Score 0 (`SAFE`).
  - Safe OTP phrase (`"do not share"`) present $\rightarrow$ Apply -20 point discount; suppress OTP word.
  - Keyword rule checks across 7 categories (+10 to +30 pts).
  - URL inspection: Shorteners (+15), Raw IPs (+25), Risky TLDs (+15), Brand Spoofing (+30).
  - Out-of-band checks: APK links (+20), 10-digit mobile (+10), excessive punctuation (+5).
  - Combination Bonus: If $\ge 3$ positive findings, add +10 bonus points.
  - Clamp: $\text{Score} = \max(0, \min(100, \text{Total}))$.
- **Speaker Notes**:
  > "Our decision tree evaluates threat signals systematically. A key design element is our safe-phrase check: if a message says 'Do not share your OTP', the detector knows it's a legitimate warning, not an attack, preventing false positives."

---

### Slide 8: Activity 6 — Object-Oriented Modelling
- **Class Architecture**:
  - `Rule` (Abstract Base Class): Encapsulates private attributes (`_name`, `_weight`) with public getters.
  - `KeywordRule` & `URLRule`: Subclasses implementing specialised detection logic (Inheritance).
  - `ScamAnalyzer`: Composes rules and history manager to run scans (Composition).
  - `Result`: Encapsulates output findings, score, verdict, and recommendations.
  - `HistoryManager`: Manages file I/O operations for CSV logging and reports.
- **Exception Hierarchy**: `ScamDetectorError` $\rightarrow$ `InvalidMessageError`.
- **Speaker Notes**:
  > "For Activity 6, we structured our code using clean OOP principles. The Rule hierarchy demonstrates inheritance and encapsulation, while ScamAnalyzer uses composition to assemble rules and storage managers cleanly."

---

### Slide 9: Live Demo Output 1 — Likely Scam (Banking Phishing)
- **Input Message**:
  > *"Dear customer your SBI KYC expired. Account will be blocked today. Click here http://sbi-kyc-update.xyz to update immediately"*
- **Scan Result**:
  - **Risk Score**: 100 / 100
  - **Verdict**: `LIKELY SCAM` | **Type**: Bank / KYC Threat
  - **Findings Breakdown**:
    - `+25` Threatens to block your account or demands KYC update
    - `+15` Creates panic or urgency to act fast
    - `+10` Pushes you to click a suspicious link
    - `+15` Suspicious domain ending '.xyz'
    - `+30` Fake SBI domain: sbi-kyc-update.xyz
    - `+10` Combination bonus (5 warning signs together)
  - **Tip**: *"DO NOT reply, click links, or share any info. Block the sender."*
- **Speaker Notes**:
  > "Here is an authentic test run on a common SBI phishing message. Notice how the engine identifies five independent red flags. Because five signs were found, the combination bonus was applied, bringing the score to 105, which capped cleanly at 100."

---

### Slide 10: Live Demo Output 2 — Safe Alert (Legitimate Banking OTP)
- **Input Message**:
  > *"482913 is your OTP for payment of Rs 499 at Amazon. Do not share it with anyone."*
- **Scan Result**:
  - **Risk Score**: 0 / 100
  - **Verdict**: `SAFE` | **Type**: None
  - **Findings Breakdown**:
    - `-20` 'Do not share' warning found (normal in genuine OTP messages)
  - **Tip**: *"No strong scam pattern found. Stay alert for new tactics."*
- **Speaker Notes**:
  > "Here is the critical counterpart: a genuine Amazon OTP. Naive detectors flag this because of the word 'OTP'. Our system identifies the delivery pattern and the 'do not share' warning, applies the safe discount, and correctly outputs a Score of 0."

---

### Slide 11: Activity 7 — Data Interpretation & Benchmark Metrics
- **Dataset**: 35 curated Indian SMS/WhatsApp samples (20 Scams, 15 Safe).
- **Confusion Matrix**:
  - True Positives (Scams caught): **20**
  - True Negatives (Safe passed): **15**
  - False Positives (Safe wrongly flagged): **0**
  - False Negatives (Scams missed): **0**
- **Evaluation Metrics**:
  - **Accuracy**: $100.0\%$ (35 / 35)
  - **Precision**: $1.00$ ($TP / [TP + FP]$)
  - **Recall**: $1.00$ ($TP / [TP + FN]$)
  - **F1-Score**: $1.00$
- **Speaker Notes**:
  > "In Activity 7, we ran our detector across a 35-sample benchmark representing common Indian fraud patterns. The tool achieved 100% accuracy with zero false positives, proving the effectiveness of our weighted heuristics."

---

### Slide 12: Automated Test Harness (Quality Assurance)
- **Coverage**: 24 automated test cases covering diverse execution paths:
  - Normal attack patterns (KYC, fake jobs, lottery, UPI fraud).
  - Exact boundary transitions (Score 15 $\rightarrow$ Safe, Score 25 $\rightarrow$ Suspicious, Score 50 $\rightarrow$ Scam).
  - Edge cases: whitespace-only, newlines, raw emoji (`🎉💰`), unicode strings.
  - Word boundary checks (ensuring `"detergent"` does not match `"urgent"`).
  - Spaced evasion detection (`"O T P"` $\rightarrow$ `"otp"`).
  - Score clamping at 100.
- **Result**: **24 passed, 0 failed (100% pass rate)** via `python scam_detector.py --test`.
- **Speaker Notes**:
  > "To ensure rigorous quality, we built an automated test harness with 24 assertion cases. It tests boundary conditions at scores 24, 25, 49, and 50, verifying that edge cases and evasion attempts are handled properly."

---

### Slide 13: Team Member Contributions
| Member | Enrollment | Primary Responsibility & Modules |
|---|---|---|
| **Amritesh Kumar** | S26CSEU0943 | Project Lead; Rule Engine, Scoring Architecture, OOP Design, Testing Harness |
| **Naved Ali** | S26CSEU0955 | History Manager, CSV Persistence, Analytics Engine, Visual Charts |
| **Tanishk Singh** | S26CSEU0934 | Console Ingestion Pipeline, 7-Option Menu Flow, 35-Sample Benchmark |
| **Aryan Chahal** | S26CSEU0933 | URL Rule Engine, Regex Domain Parser, Recursive Text Normalisation |
| **Praval Verma** | S26CSEU0935 | Safe-Phrase Heuristics, Sensitive Filter, Decision Tree & Flowcharts |
- **Speaker Notes**:
  > "Our project was developed collaboratively with clear module ownership. Each member designed and implemented their assigned subsystem, and every team member is fully prepared to explain their code during the viva."

---

### Slide 14: Limitations & Future Enhancements
- **Current Limitations**:
  - Predefined vocabulary cannot anticipate novel slang or newly emerging scam hooks without rule updates.
  - Shortened URLs cannot be unmasked to their destination host without internet access.
  - Focused primarily on English and Romanised Hinglish texts.
- **Future Roadmap**:
  - Implement a lightweight graphical user interface using Python's built-in `tkinter`.
  - Externalise detection rules into a user-editable JSON configuration file.
  - Add native transliteration support for regional Indian scripts (Devanagari, Tamil, Telugu).
- **Speaker Notes**:
  > "We recognise the practical limits of rule-based systems. While highly effective for known threat vectors, new scam patterns require rule updates. In the future, we plan to add a Tkinter GUI and support regional Indian languages."

---

### Slide 15: Conclusion & References
- **Conclusion**:
  - Successfully developed an offline, privacy-safe, explainable scam detection tool in pure Python.
  - Fulfilled all Milestone 2 course requirements and Experiential Activities 3–7.
  - 100% test pass rate across 24 automated unit tests and 35 benchmark samples.
- **References**:
  1. Bennett University Course Manual: *Computational Thinking and Programming (2026CSAE100)*.
  2. Python 3.13 Standard Library Documentation (`re`, `csv`, `os`, `sys`, `datetime`).
  3. Reserve Bank of India (RBI) / Cyber Crime Portal Awareness Guidelines on Phishing.
- **Thank You! Any Questions?**
- **Speaker Notes**:
  > "Thank you for your time and guidance. We are now happy to take any questions and demonstrate individual code modules."

