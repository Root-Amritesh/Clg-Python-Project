# Offline Scam Message Detector — Comprehensive Viva Voce Guide
**Course Code**: 2026CSAE100 — Computational Thinking and Programming  
**Bennett University, School of Computer Science Engineering and Technology**  
**Academic Year**: 2026–27 | **Batch**: B-27 / S14  
**Team Members**:
- Amritesh Kumar (S26CSEU0943) — Lead (Scoring Logic, OOP Architecture, Integration, Testing)
- Naved Ali (S26CSEU0955) — CSV History, Analytics, Flagged Reporting
- Tanishk Singh (S26CSEU0934) — Menu Flow, User Input Handling, Demo Benchmark
- Aryan Chahal (S26CSEU0933) — Regular Expressions, URL Heuristics, Edge-Case Auditing
- Praval Verma (S26CSEU0935) — Documentation, Flowchart Modeling, Visual Analytics

---

## Part 1: 40 Essential Viva Questions and Answers

### Section A: System Architecture & Core Functions (Q1 – Q10)

#### Q1: What does `ScamAnalyzer.analyse(message)` do from start to finish?
**Answer**: It acts as the pipeline controller:
1. Cleans the message via `preprocess()`.
2. Evaluates legitimate OTP context via `check_safe_phrase()` (applying a -20 discount if safe).
3. Iterates through all `KeywordRule` objects and records matching category points.
4. Calls `check_sensitive_info()` (suppressing OTP if legitimate delivery).
5. Extracts and scans URLs using `URLRule.check_urls()`.
6. Checks APKs, personal mobile numbers, and excessive punctuation via `check_other_signs()`.
7. Sums points, adds +10 combo bonus if $\ge 3$ red flags occur, and clamps the score between 0 and 100.
8. Classifies the verdict via `classify_verdict()` and returns an encapsulated `Result` object.

#### Q2: How does `KeywordRule.check(text)` ensure whole-word matching?
**Answer**: It uses `re.search(r"\b" + re.escape(pattern) + r"\b", text)`. The `\b` word boundary anchors ensure that a keyword like `"urgent"` does not falsely trigger inside legitimate words like `"detergent"`, and `"win"` does not match `"window"`. `re.escape()` prevents special regex metacharacters in phrases from corrupting the query.

#### Q3: What is the purpose of `normalise_text(text, depth)` and how does it use recursion?
**Answer**: Scammers evade keyword detection by inserting spaces between letters (e.g., `"O T P"`, `"P I N"`). `normalise_text` uses a regex lookahead `r"\b([a-zA-Z])\s+(?=[a-zA-Z]\b)"` to collapse spaced characters. If substitutions occur, the function recursively calls itself with `depth + 1` until no more spaced characters remain or the base case (`depth > 3`) is reached, preventing infinite recursion.

#### Q4: Why does `preprocess()` convert text to lowercase and remove non-ASCII characters?
**Answer**: Converting to lowercase standardises the string for case-insensitive keyword and domain comparisons. Removing non-ASCII characters strips distracting emoji (`🎉💰`) while preserving standard punctuation needed to inspect excessive exclamation points (`!!!`).

#### Q5: How does `check_safe_phrase()` eliminate false alarms on genuine OTP messages?
**Answer**: It inspects if phrases like `"do not share"` or `"never share"` exist. If present, it awards a 20-point safe discount. Concurrently, it checks regex delivery patterns (e.g., `r"your.*otp is\s*\d"`). If confirmed as an authentic dispatch rather than a request, the keyword `"otp"` is suppressed during sensitive data checks.

#### Q6: How does `check_sensitive_info()` use `filter` with `lambda`?
**Answer**:
```python
words_to_check = list(filter(lambda w: not (suppress_otp and w == "otp"), SENSITIVE_WORDS))
```
When `suppress_otp` is True, the `lambda` function filters out `"otp"`, while leaving high-risk harvest words like `"cvv"`, `"pin"`, and `"password"` active.

#### Q7: What heuristics are implemented in `URLRule.check_urls()`?
**Answer**:
1. **Shorteners**: Flags domains matching `SHORTENERS` (`bit.ly`, `tinyurl.com`) (+15 pts).
2. **Raw IPv4 Links**: Detects numerical IP hosts (`http://192.168.1.100`) (+25 pts).
3. **Suspicious TLDs**: Flags risky domain endings like `.xyz`, `.top`, `.tk` (+15 pts).
4. **Brand Impersonation**: Checks if trusted brand names (e.g., `"sbi"`, `"hdfc"`) appear in unverified domains not listed in `SAFE_DOMAINS` (+30 pts).

#### Q8: How is the combination bonus calculated and justified?
**Answer**: If 3 or more distinct positive warning signs are matched (`len(pos_findings) >= 3`), 10 points are added. In cybersecurity, multiple independent threat indicators (e.g., an urgent tone + fake link + bank mention) exponentially increase scam probability compared to an isolated urgency word.

#### Q9: What are the exact verdict thresholds, and why were they chosen?
**Answer**:
- **0 – 24**: `SAFE` (Permits single low-weight indicators like `"urgent"` [15] without raising alarms).
- **25 – 49**: `SUSPICIOUS` (Flags messages with at least one critical threat [25–30] or two moderate indicators).
- **50 – 100**: `LIKELY SCAM` (Represents compounded, high-severity attacks requiring immediate user warning).

#### Q10: How does `HistoryManager` prevent CSV injection and corruption?
**Answer**: It uses Python's standard `csv.writer`, which automatically sanitises text, wraps fields containing commas or quotes in RFC 4180-compliant quotation marks, and truncates previews to 70 characters.

---

### Section B: Python Language Concepts (Q11 – Q20)

#### Q11: Where is `enumerate()` used in the project, and why?
**Answer**: In `display_result()`, `display_history()`, `run_demo()`, and `run_tests()`. It generates an automatic, 1-indexed counter alongside sequence elements (`for i, (name, msg, check) in enumerate(tests, 1):`), eliminating manual counter variables.

#### Q12: Where is `zip()` used in the project?
**Answer**: In `display_history()`:
```python
for col_name, value in zip(header, row):
    print(f"    {col_name}: {value}")
```
It pairs column names with row values dynamically, ensuring clean tabular rendering.

#### Q13: What is the difference between a `list`, a `tuple`, and a `frozenset` in Python, and where is each used here?
**Answer**:
- **`list`** is mutable and ordered $\rightarrow$ used for `RULES` and findings that change dynamically.
- **`tuple`** is immutable and ordered $\rightarrow$ used for finding tuples `(points, description)` and `SUSPICIOUS_TLDS`.
- **`frozenset`** is immutable and unordered with $O(1)$ lookup $\rightarrow$ used for `SAFE_DOMAINS` and `SHORTENERS`.

#### Q14: Explain the `for...else` construct used in Python.
**Answer**: The `else` block following a `for` loop executes only if the loop completes normally without encountering a `break` statement. In `URLRule.check_urls()`, it handles cases where no URLs matched.

#### Q15: How does string slicing work in URL domain cleaning?
**Answer**:
```python
while domain and domain[-1] in ".,;:!?)":
    domain = domain[:-1]
```
`domain[-1]` accesses the trailing character via negative indexing, and `domain[:-1]` slices the string up to the second-to-last character, stripping punctuation without altering the host.

#### Q16: What is a custom exception class and why define `ScamDetectorError`?
**Answer**: Custom exceptions inherit from `Exception`. `ScamDetectorError` and its subclass `InvalidMessageError` differentiate domain-specific application errors (e.g., input exceeding 5,000 characters) from low-level runtime errors, allowing targeted `try/except` handling.

#### Q17: What is a `lambda` function and where is it used?
**Answer**: A `lambda` is an anonymous, single-expression function. In `ScamAnalyzer.analyse()`, it extracts sorting keys:
```python
sorted_findings = sorted(pos_findings, key=lambda f: f[0], reverse=True)
```
This sorts findings descending by weight to identify the dominant scam type.

#### Q18: What is the base case in `normalise_text()` and what happens without it?
**Answer**: The base case is `if depth > 3: return text` or `if spaced == text: return text`. Without a base case, recursive calls would consume the call stack and crash the program with a `RecursionError`.

#### Q19: Explain Encapsulation in your `Rule` class.
**Answer**: In `Rule`, attributes (`_name`, `_weight`, `_category`, `_description`) use a single leading underscore convention for private instance variables. Access is strictly controlled via public getter methods (`get_name()`, `get_weight()`), preventing accidental modification.

#### Q20: Explain Inheritance in your OOP design.
**Answer**: `KeywordRule` and `URLRule` both inherit from the abstract base class `Rule`. They inherit common properties (`_name`, `_weight`) and call `super().__init__()`, but provide specialised implementations of threat evaluation methods (`check()` vs `check_urls()`).

---

### Section C: Predict-the-Output Code Challenges (Q21 – Q25)

#### Q21: What is the output of the following snippet?
```python
message = "Urgent: call our helpline immediately."
# Urgency (+15)
analyzer = ScamAnalyzer()
res = analyzer.analyse(message)
print(res.score, res.verdict)
```
**Output**: `15 SAFE`  
*Explanation*: `"Urgent"` and `"immediately"` trigger the Urgency rule once (+15). Since 15 $\le 24$, the verdict is `SAFE`.

#### Q22: What is the output of this snippet?
```python
from scam_detector import classify_verdict
scores = [0, 24, 25, 49, 50, 100]
print([classify_verdict(s) for s in scores])
```
**Output**: `['SAFE', 'SAFE', 'SUSPICIOUS', 'SUSPICIOUS', 'LIKELY SCAM', 'LIKELY SCAM']`  
*Explanation*: Tests boundary conditions exactly at 24/25 and 49/50 thresholds.

#### Q23: What will `normalise_text("O T P   v e r i f y")` return?
**Output**: `"OTP verify"`  
*Explanation*: Collapses single letter spaced clusters into continuous words across recursive passes.

#### Q24: What is the output when this safe message is analysed?
```python
msg = "Your OTP is 123456. Never share it with anyone."
res = ScamAnalyzer().analyse(msg)
print(res.score, res.verdict)
```
**Output**: `0 SAFE`  
*Explanation*: Safe phrase discount (-20) applies, OTP is suppressed, score clamps to $\max(0, -20) = 0$.

#### Q25: What is the output of this URL domain parsing?
```python
url = "https://sbi.fake-login.xyz/verify.php?id=10"
domain = url.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
print(domain)
```
**Output**: `sbi.fake-login.xyz`  
*Explanation*: Strips protocol and splits on `/` and `?` to isolate the host.

---

### Section D: Find-the-Bug & Edge Cases (Q26 – Q30)

#### Q26: Find the bug in this naive keyword checker:
```python
def check_scam(text):
    if "win" in text:
        return True
    return False
```
**Bug**: Substring matching. It will return `True` for innocent words like `"winter"`, `"window"`, and `"Darwin"`.  
**Fix**: Use regex word boundaries: `re.search(r"\bwin\b", text)`.

#### Q27: What is the bug in this score calculation?
```python
score = sum(w for w, _ in findings)
if len(findings) >= 3:
    score += 10
# Missing bounds check!
```
**Bug**: If negative adjustments occur without positive findings, score could be negative. If multiple severe rules match, score can exceed 100.  
**Fix**: `score = max(0, min(100, score))`.

#### Q28: What bug occurs if a user inputs 100,000 characters into the console?
**Bug**: Unbounded input can cause excessive memory consumption or regex catastrophic backtracking (Denial of Service).  
**Fix**: Enforce `MAX_INPUT_LENGTH = 5000` in `preprocess()`, raising `InvalidMessageError` if exceeded.

#### Q29: What happens if `history.csv` is locked by Microsoft Excel when saving?
**Bug**: Python raises a `PermissionError`, causing an unhandled crash.  
**Fix**: Wrap file write operations in `try/except (OSError, PermissionError)` and raise a user-friendly `ScamDetectorError`.

#### Q30: Why was the URL regex `https?://[^\s<>\"']+` causing trailing punctuation issues?
**Bug**: If an SMS ends with `"...visit https://sbi.co.in."`, the period is captured into the URL, making domain lookups fail.  
**Fix**: Strip trailing punctuation `.,;:!?)` in `URLRule.check_urls()`.

---

### Section E: Code Modification & Extension Tasks (Q31 – Q35)

#### Q31: How would you add a new "Cryptocurrency Investment Scam" rule?
**Answer**: Append an entry to the `RULES` configuration list:
```python
{
    "name": "Crypto / Investment Fraud",
    "category": "crypto",
    "weight": 30,
    "patterns": ["bitcoin", "crypto", "double your money", "guaranteed profit", "telegram investment"],
    "description": "Promises unrealistic cryptocurrency or investment returns"
}
```
`ScamAnalyzer` automatically converts it into a `KeywordRule` without modifying core logic.

#### Q32: How would you adjust thresholds to make the tool more aggressive?
**Answer**: Change constants at the top of `scam_detector.py`:
```python
SAFE_THRESHOLD = 15          # was 24
SUSPICIOUS_THRESHOLD = 35    # was 49
```
Any message scoring 16+ would become Suspicious, and 36+ would become Likely Scam.

#### Q33: How would you detect fake email addresses in messages?
**Answer**:
1. Add an email regex: `re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)`.
2. Check if the email uses suspicious domains or impersonates official banking support addresses.

#### Q34: How would you export scan results to JSON instead of CSV?
**Answer**:
```python
import json
with open("history.json", "w", encoding="utf-8") as f:
    json.dump([r.to_dict() for r in history_results], f, indent=4)
```

#### Q35: How would you add a graphical file chooser for bulk message scanning?
**Answer**: Use Python's built-in `tkinter.filedialog.askopenfilename()`, read messages line-by-line, and pass each through `analyzer.analyse()`.

---

### Section F: Domain, Project Justification & Ethics (Q36 – Q40)

#### Q36: Why build this offline instead of using an online API or Cloud LLM?
**Answer**:
1. **Privacy & Data Security**: SMS messages contain sensitive personal information (account numbers, names, partial OTPs). Sending them to third-party cloud APIs leaks user data.
2. **Availability**: Users in low-connectivity areas need scam protection without internet access.
3. **Zero Cost & Latency**: Local execution takes under 3 milliseconds with zero API token costs.

#### Q37: Why avoid Machine Learning (ML) in this specific project?
**Answer**:
1. **Explainability**: ML models (e.g., Naive Bayes, Neural Nets) produce probabilistic predictions that are difficult for everyday users to interpret. Rule-based systems provide clear explanations for every point.
2. **Determinism**: The same input always produces the exact same score and reason.
3. **No Training Dataset Bias**: Avoids false positives caused by skewed training datasets.

#### Q38: How does the system handle mixed case and Unicode emoji?
**Answer**: `preprocess()` maps all characters to lowercase and strips non-ASCII emoji characters (`[^\x00-\x7F]+`), ensuring consistent matching across stylistic variations.

#### Q39: What are the primary failure modes / limitations of this tool?
**Answer**:
- Completely new scam terminology not yet in `RULES`.
- Non-English regional scripts (e.g., Hindi in Devanagari script).
- Shortened URLs cannot be resolved to their destination host without internet access.

#### Q40: What ethical considerations apply when deploying a scam detector?
**Answer**: The tool is an advisory warning aid, not an absolute guarantee. Disclaimers clarify that a "SAFE" verdict does not guarantee legitimacy, encouraging continued vigilance.

---

## Part 2: Individual Team-Member Viva Cheat Sheets

```
+--------------------------------------------------------------------------------------------------------+
|                                  TEAM MEMBER VIVA ASSIGNMENT MATRIX                                     |
+----------------------+---------------------------+--------------------------------+--------------------+
| Member Name          | Subsystem Owned           | Key Functions to Explain       | Core CTP Concepts  |
+----------------------+---------------------------+--------------------------------+--------------------+
| 1. Amritesh Kumar    | Architecture & Scoring    | ScamAnalyzer, KeywordRule,     | OOP, Inheritance,  |
|    (S26CSEU0943)     | Engine, Test Harness      | classify_verdict, run_tests    | Encapsulation, CLI |
|                      |                           |                                |                    |
| 2. Naved Ali         | CSV Persistence, Metrics, | HistoryManager, display_       | File I/O, zip(),   |
|    (S26CSEU0955)     | Visual Reporting          | statistics, _draw_charts       | map(), lambda      |
|                      |                           |                                |                    |
| 3. Tanishk Singh     | Multi-Line Input, Menu,   | get_message_input, main,       | Loops, try/except, |
|    (S26CSEU0934)     | Benchmark Dataset         | run_demo, load_samples         | EOFError, bounds   |
|                      |                           |                                |                    |
| 4. Aryan Chahal      | Regex Engine, URL Scans,  | URLRule.check_urls,            | Regex, frozenset,  |
|    (S26CSEU0933)     | Recursive Normalisation   | normalise_text, extract_urls   | Recursion, slicing |
|                      |                           |                                |                    |
| 5. Praval Verma      | Safety Heuristics, Tips,  | check_safe_phrase, get_tip,    | Higher-order funcs,|
|    (S26CSEU0935)     | Sensitive Data Checks     | check_sensitive_info           | filter(), dicts    |
+----------------------+---------------------------+--------------------------------+--------------------+
```

### Member 1: Amritesh Kumar (Lead — Architecture, Scoring & OOP)
- **Role**: Designed system architecture, OOP class hierarchy, scoring pipeline, combination bonus, and automated test harness.
- **Functions to Defend**:
  1. `ScamAnalyzer.analyse(message)`
  2. `KeywordRule.check(text)`
  3. `run_tests(analyzer)`
- **Core Concepts**: Class inheritance (`Rule` $\rightarrow$ `KeywordRule`), private attributes with getters, `sys.argv` command line handling.
- **Sample Examiner Questions**:
  1. *"Why did you design `Rule` as a base class rather than using standalone functions?"*
     - *Answer*: It enforces a clean interface (`check()`), groups rule properties with evaluation logic, and allows polymorphic extensions (like `URLRule`) without rewriting the analyzer.
  2. *"Explain how test assertion #6 verifies the 24-to-25 boundary."*
     - *Answer*: Test 6 sends `"This is an urgent notice."` scoring 15 (`SAFE`). Test 7 sends `"Urgent: click here..."` adding Link Push (+10) to reach 25 (`SUSPICIOUS`), proving the boundary transition.

---

### Member 2: Naved Ali (Persistence, Analytics & Visualisation)
- **Role**: Designed `HistoryManager`, CSV storage, summary statistics, text bar charts, and Matplotlib integration.
- **Functions to Defend**:
  1. `HistoryManager.save(message, result)` and `load()`
  2. `display_statistics(history_mgr)`
  3. `_draw_charts(verdicts, scores)`
- **Core Concepts**: File handling (`csv.reader`/`writer`), `map()` with `lambda`, pairing with `zip()`, fallback exception handling.
- **Sample Examiner Questions**:
  1. *"How did you use `zip()` when displaying history?"*
     - *Answer*: `zip(header, row)` binds each column header to its corresponding data value dynamically, allowing structured printing without hardcoded indices.
  2. *"How does the chart module behave if Matplotlib is not installed?"*
     - *Answer*: `try: import matplotlib` sets `HAS_MATPLOTLIB = False` on failure. `display_statistics()` prints clean ASCII text bar charts as a graceful fallback.

---

### Member 3: Tanishk Singh (Input Stream, Menu & Benchmark Dataset)
- **Role**: Developed console input ingestion, the 7-option menu loop, exception recovery, and curated the 35 labelled sample messages.
- **Functions to Defend**:
  1. `get_message_input()`
  2. `main()` menu loop
  3. `run_demo(analyzer)` & `load_samples()`
- **Core Concepts**: `while` loops, `try/except` with `(EOFError, KeyboardInterrupt)`, input validation, `csv.DictReader`.
- **Sample Examiner Questions**:
  1. *"How does `get_message_input()` know when the user is done typing?"*
     - *Answer*: It reads lines in a loop until the user enters an empty line (`line == ""`), which triggers a `break` and joins the buffered lines with `\n`.
  2. *"What happens if a user types 'abc' or '9' at the menu prompt?"*
     - *Answer*: `int(choice)` raises a `ValueError`, which is caught by `except ValueError:` to display a clean warning without crashing.

---

### Member 4: Aryan Chahal (Regex Engine, URL Parsing & Recursion)
- **Role**: Built URL parsing rules, shortener/IP/TLD detection, brand impersonation logic, and recursive text normalisation.
- **Functions to Defend**:
  1. `URLRule.check_urls(urls)`
  2. `normalise_text(text, depth)`
  3. `extract_urls(text)`
- **Core Concepts**: Regular expressions (`\b`, lookahead, quantifiers), recursion, string slicing, `frozenset`.
- **Sample Examiner Questions**:
  1. *"How does `normalise_text` detect spaced-out letters like 'O T P'?"*
     - *Answer*: It uses `re.sub(r"\b([a-zA-Z])\s+(?=[a-zA-Z]\b)", r"\1", text)` to collapse single letters followed by spaces, recurring up to depth 3.
  2. *"How do you verify if a domain like 'sbi-update.xyz' is impersonating SBI?"*
     - *Answer*: It checks if `"sbi"` is a substring of the domain, then checks if the domain exists in `SAFE_DOMAINS` (`sbi.co.in`). Since it does not match, a +30 Brand Impersonation penalty is applied.

---

### Member 5: Praval Verma (Heuristics, Sensitive Data & Flowcharts)
- **Role**: Implemented legitimate OTP delivery heuristics, sensitive data filters, safety recommendations, and decision tree flowcharts.
- **Functions to Defend**:
  1. `check_safe_phrase(text)`
  2. `check_sensitive_info(text, suppress_otp)`
  3. `get_tip(verdict)`
- **Core Concepts**: Higher-order `filter()` with `lambda`, membership testing (`in`), dictionary dispatch, decision flowcharting.
- **Sample Examiner Questions**:
  1. *"Why does `check_sensitive_info` use `filter` with `lambda`?"*
     - *Answer*: When a message is identified as a legitimate OTP dispatch, `filter(lambda w: not (suppress_otp and w == "otp"), SENSITIVE_WORDS)` excludes `"otp"` while keeping checks for `"cvv"` or `"pin"` active.
  2. *"How does `get_tip()` determine its output?"*
     - *Answer*: It uses a dictionary mapping verdicts (`SAFE`, `SUSPICIOUS`, `LIKELY SCAM`) to advisory strings via `tips.get(verdict)`.

---

## Part 3: One-Page Whole-Project Summary Sheet

- **Problem**: SMS/WhatsApp phishing and financial fraud target smartphone users with urgency and fake claims.
- **Solution**: A lightweight, explainable, rule-based detection engine in Python that operates 100% offline.
- **Technical Architecture**:
  - `ScamAnalyzer` orchestrates the pipeline.
  - `Rule` base class with `KeywordRule` and `URLRule` subclasses.
  - `Result` holds score, verdict, and reason breakdown.
  - `HistoryManager` logs scans to CSV and generates reports.
- **Mathematical Scoring Formula**:
  $$\text{Score} = \min\left(100, \max\left(0, \sum w_{\text{rules}} + \text{Bonus}_{(\ge 3)} - \text{Discount}_{(\text{safe})}\right)\right)$$
- **Classification**:
  - $0 \le \text{Score} \le 24 \rightarrow \text{SAFE}$
  - $25 \le \text{Score} \le 49 \rightarrow \text{SUSPICIOUS}$
  - $50 \le \text{Score} \le 100 \rightarrow \text{LIKELY SCAM}$
- **Benchmark Performance**: 35 labelled samples $\rightarrow$ **100% Accuracy, 1.00 Precision, 1.00 Recall, 0 False Positives, 0 False Negatives**.
- **Automated Test Suite**: 24 tests covering normal, boundary, empty, unicode, emoji, and evasion patterns $\rightarrow$ **24/24 PASS**.
- **Libraries Used**: `re`, `csv`, `os`, `sys`, `datetime` (Standard Library) + optional `matplotlib`.

