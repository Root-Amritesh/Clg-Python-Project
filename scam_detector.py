"""
Offline Scam Message Detector
=============================
Rule-based SMS / WhatsApp scam screening using Python.

Course  : 2026CSAE100 - Computational Thinking and Programming
Team    : Amritesh Kumar (S26CSEU0943), Naved Ali (S26CSEU0955),
          Tanishk Singh (S26CSEU0934), Aryan Chahal (S26CSEU0933),
          Praval Verma (S26CSEU0935)
Batch   : B-27 / S14, Bennett University, 2026-27

Usage   : python scam_detector.py          (interactive menu)
          python scam_detector.py --test   (run automated tests)
          python scam_detector.py --demo   (run demo on labelled samples)

Libraries: re, csv, os, sys, datetime (standard library only)
           matplotlib (optional, for charts — graceful fallback)
"""

# ──────────────────────────────────────────────────────────────
# IMPORTS
# ──────────────────────────────────────────────────────────────
import re
import csv
import os
import sys
from datetime import datetime

# Optional matplotlib (graceful fallback to text)
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# ──────────────────────────────────────────────────────────────
# CUSTOM EXCEPTION  (Exception handling — course concept)
# ──────────────────────────────────────────────────────────────

class ScamDetectorError(Exception):
    """Custom exception for scam detector errors."""
    pass


class InvalidMessageError(ScamDetectorError):
    """Raised when a message is invalid for analysis."""
    pass


# ──────────────────────────────────────────────────────────────
# CONSTANTS  (all weights and thresholds in one place)
# ──────────────────────────────────────────────────────────────

SAFE_THRESHOLD      = 24     # 0-24 = Safe
SUSPICIOUS_THRESHOLD = 49    # 25-49 = Suspicious
MAX_SCORE           = 100    # 50-100 = Likely Scam
COMBO_BONUS         = 10     # bonus when 3+ rules trigger
COMBO_MIN_FINDINGS  = 3
SAFE_PHRASE_DISCOUNT = 20    # deducted for genuine OTP messages
MAX_INPUT_LENGTH    = 5000   # reject extremely long inputs

HISTORY_FILE = "history.csv"
REPORT_FILE  = "flagged_report.txt"
SAMPLES_FILE = os.path.join("data", "samples.csv")

# ──────────────────────────────────────────────────────────────
# RULE DEFINITIONS  (list of dicts — course concept: dict, list)
# ──────────────────────────────────────────────────────────────

RULES = [
    {
        "name":     "Bank / KYC Threat",
        "category": "kyc",
        "weight":   25,
        "patterns": [
            "kyc", "account blocked", "account suspended", "verify your account",
            "update kyc", "account will be closed", "deactivated", "pan card",
            "aadhaar update", "re-kyc", "complete verification", "temporarily locked",
            "your account has been", "account on hold",
        ],
        "description": "Threatens to block your account or demands KYC update",
    },
    {
        "name":     "Urgency / Pressure",
        "category": "urgency",
        "weight":   15,
        "patterns": [
            "act now", "immediate action", "urgent", "expires today",
            "last chance", "hurry", "limited time", "within 24 hours",
            "action required", "immediately", "respond immediately",
            "time is running out", "don't delay",
        ],
        "description": "Creates panic or urgency to act fast",
    },
    {
        "name":     "Link Push",
        "category": "link_push",
        "weight":   10,
        "patterns": [
            "click here", "click link", "click this link", "open link",
            "visit link", "update here", "verify here", "claim here",
            "tap here", "click below",
        ],
        "description": "Pushes you to click a suspicious link",
    },
    {
        "name":     "Prize / Lottery",
        "category": "prize",
        "weight":   25,
        "patterns": [
            "congratulations", "you have won", "lottery", "prize",
            "lucky winner", "claim your reward", "free gift",
            "you are chosen", "winner", "cash prize", "you won",
            "lucky draw", "selected as winner",
        ],
        "description": "Claims you won a prize or lottery you never entered",
    },
    {
        "name":     "Fake Job / Fee",
        "category": "job",
        "weight":   30,
        "patterns": [
            "work from home", "earn money", "part time job",
            "registration fee", "joining fee", "pay to join",
            "easy money", "online job", "data entry job",
            "guaranteed income", "no experience needed",
            "earn daily", "start earning",
        ],
        "description": "Offers a fake job or demands an upfront fee",
    },
    {
        "name":     "UPI / Payment Trick",
        "category": "upi",
        "weight":   25,
        "patterns": [
            "send money", "pay rs", "upi", "collect request",
            "google pay", "phonepe", "paytm", "gpay",
            "scan this qr", "scan qr", "payment pending",
            "refund processing", "cashback",
        ],
        "description": "Attempts a UPI payment trick or fake refund",
    },
    {
        "name":     "Authority Impersonation",
        "category": "authority",
        "weight":   20,
        "patterns": [
            "rbi", "reserve bank", "income tax", "police",
            "cyber cell", "government", "sebi", "trai",
            "legal action", "court notice", "arrest warrant",
            "legal proceedings", "customs department",
        ],
        "description": "Impersonates a government or law enforcement authority",
    },
]

SENSITIVE_WORDS = [
    "otp", "pin", "cvv", "password", "card number", "bank details",
    "credit card", "debit card", "account number", "ifsc",
    "netbanking password", "passcode", "secret code",
]
SENSITIVE_WEIGHT = 30
SENSITIVE_DESC = "Asks for sensitive details (OTP, PIN, CVV, password, etc.)"

SAFE_PHRASES = ("do not share", "never share", "don't share", "do not disclose")

# Patterns that indicate a LEGITIMATE OTP delivery (not a request)
OTP_DELIVERY_PATTERNS = [
    r"your\b.*\botp is\s*\d",       # "Your OTP is 1234" or "Your Aadhaar OTP is 1234"
    r"\botp\s*:\s*\d",              # "OTP: 1234"
    r"\botp\s+is\s+\d",            # "OTP is 1234"
    r"\botp for\s",                 # "OTP for transaction"
    r"one.time password",           # "one-time password"
    r"verification code",           # "verification code"
    r"\botp\b.*\bvalid for",        # "OTP ... valid for 10 minutes"
]

SAFE_DOMAINS = frozenset([
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "rbi.org.in", "amazon.in", "flipkart.com", "google.com",
    "gov.in", "paytm.com", "phonepe.com", "irctc.co.in",
    "npci.org.in", "microsoft.com",
])

SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
])

SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".club", ".buzz", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".click", ".win", ".loan",
)

KNOWN_BRANDS = (
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
    "amazon", "flipkart", "jio", "airtel", "google", "rbi",
    "irctc", "whatsapp",
)


# ──────────────────────────────────────────────────────────────
# OOP CLASSES  (Activity 6 — Object Modelling)
# ──────────────────────────────────────────────────────────────

class Rule:
    """
    Base class for all detection rules.
    Demonstrates: encapsulation (private attrs + getters), inheritance.
    """
    def __init__(self, name, category, weight, description):
        self._name = name              # private attribute
        self._category = category
        self._weight = weight
        self._description = description

    # Getters (encapsulation)
    def get_name(self):
        """Return the rule name."""
        return self._name

    def get_weight(self):
        """Return the rule weight."""
        return self._weight

    def get_category(self):
        """Return the rule category."""
        return self._category

    def get_description(self):
        """Return the rule description."""
        return self._description

    def check(self, text):
        """Check if this rule matches the text. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement check()")


class KeywordRule(Rule):
    """
    Rule that matches keywords/phrases using regex word boundaries.
    Inherits from Rule (Activity 6 — inheritance).
    """
    def __init__(self, name, category, weight, description, patterns):
        super().__init__(name, category, weight, description)
        self._patterns = patterns

    def check(self, text):
        """Return True if any pattern matches as a whole word."""
        for pattern in self._patterns:
            if re.search(r"\b" + re.escape(pattern) + r"\b", text):
                return True
        return False


class URLRule(Rule):
    """
    Rule that inspects extracted URLs for suspicious signs.
    Inherits from Rule (Activity 6 — inheritance).
    """
    def __init__(self):
        super().__init__("URL Inspection", "url", 0, "Inspects URLs for suspicious patterns")

    def check_urls(self, urls):
        """
        Inspect a list of URLs.
        Returns list of tuples: (points, description, category).
        Uses: break/continue, membership (in), string methods.
        """
        findings = []
        for url in urls:
            domain = url.replace("https://", "").replace("http://", "")
            domain = domain.split("/")[0].split("?")[0]  # strip path and query
            # Strip trailing punctuation (string slicing concept)
            while domain and domain[-1] in ".,;:!?)":
                domain = domain[:-1]

            # 1. Shortened URLs
            for short in SHORTENERS:
                if short in domain:
                    findings.append((15, f"Shortened URL hides destination: {domain}", "Suspicious URL"))
                    break  # break from inner loop only (loop control)

            # 2. Raw IP address
            if re.search(r"^\d{1,3}(\.\d{1,3}){3}", domain):
                findings.append((25, f"Raw IP address link: {domain}", "Suspicious URL"))
                continue  # skip further domain checks for IP (loop control)

            # 3. Suspicious TLDs
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    findings.append((15, f"Suspicious domain ending '{tld}': {domain}", "Suspicious URL"))
                    break

            # 4. Brand impersonation
            for brand in KNOWN_BRANDS:
                if brand in domain:
                    # Check if it's a known safe domain (membership — in)
                    is_safe = any(sd in domain for sd in SAFE_DOMAINS)
                    if not is_safe:
                        findings.append((30, f"Fake {brand.upper()} domain: {domain}", "Brand Impersonation"))
                    break
        else:
            # for-else: runs if loop completes without break (no URLs at all)
            pass  # no URLs to check — that's fine

        return findings


class Result:
    """
    Stores the analysis result for a single message.
    Demonstrates: encapsulation, dict-like access.
    """
    def __init__(self, score, verdict, scam_type, findings, tip):
        self.score = score
        self.verdict = verdict
        self.scam_type = scam_type
        self.findings = findings   # list of (points, description)
        self.tip = tip

    def to_dict(self):
        """Convert to dictionary for easy access."""
        return {
            "score":    self.score,
            "verdict":  self.verdict,
            "type":     self.scam_type,
            "findings": self.findings,
            "tip":      self.tip,
        }


class HistoryManager:
    """
    Manages CSV history file — read, write, statistics.
    Demonstrates: file handling, exception handling.
    """
    def __init__(self, filepath=HISTORY_FILE):
        self._filepath = filepath
        self._columns = ["Timestamp", "Score", "Verdict", "Type", "Rules_Matched", "Message_Preview"]

    def save(self, message, result):
        """Append a check result to history CSV."""
        file_exists = os.path.isfile(self._filepath)
        try:
            with open(self._filepath, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(self._columns)
                preview = message.replace("\n", " ").strip()[:70]
                rules_str = " | ".join(desc for _, desc in result.findings if _ > 0)
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    result.score, result.verdict, result.scam_type,
                    rules_str or "None", preview,
                ])
        except (OSError, PermissionError) as e:
            raise ScamDetectorError(f"Cannot write history: {e}")

    def load(self):
        """Load all history rows. Returns (header, data_rows)."""
        if not os.path.isfile(self._filepath):
            raise FileNotFoundError(f"No history file found: {self._filepath}")
        with open(self._filepath, "r", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        if len(rows) <= 1:
            return rows[0] if rows else self._columns, []
        return rows[0], rows[1:]

    def clear(self):
        """Delete the history file."""
        if os.path.isfile(self._filepath):
            os.remove(self._filepath)
            return True
        return False


# ──────────────────────────────────────────────────────────────
# TEXT NORMALISATION  (uses RECURSION — course concept)
# ──────────────────────────────────────────────────────────────

def normalise_text(text, depth=0):
    """
    Recursively normalise text for better matching:
    1. Collapse spaced-out letters like 'O T P' → 'otp'
    2. Strip emoji/non-ASCII characters
    3. Collapse repeated punctuation ('!!!' → '!!!')  [kept for detection]

    Uses RECURSION with a base case (depth limit).
    Also uses: string methods, re, slicing.
    """
    if depth > 3:
        return text  # base case: prevent infinite recursion

    # Step 1: collapse spaced-out single letters (e.g., "O T P" → "OTP")
    spaced = re.sub(r"\b([a-zA-Z])\s+(?=[a-zA-Z]\b)", r"\1", text)

    # If we made changes, recurse to catch remaining patterns
    if spaced != text:
        return normalise_text(spaced, depth + 1)

    return text  # base case: no more changes


def preprocess(message):
    """
    Full preprocessing pipeline.
    Uses: string methods (.strip, .lower), custom function, validation.
    """
    text = message.strip()
    if len(text) > MAX_INPUT_LENGTH:
        raise InvalidMessageError(f"Message too long ({len(text)} chars, max {MAX_INPUT_LENGTH})")
    if not text:
        raise InvalidMessageError("Empty message")

    # Remove non-ASCII (emoji etc.) but keep basic punctuation
    text = re.sub(r'[^\x00-\x7F]+', ' ', text)
    # Normalise spaced-out evasion attempts (recursive)
    text = normalise_text(text)
    return text.lower()


# ──────────────────────────────────────────────────────────────
# CORE ANALYSIS FUNCTIONS
# ──────────────────────────────────────────────────────────────

def extract_urls(text):
    """Extract URLs from text using regex."""
    return re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text)


def check_safe_phrase(text):
    """
    Check if the message contains genuine OTP delivery phrases.
    Uses: membership (in), any(), lambda.
    """
    has_safe = any(phrase in text for phrase in SAFE_PHRASES)
    is_otp_delivery = any(
        re.search(pat, text) is not None
        for pat in OTP_DELIVERY_PATTERNS
    )
    return has_safe, is_otp_delivery


def check_sensitive_info(text, suppress_otp=False):
    """
    Check if the message requests sensitive information.
    If suppress_otp is True, skip 'otp' (it's a legit OTP delivery).
    Uses: filter with lambda (course concept).
    """
    words_to_check = list(
        filter(lambda w: not (suppress_otp and w == "otp"), SENSITIVE_WORDS)
    )
    for word in words_to_check:
        if re.search(r"\b" + re.escape(word) + r"\b", text):
            return True, word
    return False, None


def check_other_signs(text):
    """
    Check miscellaneous indicators: APK files, personal numbers, punctuation.
    Returns list of (points, description, category).
    """
    findings = []
    # APK file
    if re.search(r"\.apk\b", text):
        findings.append((20, "Contains APK file download link (malware risk)", "Malware"))
    # Indian mobile number (10 digits starting with 6-9)
    if re.search(r"\b[6-9]\d{9}\b", text):
        findings.append((10, "Personal mobile number found (legit services use short codes)", "Suspicious Sender"))
    # Excessive punctuation
    if re.search(r"[!]{3,}|[?]{3,}", text):
        findings.append((5, "Excessive punctuation (!!!/???) — pressure tactic", "Pressure"))
    return findings


def classify_verdict(score):
    """
    Classify score into verdict string.
    Uses: conditional statements (course concept).
    """
    if score <= SAFE_THRESHOLD:
        return "SAFE"
    elif score <= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    else:
        return "LIKELY SCAM"


def get_tip(verdict):
    """Return a safety tip based on verdict. Uses: dict lookup."""
    tips = {
        "SAFE":        "No strong scam pattern found. Stay alert for new tactics.",
        "SUSPICIOUS":  "Be cautious! Do NOT click links or share details. Verify with official channels.",
        "LIKELY SCAM": "DO NOT reply, click links, or share any info. Block the sender. Report if needed.",
    }
    return tips.get(verdict, "Stay safe online.")


# ──────────────────────────────────────────────────────────────
# MAIN ANALYSER  (ScamAnalyzer class — Activity 6)
# ──────────────────────────────────────────────────────────────

class ScamAnalyzer:
    """
    Orchestrates the full analysis pipeline.
    Composes: KeywordRule objects, URLRule, HistoryManager.
    Demonstrates: composition, encapsulation.
    """
    def __init__(self):
        # Build Rule objects from RULES config (list comprehension)
        self._keyword_rules = [
            KeywordRule(r["name"], r["category"], r["weight"],
                        r["description"], r["patterns"])
            for r in RULES
        ]
        self._url_rule = URLRule()
        self._history = HistoryManager()

    def analyse(self, message):
        """
        Full analysis pipeline. Returns a Result object.
        Uses: enumerate, lambda with sorted, list comprehension,
              break/continue, membership, exception handling.
        """
        # Step 1: Preprocess
        try:
            text = preprocess(message)
        except InvalidMessageError:
            return Result(0, "SAFE", "None", [], get_tip("SAFE"))

        findings = []  # list of (points, description, category)

        # Step 2: Check safe phrases
        has_safe, is_otp_delivery = check_safe_phrase(text)
        if has_safe:
            findings.append((-SAFE_PHRASE_DISCOUNT,
                            "'Do not share' warning found (normal in genuine OTP messages)",
                            "Safe Notice"))

        # Step 3: Keyword rule checks (using Rule objects)
        for rule in self._keyword_rules:
            if rule.check(text):
                findings.append((rule.get_weight(), rule.get_description(), rule.get_name()))

        # Step 4: Sensitive info check (suppress 'otp' if OTP delivery)
        found_sensitive, matched_word = check_sensitive_info(text, suppress_otp=is_otp_delivery)
        if found_sensitive:
            findings.append((SENSITIVE_WEIGHT, SENSITIVE_DESC, "Sensitive Info"))

        # Step 5: URL checks
        urls = extract_urls(text)
        url_findings = self._url_rule.check_urls(urls)
        findings.extend(url_findings)

        # Step 6: Other signs
        findings.extend(check_other_signs(text))

        # Step 7: Scoring
        pos_findings = [f for f in findings if f[0] > 0]
        total = sum(pts for pts, _, _ in findings)

        # Combination bonus (3+ positive findings)
        if len(pos_findings) >= COMBO_MIN_FINDINGS:
            total += COMBO_BONUS
            findings.append((COMBO_BONUS,
                            f"{len(pos_findings)} warning signs together (combination bonus)",
                            "Risk Multiplier"))

        score = max(0, min(MAX_SCORE, total))

        # Step 8: Verdict
        verdict = classify_verdict(score)

        # Step 9: Dominant scam type (lambda with sorted — course concept)
        if pos_findings:
            # Sort by weight descending, pick the strongest category
            sorted_findings = sorted(pos_findings, key=lambda f: f[0], reverse=True)
            scam_type = sorted_findings[0][2]
        else:
            scam_type = "None"

        # Build final findings as (points, description) tuples
        final_findings = [(pts, desc) for pts, desc, _ in findings]

        return Result(score, verdict, scam_type, final_findings, get_tip(verdict))

    def get_history(self):
        """Return the HistoryManager instance."""
        return self._history


# ──────────────────────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ──────────────────────────────────────────────────────────────

def display_result(result):
    """
    Print the analysis result.
    Uses: f-strings, enumerate (course concept).
    """
    print("\n" + "=" * 55)
    print("  SCAM DETECTION RESULT")
    print("=" * 55)
    print(f"  Score   : {result.score} / {MAX_SCORE}")
    print(f"  Verdict : {result.verdict}")
    print(f"  Type    : {result.scam_type}")

    if result.findings:
        print(f"  Reasons ({len(result.findings)} finding(s)):")
        # Using enumerate (course concept)
        for i, (pts, desc) in enumerate(result.findings, start=1):
            sign = f"+{pts}" if pts > 0 else str(pts)
            print(f"    {i}. [{sign:>4}] {desc}")
    else:
        print("  No warning signs detected.")

    print(f"  Tip     : {result.tip}")
    print("=" * 55)


def display_history(history_mgr):
    """
    Display check history from CSV.
    Uses: zip (course concept) to pair headers with values.
    """
    try:
        header, data = history_mgr.load()
    except FileNotFoundError:
        print("\n  No history recorded yet.")
        return

    if not data:
        print("\n  History is empty.")
        return

    print("\n" + "-" * 55)
    print("  CHECK HISTORY")
    print("-" * 55)
    for row_num, row in enumerate(data, 1):
        print(f"\n  #{row_num}")
        # zip pairs headers with row values (course concept)
        for col_name, value in zip(header, row):
            print(f"    {col_name}: {value}")
    print(f"\n  Total: {len(data)} checks")
    print("-" * 55)


def display_statistics(history_mgr):
    """
    Display summary statistics.
    Uses: map, lambda, list comprehension (course concepts).
    """
    try:
        _, data = history_mgr.load()
    except FileNotFoundError:
        print("\n  No history recorded yet.")
        return

    if not data:
        print("\n  No data to show.")
        return

    # Extract scores using map (course concept)
    scores = list(map(lambda row: int(row[1]), data))
    verdicts = [row[2] for row in data]

    total = len(data)
    safe_count = verdicts.count("SAFE")
    susp_count = verdicts.count("SUSPICIOUS")
    scam_count = verdicts.count("LIKELY SCAM")
    avg_score = sum(scores) / total

    print("\n" + "-" * 55)
    print("  STATISTICS")
    print("-" * 55)
    print(f"  Total checked   : {total}")
    print(f"  Safe            : {safe_count}")
    print(f"  Suspicious      : {susp_count}")
    print(f"  Likely Scam     : {scam_count}")
    print(f"  Average Score   : {avg_score:.1f}")
    print(f"  Highest Score   : {max(scores)}")
    print(f"  Lowest Score    : {min(scores)}")

    # Text bar chart (always works, no matplotlib needed)
    print("\n  Verdict Distribution (text bar):")
    bar_max = max(safe_count, susp_count, scam_count, 1)
    for label, count in [("Safe", safe_count), ("Suspicious", susp_count), ("Likely Scam", scam_count)]:
        bar = "#" * int(count / bar_max * 30)
        print(f"    {label:12s} |{bar} ({count})")

    print("-" * 55)

    # Matplotlib charts (optional)
    if HAS_MATPLOTLIB:
        try:
            _draw_charts(verdicts, scores)
        except Exception as e:
            print(f"  (Chart generation failed: {e})")


def _draw_charts(verdicts, scores):
    """Generate matplotlib charts if available."""
    fig, axes = plt.subplots(1, 3, figsize=(14, 4))

    # 1. Verdict pie chart
    labels = ["Safe", "Suspicious", "Likely Scam"]
    counts = [verdicts.count("SAFE"), verdicts.count("SUSPICIOUS"), verdicts.count("LIKELY SCAM")]
    colors = ["#4CAF50", "#FF9800", "#F44336"]
    nonzero = [(l, c, co) for l, c, co in zip(labels, counts, colors) if c > 0]
    if nonzero:
        axes[0].pie([c for _, c, _ in nonzero],
                    labels=[l for l, _, _ in nonzero],
                    colors=[co for _, _, co in nonzero],
                    autopct="%1.0f%%", startangle=90)
    axes[0].set_title("Verdict Distribution")

    # 2. Score histogram
    axes[1].hist(scores, bins=range(0, 110, 10), color="#2196F3", edgecolor="black")
    axes[1].set_xlabel("Risk Score")
    axes[1].set_ylabel("Count")
    axes[1].set_title("Score Distribution")

    # 3. Verdict bar chart
    axes[2].bar(labels, counts, color=colors)
    axes[2].set_title("Verdict Counts")
    axes[2].set_ylabel("Count")

    plt.tight_layout()
    chart_path = os.path.join("docs", "charts.png")
    plt.savefig(chart_path, dpi=100)
    plt.close()
    print(f"\n  Charts saved to {chart_path}")


def generate_flagged_report(history_mgr):
    """
    Write flagged (Suspicious + Likely Scam) messages to a text report.
    Uses: file handling, exception handling.
    """
    try:
        header, data = history_mgr.load()
    except FileNotFoundError:
        print("\n  No history found.")
        return

    # Filter flagged messages (list comprehension with membership — course concept)
    flagged = [row for row in data if row[2] in ("SUSPICIOUS", "LIKELY SCAM")]

    if not flagged:
        print("\n  No flagged messages found.")
        return

    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("OFFLINE SCAM DETECTOR — FLAGGED MESSAGE REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            # Using enumerate (course concept)
            for i, row in enumerate(flagged, 1):
                f.write(f"--- Flagged #{i} ---\n")
                for col, val in zip(header, row):
                    f.write(f"  {col}: {val}\n")
                f.write("\n")
            f.write(f"Total flagged: {len(flagged)}\n")
        print(f"\n  Report written to '{REPORT_FILE}' ({len(flagged)} entries).")
    except OSError as e:
        print(f"\n  Error writing report: {e}")


# ──────────────────────────────────────────────────────────────
# DEMO & TESTING
# ──────────────────────────────────────────────────────────────

def load_samples():
    """
    Load labelled samples from data/samples.csv.
    Returns list of (label, message) tuples.
    Uses: file handling, csv module, exception handling.
    """
    if not os.path.isfile(SAMPLES_FILE):
        raise FileNotFoundError(f"Samples file not found: {SAMPLES_FILE}")
    samples = []
    with open(SAMPLES_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append((row["label"].strip().upper(), row["message"].strip()))
    return samples


def run_demo(analyzer):
    """
    Run the analyser on all labelled samples and show results.
    Uses: enumerate, string formatting, f-strings.
    """
    try:
        samples = load_samples()
    except FileNotFoundError as e:
        print(f"\n  {e}")
        return

    print(f"\n  Running demo on {len(samples)} labelled samples...\n")

    correct, total = 0, len(samples)
    tp, fp, tn, fn = 0, 0, 0, 0  # for precision/recall

    for i, (label, msg) in enumerate(samples, 1):
        result = analyzer.analyse(msg)
        predicted_scam = result.verdict in ("SUSPICIOUS", "LIKELY SCAM")
        actual_scam = (label == "SCAM")

        matched = (predicted_scam == actual_scam)
        if matched:
            correct += 1

        # Confusion matrix counts
        if actual_scam and predicted_scam:
            tp += 1
        elif actual_scam and not predicted_scam:
            fn += 1
        elif not actual_scam and predicted_scam:
            fp += 1
        else:
            tn += 1

        status = "MATCH" if matched else "MISS "
        preview = msg[:50] + ("..." if len(msg) > 50 else "")
        print(f"  {i:>2}. [{label:4s}] {result.verdict:11s} (Score:{result.score:>3}) {status} | {preview}")

    print(f"\n  {'='*55}")
    print(f"  Accuracy  : {correct}/{total} ({correct/total*100:.1f}%)")
    if tp + fp > 0:
        precision = tp / (tp + fp)
        print(f"  Precision : {precision:.2f} (of predicted scams, how many were real)")
    if tp + fn > 0:
        recall = tp / (tp + fn)
        print(f"  Recall    : {recall:.2f} (of real scams, how many were caught)")
    print(f"\n  Confusion Matrix:")
    print(f"               Predicted SAFE  Predicted SCAM")
    print(f"  Actual SAFE      {tn:>3} (TN)        {fp:>3} (FP)")
    print(f"  Actual SCAM      {fn:>3} (FN)        {tp:>3} (TP)")
    print(f"  {'='*55}")


def run_tests(analyzer):
    """
    Run 20+ automated test cases. Print pass/fail table.
    Uses: enumerate, tuples, lambda, assertion-style checks.
    Tests cover: normal, boundary (24/25, 49/50), empty, special chars,
                 emoji, long input, false-positive tricky messages.
    """
    # Each test: (name, message, check_function)
    tests = [
        # --- Normal cases ---
        ("heavy_scam_sbi_kyc",
         "URGENT: SBI account blocked! Update KYC at http://sbi-update.xyz Share OTP now",
         lambda r: r.verdict == "LIKELY SCAM" and r.score == 100),

        ("genuine_otp_safe",
         "Your OTP is 849302. Do not share this with anyone. Valid for 5 min.",
         lambda r: r.verdict == "SAFE" and r.score == 0),

        ("prize_scam",
         "Congratulations! You won Rs 10 lakh in Lucky Draw! Click http://prize.xyz/claim",
         lambda r: r.verdict in ("SUSPICIOUS", "LIKELY SCAM")),

        ("fake_job_scam",
         "Work from home earn money daily. Pay Rs 500 registration fee. No experience needed. Call 9876543210",
         lambda r: r.verdict == "LIKELY SCAM"),

        ("upi_trick",
         "UPI account locked! Send Rs 1 to verify identity via Google Pay. Collect request sent. Act immediately!!!",
         lambda r: r.verdict == "LIKELY SCAM"),

        # --- Boundary cases ---
        ("boundary_safe_24",
         "This is an urgent notice.",
         lambda r: r.score <= SAFE_THRESHOLD and r.verdict == "SAFE"),

        ("boundary_suspicious_25",
         "Urgent: click here to verify your details immediately.",
         lambda r: r.score >= 25 and r.verdict in ("SUSPICIOUS", "LIKELY SCAM")),

        ("boundary_scam_50",
         "Your account blocked! Update KYC at http://sbi-update.xyz",
         lambda r: r.score >= 50 and r.verdict == "LIKELY SCAM"),

        # --- Empty / special input ---
        ("empty_whitespace",
         "   ",
         lambda r: r.verdict == "SAFE" and r.score == 0),

        ("only_newlines",
         "\n\n\n",
         lambda r: r.verdict == "SAFE" and r.score == 0),

        ("emoji_only",
         "🎉🎊🏆👑💰",
         lambda r: r.verdict == "SAFE" and r.score == 0),

        ("unicode_mixed",
         "Hello! How are you? 😊 Have a great day.",
         lambda r: r.verdict == "SAFE"),

        # --- False-positive resistance (tricky safe messages) ---
        ("genuine_bank_credit",
         "Your SBI account XXXX1234 has been credited with Rs 5,000.00. Avl Bal: Rs 12,345.67",
         lambda r: r.verdict == "SAFE"),

        ("genuine_aadhaar_otp",
         "Your Aadhaar OTP is 745821. It is valid for 10 minutes. Do not share this OTP with anyone.",
         lambda r: r.verdict == "SAFE" and r.score == 0),

        ("genuine_delivery",
         "Zomato: Your order from Domino's is out for delivery. Track live on the Zomato app.",
         lambda r: r.verdict == "SAFE"),

        ("genuine_emi_reminder",
         "Reminder: EMI of Rs 8,500 for HDFC loan A/c XXXX5678 is due on 5th Dec.",
         lambda r: r.verdict == "SAFE"),

        # --- URL checks ---
        ("real_bank_url_safe",
         "Visit https://www.hdfcbank.com for online banking services.",
         lambda r: r.verdict == "SAFE"),

        ("fake_domain_flagged",
         "Update at http://hdfc-secure-login.xyz/verify",
         lambda r: r.verdict != "SAFE"),

        ("raw_ip_flagged",
         "Login at http://192.168.1.50/bank-verify",
         lambda r: r.verdict != "SAFE"),

        ("shortened_url_flagged",
         "Click http://bit.ly/free-gift to claim your reward",
         lambda r: r.verdict != "SAFE"),

        # --- Word boundary ---
        ("word_boundary_no_fp",
         "The detergent arrived. Payment window is open today.",
         lambda r: r.score == 0),

        # --- Score cap ---
        ("score_capped_at_100",
         "URGENT! Congratulations winner! KYC blocked! Send OTP PIN CVV! "
         "Pay Rs 500 via UPI! RBI notice! http://scam.xyz/hack.apk Call 9876543210 NOW!!!",
         lambda r: r.score == MAX_SCORE),

        # --- Spaced-out evasion ---
        ("spaced_otp_evasion",
         "Dear customer, send your O T P and P I N to verify account",
         lambda r: r.score > 0),

        # --- APK detection ---
        ("apk_malware",
         "Download security patch: http://update.tk/patch.apk",
         lambda r: r.score > 0 and r.verdict != "SAFE"),
    ]

    print(f"\n{'='*60}")
    print(f"  AUTOMATED TEST SUITE ({len(tests)} tests)")
    print(f"{'='*60}\n")

    passed, failed = 0, 0
    for i, (name, message, check_fn) in enumerate(tests, 1):
        result = analyzer.analyse(message)
        ok = check_fn(result)
        if ok:
            passed += 1
            status = "PASS"
        else:
            failed += 1
            status = "FAIL"
        # Pad name for alignment
        print(f"  {i:>2}. {name:30s} Score:{result.score:>3}  {result.verdict:11s}  [{status}]")

    print(f"\n{'-'*60}")
    print(f"  Results: {passed} passed, {failed} failed out of {len(tests)}")
    if failed == 0:
        print("  ALL TESTS PASSED!")
    print(f"{'='*60}\n")
    return failed == 0


# ──────────────────────────────────────────────────────────────
# MENU / MAIN
# ──────────────────────────────────────────────────────────────

def get_message_input():
    """
    Read a multi-line message from the user.
    Uses: exception handling (EOFError, KeyboardInterrupt).
    """
    print("\n  Paste the SMS/WhatsApp message below.")
    print("  Press Enter on an empty line when done.\n")
    lines = []
    while True:
        try:
            line = input("  > ")
            if line == "":
                break
            lines.append(line)
        except (EOFError, KeyboardInterrupt):
            break
    return "\n".join(lines)


def print_menu():
    """Display the main menu."""
    print("\n" + "=" * 55)
    print("  OFFLINE SCAM MESSAGE DETECTOR")
    print("  SMS / WhatsApp Scam Screening (Python)")
    print("=" * 55)
    print("  1. Analyse a message")
    print("  2. View check history")
    print("  3. Statistics & charts")
    print("  4. Generate flagged report")
    print("  5. Run demo (labelled samples)")
    print("  6. Run automated tests")
    print("  7. Exit")
    print("-" * 55)


def main():
    """
    Main entry point. Handles CLI flags and interactive menu.
    Uses: sys.argv, exception handling, while loop.
    """
    analyzer = ScamAnalyzer()

    # CLI flags
    if "--test" in sys.argv:
        success = run_tests(analyzer)
        sys.exit(0 if success else 1)
    if "--demo" in sys.argv:
        run_demo(analyzer)
        sys.exit(0)

    # Interactive menu loop
    while True:
        print_menu()
        try:
            choice = input("  Choice (1-7): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  Goodbye! Stay safe online.")
            break

        try:
            if choice == "1":
                msg = get_message_input()
                if not msg.strip():
                    print("  No message entered.")
                    continue
                result = analyzer.analyse(msg)
                display_result(result)
                try:
                    analyzer.get_history().save(msg, result)
                    print("  [Saved to history.csv]")
                except ScamDetectorError as e:
                    print(f"  [{e}]")

            elif choice == "2":
                display_history(analyzer.get_history())

            elif choice == "3":
                display_statistics(analyzer.get_history())

            elif choice == "4":
                generate_flagged_report(analyzer.get_history())

            elif choice == "5":
                run_demo(analyzer)

            elif choice == "6":
                run_tests(analyzer)

            elif choice == "7":
                print("\n  Goodbye! Stay safe online.")
                break

            else:
                # Input validation for menu (course concept)
                try:
                    num = int(choice)
                    if num < 1 or num > 7:
                        raise ValueError
                except ValueError:
                    print("  Invalid choice. Enter a number from 1 to 7.")

        except ScamDetectorError as e:
            print(f"\n  Error: {e}")
        except Exception as e:
            print(f"\n  Unexpected error: {e}")


# ──────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
