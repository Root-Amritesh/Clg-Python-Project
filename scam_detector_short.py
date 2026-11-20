# Offline Scam Message Detector
# Course : 2026CSAE100 - Computational Thinking and Programming
# Bennett University (2026-27)
# Team   : Amritesh Kumar, Naved Ali, Tanishk Singh, Aryan Chahal, Praval Verma

import re
import csv
import os
import sys
from datetime import datetime

# --- Scam Rules & Keywords ---
RULES = [
    ("Bank / KYC", 25, [
        "kyc", "account blocked", "account suspended", "verify your account",
        "update kyc", "account will be closed", "deactivated", "pan card",
        "aadhaar update", "re-kyc", "complete verification", "temporarily locked"
    ], "Threatens to block your account or card"),
    ("Urgency", 15, [
        "act now", "immediate action", "urgent", "expires today", "last chance",
        "hurry", "limited time", "within 24 hours", "action required",
        "immediately", "respond immediately", "time is running out"
    ], "Creates panic / urgency"),
    ("Link Push", 10, [
        "click here", "click link", "click this link", "open link",
        "visit link", "update here", "verify here", "claim here"
    ], "Pushes you to click a link"),
    ("Prize / Lottery", 25, [
        "congratulations", "you have won", "lottery", "prize", "lucky winner",
        "claim your reward", "free gift", "you are chosen", "winner",
        "cash prize", "you won", "lucky draw"
    ], "Claims an unexpected reward or prize"),
    ("Fake Job", 30, [
        "work from home", "earn money", "part time job", "registration fee",
        "joining fee", "pay to join", "easy money", "online job",
        "data entry job", "guaranteed income", "no experience needed"
    ], "Offers fake job or demands upfront fee"),
    ("UPI / Payment", 25, [
        "send money", "pay rs", "upi", "collect request", "google pay",
        "phonepe", "paytm", "gpay", "scan this qr", "scan qr",
        "payment pending", "refund processing", "cashback"
    ], "Attempts payment or UPI trick"),
    ("Authority", 20, [
        "rbi", "reserve bank", "income tax", "police", "cyber cell",
        "government", "sebi", "legal action", "court notice",
        "arrest warrant", "legal proceedings"
    ], "Impersonates government or police authority"),
]

SENSITIVE_WORDS = [
    "otp", "pin", "cvv", "password", "card number", "bank details",
    "credit card", "debit card", "account number", "ifsc", "netbanking password"
]

SAFE_DOMAINS = [
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "rbi.org.in",
    "amazon.in", "flipkart.com", "google.com", "gov.in", "paytm.com", "phonepe.com"
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".buzz", ".tk", ".ml", ".ga", ".click", ".win"]
KNOWN_BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon", "jio", "airtel", "rbi"]

HISTORY_FILE = "history.csv"


def analyse(msg):
    """Analyses a message and returns score, verdict, reasons, and scam type."""
    cleaned_input = msg.strip()
    if not cleaned_input:
        return {
            "score": 0, "verdict": "SAFE", "type": "None",
            "why": [], "tip": "Empty message entered."
        }

    text = cleaned_input.lower()
    findings = []  # tuples of (points, description, category)

    # 1. Check for genuine OTP delivery safe phrase
    is_safe_otp = ("do not share" in text or "never share" in text or "don't share" in text)
    if is_safe_otp:
        findings.append((-20, "Contains a 'do not share' warning, which is normal in many genuine OTP messages", "Safe Notice"))

    # 2. Match rule keywords with word boundaries
    for cat, weight, patterns, desc in RULES:
        for p in patterns:
            if re.search(r"\b" + re.escape(p) + r"\b", text):
                findings.append((weight, desc, cat))
                break

    # 3. Check for sensitive details requests (suppressed if legit OTP delivery)
    if not is_safe_otp:
        for sw in SENSITIVE_WORDS:
            if re.search(r"\b" + re.escape(sw) + r"\b", text):
                findings.append((30, "Asks for sensitive banking or login details (OTP, PIN, Password)", "Sensitive Info"))
                break

    # 4. URL and link inspection
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text)
    for url in urls:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        for s in SHORTENERS:
            if s in domain:
                findings.append((15, f"Uses shortened URL '{domain}', hiding destination", "Suspicious URL"))
                break

        if re.search(r"^\d{1,3}(\.\d{1,3}){3}", domain):
            findings.append((25, f"Link uses raw IP address '{domain}' instead of a domain name", "Suspicious URL"))

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append((15, f"Link ends in '{tld}', a common warning sign in scam messages", "Suspicious URL"))
                break

        for b in KNOWN_BRANDS:
            if b in domain and not any(sd in domain for sd in SAFE_DOMAINS):
                findings.append((30, f"Link pretends to be {b.upper()} but domain is '{domain}'", "Brand Impersonation"))
                break

    # 5. Check APK files, personal numbers, and excessive punctuation
    if re.search(r"\.apk\b", text):
        findings.append((20, "Contains link to install an APK file directly", "Malware Threat"))
    if re.search(r"\b[6-9]\d{9}\b", text):
        findings.append((10, "Contains a personal 10-digit mobile number", "Suspicious Sender"))
    if re.search(r"[!]{3,}|[?]{3,}", text):
        findings.append((5, "Uses excessive punctuation (!!! / ???)", "Pressure Tactic"))

    # 6. Score calculation with combination bonus
    pos_findings = [f for f in findings if f[0] > 0]
    total_score = sum(f[0] for f in findings)

    # 3+ warning signs gets a 10-point combination bonus
    if len(pos_findings) >= 3:
        total_score += 10
        findings.append((10, "Multiple warning signs found together (combination bonus)", "Risk Multiplier"))

    score = max(0, min(100, total_score))

    # 7. Classification
    if score <= 24:
        verdict = "SAFE"
    elif score <= 49:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SCAM"

    # Dominant scam category (prioritize main rule category if matched)
    rule_findings = [f for f in pos_findings if any(f[2] == r[0] for r in RULES)]
    if rule_findings:
        dominant_cat = max(rule_findings, key=lambda x: x[0])[2]
    elif pos_findings:
        dominant_cat = max(pos_findings, key=lambda x: x[0])[2]
    else:
        dominant_cat = "None"

    # Tips
    if verdict == "LIKELY SCAM":
        tip = "Banks do not ask for KYC, OTP or PIN through suspicious SMS links."
    elif verdict == "SUSPICIOUS":
        tip = "Do not click any link or send money. Verify independently with official support."
    else:
        tip = "No strong scam pattern was found. That does not guarantee the message is safe."

    return {
        "score": score,
        "verdict": verdict,
        "type": dominant_cat,
        "why": [(f[0], f[1]) for f in findings],
        "tip": tip
    }


def display_result(res):
    """Prints result in the format specified in the report."""
    print(f"\nScore    : {res['score']} / 100")
    print(f"Verdict  : {res['verdict']}")
    print(f"Type     : {res['type']}")
    print("Why:")
    if res["why"]:
        for pts, reason in res["why"]:
            sign = f"+{pts}" if pts > 0 else str(pts)
            print(f"  {sign:<4} {reason}")
    else:
        print("  None detected.")
    print(f"Tip      : {res['tip']}")


def save_history(msg, res):
    """Appends checked message to history.csv."""
    file_exists = os.path.isfile(HISTORY_FILE)
    try:
        with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if not file_exists:
                w.writerow(["Timestamp", "Score", "Verdict", "Type", "Message"])
            preview = msg.replace("\n", " ").strip()[:70]
            w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M"), res["score"], res["verdict"], res["type"], preview])
    except Exception as e:
        print(f"  (Failed to write history: {e})")


def view_history():
    if not os.path.isfile(HISTORY_FILE):
        print("\nNo history recorded yet.")
        return
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if len(rows) <= 1:
        print("\nHistory file is empty.")
        return
    print("\n--- Check History ---")
    for r in rows[1:]:
        print(f"[{r[0]}] {r[2]:12s} Score: {r[1]:<3} Type: {r[3]:<16} Msg: {r[4]}")


def show_statistics():
    if not os.path.isfile(HISTORY_FILE):
        print("\nNo history recorded yet.")
        return
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))[1:]
    if not rows:
        print("\nNo checks logged.")
        return
    scores = [int(r[1]) for r in rows]
    verdicts = [r[2] for r in rows]
    print("\n--- Summary Statistics ---")
    print(f"Total checked : {len(rows)}")
    print(f"Safe          : {verdicts.count('SAFE')}")
    print(f"Suspicious    : {verdicts.count('SUSPICIOUS')}")
    print(f"Likely Scam   : {verdicts.count('LIKELY SCAM')}")
    print(f"Average Score : {sum(scores) / len(scores):.1f}")


def generate_flagged_report():
    if not os.path.isfile(HISTORY_FILE):
        print("\nNo history found.")
        return
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))[1:]
    flagged = [r for r in rows if r[2] in ("SUSPICIOUS", "LIKELY SCAM")]
    with open("flagged_report.txt", "w", encoding="utf-8") as f:
        f.write("OFFLINE SCAM DETECTOR - FLAGGED MESSAGES\n" + "=" * 45 + "\n\n")
        for r in flagged:
            f.write(f"Date: {r[0]} | Score: {r[1]} | Verdict: {r[2]} | Type: {r[3]}\nMessage: {r[4]}\n\n")
    print(f"\nReport written to flagged_report.txt ({len(flagged)} flagged entries).")


# --- Automated Testing Suite (Matches Report Screenshot 3 & Table 8) ---
def run_tests():
    tests = [
        ("normal scam", "Dear customer your SBI KYC expired. Account will be blocked today. Click here http://sbi-kyc-update.xyz to update immediately", lambda r: r["verdict"] == "LIKELY SCAM" and r["score"] == 100, " (score 100 )"),
        ("genuine OTP", "482913 is your OTP for payment of Rs 499 at Amazon. Do not share it with anyone.", lambda r: r["verdict"] == "SAFE" and r["score"] == 0, " (score 0 )"),
        ("boundary 15 vs 25", "Urgent: click here to view the circular.", lambda r: r["verdict"] == "SUSPICIOUS" and r["score"] == 25, ""),
        ("empty message", "   ", lambda r: r["verdict"] == "SAFE" and r["score"] == 0, ""),
        ("real bank link", "Visit https://www.hdfcbank.com for online banking services.", lambda r: r["verdict"] == "SAFE" and r["score"] == 0, ""),
        ("fake domain / IP link", "Verify immediately at http://192.168.1.100/sbi-verify", lambda r: r["verdict"] != "SAFE", ""),
        ("word boundary", "The detergent arrived. Payment window is open today.", lambda r: r["score"] == 0, ""),
        ("score capped at 100", "URGENT! Congratulations winner! KYC blocked! Send OTP PIN CVV! Pay Rs 500 via UPI! http://scam.xyz/hack.apk Call 9876543210 NOW!!!", lambda r: r["score"] == 100, "")
    ]

    all_pass = True
    for i, (name, sample, cond, extra) in enumerate(tests, 1):
        res = analyse(sample)
        ok = cond(res)
        if not ok:
            all_pass = False
        dots = "." * (26 - len(name))
        status = f"passed{extra}" if ok else "FAILED"
        print(f"Test {i}  {name} {dots} {status}")

    if all_pass:
        print("\nAll tests passed.\n")
    return all_pass


# --- Demo Suite (17 Student-Style Samples) ---
DEMO_SAMPLES = [
    ("SCAM", "URGENT: Your SBI account will be blocked in 24 hours! Update KYC now at http://sbi-kyc-update.xyz/verify"),
    ("SCAM", "Congratulations! You have won Rs 50,00,000 in the Jio Lucky Draw! Click http://jio-prize.top/claim"),
    ("SCAM", "Dear Customer, your HDFC bank account has been suspended. Verify immediately: http://192.168.1.100/hdfc-verify"),
    ("SCAM", "PART TIME JOB - Earn Rs 5000 daily from home! No experience needed. Pay Rs 200 registration fee. Call 9876543210"),
    ("SCAM", "Your UPI account is locked! Send Rs 1 to verify identity via Google Pay. Collect request sent. Act immediately!!!"),
    ("SCAM", "RBI Notice: PAN linked to suspicious transactions. Legal action within 48 hours. Send Aadhaar and OTP immediately."),
    ("SCAM", "AMAZON LUCKY WINNER! You are chosen for a free iPhone 15. Click http://amazon-gifts.click/win expires today!"),
    ("SCAM", "Income Tax Department: Refund of Rs 15,000 is pending. Enter your bank details and OTP at http://bit.ly/tax-refund"),
    ("SCAM", "Install this security update for your phone: http://secure-update.tk/download.apk"),
    ("SCAM", "Dear user, your Paytm wallet will be deactivated. Complete re-KYC by sharing Aadhaar and OTP. Call 8765432109"),
    ("SAFE", "Your OTP is 482931. Do not share this with anyone. Valid for 10 minutes."),
    ("SAFE", "Hi Amritesh, your Amazon order #402-1234567 has been shipped. Track at amazon.in/tracking"),
    ("SAFE", "Reminder: Your electricity bill of Rs 1,250 is due on 15th Nov. Pay via official UPPCL app."),
    ("SAFE", "Bennett University: Your exam schedule has been updated. Check the student portal for details."),
    ("SAFE", "Happy Birthday! Wishing you a wonderful year ahead. - Mom"),
    ("SAFE", "Your SBI account XXXX1234 has been credited with Rs 5,000.00 on 07-Nov. Avl Bal: Rs 12,345.67"),
    ("SAFE", "Meeting rescheduled to 3 PM tomorrow. Please confirm your availability. - Prof. Sharma")
]


def run_demo():
    print("\nRunning Demo Dataset (17 Samples)...\n")
    correct = 0
    for label, msg in DEMO_SAMPLES:
        res = analyse(msg)
        is_scam = res["verdict"] in ("SUSPICIOUS", "LIKELY SCAM")
        expected_scam = (label == "SCAM")
        matched = (is_scam == expected_scam)
        if matched:
            correct += 1
        status = "MATCH" if matched else "MISMATCH"
        print(f"[{label:4s}] {res['verdict']:11s} (Score: {res['score']:<3}) -> {status}")
    print(f"\nDemo accuracy: {correct}/{len(DEMO_SAMPLES)} correctly classified.\n")


def main():
    # Direct command-line flag support (Screenshot 3 in report)
    if "--test" in sys.argv:
        run_tests()
        return

    while True:
        print("\n" + "=" * 45)
        print("  Offline Scam Message Detector")
        print("=" * 45)
        print("1. Analyse a message")
        print("2. View check history")
        print("3. View statistics")
        print("4. Generate flagged-message report")
        print("5. Run demo dataset (17 samples)")
        print("6. Run automated test suite")
        print("7. Exit")

        choice = input("\nChoice: ").strip()

        if choice == "1":
            print("\nPaste the message. Press Enter on an empty line when done.")
            lines = []
            while True:
                try:
                    line = input()
                    if line == "":
                        break
                    lines.append(line)
                except EOFError:
                    break
            msg = "\n".join(lines)
            if not msg.strip():
                print("No message entered.")
                continue
            res = analyse(msg)
            display_result(res)
            save_history(msg, res)

        elif choice == "2":
            view_history()
        elif choice == "3":
            show_statistics()
        elif choice == "4":
            generate_flagged_report()
        elif choice == "5":
            run_demo()
        elif choice == "6":
            run_tests()
        elif choice == "7":
            print("Exiting program.")
            break
        else:
            print("Invalid choice, please select between 1 and 7.")


if __name__ == "__main__":
    main()
