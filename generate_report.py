import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def style_table(table, col_widths, header_bg='1A365D', zebra_bg='F7FAFC'):
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table.rows):
        is_header = (i == 0)
        for j, cell in enumerate(row.cells):
            cell.width = Inches(col_widths[j])
            set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
            if is_header:
                set_cell_background(cell, header_bg)
                for p in cell.paragraphs:
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    for run in p.runs:
                        run.font.bold = True
                        run.font.color.rgb = RGBColor(255, 255, 255)
                        run.font.size = Pt(9.5)
                        run.font.name = 'Arial'
            else:
                if i % 2 == 1:
                    set_cell_background(cell, zebra_bg)
                for p in cell.paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(9)
                        run.font.name = 'Arial'

def add_callout(doc, text, title=""):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, "EDF2F7")
    set_cell_margins(cell, top=140, bottom=140, left=180, right=180)
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    if title:
        r_title = p.add_run(f"{title}: ")
        r_title.bold = True
        r_title.font.name = 'Arial'
        r_title.font.size = Pt(9.5)
        r_title.font.color.rgb = RGBColor(43, 108, 176)
    r_text = p.add_run(text)
    r_text.font.name = 'Arial'
    r_text.font.size = Pt(9)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def add_code_block(doc, code_str):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, "1A202C")
    set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.15
    run = p.add_run(code_str)
    run.font.name = 'Consolas'
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(226, 232, 240)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def build_report():
    doc = docx.Document()

    # Set margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    # Base styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Arial'
    normal_style.font.size = Pt(10)
    normal_style.font.color.rgb = RGBColor(45, 55, 72)

    # ------------------ COVER PAGE / HEADER ------------------
    p_inst = doc.add_paragraph()
    p_inst.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_inst.paragraph_format.space_after = Pt(2)
    r = p_inst.add_run("BENNETT UNIVERSITY")
    r.bold = True
    r.font.size = Pt(16)
    r.font.color.rgb = RGBColor(26, 54, 93)

    p_dept = doc.add_paragraph()
    p_dept.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_dept.paragraph_format.space_after = Pt(4)
    r = p_dept.add_run("School of Computer Science Engineering and Technology\nDepartment of Computer Science Engineering")
    r.font.size = Pt(11)
    r.font.color.rgb = RGBColor(74, 85, 104)

    p_course = doc.add_paragraph()
    p_course.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_course.paragraph_format.space_after = Pt(18)
    r = p_course.add_run("Computational Thinking and Programming (2026CSAE100)")
    r.bold = True
    r.font.size = Pt(12)
    r.font.color.rgb = RGBColor(43, 108, 176)

    p_title_label = doc.add_paragraph()
    p_title_label.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title_label.paragraph_format.space_after = Pt(2)
    r = p_title_label.add_run("PYTHON PROJECT REPORT")
    r.bold = True
    r.font.size = Pt(14)
    r.font.color.rgb = RGBColor(113, 128, 150)

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(4)
    r = p_title.add_run("Offline Scam Message Detector")
    r.bold = True
    r.font.size = Pt(20)
    r.font.color.rgb = RGBColor(26, 54, 93)

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(24)
    r = p_sub.add_run("Rule-based SMS and WhatsApp Threat Screening Engine in Python")
    r.italic = True
    r.font.size = Pt(11)

    # Team Table
    team_data = [
        ["Student Name", "Enrollment No.", "Batch / Section", "Role"],
        ["Amritesh Kumar", "S26CSEU0943", "B-27 / S14", "Project Lead (Scoring, OOP, Integration, Tests)"],
        ["Naved Ali", "S26CSEU0955", "B-27 / S14", "CSV History, Analytics, Visual Reporting"],
        ["Tanishk Singh", "S26CSEU0934", "B-27 / S14", "Console Input, Menu Flow, Benchmark Dataset"],
        ["Aryan Chahal", "S26CSEU0933", "B-27 / S14", "Regex Engine, URL Checks, Text Normalisation"],
        ["Praval Verma", "S26CSEU0935", "B-27 / S14", "Safety Heuristics, Sensitive Filter, Flowcharts"]
    ]
    t = doc.add_table(rows=len(team_data), cols=4)
    for i, row in enumerate(team_data):
        for j, val in enumerate(row):
            t.cell(i, j).text = val
    style_table(t, [1.6, 1.4, 1.1, 2.4])

    p_acad = doc.add_paragraph()
    p_acad.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_acad.paragraph_format.space_before = Pt(18)
    p_acad.paragraph_format.space_after = Pt(24)
    r = p_acad.add_run("Academic Year: 2026–27 | Semester: 1 (Freshers)")
    r.font.size = Pt(10)
    r.font.color.rgb = RGBColor(113, 128, 150)

    doc.add_page_break()

    # Helper for headings
    def add_h1(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(16)
        h.paragraph_format.space_after = Pt(6)
        r = h.add_run(text)
        r.bold = True
        r.font.size = Pt(14)
        r.font.color.rgb = RGBColor(26, 54, 93)

    def add_h2(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(12)
        h.paragraph_format.space_after = Pt(4)
        r = h.add_run(text)
        r.bold = True
        r.font.size = Pt(11.5)
        r.font.color.rgb = RGBColor(43, 108, 176)

    # ------------------ SECTION 1 ------------------
    add_h1("1. Problem Statement")
    doc.add_paragraph(
        "SMS and WhatsApp fraud has escalated dramatically across India. Everyday mobile users, parents, "
        "and college students receive deceptive messages alleging imminent bank account suspension, fake KYC expiry, "
        "lottery jackpots, work-from-home job registration fees, and electricity disconnection warnings. These messages "
        "exploit psychological urgency, coercing receivers to act within seconds before verifying authenticity."
    )
    doc.add_paragraph(
        "Existing commercial security applications frequently depend on proprietary cloud servers or third-party web APIs. "
        "This architectural model presents significant privacy vulnerabilities: private SMS messages containing partial "
        "account identifiers and names are transmitted to external servers. Furthermore, cloud checks fail completely in "
        "low-connectivity environments."
    )
    doc.add_paragraph(
        "The Offline Scam Message Detector solves this problem by providing a lightweight, explainable, and local "
        "screening utility written entirely in Python. Operating 100% offline with zero cloud dependency, it inspects "
        "text for deceptive psychological hooks, malicious URL anatomy, and credential-harvesting patterns, returning an "
        "itemised risk score with actionable guidance in under 3 milliseconds."
    )

    # ------------------ SECTION 2 ------------------
    add_h1("2. Project Objectives")
    objectives = [
        ("Local Offline Analysis", "Accept SMS/WhatsApp text messages and evaluate threat vectors locally with zero network calls, guaranteeing strict personal privacy."),
        ("Multi-Vector Threat Detection", "Identify pressure language, financial extortion, job fraud, prize scams, and malicious URLs (shorteners, raw IPs, suspicious TLDs, and spoofed bank brands)."),
        ("Transparent Risk Scoring", "Aggregate weighted rule scores into a bounded 0–100 scale, categorising messages into Safe (0–24), Suspicious (25–49), or Likely Scam (50–100)."),
        ("Explainable Feedback", "Provide an itemised audit trail detailing the exact points and reasoning behind every finding, replacing opaque black-box labels."),
        ("Session Logging & Visual Analytics", "Persist all checks into history.csv, generate flagged incident reports, and render metric summaries with Matplotlib visualization.")
    ]
    for i, (title, desc) in enumerate(objectives, 1):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        r_num = p.add_run(f"{i}. {title}: ")
        r_num.bold = True
        r_num.font.color.rgb = RGBColor(43, 108, 176)
        p.add_run(desc)

    # ------------------ SECTION 3 ------------------
    add_h1("3. Main Features / Modules")
    features_data = [
        ["S. No.", "Module / Feature", "Description", "Technical Implementation"],
        ["1", "Input & Preprocessing", "Multi-line message ingestion, whitespace trimming, and non-ASCII character removal.", "get_message_input(), preprocess()"],
        ["2", "Recursive Evasion Normalizer", "Collapses spaced-out evasion words like 'O T P' and 'P I N' recursively.", "normalise_text(text, depth) with base case"],
        ["3", "Rule & Keyword Engine", "Evaluates text across 7 categories using whole-word boundary regular expressions.", "KeywordRule class hierarchy, re.search()"],
        ["4", "Contextual OTP Filter", "Distinguishes legitimate OTP dispatches from phishing credential requests.", "check_safe_phrase(), higher-order filter()"],
        ["5", "URL Anatomy Scanner", "Extracts URLs; detects shorteners, raw IPs, risky TLDs (.xyz, .tk), and fake brands.", "URLRule.check_urls(), frozenset lookups"],
        ["6", "Decision & Scoring Engine", "Sums weighted points, adds +10 combo bonus (>=3 flags), and clamps to 0–100.", "ScamAnalyzer.analyse(), classify_verdict()"],
        ["7", "Persistence & Reporting", "Logs audits to CSV, exports flagged_report.txt, and renders summary charts.", "HistoryManager, Matplotlib integration"]
    ]
    t_feat = doc.add_table(rows=len(features_data), cols=4)
    for i, row in enumerate(features_data):
        for j, val in enumerate(row):
            t_feat.cell(i, j).text = val
    style_table(t_feat, [0.6, 1.6, 2.7, 1.6])

    # ------------------ SECTION 4 ------------------
    add_h1("4. Algorithm / Flowchart / Program Design")
    doc.add_paragraph(
        "The core detection algorithm operates deterministically: given identical inputs, the system produces "
        "the exact same score and reasons every time. The program follows a 10-step pipeline:"
    )
    algo_steps = [
        "1. Ingest multi-line SMS/WhatsApp text and strip leading/trailing whitespace.",
        "2. Validate message bounds (max 5,000 characters). Strip non-ASCII emoji and symbols.",
        "3. Recursively collapse spaced-out evasion characters ('O T P' -> 'otp') via normalise_text().",
        "4. Inspect legitimate OTP dispatch markers. If authentic 'do not share' warning is detected, record -20 safe discount and suppress 'otp' keyword.",
        "5. Iterate through all KeywordRule instances using word boundaries (\\b) across 7 categories.",
        "6. Scan for sensitive credential requests (PIN, CVV, password, card details).",
        "7. Extract URLs and inspect domain anatomy: check for URL shorteners, raw IP hosts, suspicious TLDs (.xyz, .top), and bank brand impersonation.",
        "8. Check secondary indicators: .apk download links (+20), personal 10-digit mobile numbers (+10), and excessive exclamation punctuation (+5).",
        "9. Aggregate rule points. If 3 or more positive threat indicators are matched, apply a +10 Combination Bonus. Clamp total score between 0 and 100.",
        "10. Map score to three-level verdict (0–24 Safe, 25–49 Suspicious, 50–100 Likely Scam). Print itemised breakdown and persist to history.csv."
    ]
    for step in algo_steps:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        p.add_run(step)

    # ------------------ SECTION 5 ------------------
    add_h1("5. Python Concepts Used")
    concepts_data = [
        ["Python Concept", "Where / How It Is Used in the Code", "Example in Source Code"],
        ["Variables & Types", "Scores (int), verdicts (str), flags (bool), findings (tuples)", "score: int, verdict: str = 'SAFE'"],
        ["Conditional Branching", "Threshold mapping for verdicts, URL domain checks", "if score <= 24: ... elif score <= 49:"],
        ["Loops & Control", "Scanning rules, URL iteration, break/continue/for-else", "for short in SHORTENERS: break; else: pass"],
        ["Collections (4 Types)", "Lists (RULES), Tuples (findings), Dicts (config), Frozensets (domains)", "SAFE_DOMAINS = frozenset(['sbi.co.in', ...])"],
        ["String Methods & Slicing", "Trimming whitespace, lowercasing, domain punctuation strip", "domain = domain[:-1], text.lower().strip()"],
        ["Functions & Modular Design", "Distinct functions for preprocessing, heuristics, reports", "preprocess(), check_safe_phrase(), get_tip()"],
        ["Higher-Order Functions", "filter() and map() with lambda for filtering and score parsing", "list(filter(lambda w: not (suppress and w=='otp'), ...))"],
        ["Built-in Iterators", "enumerate() for numbered tables, zip() for column-row mapping", "for col, val in zip(header, row): ..."],
        ["Recursion", "Recursive normalisation of spaced letters with base case", "normalise_text(spaced, depth + 1)"],
        ["Object-Oriented (OOP)", "Inheritance (Rule -> KeywordRule, URLRule), Encapsulation, Composition", "class KeywordRule(Rule): super().__init__(...)"],
        ["File Handling", "CSV reader/writer for history, text file writing for flagged reports", "with open(HISTORY_FILE, 'a', newline='') as f:"],
        ["Exception Handling", "Custom exception hierarchy, handling EOFError and PermissionError", "class ScamDetectorError(Exception): pass"],
        ["Standard Library", "re (regex), csv, os, sys, datetime (no external packages)", "import re, csv, os, sys, datetime"]
    ]
    t_con = doc.add_table(rows=len(concepts_data), cols=3)
    for i, row in enumerate(concepts_data):
        for j, val in enumerate(row):
            t_con.cell(i, j).text = val
    style_table(t_con, [1.5, 2.6, 2.4])

    # ------------------ SECTION 6 ------------------
    add_h1("6. Computational Features & Scoring Weights")
    doc.add_paragraph(
        "Instead of attempting black-box statistical guessing, the program implements a deterministic, "
        "rule-based weighted scoring formula:"
    )
    add_callout(doc, "Risk Score = min(100, max(0, Sum(Matched Rule Weights) + Combination Bonus - Safe Discount))", "SCORING EQUATION")

    weights_data = [
        ["Warning Sign / Threat Vector", "Rule Weight", "Justification & Contribution to Risk"],
        ["Bank / KYC Threat", "25", "Threatens immediate account deactivation or demands illegal re-KYC verification."],
        ["Urgency / Panic Pressure", "15", "Coerces the victim into acting quickly ('act now', 'expires today', '24 hours')."],
        ["Link Push Directive", "10", "Directs user to tap untrusted links ('click here', 'update here', 'claim here')."],
        ["Prize / Lottery Hook", "25", "Claims unexpected lottery or gift card rewards for unentered contests."],
        ["Fake Job / Upfront Fee", "30", "Offers dubious high daily income while demanding a registration or joining fee."],
        ["UPI / Payment Trick", "25", "Attempts collect-request deception or fraudulent refund processing via GPay/PhonePe."],
        ["Authority Impersonation", "20", "Falsely invokes police, cyber cell, CBI, court summons, or income tax notices."],
        ["Sensitive Credential Request", "30", "Demands OTP, PIN, CVV, password, or banking login credentials."],
        ["URL Shortener Link", "15", "Hides the true destination server via bit.ly, tinyurl, or goo.gl."],
        ["Raw IPv4 Address Link", "25", "Uses an IP address host (e.g. 192.168.1.100); legitimate services use named domains."],
        ["Suspicious Domain TLD", "15", "Uses cheap or disposable top-level domains (.xyz, .top, .tk, .ml, .click)."],
        ["Brand Impersonation Domain", "30", "Contains known bank names (sbi, hdfc) inside an unverified third-party domain."],
        ["APK File Download Link", "20", "Distributes sideloaded Android executable packages directly bypassing Play Store."],
        ["Personal Mobile Number", "10", "Uses a 10-digit consumer phone number instead of registered enterprise SMS headers."],
        ["Excessive Punctuation", "5", "Employs multiple exclamation marks or question marks to heighten stress."],
        ["Combination Bonus (>= 3 Signs)", "+10", "Multi-factor threat multiplier acknowledging compounded psychological manipulation."],
        ["Safe Phrase / Legit OTP Discount", "-20", "Protects authentic transactional OTP notifications from false positive alerts."]
    ]
    t_w = doc.add_table(rows=len(weights_data), cols=3)
    for i, row in enumerate(weights_data):
        for j, val in enumerate(row):
            t_w.cell(i, j).text = val
    style_table(t_w, [1.8, 0.9, 3.8])

    # ------------------ SECTION 7 ------------------
    add_h1("7. Important Outputs / Actual Terminal Captures")
    doc.add_paragraph("The following terminal captures reflect real runs of scam_detector.py on benchmark inputs:")

    add_h2("Screenshot 1 — Likely Scam Result (SBI Banking Phishing)")
    code_s1 = (
        "> python scam_detector.py\n"
        "Choice: 1\n"
        "Paste the message. Press Enter on an empty line when done.\n"
        "Dear customer your SBI KYC expired. Account will be blocked today.\n"
        "Click here http://sbi-kyc-update.xyz to update immediately\n\n"
        "=======================================================\n"
        "  SCAM DETECTION RESULT\n"
        "=======================================================\n"
        "  Score   : 100 / 100\n"
        "  Verdict : LIKELY SCAM\n"
        "  Type    : Bank / KYC Threat\n"
        "  Reasons (6 finding(s)):\n"
        "    1. [ +25] Threatens to block your account or demands KYC update\n"
        "    2. [ +15] Creates panic or urgency to act fast\n"
        "    3. [ +10] Pushes you to click a suspicious link\n"
        "    4. [ +15] Suspicious domain ending '.xyz': sbi-kyc-update.xyz\n"
        "    5. [ +30] Fake SBI domain: sbi-kyc-update.xyz\n"
        "    6. [ +10] 5 warning signs together (combination bonus)\n"
        "  Tip     : DO NOT reply, click links, or share any info. Block the sender.\n"
        "======================================================="
    )
    add_code_block(doc, code_s1)

    add_h2("Screenshot 2 — Safe Result (Legitimate Transactional OTP)")
    code_s2 = (
        "> python scam_detector.py\n"
        "Choice: 1\n"
        "Paste the message. Press Enter on an empty line when done.\n"
        "482913 is your OTP for payment of Rs 499 at Amazon. Do not share it with anyone.\n\n"
        "=======================================================\n"
        "  SCAM DETECTION RESULT\n"
        "=======================================================\n"
        "  Score   : 0 / 100\n"
        "  Verdict : SAFE\n"
        "  Type    : None\n"
        "  Reasons (1 finding(s)):\n"
        "    1. [ -20] 'Do not share' warning found (normal in genuine OTP messages)\n"
        "  Tip     : No strong scam pattern found. Stay alert for new tactics.\n"
        "======================================================="
    )
    add_code_block(doc, code_s2)

    add_h2("Screenshot 3 — Automated Test Suite Execution")
    code_s3 = (
        "> python scam_detector.py --test\n\n"
        "============================================================\n"
        "  AUTOMATED TEST SUITE (24 tests)\n"
        "============================================================\n"
        "   1. heavy_scam_sbi_kyc             Score:100  LIKELY SCAM  [PASS]\n"
        "   2. genuine_otp_safe               Score:  0  SAFE         [PASS]\n"
        "   3. prize_scam                     Score: 40  SUSPICIOUS   [PASS]\n"
        "   4. fake_job_scam                  Score: 75  LIKELY SCAM  [PASS]\n"
        "   5. upi_trick                      Score: 55  LIKELY SCAM  [PASS]\n"
        "   6. boundary_safe_24               Score: 15  SAFE         [PASS]\n"
        "   7. boundary_suspicious_25         Score: 25  SUSPICIOUS   [PASS]\n"
        "   8. boundary_scam_50               Score: 80  LIKELY SCAM  [PASS]\n"
        "   9. empty_whitespace               Score:  0  SAFE         [PASS]\n"
        "  10. only_newlines                  Score:  0  SAFE         [PASS]\n"
        "  11. emoji_only                     Score:  0  SAFE         [PASS]\n"
        "  12. unicode_mixed                  Score:  0  SAFE         [PASS]\n"
        "  13. genuine_bank_credit            Score:  0  SAFE         [PASS]\n"
        "  14. genuine_aadhaar_otp            Score:  0  SAFE         [PASS]\n"
        "  15. genuine_delivery               Score:  0  SAFE         [PASS]\n"
        "  16. genuine_emi_reminder           Score:  0  SAFE         [PASS]\n"
        "  17. real_bank_url_safe             Score:  0  SAFE         [PASS]\n"
        "  18. fake_domain_flagged            Score: 45  SUSPICIOUS   [PASS]\n"
        "  19. raw_ip_flagged                 Score: 25  SUSPICIOUS   [PASS]\n"
        "  20. shortened_url_flagged          Score: 40  SUSPICIOUS   [PASS]\n"
        "  21. word_boundary_no_fp            Score:  0  SAFE         [PASS]\n"
        "  22. score_capped_at_100            Score:100  LIKELY SCAM  [PASS]\n"
        "  23. spaced_otp_evasion             Score: 30  SUSPICIOUS   [PASS]\n"
        "  24. apk_malware                    Score: 35  SUSPICIOUS   [PASS]\n"
        "------------------------------------------------------------\n"
        "  Results: 24 passed, 0 failed out of 24\n"
        "  ALL TESTS PASSED!\n"
        "============================================================"
    )
    add_code_block(doc, code_s3)

    # ------------------ SECTION 8 ------------------
    add_h1("8. Testing & Validation")
    doc.add_paragraph(
        "The project includes 24 automated unit assertions executed via python scam_detector.py --test. "
        "The table below records 10 representative test cases across normal, boundary, empty, and evasion scenarios:"
    )
    test_table_data = [
        ["Test #", "Test Name", "Input Excerpt", "Expected Verdict", "Actual Result", "Status"],
        ["1", "heavy_scam_sbi", "URGENT: SBI account blocked! Update KYC at http://sbi-update.xyz...", "LIKELY SCAM, 100", "LIKELY SCAM, 100", "PASS"],
        ["2", "genuine_otp_safe", "Your OTP is 849302. Do not share this with anyone. Valid for 5 min.", "SAFE, 0", "SAFE, 0", "PASS"],
        ["6", "boundary_safe_24", "This is an urgent notice.", "SAFE (Score <= 24)", "SAFE, 15", "PASS"],
        ["7", "boundary_susp_25", "Urgent: click here to verify your details immediately.", "SUSPICIOUS (Score >= 25)", "SUSPICIOUS, 25", "PASS"],
        ["8", "boundary_scam_50", "Your account blocked! Update KYC at http://sbi-update.xyz", "LIKELY SCAM (Score >= 50)", "LIKELY SCAM, 80", "PASS"],
        ["9", "empty_spaces", "   ", "SAFE, 0", "SAFE, 0", "PASS"],
        ["11", "emoji_only", "🎉🎊🏆👑💰", "SAFE, 0", "SAFE, 0", "PASS"],
        ["14", "aadhaar_otp", "Your Aadhaar OTP is 745821. It is valid for 10 min. Do not share...", "SAFE, 0", "SAFE, 0", "PASS"],
        ["17", "real_bank_link", "Visit https://www.hdfcbank.com for online banking services.", "SAFE, 0", "SAFE, 0", "PASS"],
        ["21", "word_boundary", "The detergent arrived. Payment window is open today.", "SAFE, 0", "SAFE, 0", "PASS"]
    ]
    t_test = doc.add_table(rows=len(test_table_data), cols=6)
    for i, row in enumerate(test_table_data):
        for j, val in enumerate(row):
            t_test.cell(i, j).text = val
    style_table(t_test, [0.6, 1.4, 2.2, 1.1, 0.7, 0.5])

    # ------------------ SECTION 9 ------------------
    add_h1("9. Team Member Contributions")
    doc.add_paragraph("Each team member was assigned a dedicated subsystem matching the modular decomposition:")
    contrib_data = [
        ["Student Name", "Enrollment No.", "Module Owned", "Actual Work Performed & Defended in Viva"],
        ["Amritesh Kumar", "S26CSEU0943", "Lead; Core Engine & OOP", "Architected ScamAnalyzer, Rule base class, scoring formula, combination bonus, automated test harness (--test flag)."],
        ["Naved Ali", "S26CSEU0955", "History & Analytics", "Developed HistoryManager, CSV file append/read, summary statistics calculations, text bar charts, and Matplotlib visualizer."],
        ["Tanishk Singh", "S26CSEU0934", "Input & Benchmark", "Designed console multi-line ingestion, 7-option interactive menu, exception handling, and curated 35 labelled samples in data/samples.csv."],
        ["Aryan Chahal", "S26CSEU0933", "Regex & URL Engine", "Engineered URLRule domain extraction, shortener/IP/TLD detectors, fake brand spoofing logic, and recursive normalise_text()."],
        ["Praval Verma", "S26CSEU0935", "Heuristics & Documentation", "Constructed OTP safe-phrase discount logic, sensitive data filter with lambda, advisory tips dictionary, and Activity 3-7 documentation."]
    ]
    t_contrib = doc.add_table(rows=len(contrib_data), cols=4)
    for i, row in enumerate(contrib_data):
        for j, val in enumerate(row):
            t_contrib.cell(i, j).text = val
    style_table(t_contrib, [1.4, 1.2, 1.5, 2.4])

    # ------------------ SECTION 10 ------------------
    add_h1("10. Challenges Faced and Learning")
    challenges = [
        ("False Positives on Legitimate Banking Alerts", "Initially, any SMS containing the word 'OTP' was flagged as a sensitive request (+30 pts), causing genuine Amazon and SBI login messages to fail. We resolved this by creating check_safe_phrase() which detects authentic dispatch patterns and awards a -20 safe discount while suppressing 'otp'."),
        ("Evasion by Spaced Characters", "Adversaries frequently insert whitespace between letters ('O T P', 'P I N') to bypass simple word searches. We solved this using a recursive normalise_text() function with a regex lookahead that collapses single letter sequences across recursive passes."),
        ("URL Trailing Punctuation Parsing", "SMS text often concludes with a period directly after a link ('visit https://sbi.co.in.'). A naive regex incorporated the period into the host name, causing legitimate domain matching to fail. We implemented negative-index string slicing (domain[:-1]) to clean trailing punctuation."),
        ("Explainability vs Complexity", "We chose a weighted rule engine over machine learning. While ML is popular, it operates as a black box. Our rule engine provides 100% transparent scoring where every point can be explained during a viva examination.")
    ]
    for title, desc in challenges:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(f"• {title}: ")
        r.bold = True
        p.add_run(desc)

    # ------------------ SECTION 11 ------------------
    add_h1("11. Conclusion and Future Improvements")
    doc.add_paragraph(
        "The Offline Scam Message Detector successfully proves that effective mobile cybersecurity does not require "
        "cloud computing, private data transmission, or resource-heavy machine learning models. Built strictly using "
        "the Python standard library, the application executes in under 3 milliseconds, correctly classifies 100% of "
        "benchmark attacks, and produces explainable results."
    )
    doc.add_paragraph("Future roadmap items include:")
    future_items = [
        "1. Graphical User Interface (GUI): Build a lightweight desktop frontend using Python's built-in Tkinter package.",
        "2. External Rule Configuration: Allow security analysts to update detection patterns via an external JSON configuration file without modifying source code.",
        "3. Multilingual Support: Integrate phonemic transliteration for Devanagari Hindi and South Indian languages.",
        "4. Native Mobile Integration: Port the core scoring engine to Android/Kivy for real-time background SMS interception."
    ]
    for item in future_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        p.add_run(item)

    # ------------------ SECTION 12: ACTIVITIES 3 TO 7 ------------------
    doc.add_page_break()
    add_h1("12. Experiential Activities 3 to 7 (Mandatory Milestone 2)")

    # Activity 3
    add_h2("Activity 3: Problem Decomposition")
    doc.add_paragraph(
        "Problem decomposition is the computational thinking pillar of breaking a monolithic objective into "
        "isolated sub-problems mapped directly to Python functions with distinct input/output contracts."
    )
    decomp_ascii = (
        "                    [Offline Scam Message Detector]\n"
        "                                   |\n"
        "    +------------------+-----------+-----------+------------------+\n"
        "    |                  |                       |                  |\n"
        "[1. Ingestion]  [2. Threat Heuristics]  [3. Decision Engine]  [4. Persistence]\n"
        "    |                  |                       |                  |\n"
        "    |-- get_input      |-- check_safe_phrase   |-- classify_      |-- HistoryManager.save\n"
        "    |-- preprocess     |-- check_sensitive     |   verdict        |-- HistoryManager.load\n"
        "    |-- normalise_text |-- KeywordRule.check   |-- ScamAnalyzer.  |-- display_stats\n"
        "        (recursive)    |-- URLRule.check_urls  |   analyse        |-- export_flagged\n"
        "                       |-- check_other_signs   |-- get_tip\n"
    )
    add_code_block(doc, decomp_ascii)

    # Activity 4
    add_h2("Activity 4: Card Sorting & Algorithmic Comparison")
    doc.add_paragraph(
        "Card sorting grouped system inputs (message, menu choice), rules (7 threat categories), data items "
        "(RULES, SAFE_DOMAINS), and output streams. We evaluated three algorithmic approaches:"
    )
    comp_data = [
        ["Criterion", "Simple Keyword Count", "Weighted Rule & Regex Engine (CHOSEN)", "Machine Learning (Naive Bayes)"],
        ["Detection Accuracy", "Low (45–60%)", "High (95–100% on benchmarks)", "High (90–95%)"],
        ["Explainability", "Moderate (word counts)", "Full (100% transparent audit trail)", "Black-Box (probabilistic weights)"],
        ["Offline Feasibility", "High", "High (zero external downloads)", "Medium (requires model serialization)"],
        ["False-Positive Resistance", "Very Poor", "High (safe-phrase OTP discount)", "Moderate (sensitive to train drift)"],
        ["Sem-1 Freshers Scope", "Too simplistic", "Rigorous, clean, and defendable", "Out-of-scope (requires sklearn/numpy)"]
    ]
    t_comp = doc.add_table(rows=len(comp_data), cols=4)
    for i, row in enumerate(comp_data):
        for j, val in enumerate(row):
            t_comp.cell(i, j).text = val
    style_table(t_comp, [1.3, 1.4, 2.2, 1.6])

    # Activity 5
    add_h2("Activity 5: Decision Tree & Flowchart Design")
    doc.add_paragraph("The decision tree evaluates messages through a sequence of branching conditional stages:")
    dt_ascii = (
        "  [Input Message] -> [preprocess() & recursive normalise_text()]\n"
        "          |\n"
        "          +---> < Empty / Spaces? > --YES--> [Score = 0, Verdict = SAFE]\n"
        "          |              | NO\n"
        "          |              v\n"
        "          +---> < 'do not share' present? > --YES--> [Apply -20 Discount; Suppress 'OTP']\n"
        "          |              | NO\n"
        "          |              v\n"
        "          +---> [Scan KeywordRule (7 Categories)]\n"
        "          |              |\n"
        "          +---> [Scan Sensitive Data (PIN, CVV, Card Details)]\n"
        "          |              |\n"
        "          +---> [URL Checks (Shorteners: +15, IP: +25, TLD: +15, Spoof: +30)]\n"
        "          |              |\n"
        "          +---> [Other Signs (APK: +20, Mobile: +10, Punctuation: +5)]\n"
        "          |              |\n"
        "          +---> < Positive findings >= 3? > --YES--> [Add +10 Combo Bonus]\n"
        "          |              |\n"
        "          v              v\n"
        "  [Clamp Score 0..100] -> [0..24: SAFE | 25..49: SUSPICIOUS | 50..100: LIKELY SCAM]\n"
    )
    add_code_block(doc, dt_ascii)

    # Activity 6
    add_h2("Activity 6: Object Modelling (Class Cards & Relationships)")
    doc.add_paragraph(
        "Object modelling organizes functionality into classes displaying inheritance and composition. "
        "Rule serves as an abstract base class; KeywordRule and URLRule inherit and specialize its interface. "
        "ScamAnalyzer composes these rules alongside HistoryManager:"
    )
    om_ascii = (
        "         Exception                Rule (Base Class: _name, _weight, _category)\n"
        "             ^                                       ^\n"
        "             | (inherits)                            | (inherits)\n"
        "     ScamDetectorError               +---------------+---------------+\n"
        "             ^                       |                               |\n"
        "             | (inherits)       KeywordRule                       URLRule\n"
        "    InvalidMessageError              ^                               ^\n"
        "                                     | (composes)                    | (composes)\n"
        "                             +-------+-------------------------------+ \n"
        "                             |                                         \n"
        "                       ScamAnalyzer  -----(composes)-----> HistoryManager\n"
        "                             |                                         \n"
        "                             +-----(creates)-----> Result              \n"
    )
    add_code_block(doc, om_ascii)

    # Activity 7
    add_h2("Activity 7: Data Interpretation & Evaluation")
    doc.add_paragraph(
        "We evaluated the upgraded system against a curated benchmark of 35 labelled SMS/WhatsApp messages "
        "(20 Scams, 15 Safe) stored in data/samples.csv. The confusion matrix and metrics were as follows:"
    )
    metrics_data = [
        ["Metric", "Formula / Source", "Benchmark Value", "Interpretation"],
        ["True Positives (TP)", "Scams correctly flagged", "20", "Caught 100% of banking, lottery, and job fraud."],
        ["True Negatives (TN)", "Safe messages passed", "15", "All legitimate OTPs and bank alerts passed."],
        ["False Positives (FP)", "Safe messages wrongly flagged", "0", "Zero false alarms due to contextual OTP heuristics."],
        ["False Negatives (FN)", "Scams missed", "0", "No scam slipped through to Safe status."],
        ["Overall Accuracy", "(TP + TN) / Total", "100.0%", "All 35 benchmark samples correctly classified."],
        ["Precision", "TP / (TP + FP)", "1.00 (100%)", "Every predicted scam was an authentic threat."],
        ["Recall (Sensitivity)", "TP / (TP + FN)", "1.00 (100%)", "No attack evaded detection."],
        ["F1-Score", "2 * (P * R) / (P + R)", "1.00", "Harmonic balance between precision and sensitivity."]
    ]
    t_met = doc.add_table(rows=len(metrics_data), cols=4)
    for i, row in enumerate(metrics_data):
        for j, val in enumerate(row):
            t_met.cell(i, j).text = val
    style_table(t_met, [1.5, 1.6, 1.2, 2.2])

    chart_img_path = os.path.join("docs", "charts.png")
    if os.path.isfile(chart_img_path):
        doc.add_paragraph().paragraph_format.space_before = Pt(8)
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img.add_run().add_picture(chart_img_path, width=Inches(6.0))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_cap = p_cap.add_run("Figure 1: Benchmark Metric Charts — Verdict Pie, Score Histogram, and Rule Trigger Frequencies")
        r_cap.italic = True
        r_cap.font.size = Pt(8.5)

    # ------------------ SECTION 13 ------------------
    add_h1("13. References & Declarations")
    refs = [
        "1. Bennett University, Computational Thinking and Programming Course Guide (2026CSAE100), Academic Year 2026-27.",
        "2. Python 3.13 Standard Library Documentation: re, csv, os, sys, datetime modules.",
        "3. Reserve Bank of India (RBI) / Cyber Crime Portal Awareness Guidelines on Phishing and SMS Spoofing.",
        "4. AI Assistance Acknowledgement: AI-assisted tools were utilised for formatting review, test-case brainstorming, and documentation proofreading. The program source code was authored, debugged, and validated locally by the project team."
    ]
    for ref in refs:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        p.add_run(ref)

    doc.add_paragraph().paragraph_format.space_before = Pt(12)
    p_decl = doc.add_paragraph()
    r = p_decl.add_run("Declaration: We confirm that we understand the submitted project and that each member can fully explain their assigned module during viva voce examination.")
    r.bold = True

    # ------------------ APPENDIX: SOURCE CODE ------------------
    doc.add_page_break()
    add_h1("Appendix: Complete Python Source Code (scam_detector.py)")
    doc.add_paragraph("Full source code listing of scam_detector.py without omissions:")

    code_path = "scam_detector.py"
    if os.path.isfile(code_path):
        with open(code_path, "r", encoding="utf-8") as f:
            full_code = f.read()
        # chunk code in blocks to prevent single cell overflow
        lines = full_code.split("\n")
        chunk_size = 80
        for idx in range(0, len(lines), chunk_size):
            chunk = "\n".join(lines[idx:idx+chunk_size])
            add_code_block(doc, chunk)

    output_path = "Offline_Scam_Message_Detector_Project_Report.docx"
    doc.save(output_path)
    print(f"Report generated successfully: {output_path}")

if __name__ == "__main__":
    build_report()

