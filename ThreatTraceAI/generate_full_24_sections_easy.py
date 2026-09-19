import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_cell_margins(cell, top=120, bottom=120, left=160, right=160):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def add_callout(doc, text, title="💡 EASY EXPLANATION (FOR KIDS & BEGINNERS)", bg_hex="F0FDF4", border_hex="22C55E"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
    
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    
    left = OxmlElement('w:left')
    left.set(qn('w:val'), 'single')
    left.set(qn('w:sz'), '24')
    left.set(qn('w:space'), '0')
    left.set(qn('w:color'), border_hex)
    tcBorders.append(left)
    
    for side in ['top', 'bottom', 'right']:
        b = OxmlElement(f'w:{side}')
        b.set(qn('w:val'), 'none')
        tcBorders.append(b)
    tcPr.append(tcBorders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(3)
    run_t = p.add_run(f"{title}\n")
    run_t.bold = True
    run_t.font.size = Pt(10)
    run_t.font.color.rgb = RGBColor(15, 23, 42)
    
    run_b = p.add_run(text)
    run_b.font.size = Pt(9.5)
    run_b.font.color.rgb = RGBColor(51, 65, 85)
    
    sp = doc.add_paragraph()
    sp.paragraph_format.space_before = Pt(0)
    sp.paragraph_format.space_after = Pt(4)

def style_heading_1(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(14)
    run.font.color.rgb = RGBColor(2, 132, 199) # Ocean Blue
    return p

def style_heading_2(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(11.5)
    run.font.color.rgb = RGBColor(15, 23, 42)
    return p

def style_heading_3(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(10.5)
    run.font.color.rgb = RGBColor(71, 85, 105)
    return p

def style_body(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.15
    run = p.add_run(text)
    run.font.size = Pt(9.5)
    run.font.color.rgb = RGBColor(51, 65, 85)
    return p

def create_table(doc, headers, rows):
    table = doc.add_table(rows=len(rows)+1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    for i, h in enumerate(headers):
        cell = table.cell(0, i)
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        run = p.add_run(h)
        run.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)
        run.font.size = Pt(9)

    for r_idx, row_data in enumerate(rows, start=1):
        bg = "F8FAFC" if r_idx % 2 == 1 else "FFFFFF"
        for c_idx, val in enumerate(row_data):
            cell = table.cell(r_idx, c_idx)
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=60, bottom=60, left=80, right=80)
            p = cell.paragraphs[0]
            run = p.add_run(str(val))
            run.font.size = Pt(8.5)
            run.font.color.rgb = RGBColor(30, 41, 59)
            if c_idx == 0:
                run.bold = True

    sp = doc.add_paragraph()
    sp.paragraph_format.space_after = Pt(4)

def build_full_report():
    doc = docx.Document()
    for s in doc.sections:
        s.top_margin = Inches(0.8)
        s.bottom_margin = Inches(0.8)
        s.left_margin = Inches(0.8)
        s.right_margin = Inches(0.8)

    # Title Block
    tp = doc.add_paragraph()
    tp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    trun = tp.add_run("🛡️ THREAT TRACE AI\nCOMPREHENSIVE PROJECT REPORT")
    trun.bold = True
    trun.font.size = Pt(22)
    trun.font.color.rgb = RGBColor(2, 132, 199)

    sp = doc.add_paragraph()
    sp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    srun = sp.add_run("Smart India Hackathon (SIH) 2026 • Master Architecture & Explanatory Guide\nWritten So Even a 10-Year-Old Can Read and Master Every Detail!")
    srun.font.size = Pt(11)
    srun.font.italic = True
    srun.font.color.rgb = RGBColor(100, 116, 139)

    # TABLE OF CONTENTS
    style_heading_1(doc, "TABLE OF CONTENTS")
    toc_items = [
        "1. Executive Summary",
        "2. Project Architecture Overview",
        "3. Directory Structure (Full Tree)",
        "4. Backend — FastAPI Server (4.1 Entry Point, 4.2 Config, 4.3 Database, 4.4 All Routes)",
        "5. Core Analysis Pipeline — 14 Steps (5.1 to 5.14)",
        "6. Risk Engine — Full Breakdown",
        "7. Cryptographic Security Layer (7.1 to 7.7)",
        "8. Blockchain Chain-of-Custody (8.1 Service, 8.2 Smart Contract)",
        "9. Salting & Peppering — ID Obfuscation",
        "10. Report Generation System",
        "11. SOC Orchestration & Notifier (11.1 CEF, 11.2 Jira, 11.3 Slack, 11.4 Actions)",
        "12. SSRF Protection Layer",
        "13. Geolocation Service",
        "14. Browser Extension — Chrome MV3 (with Account Binding Lock)",
        "15. Frontend — React Dashboard (15.1 Pages, 15.2 Components)",
        "16. Frontend Services Layer (api.js)",
        "17. Data Models — Full Schema",
        "18. Utility Layer",
        "19. Security Mechanisms Summary Table",
        "20. Technology Stack Summary",
        "21. Full Data Flow (End-to-End)",
        "22. API Endpoint Reference (All Routes)",
        "23. Keyword Dictionaries & Signal Lists",
        "24. Configuration Variables Reference"
    ]
    for item in toc_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(item)
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(15, 23, 42)

    # =========================================================================
    # 1. EXECUTIVE SUMMARY
    # =========================================================================
    style_heading_1(doc, "1. Executive Summary")
    style_body(doc, 
        "ThreatTrace AI is a full-stack, AI-powered email threat detection and digital forensic intelligence platform. "
        "It protects individuals, organizations, and law enforcement teams by analyzing suspicious emails, detecting phishing attacks, "
        "generating explainable evidence, and cryptographically sealing proof onto a tamper-proof blockchain.")
    add_callout(doc,
        "Imagine your email inbox is a mailbox outside your home. Tricksters send fake letters pretending to be the bank or school principal, "
        "screaming 'URGENT! Give me your password or your account will be deleted in 24 hours!' That is called Phishing. "
        "ThreatTrace AI is a superhero robot detective that uses a magnifying glass to inspect the letter, spots the fake mask, checks the return address, "
        "and locks the evidence in an unbreakable digital safe so you never get tricked!",
        title="🧒 1. KID-FRIENDLY SUMMARY: THE DIGITAL DETECTIVE")

    # =========================================================================
    # 2. PROJECT ARCHITECTURE OVERVIEW
    # =========================================================================
    style_heading_1(doc, "2. Project Architecture Overview")
    style_body(doc,
        "The system uses a 4-tier decoupled defense-in-depth architecture:\n"
        "• Tier 1: Ingestion Tier (Chrome MV3 Extension scraping Gmail DOM without requiring SMTP relay access).\n"
        "• Tier 2: Analytical Core (FastAPI Python asynchronous server hosting the 14-step forensic engine).\n"
        "• Tier 3: SOC Cockpit Tier (React 18 single-page application with risk gauges, 3D globes, and interactive graph visualizations).\n"
        "• Tier 4: Persistence & Notary Tier (SQLite database with WAL mode and Polygon Amoy blockchain smart contract).")
    add_callout(doc,
        "Think of it like an amusement park security team:\n"
        "1. The Guard at the Gate (Chrome Extension): Watches the visitors entering your Gmail.\n"
        "2. The Lab Scientist (Python Backend): Tests every clue under a microscope.\n"
        "3. The Control Tower (React Cockpit): Big glowing screens with maps and alarms.\n"
        "4. The Metal Safe & Stone Wall (Database & Blockchain): Stores the record forever where nobody can erase it!",
        title="🧒 2. ARCHITECTURE ANALOGY: THE 4 DEFENDERS")

    # =========================================================================
    # 3. DIRECTORY STRUCTURE (FULL TREE)
    # =========================================================================
    style_heading_1(doc, "3. Directory Structure (Full Tree)")
    style_body(doc,
        "The codebase is cleanly organized into backend, frontend, extension, and contracts:\n"
        "• backend/app/main.py: Entry point bootstrapping FastAPI.\n"
        "• backend/app/routes/: auth.py, analyze.py, cases.py, reports.py, intelligence.py, blockchain.py, crypto.py, soc.py.\n"
        "• backend/app/services/: email_parser.py, header_analyzer.py, ioc_extractor.py, url_unmasker.py, risk_engine.py, etc.\n"
        "• frontend/src/pages/ & components/: ThreatTraceCockpit.jsx, LiveRiskGauge.jsx, IOCPanel.jsx, IPGeolocation.jsx, etc.\n"
        "• extension/: manifest.json, background.js, content.js, popup.js, popup.html, content.css.\n"
        "• contracts/: ThreatTraceRegistry.sol (Solidity smart contract on Polygon).")
    add_callout(doc,
        "Just like a school backpack has different pockets for your pencils, your math book, and your lunchbox, "
        "ThreatTrace AI puts the detective brains in 'backend', the glowing screens in 'frontend', and the magnifying glass in 'extension'!",
        title="🧒 3. DIRECTORY STRUCTURE: THE BACKPACK POCKETS")

    # =========================================================================
    # 4. BACKEND — FASTAPI SERVER
    # =========================================================================
    style_heading_1(doc, "4. Backend — FastAPI Server")
    style_heading_2(doc, "4.1 Entry Point & Application Bootstrap (main.py)")
    style_body(doc, "FastAPI app instance running with lifespan context manager to initialize SQLite database tables asynchronously on startup. CORS configured with wildcard allow_origins=['*'].")
    style_heading_2(doc, "4.2 Configuration System (config.py)")
    style_body(doc, "Pydantic BaseSettings loading from .env: APP_NAME, DEMO_MODE, BLOCKCHAIN_ENABLED, POLYGON_RPC_URL, CONTRACT_ADDRESS, PRIVATE_KEY, SECRET_PEPPER.")
    style_heading_2(doc, "4.3 Database Layer (database.py & models.py)")
    style_body(doc, "SQLAlchemy AsyncEngine with SQLite (aiosqlite). Models: Case (stores case_id, risk_score, risk_factors, blockchain_hash, salt, pepper) and ThreatIntelCache (cached IOC threat feeds).")
    style_heading_2(doc, "4.4 API Routes — All Endpoints")
    style_body(doc, "Routers mounted for Auth (/api/auth), Analyze (/api/analyze), Cases (/api/cases), Reports (/api/reports), Intelligence (/api/intelligence), Blockchain (/api/blockchain), Crypto (/api/crypto), and SOC (/api/soc).")
    add_callout(doc,
        "main.py is like the power switch that turns on the robot's brain. config.py is the robot's secret notebook of rules. "
        "database.py is the robot's memory filing cabinet where it remembers every case it ever solved!",
        title="🧒 4. BACKEND: THE ROBOT'S HEADQUARTERS")

    # =========================================================================
    # 5. CORE ANALYSIS PIPELINE — 14 STEPS
    # =========================================================================
    style_heading_1(doc, "5. Core Analysis Pipeline — 14 Steps")
    
    steps_data = [
        ("5.1 Step 1: Email Parsing (email_parser.py)",
         "Parses raw MIME text, headers, multipart/alternative plain text, and HTML bodies into a normalized Python dictionary.",
         "Gently opening the envelope, unfolding the letter, and laying it flat on the desk so you can read every word clearly."),
        
        ("5.2 Step 2: Header Analysis (header_analyzer.py)",
         "Evaluates Authentication-Results for SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC alignment passes/fails.",
         "Checking the official postmark stamp on the envelope. Did Google really send this, or was the stamp drawn with fake markers?"),
        
        ("5.3 Step 3: Display Name Spoofing (header_analyzer.py)",
         "Compares RFC 5322 From display name (e.g. 'PayPal Security') against the actual domain in the email address (e.g. 'bad-guy.ru').",
         "The trickster is wearing a funny paper mask that says 'Bank Manager'. We pull off the mask and see their real pirate identity!"),
        
        ("5.4 Step 4: IOC Extraction (ioc_extractor.py)",
         "Extracts Indicators of Compromise: IPv4 addresses, domain names, and HTTP/HTTPS URLs with RFC 1918 private IP suppression.",
         "Looking for footprints in the mud, candy wrappers dropped on the floor, and fingerprints on the door handle."),
        
        ("5.5 Step 5: URL Unmasking & Deobfuscation (url_unmasker.py)",
         "Unwraps Google redirect URLs (google.com/url?q=), resolves URL shorteners (bit.ly, tinyurl), and unmasks hex/octal encoded IP URLs.",
         "The villain put a shiny golden candy wrapper over a sour lemon. We peel off the wrapper to see the real rotten fruit inside!"),
        
        ("5.6 Step 6: Live Threat Intelligence Feeds (threat_intelligence.py)",
         "Queries URLhaus, VirusTotal, and PhishTank feeds asynchronously with in-memory caching in ThreatIntelCache.",
         "Calling the International Police Hotline: 'Has this shady website ever robbed anyone before?' If yes, BUSTED!"),
        
        ("5.7 Step 7: Content Scoring (risk_engine.py)",
         "Keyword and phrase matching across Urgency, Credential Harvest, Financial Panic, Account Suspension, and Executive Impersonation.",
         "Listening for scary screaming words: 'QUICK! YOUR ACCOUNT IS EXPIRING IN 1 HOUR! GIVE ME YOUR MONEY NOW!'"),
        
        ("5.8 Step 8: URL Heuristic Scoring (risk_engine.py)",
         "Detects IP-as-hostname, suspicious top-level domains (.xyz, .top, .ru, .work), excessive subdomains, and punycode homoglyphs.",
         "Looking for sneaky spelling tricks like 'paypa1.com' with a number 1, or weird websites with 10 dots like 'free.games.win.ru'."),
        
        ("5.9 Step 9: Link Mismatch Detection (risk_engine.py)",
         "Compares anchor tag inner text (e.g. 'https://bank.com') with the actual href destination attribute.",
         "A road sign pointing left says 'To Disneyland!', but if you walk down that path, you fall right into a robber's trap!"),
        
        ("5.10 Step 10: Sender Heuristics (risk_engine.py)",
         "Scores free webmail providers (gmail, yahoo) used for corporate notices, high-entropy usernames, and mismatched Reply-To headers.",
         "The letter claims to be from Microsoft headquarters, but the return envelope says: 'bob_secret_mailbox99@free-mail.com'."),
        
        ("5.11 Step 11: Redirect Chain Analysis (url_unmasker.py)",
         "Follows HTTP 301/302/307/308 redirect chains up to 5 hops with timeout and loop protection.",
         "Chasing the trickster through a crazy maze of funhouse mirrors where they bounce from door A, to door B, to door C!"),
        
        ("5.12 Step 12: Risk Score Combiner & Verdict (risk_engine.py)",
         "Combines sub-scores via non-linear weighted formula capped at 100. Categorizes: LOW (0-39), MEDIUM (40-69), HIGH (70-100).",
         "The Danger Thermometer: 🟢 Green = Safe, 🟡 Yellow = Be careful, 🔴 Red = DANGER! Do not click!"),
        
        ("5.13 Step 13: Geolocation (geolocation.py)",
         "Geolocates sender and domain IP addresses via ip-api.com: country, city, ISP, ASN, latitude, longitude.",
         "Spinning a giant 3D globe and putting a glowing pin right on the exact city and country where the villain's computer lives!"),
        
        ("5.14 Step 14: Infrastructure Graph (graph_engine.py)",
         "Generates a multi-node force-directed graph connecting the email sender, domains, IP addresses, and threat intel status.",
         "The detective's pin-board in the movies with red yarn strings connecting all the suspects together!")
    ]

    for title, tech, kid in steps_data:
        style_heading_2(doc, title)
        style_body(doc, tech)
        add_callout(doc, kid, title=f"🧒 SIMPLE EXPLANATION: {title.split(':')[1].strip()}")

    # =========================================================================
    # 6. RISK ENGINE — FULL BREAKDOWN
    # =========================================================================
    style_heading_1(doc, "6. Risk Engine — Full Breakdown")
    style_body(doc,
        "The risk engine calculates the final score mathematically: Total = combine_scores(content_score, url_score, sender_score, header_score, mismatch_score). "
        "Every single score is explainable — no mysterious black-box neural networks where nobody knows why a decision was made.")
    add_callout(doc,
        "Imagine a report card where your teacher gives you points for showing your work: "
        "+25 points for fake mask, +30 points for panic words, +40 points for dangerous link. "
        "Add them up and you get 95 out of 100 on the Danger Meter!",
        title="🧒 6. RISK ENGINE: THE DANGER REPORT CARD")

    # =========================================================================
    # 7. CRYPTOGRAPHIC SECURITY LAYER
    # =========================================================================
    style_heading_1(doc, "7. Cryptographic Security Layer")
    style_heading_2(doc, "7.1 ECDSA Key Management (crypto_service.py)")
    style_body(doc, "Uses SECP256R1 elliptic curve cryptography. The private key signs evidence; the public key is distributed for universal verification.")
    style_heading_2(doc, "7.2 Canonical SHA-256 Hashing")
    style_body(doc, "Sorts JSON keys alphabetically and eliminates whitespace before hashing to ensure identical hash output regardless of platform.")
    style_heading_2(doc, "7.3 Digital Signature (ECDSA SECP256R1)")
    style_body(doc, "Creates a DER-encoded cryptographic signature proving the evidence was produced by ThreatTrace AI at that exact millisecond.")
    style_heading_2(doc, "7.4 Cryptographic Evidence Seal")
    style_body(doc, "Bundles the canonical hash, digital signature, public key fingerprint, and UTC timestamp into an evidence envelope.")
    style_heading_2(doc, "7.5 Tamper Detection Engine")
    style_body(doc, "Verifies the ECDSA signature against the case payload. If even a single byte has changed, it alerts: TAMPERED.")
    style_heading_2(doc, "7.6 AES-256-GCM Encrypted Vault")
    style_body(doc, "Encrypts raw email bodies with 256-bit AES in Galois/Counter Mode with 12-byte initialization vectors and 16-byte auth tags.")
    style_heading_2(doc, "7.7 DKIM Header Cryptographic Inspector")
    style_body(doc, "Validates cryptographic DKIM-Signature headers against public RSA/Ed25519 DNS records.")
    add_callout(doc,
        "Police detectives put stolen jewels in a plastic evidence bag with a tamper-proof sticker. "
        "ThreatTrace AI puts the email in a mathematical steel safe with an invisible digital seal. "
        "If anyone tries to scratch off even one letter, the alarm screams: 'SOMEONE TAMPERED WITH THE EVIDENCE!'",
        title="🧒 7. CRYPTOGRAPHY: THE MAGIC EVIDENCE BAG")

    # =========================================================================
    # 8. BLOCKCHAIN CHAIN-OF-CUSTODY
    # =========================================================================
    style_heading_1(doc, "8. Blockchain Chain-of-Custody")
    style_heading_2(doc, "8.1 Blockchain Service (blockchain_service.py)")
    style_body(doc, "Connects via Web3.py to the Polygon Amoy testnet. Records case_id, sha256_hash, risk_score, and timestamp.")
    style_heading_2(doc, "8.2 Smart Contract (ThreatTraceRegistry.sol)")
    style_body(doc, "Solidity contract storing CaseRecord structs in a mapping(string => CaseRecord) with CaseLogged events for public verification.")
    add_callout(doc,
        "Imagine a giant stone wall in the sky that thousands of computers all around the world copy and protect. "
        "ThreatTrace AI chisels the fingerprint of the bad email into this stone wall. "
        "Nobody in the world — not even the best hacker alive — can ever erase it! So in real court, the judge has 100% indisputable proof!",
        title="🧒 8. BLOCKCHAIN: THE FLOATING STONE WALL")

    # =========================================================================
    # 9. SALTING & PEPPERING — ID OBFUSCATION
    # =========================================================================
    style_heading_1(doc, "9. Salting & Peppering — ID Obfuscation")
    style_body(doc, "Prevents enumeration attacks. Each case ID is generated as: SHA256(UUID + Random Salt + Server Secret Pepper)[:16].")
    add_callout(doc,
        "Just like adding salt and pepper to food makes it taste unique, adding digital salt and pepper scrambles the case numbers "
        "so sneaky outsiders can never guess or peek at other people's private cases!",
        title="🧒 9. SALTING & PEPPERING: SECRET SPICES")

    # =========================================================================
    # 10. REPORT GENERATION SYSTEM
    # =========================================================================
    style_heading_1(doc, "10. Report Generation System")
    style_body(doc, "Generates downloadable forensic reports in both machine-readable JSON and human-readable, beautifully styled standalone HTML with embedded cryptographic signatures.")
    add_callout(doc,
        "ThreatTrace AI prints out a shiny, colorful graduation diploma for the case, showing all the clues, maps, and stamps, "
        "ready to hand to your boss or the police officer!",
        title="🧒 10. REPORTS: THE DETECTIVE'S FINAL DIPLOMA")

    # =========================================================================
    # 11. SOC ORCHESTRATION & NOTIFIER
    # =========================================================================
    style_heading_1(doc, "11. SOC Orchestration & Notifier")
    style_heading_2(doc, "11.1 CEF (Common Event Format)")
    style_body(doc, "Formats alerts for enterprise SIEMs: CEF:0|ThreatTrace|ThreatTraceAI|1.0|PHISH_DETECTED|Critical Threat|8|src=... msg=...")
    style_heading_2(doc, "11.2 Jira Service Management")
    style_body(doc, "Dispatches REST API calls to create high-priority incident response tickets for SOC engineers.")
    style_heading_2(doc, "11.3 Slack Alert Dispatch")
    style_body(doc, "Posts rich Block Kit JSON cards with colored threat levels, risk factors, and direct Cockpit links to Slack channels.")
    style_heading_2(doc, "11.4 SOC Route Extra Capabilities")
    style_body(doc, "Simulates quarantine commands, blocklisting IPs, and dispatching multi-channel webhook notifications.")
    add_callout(doc,
        "When a fire breaks out, the fire alarm rings! ThreatTrace AI rings the fire bell on Slack ('Fire in the building!'), "
        "hands a work clipboard to Jira ('Fix this now!'), and radios the city police on Splunk!",
        title="🧒 11. SOC ALERTS: THE FIRE STATION ALARM")

    # =========================================================================
    # 12. SSRF PROTECTION LAYER
    # =========================================================================
    style_heading_1(doc, "12. SSRF Protection Layer")
    style_body(doc, "Server-Side Request Forgery protection: Validates every outgoing URL before fetching. Strictly blocks private/internal IP ranges: 127.0.0.1 (localhost), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and AWS metadata 169.254.169.254.")
    add_callout(doc,
        "A villain might try to trick our detective robot into investigating its own house and stealing its own secrets! "
        "Our SSRF shield stops the robot: 'Hold on! That address is inside our own home! We refuse to go there!'",
        title="🧒 12. SSRF SHIELD: PROTECTING OUR OWN HOUSE")

    # =========================================================================
    # 13. GEOLOCATION SERVICE
    # =========================================================================
    style_heading_1(doc, "13. Geolocation Service")
    style_body(doc, "Queries ip-api.com to resolve external IP addresses into country, country code, region, city, zip, latitude, longitude, and ISP.")
    add_callout(doc,
        "Like looking at the postal stamp on a letter and seeing the city postmark: 'This was mailed from London, England!'",
        title="🧒 13. GEOLOCATION: THE WORLD ATLAS")

    # =========================================================================
    # 14. BROWSER EXTENSION — CHROME MV3
    # =========================================================================
    style_heading_1(doc, "14. Browser Extension — Chrome MV3")
    style_body(doc,
        "Manifest V3 compliant extension with background service worker, in-page content scripts, and floating action button. "
        "NEW ENHANCED CAPABILITY: Account Binding & Login Lock System! The extension authenticates via /api/auth/login and locks itself strictly to the authorized email address. "
        "If a user opens an unmatched Gmail account, the shield turns red (UNMATCHED MAILBOX) and denies scanning.")
    add_callout(doc,
        "The extension is your magic magnifying glass inside Gmail! It now has a personal key: it only unlocks for YOUR email address. "
        "If a stranger borrows your computer, the shield locks itself: 'Access Denied! You are not the registered owner!'",
        title="🧒 14. EXTENSION: THE MAGNIFYING GLASS WITH A KEY")

    # =========================================================================
    # 15. FRONTEND — REACT DASHBOARD
    # =========================================================================
    style_heading_1(doc, "15. Frontend — React Dashboard")
    style_heading_2(doc, "15.1 Pages (ThreatTraceCockpit.jsx)")
    style_body(doc, "Single-page responsive dashboard powered by Vite and React 18 with dark-mode cybersecurity theme.")
    style_heading_2(doc, "15.2 Components")
    style_body(doc, "Header, LiveRiskGauge (SVG semi-circle gauge), RiskFactors, IOCPanel, IPGeolocation (interactive leaflet map), GraphViewer (SVG force-directed network), CryptoSealModal, CaseHistory, ReportPanel, and ExtensionNotice.")
    add_callout(doc,
        "The superhero control room! Big glowing dashboards, animated dials that spin, 3D world maps, and glowing spiderweb lines connecting all the suspects!",
        title="🧒 15. FRONTEND: THE BATCAVE COMMAND CENTER")

    # =========================================================================
    # 16. FRONTEND SERVICES LAYER (api.js)
    # =========================================================================
    style_heading_1(doc, "16. Frontend Services Layer (api.js)")
    style_body(doc, "Encapsulates all asynchronous fetch() calls to the backend with URL fallback (Render cloud API -> local 127.0.0.1:8000 -> localhost:8000).")
    add_callout(doc,
        "The invisible telephone wire that connects the superhero control room to the detective's brain in the laboratory!",
        title="🧒 16. API SERVICES: THE MAGIC TELEPHONE WIRE")

    # =========================================================================
    # 17. DATA MODELS — FULL SCHEMA
    # =========================================================================
    style_heading_1(doc, "17. Data Models — Full Schema")
    style_body(doc,
        "Case Table: id, case_id (VARCHAR 64), subject, sender, recipient, raw_headers, body_text, risk_score, risk_level, risk_factors (JSON), urls (JSON), domains (JSON), ips (JSON), geo_locations (JSON), recommendation, blockchain_tx, blockchain_hash, case_salt, case_pepper, created_at.\n"
        "ThreatIntelCache Table: id, ioc, ioc_type, is_malicious, source, raw, checked_at.")
    add_callout(doc,
        "The neatly labeled drawers in the police filing cabinet where every single photo, letter, and clue is filed alphabetically!",
        title="🧒 17. DATA MODELS: THE LABELED DRAWERS")

    # =========================================================================
    # 18. UTILITY LAYER
    # =========================================================================
    style_heading_1(doc, "18. Utility Layer")
    style_body(doc, "Helper modules in app/utils/: hashing.py (canonical SHA-256), salting.py (salt/pepper cryptographic blending), and formatting utilities.")
    add_callout(doc,
        "The detective's toolbelt: mini-scissors, ruler, magnifying glass, and fingerprint powder!",
        title="🧒 18. UTILITIES: THE DETECTIVE'S TOOLBELT")

    # =========================================================================
    # 19. SECURITY MECHANISMS SUMMARY TABLE
    # =========================================================================
    style_heading_1(doc, "19. Security Mechanisms Summary Table")
    headers_19 = ["Security Mechanism", "Technology", "What it Protects Against"]
    rows_19 = [
        ["Digital Evidence Seal", "ECDSA SECP256R1 + SHA-256", "Tampering with evidence after analysis"],
        ["Chain-of-Custody", "Polygon Amoy Smart Contract", "Denial in court; guarantees immutability"],
        ["SSRF Shield", "ipaddress Python library", "Attacks against internal server networks"],
        ["Account Binding Lock", "chrome.storage + Gmail DOM Match", "Unauthorized extension use on different accounts"],
        ["Data Privacy Vault", "AES-256-GCM Encryption", "Snooping on private email contents in transit"],
        ["ID Obfuscation", "Salt + Pepper Cryptography", "Enumeration attacks guessing case numbers"]
    ]
    create_table(doc, headers_19, rows_19)

    # =========================================================================
    # 20. TECHNOLOGY STACK SUMMARY
    # =========================================================================
    style_heading_1(doc, "20. Technology Stack Summary")
    headers_20 = ["Layer", "Technology", "Role & Purpose"]
    rows_20 = [
        ["Analytical Core", "FastAPI (Python 3.11+)", "Asynchronous, sub-second forensic execution"],
        ["Frontend UI", "React 18 + Vite", "High-performance reactive cyber cockpit"],
        ["Browser Shield", "Chrome Manifest V3", "Native Gmail in-page DOM inspection"],
        ["Database", "SQLite + SQLAlchemy Async", "Zero-config persistent case storage"],
        ["Blockchain", "Polygon Amoy + Solidity", "Decentralized legal timestamping & notary"],
        ["Cryptography", "Cryptography.io (ECDSA/AES)", "Military-grade evidence signing and sealing"]
    ]
    create_table(doc, headers_20, rows_20)

    # =========================================================================
    # 21. FULL DATA FLOW (END-TO-END)
    # =========================================================================
    style_heading_1(doc, "21. Full Data Flow (End-to-End)")
    style_body(doc,
        "1. User views email in Gmail.\n"
        "2. Extension checks active mailbox account matches bound user email.\n"
        "3. Extension extracts subject, sender, body, and unwraps redirect links.\n"
        "4. Extension dispatches ANALYZE_EMAIL to background service worker.\n"
        "5. Backend runs 14-step pipeline in parallel.\n"
        "6. Risk score (0-100) and explainable factors generated.\n"
        "7. Case signed with ECDSA SECP256R1 and hashed with SHA-256.\n"
        "8. Blockchain service anchors hash to Polygon Amoy testnet.\n"
        "9. Results rendered in Gmail drawer and available in React Cockpit.\n"
        "10. Optional SOC notifications fired to Slack, Jira, and SIEM.")
    add_callout(doc,
        "Like a relay race where the baton is passed smoothly from the runner in Gmail, to the scientist in the lab, "
        "to the stone diary in the sky, and finally to the scoreboard in less than 1 second!",
        title="🧒 21. FULL FLOW: THE 1-SECOND RELAY RACE")

    # =========================================================================
    # 22. API ENDPOINT REFERENCE (ALL ROUTES)
    # =========================================================================
    style_heading_1(doc, "22. API Endpoint Reference (All Routes)")
    headers_22 = ["Method", "Endpoint", "Purpose"]
    rows_22 = [
        ["POST", "/api/auth/login", "Authenticates user and binds extension session"],
        ["GET", "/api/auth/verify", "Validates active session token"],
        ["POST", "/api/analyze", "Runs full 14-step forensic analysis pipeline"],
        ["GET", "/api/cases", "Retrieves all analyzed cases"],
        ["GET", "/api/cases/{case_id}", "Retrieves single case with full forensic breakdown"],
        ["GET", "/api/reports/{case_id}/html", "Generates styled standalone HTML forensic report"],
        ["GET", "/api/reports/{case_id}/json", "Exports raw JSON forensic report with crypto seal"],
        ["POST", "/api/crypto/verify-seal", "Verifies ECDSA signature and detects tampering"],
        ["POST", "/api/blockchain/verify-chain", "Checks hash against Polygon Amoy smart contract"],
        ["POST", "/api/soc/quarantine", "Dispatches quarantine action to mail servers"],
        ["POST", "/api/soc/notify/slack", "Dispatches Slack webhook threat notification"],
        ["POST", "/api/soc/notify/jira", "Creates incident ticket in Jira Service Management"]
    ]
    create_table(doc, headers_22, rows_22)

    # =========================================================================
    # 23. KEYWORD DICTIONARIES & SIGNAL LISTS
    # =========================================================================
    style_heading_1(doc, "23. Keyword Dictionaries & Signal Lists")
    style_body(doc,
        "The engine maintains curated dictionaries of high-confidence threat signals:\n"
        "• Urgency Keywords: urgent, immediately, 24 hours, suspend, terminate, deadline, action required, expires today.\n"
        "• Credential Theft: verify your password, login to your account, reset credentials, confirm identity, security update.\n"
        "• Financial Panic: payment failed, invoice overdue, wire transfer, cryptocurrency wallet, gift card, refund approved.\n"
        "• Brand Spoofing: PayPal, Netflix, Microsoft, Apple, Amazon, Google, Bank of America, Wells Fargo.")
    add_callout(doc,
        "The detective's list of 'Red Flag Words'. Whenever someone on the internet says 'Hurry! Give me your password right now or you will lose your toys!', "
        "the detective knows 100% that it's a trick!",
        title="🧒 23. RED FLAG WORDS: TRICKSTER ALARM BELLS")

    # =========================================================================
    # 24. CONFIGURATION VARIABLES REFERENCE
    # =========================================================================
    style_heading_1(doc, "24. Configuration Variables Reference")
    headers_24 = ["Variable Name", "Default / Example Value", "Description"]
    rows_24 = [
        ["APP_NAME", "ThreatTrace AI", "Platform title displayed across logs and UI"],
        ["DEMO_MODE", "True", "Allows standalone operation without mandatory API keys"],
        ["BLOCKCHAIN_ENABLED", "True", "Enables Polygon Amoy blockchain smart contract anchoring"],
        ["POLYGON_RPC_URL", "https://rpc-amoy.polygon.technology", "Ethereum JSON-RPC node endpoint"],
        ["CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3", "ThreatTraceRegistry smart contract on Polygon"],
        ["SECRET_PEPPER", "tt_pepper_sih2026", "Cryptographic pepper for case ID hashing"],
        ["SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/...", "Target webhook for SOC Slack alerts"]
    ]
    create_table(doc, headers_24, rows_24)

    # Final Conclusion Box
    add_callout(doc,
        "ThreatTrace AI combines deep cybersecurity science with pure simplicity. "
        "Whether you are a 10-year-old student protecting your school email, a hackathon judge evaluating high-tech code, "
        "or a police digital forensics investigator bringing evidence to a courtroom, ThreatTrace AI makes the internet safe, transparent, and trustworthy!",
        title="🎉 GRAND CONCLUSION: CYBER FORENSICS FOR EVERYONE",
        bg_hex="F0FDF4",
        border_hex="16A34A"
    )

    targets = [
        "report.docx",
        "ThreatTraceAI_Easy_Understandable_Report.docx",
        "ThreatTraceAI_Comprehensive_Report.docx"
    ]
    for target in targets:
        try:
            doc.save(target)
            print(f"Master 24-section easy report built successfully: {target} ({os.path.getsize(target)} bytes)")
        except Exception as e:
            print(f"Could not save {target} (may be open in another program): {e}")

if __name__ == "__main__":
    build_full_report()
