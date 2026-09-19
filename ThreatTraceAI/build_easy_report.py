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

def set_cell_margins(cell, top=140, bottom=140, left=200, right=200):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def add_callout(doc, text, title="💡 EASY EXPLANATION", bg_hex="F0FDF4", border_hex="22C55E"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=160, bottom=160, left=220, right=220)
    
    # Left border only styling via XML
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
    p.paragraph_format.space_after = Pt(4)
    run_t = p.add_run(f"{title}\n")
    run_t.bold = True
    run_t.font.size = Pt(11)
    run_t.font.color.rgb = RGBColor(15, 23, 42)
    
    run_b = p.add_run(text)
    run_b.font.size = Pt(10.5)
    run_b.font.color.rgb = RGBColor(51, 65, 85)
    
    # Add small spacing after table
    sp = doc.add_paragraph()
    sp.paragraph_format.space_before = Pt(0)
    sp.paragraph_format.space_after = Pt(6)

def style_heading_1(p, text):
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(16)
    run.font.color.rgb = RGBColor(2, 132, 199) # Ocean blue
    return run

def style_heading_2(p, text):
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(13)
    run.font.color.rgb = RGBColor(15, 23, 42)
    return run

def style_body(p, text):
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    run = p.add_run(text)
    run.font.size = Pt(10.5)
    run.font.color.rgb = RGBColor(51, 65, 85)
    return run

def build_report():
    doc = docx.Document()
    
    # Page setup: Standard 1 inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
        
    # Document Title Block
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(12)
    title_p.paragraph_format.space_after = Pt(4)
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    trun = title_p.add_run("🛡️ THREAT TRACE AI")
    trun.bold = True
    trun.font.size = Pt(26)
    trun.font.color.rgb = RGBColor(2, 132, 199)
    
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_before = Pt(0)
    sub_p.paragraph_format.space_after = Pt(4)
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    srun = sub_p.add_run("The Digital Detective That Keeps Your Email Safe from Internet Tricksters")
    srun.bold = True
    srun.font.size = Pt(13)
    srun.font.color.rgb = RGBColor(15, 23, 42)
    
    tag_p = doc.add_paragraph()
    tag_p.paragraph_format.space_before = Pt(0)
    tag_p.paragraph_format.space_after = Pt(18)
    tag_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tag_run = tag_p.add_run("A Complete, Crystal-Clear Guide — Explained So Simply Even a Child Can Understand!\nSmart India Hackathon (SIH) 2026 Project")
    tag_run.font.size = Pt(10.5)
    tag_run.font.italic = True
    tag_run.font.color.rgb = RGBColor(100, 116, 139)
    
    # Quick Overview Box
    add_callout(doc, 
        "Have you ever received a weird letter or message pretending to be a bank, a game, or a school teacher asking for your secret password? "
        "ThreatTrace AI is like a superhero robot detective that reads those emails with a magic magnifying glass, catches the sneaky bad guys in less than 1 second, "
        "locks the evidence in an unbreakable digital safe, and protects your inbox!",
        title="🌟 WHAT IS THREAT TRACE AI IN ONE SENTENCE?",
        bg_hex="EFF6FF",
        border_hex="0284C7"
    )

    # -------------------------------------------------------------
    # Chapter 1: The Big Story
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 1: The Big Story — The Mystery of Fake Letters")
    
    style_body(doc.add_paragraph(), 
        "Imagine your computer or phone has a physical mailbox in front of your house. "
        "Every single morning, the mail carrier drops in friendly letters: postcards from your friends, birthday invitations, and notes from school.\n\n"
        "But one day, a sneaky trickster wearing a disguise sneaks up and drops a very scary letter in your box! It says:\n\n"
        "   🚨 'URGENT! I am your Bank Manager! Your account will be DELETED in 24 hours! Give me your password RIGHT NOW or you will lose everything!'\n\n"
        "This trick is called Phishing (just like fishing with a worm on a hook!). The trickster is dangling fake bait, hoping you panic, click a dangerous link, "
        "and give away your secret keys. Every year, millions of people get tricked because these fake letters look so real!"
    )
    
    add_callout(doc,
        "Why don't normal spam filters catch them?\n"
        "Because the tricksters are smart! They wear masks (fake sender names), use fake postmark stamps, and hide traps inside innocent-looking buttons. "
        "That's why the world needs ThreatTrace AI — an intelligent, super-smart digital detective!",
        title="🤔 WHY DO WE NEED A DETECTIVE?",
        bg_hex="FEF3C7",
        border_hex="F59E0B"
    )

    # -------------------------------------------------------------
    # Chapter 2: The 3 Superhero Teammates
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 2: Meet the 3 Superhero Teammates")
    
    style_body(doc.add_paragraph(),
        "ThreatTrace AI is built like a superhero team of 3 best friends who work together to protect you:"
    )

    # Team Table
    table = doc.add_table(rows=4, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    headers = ["Teammate", "Real Tech Name", "What They Do in Plain English"]
    for i, h in enumerate(headers):
        cell = table.cell(0, i)
        set_cell_background(cell, "0F172A")
        set_cell_margins(cell, top=120, bottom=120, left=150, right=150)
        p = cell.paragraphs[0]
        run = p.add_run(h)
        run.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)
        run.font.size = Pt(10)

    rows_data = [
        ("🔍 1. The Magic Magnifying Glass", "Chrome Browser Extension (MV3)", "Lives right inside your Gmail screen! It puts a glowing shield button on your screen so you can inspect any email with just 1 click."),
        ("🧠 2. The Detective Brain", "FastAPI Python Backend", "The super-fast computer brain. In less than 1 second, it inspects 14 different clues, calculates the danger level, and figures out if the email is safe or dangerous."),
        ("🚀 3. The Superhero Mission Control", "React Web Dashboard (Cockpit)", "A giant glowing command center where cybersecurity officers can see world maps, inspect the evidence, and press the big red 'Quarantine' button!")
    ]
    
    for row_idx, data in enumerate(rows_data, start=1):
        bg = "F8FAFC" if row_idx % 2 == 1 else "FFFFFF"
        for col_idx, text in enumerate(data):
            cell = table.cell(row_idx, col_idx)
            set_cell_background(cell, bg)
            set_cell_margins(cell, top=100, bottom=100, left=120, right=120)
            p = cell.paragraphs[0]
            p.paragraph_format.line_spacing = 1.1
            run = p.add_run(text)
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(30, 41, 59)
            if col_idx == 0:
                run.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # -------------------------------------------------------------
    # Chapter 3: The Special Key & Mailbox Lock (New Feature!)
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 3: The Magic Key — Locking the Extension to Your Mailbox Only")
    
    style_body(doc.add_paragraph(),
        "Think about your house front door. You have a special metal key that only opens YOUR front door. "
        "Your key cannot open your neighbor's door, and your neighbor's key cannot open yours! That's what keeps your family safe and private.\n\n"
        "ThreatTrace AI works the exact same way with its brand-new **Account Binding & Login System**:"
    )

    add_callout(doc,
        "1. When you first open the extension, it is LOCKED in amber: 🔒 'ThreatTrace Locked'.\n"
        "2. You log in with your authorized email (e.g. yourname@gmail.com) and security key.\n"
        "3. Once logged in, the extension is BOUND ONLY TO YOUR EMAIL!\n"
        "4. If you open your Gmail, the shield lights up green: 🛡️ 'ThreatTrace Active — Verified Mailbox'.\n"
        "5. BUT if someone else opens a different email account on that computer, the shield immediately spots the mismatch and turns RED: ⛔ 'UNMATCHED MAILBOX — ACCESS DENIED!'. "
        "It refuses to scan strangers' emails, keeping your tools and private accounts 100% secure!",
        title="🔑 HOW THE MAILBOX LOCK WORKS",
        bg_hex="ECFDF5",
        border_hex="10B981"
    )

    # -------------------------------------------------------------
    # Chapter 4: The 14 Clues Pipeline
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 4: The 14 Clues — The Step-by-Step Detective Investigation")
    
    style_body(doc.add_paragraph(),
        "When you click 'Scan Forensic Threat', ThreatTrace AI doesn't just make a lucky guess. "
        "It follows a strict 14-step detective checklist. Here is exactly what happens behind the scenes in under 1 second:"
    )

    clues = [
        ("Step 1: Unfolding the Envelope (Email Parsing)", 
         "Like taking a letter out of the mailbox, gently opening the envelope, and separating the paper, the sender, the date, and the subject line so we can read them clearly."),
        
        ("Step 2: Checking the Royal Wax Stamps (SPF, DKIM, DMARC)", 
         "Long ago, kings sealed letters with hot red wax and their royal signet ring. On the internet, computers use digital stamps called SPF, DKIM, and DMARC. "
         "ThreatTrace AI checks: 'Did this email REALLY come from Google or PayPal, or was this stamp forged with crayons?'"),
        
        ("Step 3: Looking Behind the Mask (Display Name Spoofing)", 
         "The trickster puts on a paper mask that says 'PRINCIPAL OF YOUR SCHOOL' or 'NETFLIX SUPPORT'. "
         "ThreatTrace AI pulls off the mask and looks at the real return address. If the mask says 'Google' but the real email is 'pirate99@fake-mail.ru', BUSTED!"),
        
        ("Step 4: Gathering Footprints & Fingerprints (IOC Extraction)", 
         "Detectives look for muddy footprints and fingerprints at a crime scene. In digital forensics, we look for website addresses (URLs), computer house numbers (IP addresses), and domain names."),
        
        ("Step 5: Peeling Off the Candy Wrapper (URL Unmasking & Google Redirects)", 
         "A bad guy might put a shiny candy wrapper over a sour lemon. They use Google redirect links or URL shorteners to hide where the link actually goes. "
         "ThreatTrace AI unrolls the wrapper to reveal the real destination website!"),
        
        ("Step 6: Calling the International Police HQ (Live Threat Intelligence)", 
         "ThreatTrace AI instantly calls global security databases (like URLhaus, VirusTotal, and PhishTank) to ask: "
         "'Has this website or computer ever been caught robbing someone before?' If yes, an immediate alarm sounds!"),
        
        ("Step 7: Listening for Panic Words (Content Urgency Scoring)", 
         "Tricksters always shout: 'HURRY! 24 HOURS LEFT! YOUR ACCOUNT WILL BE TERMINATED! CLICK NOW!' "
         "Why? Because when people are scared and rushed, they forget to think. ThreatTrace AI listens for these panic words and adds warning points."),
        
        ("Step 8: Spotting Weird Spelling Tricks (URL Heuristics)", 
         "Look closely at this word: 'paypa1.com'. Did you notice? The letter 'l' was replaced by the number '1'! "
         "Or 'micros0ft.com' with a zero! ThreatTrace AI has super-sharp eyes that spot typos and sneaky lookalike letters immediately."),
        
        ("Step 9: The Sneaky Button Trap (Link Mismatch Detection)", 
         "Imagine a road sign that says: '👉 This way to Disneyland!' But if you follow the road, it takes you to a dark spooky swamp! "
         "In emails, a button might say 'www.bank.com', but when you click it, it secretly sends you to 'www.rob-my-bank.xyz'. ThreatTrace AI catches this mismatch every time!"),
        
        ("Step 10: Checking the Sender's Reputation (Sender Heuristics)", 
         "Was this sender address created just 2 hours ago? Does it have weird random numbers like 'x88q29z@temp.com'? "
         "If the sender looks shady, ThreatTrace AI marks them as suspicious."),
        
        ("Step 11: The Mirror Maze (Redirect Chain Analysis)", 
         "Sometimes a link bounces you from website A, to website B, to website C, to website D to confuse security guards. "
         "ThreatTrace AI chases the link through the entire maze to see where it ends."),
        
        ("Step 12: The Danger Thermometer (Risk Score 0 to 100)", 
         "ThreatTrace AI adds up all the clues and puts them on a clear Danger Thermometer:\n"
         "   🟢 0 to 39: SAFE (Everything looks good!)\n"
         "   🟡 40 to 69: SUSPICIOUS (Be careful! Something looks fishy!)\n"
         "   🔴 70 to 100: CRITICAL DANGER (A trap! Do not touch or click!)"),
        
        ("Step 13: The Spinning 3D World Map (IP Geolocation)", 
         "ThreatTrace AI shows you a real globe! It pins the exact city and country where the trickster's computer was located when they sent the email."),
        
        ("Step 14: The Detective Web Board (Infrastructure Graph)", 
         "Just like in detective movies with red strings on a corkboard, ThreatTrace AI draws a glowing map connecting the email, the website, the server, and the IP address so you can see the whole criminal network!")
    ]

    for title, desc in clues:
        style_heading_2(doc.add_paragraph(), title)
        style_body(doc.add_paragraph(), desc)

    # -------------------------------------------------------------
    # Chapter 5: The Magic Wax Seal & Stone Diary (Crypto & Blockchain)
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 5: The Magic Wax Seal & The Stone Diary in the Sky")
    
    style_body(doc.add_paragraph(),
        "One of the coolest things about ThreatTrace AI is that its evidence can be taken to a REAL court of law to show a judge and police officers! "
        "To make sure nobody can ever cheat or fake the evidence, it uses two magical technologies:"
    )

    style_heading_2(doc.add_paragraph(), "1. The Digital Wax Seal (ECDSA Cryptography & SHA-256 Fingerprints)")
    style_body(doc.add_paragraph(),
        "Whenever a police officer collects evidence (like a suspicious letter), they place it in a clear plastic evidence bag and put an official tamper-proof sticker on it. "
        "If someone tries to open the bag or scribble on the letter, the seal rips!\n\n"
        "ThreatTrace AI creates a unique digital fingerprint (called SHA-256) of the entire email and seals it with a mathematical lock (called ECDSA). "
        "If a criminal changes even ONE single dot or letter in the evidence later, ThreatTrace AI's alarm goes off: 'TAMPER DETECTED! THE EVIDENCE WAS CHANGED!'"
    )

    style_heading_2(doc.add_paragraph(), "2. The Magic Stone Diary in the Sky (Polygon Blockchain)")
    style_body(doc.add_paragraph(),
        "Imagine a giant stone diary that floats in the sky. Thousands of computers all over the world hold an identical copy of this stone diary. "
        "Once you write something in it with a chisel, NO ONE in the world — not even the creator, and not even the smartest hacker — can ever erase or change it!\n\n"
        "ThreatTrace AI carves the digital fingerprint and timestamp of the bad email onto the Polygon Amoy blockchain. "
        "This proves beyond any doubt: 'This phishing email was received at exactly 10:45 AM on Friday, and here is the permanent proof!'"
    )

    add_callout(doc,
        "Why is this so important?\n"
        "In many cyber crimes, criminals lie and say: 'That wasn't me! Someone faked that screenshot!' "
        "With ThreatTrace AI's blockchain proof, the judge can verify the mathematical seal in 2 seconds. The criminal cannot lie!",
        title="⚖️ COURT-READY EVIDENCE",
        bg_hex="FDF2F8",
        border_hex="DB2777"
    )

    # -------------------------------------------------------------
    # Chapter 6: The Super Alarm Siren (SOC Alerts)
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 6: Sounding the Alarm — Automatic Rescue for Companies")
    
    style_body(doc.add_paragraph(),
        "When ThreatTrace AI finds a critical danger, it doesn't just quietly sit there — it immediately sounds the fire alarm to protect everyone in the organization!\n\n"
        "• 💬 Slack Siren: Sends an instant red alert message to the cybersecurity team's chatroom: '🚨 CRITICAL PHISH DETECTED! Target: finance team!'\n"
        "• 🎫 Jira Helper: Automatically creates a work ticket for computer technicians: 'Task: Quarantine this dangerous link immediately.'\n"
        "• 📡 Splunk & Sentinel Police Radio: Sends formal digital reports (called CEF) to big enterprise security towers so the whole company's firewall blocks the attacker in seconds!"
    )

    # -------------------------------------------------------------
    # Chapter 7: Kid-Friendly Tech Dictionary
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 7: Fun Mini-Dictionary — Big Tech Words Made Super Simple!")

    dict_items = [
        ("Phishing", "A fake email or message pretending to be a friend, company, or bank to trick you into giving away your passwords or secret information."),
        ("AI (Artificial Intelligence)", "A computer program trained to think, learn, and solve problems like a super-fast smart detective."),
        ("Extension", "A helpful mini-tool you add to your web browser (like Google Chrome) to give it new superpowers, like a shield button!"),
        ("IP Address", "The computer's phone number or house address on the internet so other computers know where it is located."),
        ("URL (Link)", "The website address you type or click on (like https://www.google.com)."),
        ("Cryptography", "Secret mathematical codes and locks that protect information so only the right person can unlock and read it."),
        ("Blockchain", "An unbreakable digital diary shared across thousands of computers that permanently stores records without anyone being able to erase them."),
        ("Quarantine", "Putting a dangerous file or email in a safe, locked digital cage so it cannot hurt anyone.")
    ]

    for term, definition in dict_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(4)
        run_term = p.add_run(f"• {term}: ")
        run_term.bold = True
        run_term.font.size = Pt(10.5)
        run_term.font.color.rgb = RGBColor(2, 132, 199)
        run_def = p.add_run(definition)
        run_def.font.size = Pt(10)
        run_def.font.color.rgb = RGBColor(51, 65, 85)

    # -------------------------------------------------------------
    # Chapter 8: Why ThreatTrace AI is a Winner
    # -------------------------------------------------------------
    style_heading_1(doc.add_paragraph(), "Chapter 8: Why ThreatTrace AI is a Winner for Smart India Hackathon (SIH)")
    
    style_body(doc.add_paragraph(),
        "Here is why judges, teachers, cybersecurity experts, and everyday users love ThreatTrace AI:\n\n"
        "1. ⚡ Super Simple for Anyone: You don't need to be a computer scientist. You just click the shield in Gmail, and it tells you if you're safe.\n"
        "2. 💡 100% Explainable: It doesn't just give a random number. It shows you the exact words, fake links, and hidden traps so you learn how to stay safe.\n"
        "3. 🔒 Unbreakable Legal Proof: With mathematical signatures and blockchain, evidence is tamper-proof and ready for police and courtrooms.\n"
        "4. 🛡️ Personal Mailbox Lock: Keeps your tool strictly bound to your authorized email, stopping strangers from misusing your scanner.\n"
        "5. 🌍 Keeps Families & Companies Safe: Protects students, grandmothers, schools, banks, and hospitals from cyber tricksters every single day!"
    )
    
    # Final Sign-off Box
    add_callout(doc,
        "ThreatTrace AI proves that advanced cybersecurity doesn't have to be confusing, scary, or boring. "
        "By combining AI, cryptography, blockchain, and intuitive design, we make the internet a safer, friendlier place for everyone — from young students to enterprise security officers!",
        title="🎉 SUMMARY: SAFEGUARDING THE DIGITAL WORLD",
        bg_hex="F0FDF4",
        border_hex="16A34A"
    )

    # Save as easily accessible new document
    easy_filename = "ThreatTraceAI_Easy_Understandable_Report.docx"
    doc.save(easy_filename)
    print(f"Report saved successfully as {easy_filename}!")

    # Attempt to also overwrite the original if not locked by MS Word
    orig_filename = "ThreatTraceAI_Comprehensive_Report.docx"
    try:
        doc.save(orig_filename)
        print(f"Also updated {orig_filename}!")
    except PermissionError:
        print(f"Note: {orig_filename} is currently open in Microsoft Word. Saved to {easy_filename} so you can open it right away!")

if __name__ == "__main__":
    build_report()
