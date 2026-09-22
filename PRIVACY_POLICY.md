# Privacy Policy for ThreatTrace AI – Gmail Forensic Shield

**Last Updated:** September 2026

ThreatTrace AI ("we", "our", or "the extension") is an open-source cybersecurity and email forensics tool developed for threat analysis and educational purposes during hackathons. We are committed to protecting your privacy.

## 1. Information We Process
- **Email Content for Forensic Analysis**: When you click "Scan Forensic Threat" or trigger an on-demand analysis, the extension inspects the text, headers, and hyperlinks of the active email solely to identify indicators of compromise (IOCs), malicious URLs, phishing markers, and domain spoofing.
- **Local Settings & State**: The extension uses local browser storage (`chrome.storage.local`) exclusively to cache analysis results and user interface preferences locally on your machine.

## 2. How Information is Used
- All analysis is performed on-demand when explicitly triggered by the user.
- The processed email data is used strictly for calculating threat risk scores, deobfuscating malicious links, and generating cryptographic chain-of-custody hashes.
- We do **not** sell, rent, or monetize your data.
- We do **not** collect personal identifiable information (PII), passwords, financial data, or browsing history outside of the explicit forensic scan requested by you.

## 3. Data Storage & Security
- Cryptographic evidence hashing is performed client-side using standard cryptographic libraries (SHA-256).
- Communication with our analysis API is encrypted using industry-standard TLS (HTTPS).

## 4. Permissions Justification
- **activeTab**: Enables interaction only with the currently viewed email tab when you click the extension.
- **storage**: Saves local scan state and configuration preferences on your local browser.
- **scripting**: Injects the forensic scan button and threat status banner into the webmail interface.
- **Host Permissions**: Limited to `mail.google.com` to allow Gmail forensic inspection, and the backend API endpoint for threat scoring.

## 5. Contact
If you have any questions regarding this privacy policy, you can contact the project maintainers via our repository:
https://github.com/muniswami-y/threat.trace.ai
