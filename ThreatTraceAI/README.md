# THREAT TRACE AI

**Blockchain + Cybersecurity**  
Intelligent email forensics & threat attribution platform (Gmail extension + backend + dashboard).


## Core Capabilities & Architecture

- **1. Obfuscated & Masked URL Deobfuscator (`services/url_unmasker.py`)**
  - SSRF protection: Pre-resolves DNS and blocks loopback, private ranges (RFC 1918), and cloud metadata (`169.254.169.254`)
  - Hex (`%xx`), Octal, Base64 (`data:text/html;base64,...`), and Google redirect unwrapping
  - Homoglyph & Punycode (IDN) lookalike spoof detection
  - Safe multi-hop redirection tracing via HTTP `HEAD` before `GET`

- **2. Live IP Extraction & Socket Liveness Engine (`services/ip_intel.py`)**
  - Non-intrusive async TCP socket probing on ports 80, 443, 22, 8080, 53 (`LIVE_HOST` vs `OFFLINE`)
  - Autonomous System (ASN) and BGP provider identification
  - Real-time IP geolocation & threat intelligence correlation

- **3. Cybersecurity Department & SOC Orchestration (`services/soc_notifier.py`, `routes/soc.py`)**
  - Common Event Format (CEF) generator for SIEMs (Splunk, ArcSight, Microsoft Sentinel, QRadar)
  - Interactive Slack / Microsoft Teams security alert webhooks
  - Automated Jira Service Management incident ticket formatting
  - Direct SOC Dispatch action inside the Cockpit UI

- **4. Cryptography + Blockchain Provenance (`services/crypto_service.py`, `contracts/ThreatTraceRegistry.sol`)**
  - Client-side WebCrypto SHA-256 ingestion digest directly inside Chrome extension
  - Deterministic canonical SHA-256 evidence hashing (RFC-compliant normalization)
  - Asymmetric digital signing (ECDSA SECP256R1 / FIPS 186-4) with authority public key fingerprinting
  - End-to-End Encrypted Evidence Vault (AES-256-GCM + 100,000 PBKDF2 rounds)
  - Production Solidity smart contract (`ThreatTraceRegistry.sol`) with Merkle root anchoring for Polygon Amoy
  - Live Tamper Attack Simulator in the Cockpit UI for Hackathon judges

## Quick start (Windows / PowerShell)

### 1. Backend
```powershell
cd D:\SIH\ThreatTraceAI\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# edit .env if you have real keys
python -m uvicorn app.main:app --reload --port 8001
```
Open http://127.0.0.1:8000/docs

### 2. Frontend
```powershell
cd D:\ThreatTraceAI\frontend
npm install
npm run dev
```
Open http://127.0.0.1:5173

### 3. Extension (Chrome & Microsoft Edge)
- **Microsoft Edge Add-ons Store**: Submitted & In Review
  - **Store ID**: `0RDCKH3690TK`
  - **CRX ID**: `ffbmoglonkpaakkobfkkfappameldfab`
- **Local Testing / Demo**:
  1. Edge or Chrome → `edge://extensions` or `chrome://extensions` → Enable **Developer mode**  
  2. Click **Load unpacked** → select the `extension` folder (or download `ThreatTraceAI-Extension.zip`)  
  3. Open Gmail → you will see the blue **“THREAT TRACE”** forensic shield button  

## Live data notes


| Component              | Status                                      |
|------------------------|---------------------------------------------|
| OpenPhish feed         | Live (public text feed)                     |
| IP Geolocation         | Live (ip-api.com free tier)                 |
| URL redirect following | Live (httpx)                                |
| Gmail API              | Ready for Testing-mode OAuth (fill .env)    |
| Blockchain             | Hash always computed; on-chain write needs PRIVATE_KEY + CONTRACT_ADDRESS on Polygon Amoy |

## Blockchain (chain-of-custody only)

A simple logger contract that accepts `logCaseHash(bytes32, string)` is enough.  
Deploy once on Amoy, put the address + a testnet private key in `.env`.  
Only the forensic hash goes on-chain – never the email content.

## Risk scoring

Additive, transparent rubric (see `services/risk_engine.py`):  
header authentication failures + urgency/credential keywords + live phishing URL hits.  
UI always shows the factor list – this is the explainability story for judges.

## Project structure matches the tree you provided.

## Important limitations (be ready to tell judges)

- GeoIP is approximate city-level, not “live tracking”.  
- Campaign clustering is lightweight / seeded.  
- “Report to cybersecurity department” currently generates a local report + optional on-chain hash (demo webhook can be added).  
- Gmail DOM scraping is fragile; production path is Gmail API with Testing-mode OAuth.
