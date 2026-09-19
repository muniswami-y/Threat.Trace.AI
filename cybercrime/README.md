# 🏛️ Cyber Crime Investigation Wing (CCIW) - Admin Dashboard

### ThreatTrace AI Forensic & Law Enforcement Command Center
**Direct Folder Path:** `D:\SIH\cybercrime`

---

## 📋 System Architecture

The **Cybercrime Admin Dashboard** provides a centralized, military-grade command interface for law enforcement officials, cyber forensic examiners, and department heads to handle escalations from ThreatTrace AI users.

```
+-------------------------------------------------------------------------------+
|  NATIONAL CYBER CRIME INVESTIGATION WING (CCIW) - ADMIN COMMAND DASHBOARD     |
+-------------------------------------------------------------------------------+
| SIDEBAR         | MAIN COMMAND VIEW                                           |
|-----------------+-------------------------------------------------------------|
| 👤 Profile      | [QUEUE] ThreatTrace user-reported cases awaiting triage     |
| 📥 Queue        |         - Case ID, Reporting Email, Risk Score              |
| ❌ Rejected     |         - Full-Screen Review: Approve or Reject             |
| ✅ Completed    |                                                             |
| ⚙️ Process      | [REJECTED] Cases declined with justification explanation     |
| 🚪 Logout       |            - Re-investigation button restores to Queue      |
|                 |                                                             |
|                 | [PROCESS] Active day-to-day investigations                  |
|                 |           - 100% Sealed with Salt, Pepper & Blockchain      |
|                 |           - 3-Layer Separated Keys (Admin/Officer/Enclave)  |
|                 |                                                             |
|                 | [COMPLETED] Solved incidents with judicial FIR records      |
|                 |             - Day-to-Day history & Criminal threat dossier  |
|                 |             - Printable official police FIR document        |
+-------------------------------------------------------------------------------+
```

---

## 🔑 Core Features & Workflow

### 1. Profile (`/cybercrime?tab=profile`)
- **Administrator Identity**: Superintendent of Police / Joint Director Cyber Crime.
- **Security Clearance**: Level 5 Supreme Command.
- **Layer 1 Master Signing Root**: Used to bind evidence upon officer dispatch.

### 2. Queue (`/cybercrime?tab=queue`)
- ThreatTrace users click **"Report"** on any analyzed email or threat incident.
- That request is immediately redirected to the **Admin Queue** showing `Case ID` and `Email ID`.
- Clicking the `Case ID` opens the **Full-Screen Dossier**:
  - Displays all reporting person details (Email, Name, Phone, Timestamp).
  - Displays full email details (Raw Headers, Message Body, Extracted URLs, Host Domains, Target IPs, AI risk factors).
- **Two Exclusive Triage Options**:
  1. **Reject**: Asks for an explanation of why the report is being declined. Moves case to **Rejected**.
  2. **Approve**: Opens the Officer Assignment Directory showing active cybercrime officers (with badges, specializations, ratings, and case loads). Submitting transfers all evidence, derives 3-Layer keys, and moves case to **Process**.

### 3. Rejected (`/cybercrime?tab=rejected`)
- Lists rejected cases with `Case ID` and `Email ID`.
- Clicking `Case ID` opens full screen showing original case details and **why it was rejected**.
- Features a **"Re-investigation"** button to restore the case back into the active Queue for fresh triage.

### 4. Process (`/cybercrime?tab=process`)
- Active cases under investigation.
- Assigned officers file daily investigation reports.
- **100% Tamper-Proof Sealing**:
  - **Dynamic Salting (`S_XXXX`) & Peppering (`P_YYYY`)**: Unique entropy seeds on each entry.
  - **Blockchain Transaction Hash (`0x...`)**: Recorded to ledger for cryptographic provenance.
  - **3-Layer Separated Cryptographic Keys**:
    - *Layer 1*: Admin Oversight Key (`K1-ADM-...`)
    - *Layer 2*: Assigned Officer Key (`K2-OFF-...`)
    - *Layer 3*: Hardware Enclave / HSM Root (`K3-ENC-...`)
- Form to log new daily progress.
- "Conclude Investigation & Issue FIR" button to finalize case.

### 5. Completed (`/cybercrime?tab=completed`)
- Archive of solved and concluded cases.
- Full-Screen view showing:
  - Investigating Officer details
  - Chronological Day-to-Day process history
  - Criminal data & suspect intelligence (Syndicate alias, accused names, geolocation, seized hardware, mule accounts)
  - Reporting data & original headers
  - **Official First Information Report (FIR)**: Under IT Act 2000 (Sec 66C, 66D) & IPC (Sec 419, 420) with print/save support.

### 6. Top Right Corner: Notification Center
- Bell icon with live unread counter badge.
- Interactive dropdown showing new case queue arrivals, officer daily report submissions, and FIR registrations.

### 7. Logout
- Clean administrative unmount with cryptographic session invalidation.

---

## 🚀 How to Run

### Option A: Standalone Web App
1. Open `D:\SIH\cybercrime` in File Explorer.
2. Double-click `run.bat` or open `index.html` in any web browser.

### Option B: Integrated in ThreatTrace AI
1. Run `run_frontend.bat` from `D:\SIH\ThreatTraceAI`.
2. Navigate to `http://localhost:5173/cybercrime` or click the **"Cybercrime Portal"** button in ThreatTrace Cockpit.
3. In ThreatTrace Cockpit, clicking **"Report"** automatically forwards the case into this Admin Queue!
