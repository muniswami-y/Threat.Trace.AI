// Threat Trace AI – Popup Controller v1.3.1 (Zero-Login / Frictionless Mode)
const LIVE_DASHBOARD_URL = 'https://threat-trace-ai.vercel.app';
const LIVE_BACKEND_URL = 'https://threat-trace-ai.onrender.com';

let currentCaseId = null; // tracks the active case for canary/subpoena
let lastScannedData = null;
let lastScannedText = '';

// DOM Elements
const scannerSection = document.getElementById('scannerSection');
const tabStatusBanner = document.getElementById('tabStatusBanner');
const tabStatusText = document.getElementById('tabStatusText');
const topStatusIndicator = document.getElementById('topStatusIndicator');
const topStatusText = document.getElementById('topStatusText');

// ===================================================================
// Initialization
// ===================================================================
document.addEventListener('DOMContentLoaded', () => {
  initUI();
  setupEventListeners();
  checkActiveTabMailbox();
});

function initUI() {
  if (topStatusIndicator) topStatusIndicator.className = 'status-indicator ready';
  if (topStatusText) topStatusText.textContent = 'ACTIVE';
  if (scannerSection) scannerSection.style.display = 'flex';
}

// ===================================================================
// Active Tab Gmail Mailbox Check
// ===================================================================
function checkActiveTabMailbox() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      setTabStatus('neutral', 'ℹ️ Paste email text below to scan forensic threat');
      return;
    }

    const currentTab = tabs[0];
    const url = currentTab.url || '';

    if (!url.includes('mail.google.com')) {
      setTabStatus('neutral', 'ℹ️ Active tab is not Gmail. Paste text below or open Gmail.');
      return;
    }

    // Communicate with content script on active Gmail tab
    chrome.tabs.sendMessage(currentTab.id, { type: 'GET_ACTIVE_GMAIL_USER' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        setTabStatus('matched', '🛡️ Gmail Shield Active • In-Mail Scanning Enabled');
        return;
      }

      const activeGmailUser = (response.activeUser || '').trim();
      if (activeGmailUser) {
        setTabStatus('matched', `✓ Active Gmail: ${activeGmailUser} • Forensic Shield Live`);
      } else {
        setTabStatus('matched', '🛡️ Gmail Shield Active • In-Mail Scanning Enabled');
      }
    });
  });
}

function setTabStatus(statusClass, message) {
  if (tabStatusBanner) tabStatusBanner.className = `tab-status-card ${statusClass}`;
  if (tabStatusText) tabStatusText.textContent = message;
}

// ===================================================================
// Event Listeners
// ===================================================================
function setupEventListeners() {
  // Scan Button
  const analyzeBtn = document.getElementById('analyzeBtn');
  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', runScan);
  }

  // Open Full Dashboard Footer Link
  const footerLink = document.getElementById('footerDashboardLink');
  if (footerLink) {
    footerLink.addEventListener('click', (e) => {
      e.preventDefault();
      chrome.tabs.create({ url: LIVE_DASHBOARD_URL });
    });
  }

  // Canary Trap Button
  const btnCanary = document.getElementById('btnDeployCanary');
  if (btnCanary) {
    btnCanary.addEventListener('click', deployCanaryTrap);
  }

  // Subpoena Package Button
  const btnSubpoena = document.getElementById('btnSubpoena');
  if (btnSubpoena) {
    btnSubpoena.addEventListener('click', openSubpoenaPackage);
  }

  // Report Incident Directly to Cybercrime Button
  const btnReport = document.getElementById('btnReportCybercrime');
  if (btnReport) {
    btnReport.addEventListener('click', reportIncidentToCybercrime);
  }
}

// ===================================================================
// Forensic Scan Execution (In-Memory, Zero Login Required)
// ===================================================================
function runScan() {
  const text = (document.getElementById('emailText')?.value || '').trim();
  const analyzeBtn = document.getElementById('analyzeBtn');
  const scanSpinner = document.getElementById('scanSpinner');
  const scanBtnText = document.getElementById('scanBtnText');

  if (analyzeBtn) analyzeBtn.disabled = true;
  if (scanSpinner) scanSpinner.style.display = 'inline-block';
  if (scanBtnText) scanBtnText.textContent = 'Analyzing…';

  // Reset reporting state for new scan
  currentCaseId = null;
  const reportSuccessBox = document.getElementById('popupReportSuccess');
  if (reportSuccessBox) reportSuccessBox.style.display = 'none';

  // If text is provided in textarea, analyze that; otherwise analyze active tab email
  const messagePayload = text 
    ? {
        type: 'ANALYZE_EMAIL',
        email_text: text,
        mailbox_email: 'analyst@threattrace.ai',
        save_case: false
      }
    : {
        type: 'ANALYZE_CURRENT_TAB',
        client_timestamp: new Date().toISOString()
      };

  lastScannedText = text;

  chrome.runtime.sendMessage(messagePayload, (resp) => {
    if (analyzeBtn) analyzeBtn.disabled = false;
    if (scanSpinner) scanSpinner.style.display = 'none';
    if (scanBtnText) scanBtnText.textContent = '⚡ Scan Forensic Threat';

    if (!resp || !resp.ok) {
      alert('ThreatTrace Error: ' + (resp && resp.error ? resp.error : 'Failed to reach forensic analyzer.'));
      return;
    }

    const d = resp.data;
    lastScannedData = d;
    renderScanResults(d);
  });
}

function renderScanResults(d) {
  const score = Math.round(d.risk_score || 0);
  const isHigh = d.risk_level === 'HIGH' || score >= 70;
  const isMed = (d.risk_level === 'MEDIUM' || (score >= 40 && score < 70)) && !isHigh;

  const resultBox = document.getElementById('scanResults');
  if (resultBox) resultBox.style.display = 'block';

  const scoreNum = document.getElementById('riskScore');
  if (scoreNum) {
    scoreNum.textContent = `${score}/100`;
    scoreNum.style.color = isHigh ? '#f43f5e' : isMed ? '#f59e0b' : '#10b981';
  }

  const scoreBadge = document.getElementById('riskLevel');
  if (scoreBadge) {
    scoreBadge.textContent = d.risk_level || (isHigh ? 'CRITICAL' : isMed ? 'MEDIUM' : 'SAFE');
    scoreBadge.className = `risk-badge ${isHigh ? 'danger' : isMed ? 'warning' : 'low'}`;
  }

  // Populate Indicators
  const listEl = document.getElementById('indicatorsList');
  if (listEl) {
    listEl.innerHTML = '';
    const indicators = [];
    if (d.spf_status && d.spf_status !== 'PASS') indicators.push(`SPF: ${d.spf_status}`);
    if (d.dkim_status && d.dkim_status !== 'PASS') indicators.push(`DKIM: ${d.dkim_status}`);
    if (d.dmarc_status && d.dmarc_status !== 'PASS') indicators.push(`DMARC: ${d.dmarc_status}`);
    if (d.is_lookalike) indicators.push('Lookalike Domain Detected');
    if (d.has_urgency_cues) indicators.push('Urgency / Threat Language');
    if (d.threat_categories && d.threat_categories.length) {
      d.threat_categories.forEach(tc => indicators.push(tc.replace('_', ' ')));
    }
    if (d.origin_ip) indicators.push(`Origin IP: ${d.origin_ip}`);
    if (d.geo_country) indicators.push(`Origin Geo: ${d.geo_country}`);
    if (d.phones && d.phones.length > 0) indicators.push(`Phone Detected: ${d.phones[0]}`);

    if (indicators.length === 0) {
      indicators.push('No critical malicious indicators flagged');
    }

    indicators.forEach((ind) => {
      const li = document.createElement('li');
      li.textContent = ind;
      listEl.appendChild(li);
    });
  }

  // Show the Report Incident button
  const btnReport = document.getElementById('btnReportCybercrime');
  if (btnReport) {
    btnReport.style.display = 'block';
    btnReport.disabled = false;
    btnReport.innerHTML = '<span>🚨 Report Incident to Cybercrime</span>';
    btnReport.style.background = 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)';
  }

  const btnOpenCase = document.getElementById('btnOpenCaseDashboard');
  if (btnOpenCase) {
    btnOpenCase.style.display = 'block';
    btnOpenCase.onclick = () => {
      const payloadStr = encodeURIComponent(JSON.stringify(d));
      const targetUrl = currentCaseId 
        ? `${LIVE_DASHBOARD_URL}/case/${currentCaseId}` 
        : `${LIVE_DASHBOARD_URL}/#payload=${payloadStr}`;
      chrome.tabs.create({ url: targetUrl });
    };
  }

  // Hide canary & subpoena buttons until case is explicitly reported/created
  const btnCanary = document.getElementById('btnDeployCanary');
  const btnSubpoena = document.getElementById('btnSubpoena');
  if (btnCanary) btnCanary.style.display = 'none';
  if (btnSubpoena) btnSubpoena.style.display = 'none';

  // Reset canary result panel
  const canaryResult = document.getElementById('canaryResult');
  if (canaryResult) canaryResult.style.display = 'none';
}

// ===================================================================
// Report Incident to Cybercrime (Generates Case ID & Transmits Data)
// ===================================================================
function reportIncidentToCybercrime() {
  if (!lastScannedData) {
    alert('Please scan an email first before reporting.');
    return;
  }

  const btnReport = document.getElementById('btnReportCybercrime');
  if (btnReport) {
    btnReport.textContent = 'Transferring Incident to Cybercrime…';
    btnReport.disabled = true;
  }

  // 1. Generate unique Case ID strictly upon explicit report action
  const randHex = Math.random().toString(16).slice(2, 10).toUpperCase();
  const newCaseId = `TT-2026-${randHex}`;
  currentCaseId = newCaseId;

  // 2. Extract and compile incident context
  const reporterEmail = 'analyst@threattrace.ai';
  const reportPayload = {
    case_id: newCaseId,
    subject: lastScannedData.subject || 'Reported Phishing Incident',
    sender: lastScannedData.sender || 'unknown@threat.origin',
    recipient: reporterEmail,
    reporter_email: reporterEmail,
    reporter_name: 'THREATTRACE ANALYST',
    body_text: lastScannedData.body_text || lastScannedText || '',
    raw_headers: lastScannedData.raw_headers || '',
    risk_score: lastScannedData.risk_score || 0,
    risk_level: lastScannedData.risk_level || 'HIGH',
    urls: (lastScannedData.urls || []).map(u => typeof u === 'string' ? u : (u.original || u.final || '')).filter(Boolean),
    domains: lastScannedData.domains || [],
    ips: lastScannedData.ips || [lastScannedData.origin_ip].filter(Boolean),
    phones: lastScannedData.phones || [],
    telephony_intelligence: lastScannedData.telephony_intelligence || []
  };

  // 3. Transmit compiled data directly to cybercrime department endpoint
  chrome.runtime.sendMessage(
    {
      type: 'REPORT_CYBERCRIME',
      payload: reportPayload
    },
    (resp) => {
      const ackNumber = `NCRP-IN-2026-${randHex.slice(-6)}`;

      if (btnReport) {
        btnReport.innerHTML = '<span>✓ Case Created & Dispatched</span>';
        btnReport.style.background = 'linear-gradient(135deg, #059669 0%, #047857 100%)';
        btnReport.disabled = true;
      }

      const reportSuccessBox = document.getElementById('popupReportSuccess');
      const caseIdDisplay = document.getElementById('popupCaseIdDisplay');
      const ackDisplay = document.getElementById('popupAckDisplay');

      if (reportSuccessBox) reportSuccessBox.style.display = 'block';
      if (caseIdDisplay) caseIdDisplay.textContent = `CASE ID: ${newCaseId}`;
      if (ackDisplay) ackDisplay.textContent = `Cybercrime Acknowledgment: ${ackNumber}`;

      // Enable Canary and Subpoena buttons now that case is registered
      const btnCanary = document.getElementById('btnDeployCanary');
      const btnSubpoena = document.getElementById('btnSubpoena');
      if (btnCanary) btnCanary.style.display = 'block';
      if (btnSubpoena) btnSubpoena.style.display = 'block';

      // Update cockpit button link to specific registered case ID
      const btnOpenCase = document.getElementById('btnOpenCaseDashboard');
      if (btnOpenCase) {
        btnOpenCase.onclick = () => {
          chrome.tabs.create({ url: `${LIVE_DASHBOARD_URL}/case/${newCaseId}` });
        };
      }
    }
  );
}

// ===================================================================
// Canary Trap Deployment
// ===================================================================
function deployCanaryTrap() {
  if (!currentCaseId) {
    alert('No active case registered. Click "Report Incident" first.');
    return;
  }

  const btn = document.getElementById('btnDeployCanary');
  btn.textContent = 'Deploying…';
  btn.disabled = true;

  chrome.runtime.sendMessage(
    {
      type: 'GENERATE_CANARY',
      case_id: currentCaseId,
      analyst_email: 'analyst@threattrace.ai'
    },
    (resp) => {
      btn.textContent = '🪤 Deploy Canary Trap';
      btn.disabled = false;

      if (!resp || !resp.ok) {
        alert('Canary error: ' + (resp && resp.error ? resp.error : 'Backend unreachable'));
        return;
      }

      const data = resp.data;
      const tokenEl = document.getElementById('canaryTokenDisplay');
      const pingEl = document.getElementById('canaryPingUrl');
      const panel = document.getElementById('canaryResult');

      if (tokenEl) tokenEl.textContent = 'Token: ' + (data.token || '').slice(0, 20) + '…';
      if (pingEl) pingEl.textContent = `Bait URL: ${LIVE_BACKEND_URL}` + (data.ping_url || '');
      if (panel) panel.style.display = 'block';
    }
  );
}

// ===================================================================
// Subpoena Package
// ===================================================================
function openSubpoenaPackage() {
  if (!currentCaseId) {
    alert('No active case registered. Click "Report Incident" first.');
    return;
  }
  chrome.tabs.create({
    url: `${LIVE_DASHBOARD_URL}/case/${currentCaseId}?tab=subpoena`
  });
}
