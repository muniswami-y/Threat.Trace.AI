// Threat Trace AI – Popup Controller v1.2.0
let currentSession = null;
let currentCaseId = null; // tracks the last analyzed case for canary/subpoena

// DOM Elements
const authSection = document.getElementById('authSection');
const scannerSection = document.getElementById('scannerSection');
const authAlert = document.getElementById('authAlert');
const openOnboardingBtn = document.getElementById('openOnboardingBtn');
const boundEmailDisplay = document.getElementById('boundEmailDisplay');
const sessionDaysRemaining = document.getElementById('sessionDaysRemaining');
const logoutBtn = document.getElementById('logoutBtn');
const tabStatusBanner = document.getElementById('tabStatusBanner');
const tabStatusText = document.getElementById('tabStatusText');
const topStatusIndicator = document.getElementById('topStatusIndicator');
const topStatusText = document.getElementById('topStatusText');

// ===================================================================
// Initialization & Session Check
// ===================================================================
document.addEventListener('DOMContentLoaded', () => {
  initSession();
  setupEventListeners();
});

function initSession() {
  chrome.runtime.sendMessage({ type: 'GET_SESSION' }, (resp) => {
    if (chrome.runtime.lastError) {
      console.warn('[ThreatTrace AI]', chrome.runtime.lastError.message);
      return;
    }
    const session = resp && resp.session;
    if (session && session.isAuthenticated && !session.isExpired && session.boundEmail) {
      currentSession = session;
      renderAuthenticatedView(session);
    } else {
      currentSession = null;
      renderLoginView(session && session.isExpired);
    }
  });
}

function renderLoginView(isExpired) {
  authSection.style.display = 'flex';
  scannerSection.style.display = 'none';

  topStatusIndicator.className = 'status-indicator locked';
  topStatusText.textContent = isExpired ? 'EXPIRED' : 'LOCKED';

  if (isExpired) {
    showAuthAlert('Your 1-month session has expired. Please complete OTP verification to re-bind.', 'error');
  }
}

function renderAuthenticatedView(session) {
  authSection.style.display = 'none';
  scannerSection.style.display = 'flex';

  topStatusIndicator.className = 'status-indicator ready';
  topStatusText.textContent = 'READY';

  boundEmailDisplay.textContent = session.boundEmail;
  boundEmailDisplay.title = session.boundEmail;

  if (sessionDaysRemaining) {
    const days = session.daysRemaining !== undefined ? session.daysRemaining : 30;
    sessionDaysRemaining.textContent = `${days} days remaining`;
  }

  checkActiveTabMailbox(session.boundEmail);
}

// ===================================================================
// Active Tab Gmail Mailbox Verification
// ===================================================================
function checkActiveTabMailbox(boundEmail) {
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

    // Try communicating with content script on active tab
    chrome.tabs.sendMessage(currentTab.id, { type: 'GET_ACTIVE_GMAIL_USER' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        setTabStatus('checking', `🛡️ Gmail open. Shield strictly bound to: ${boundEmail}`);
        return;
      }

      const activeGmailUser = (response.activeUser || '').trim().toLowerCase();
      const bound = boundEmail.trim().toLowerCase();

      if (!activeGmailUser) {
        setTabStatus('checking', `🛡️ Gmail open. Verifying mailbox ownership for ${bound}…`);
      } else if (activeGmailUser === bound) {
        setTabStatus('matched', `✓ Verified: Active Gmail matches bound account (${bound})`);
      } else {
        setTabStatus('mismatched', `⛔ Mismatch: Gmail is [${activeGmailUser}], but extension locked to [${bound}]`);
      }
    });
  });
}

function setTabStatus(statusClass, message) {
  tabStatusBanner.className = `tab-status-card ${statusClass}`;
  tabStatusText.textContent = message;
}

// ===================================================================
// Event Listeners
// ===================================================================
function setupEventListeners() {
  // Open Onboarding & OTP Page
  if (openOnboardingBtn) {
    openOnboardingBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'OPEN_AUTH_PAGE' });
      window.close();
    });
  }

  // Logout Click
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleLogout);
  }

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
      chrome.tabs.create({ url: 'http://localhost:5173/' });
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

  // Catch-all link handler for popup
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (link && link.href && !link.href.startsWith('javascript:')) {
      e.preventDefault();
      chrome.tabs.create({ url: link.href });
    }
  });
}

// ===================================================================
// Authentication Handlers
// ===================================================================

function handleLogout() {
  if (!confirm('Are you sure you want to sign out? This extension will be locked until re-authenticated.')) {
    return;
  }

  chrome.runtime.sendMessage({ type: 'LOGOUT' }, () => {
    currentSession = null;
    document.getElementById('resultBox').style.display = 'none';
    document.getElementById('emailText').value = '';
    renderLoginView(false);
  });
}

function showAuthAlert(msg, type) {
  authAlert.textContent = msg;
  authAlert.className = `auth-alert ${type}`;
  authAlert.style.display = 'block';
}

function hideAuthAlert() {
  authAlert.style.display = 'none';
}

// ===================================================================
// Forensic Scan Execution
// ===================================================================
function runScan() {
  if (!currentSession || !currentSession.isAuthenticated) {
    alert('Extension is locked. Please authenticate with your email first.');
    renderLoginView(false);
    return;
  }

  const text = document.getElementById('emailText').value.trim();
  if (!text) return;

  const btn = document.getElementById('analyzeBtn');
  btn.textContent = 'Analyzing Forensic Threat…';
  btn.disabled = true;

  chrome.runtime.sendMessage(
    {
      type: 'ANALYZE_EMAIL',
      email_text: text,
      mailbox_email: currentSession.boundEmail
    },
    (resp) => {
      btn.textContent = '⚡ Scan Forensic Threat';
      btn.disabled = false;

      if (!resp || !resp.ok) {
        alert('ThreatTrace Error: ' + (resp && resp.error ? resp.error : 'Failed to reach forensic analyzer.'));
        return;
      }

      const d = resp.data;
      const score = Math.round(d.risk_score || 0);
      const isHigh = d.risk_level === 'HIGH' || score >= 70;
      const isMed = (d.risk_level === 'MEDIUM' || (score >= 40 && score < 70)) && !isHigh;

      // Track case ID for canary/subpoena buttons
      currentCaseId = d.case_id || null;

      const resultBox = document.getElementById('resultBox');
      resultBox.style.display = 'block';

      const scoreNum = document.getElementById('scoreVal');
      scoreNum.textContent = score;
      scoreNum.style.color = isHigh ? '#f43f5e' : isMed ? '#f59e0b' : '#10b981';

      const scoreBadge = document.getElementById('scoreBadge');
      scoreBadge.textContent = d.risk_level || (isHigh ? 'CRITICAL' : isMed ? 'MEDIUM' : 'SAFE');
      scoreBadge.className = `score-badge ${isHigh ? 'danger' : isMed ? 'warning' : 'success'}`;

      document.getElementById('recLine').innerHTML = `Action: <strong>${d.recommendation || 'REVIEW'}</strong>`;

      const listEl = document.getElementById('factorList');
      listEl.innerHTML = '';
      (d.risk_factors || []).slice(0, 4).forEach((f) => {
        const li = document.createElement('li');
        li.textContent = f;
        listEl.appendChild(li);
      });

      const btnOpenCase = document.getElementById('btnOpenCaseDashboard');
      if (btnOpenCase) {
        btnOpenCase.style.display = 'block';
        btnOpenCase.onclick = () => {
          const targetUrl = d.case_id ? `http://localhost:5173/case/${d.case_id}` : 'http://localhost:5173/';
          chrome.tabs.create({ url: targetUrl });
        };
      }

      // Show canary + subpoena buttons only when a case was saved
      const btnCanary = document.getElementById('btnDeployCanary');
      const btnSubpoena = document.getElementById('btnSubpoena');
      if (currentCaseId) {
        if (btnCanary) btnCanary.style.display = 'block';
        if (btnSubpoena) btnSubpoena.style.display = 'block';
      } else {
        if (btnCanary) btnCanary.style.display = 'none';
        if (btnSubpoena) btnSubpoena.style.display = 'none';
      }

      // Reset canary result panel
      const canaryResult = document.getElementById('canaryResult');
      if (canaryResult) canaryResult.style.display = 'none';
    }
  );
}

// ===================================================================
// Canary Trap Deployment
// ===================================================================
function deployCanaryTrap() {
  if (!currentCaseId) {
    alert('No active case. Run a scan first.');
    return;
  }

  const btn = document.getElementById('btnDeployCanary');
  btn.textContent = 'Deploying…';
  btn.disabled = true;

  chrome.runtime.sendMessage(
    {
      type: 'GENERATE_CANARY',
      case_id: currentCaseId,
      analyst_email: currentSession && currentSession.boundEmail
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
      if (pingEl) pingEl.textContent = 'Bait URL: http://127.0.0.1:8000' + (data.ping_url || '');
      if (panel) panel.style.display = 'block';
    }
  );
}

// ===================================================================
// Subpoena Package
// ===================================================================
function openSubpoenaPackage() {
  if (!currentCaseId) {
    alert('No active case. Run a scan first.');
    return;
  }
  chrome.tabs.create({
    url: `http://localhost:5173/case/${currentCaseId}?tab=subpoena`
  });
}
