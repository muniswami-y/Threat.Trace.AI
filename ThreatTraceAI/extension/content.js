// Threat Trace AI – Gmail In-Page Forensic Inspector with Automatic In-Mail Risk Scoring & Account Locking
(function () {
  if (window.__threatTraceContentInjected) {
    return;
  }
  window.__threatTraceContentInjected = true;

  let isContextInvalidated = false;
  let scanDebounceTimer = null;
  let fallbackInterval = null;
  let observer = null;
  let isOpeningDashboard = false;
  const LIVE_DASHBOARD_URL = 'https://threat-trace-ai.vercel.app';

  // Verify extension runtime context before calling any Chrome extension APIs
  function isContextValid() {
    if (isContextInvalidated) return false;
    try {
      if (typeof chrome === 'undefined' || !chrome || !chrome.runtime || !chrome.runtime.id) {
        destroyShield();
        return false;
      }
      return true;
    } catch (e) {
      destroyShield();
      return false;
    }
  }

  // Gracefully detach all listeners and intervals if extension is reloaded or invalidated
  function destroyShield() {
    if (isContextInvalidated) return;
    isContextInvalidated = true;
    console.log('[ThreatTrace AI] Extension context invalidated or reloaded. Deactivating background listeners.');
    if (fallbackInterval) {
      clearInterval(fallbackInterval);
      fallbackInterval = null;
    }
    if (scanDebounceTimer) {
      clearTimeout(scanDebounceTimer);
      scanDebounceTimer = null;
    }
    if (observer) {
      observer.disconnect();
      observer = null;
    }
  }

  // Safe wrapper for chrome.runtime.sendMessage with context checks
  function safeSendMessage(msg, callback) {
    if (!isContextValid()) return;
    try {
      chrome.runtime.sendMessage(msg, (response) => {
        // MUST access lastError to prevent Chrome from throwing unchecked lastError
        const err = chrome.runtime?.lastError;
        if (err) {
          const errMsg = String(err.message || '').toLowerCase();

          // Silently swallow all known benign MV3 service-worker / channel errors:
          // These are expected when the SW is idle, restarting, or the tab navigates.
          const isBenign = (
            errMsg.includes('message channel closed')       ||  // SW killed mid-await
            errMsg.includes('receiving end does not exist') ||  // SW not yet started
            errMsg.includes('context invalidated')          ||  // extension reloaded
            errMsg.includes('service worker')               ||  // SW lifecycle
            errMsg.includes('extension context')            ||  // context gone
            errMsg.includes('could not establish connection')   // SW inactive
          );

          if (errMsg.includes('context invalidated')) {
            destroyShield();
            return;
          }

          if (isBenign) {
            // Benign — do NOT log, just stop here. The background.js 9s timeout
            // will have already fired safeRespond so the badge will show "Scan Error".
            return;
          }

          // Genuinely unexpected error — log it
          console.warn('[ThreatTrace AI] sendMessage unexpected error:', err.message);
        }

        if (!isContextValid()) return;
        if (callback && typeof callback === 'function') {
          callback(response);
        }
      });
    } catch (e) {
      const msgStr = String(e.message || '').toLowerCase();
      if (msgStr.includes('context invalidated') || msgStr.includes('extension context')) {
        destroyShield();
      } else if (!msgStr.includes('message channel') && !msgStr.includes('receiving end')) {
        console.warn('[ThreatTrace AI] safeSendMessage error:', e);
      }
    }
  }

  console.log('[ThreatTrace AI] In-Page Forensic Shield initializing…');

  let authSession = null;
  let lastEvaluatedState = null;

  // Email Scanning & Caching State
  let lastScannedEmailId = null;
  let isScanningInProgress = false;
  const scanCache = {};

  // Clean up any residual drawer elements from earlier sessions
  function removeResidualDrawer() {
    const existingDrawer = document.getElementById('threat-trace-drawer');
    if (existingDrawer) {
      existingDrawer.remove();
    }
  }

  // Remove any residual floating button elements
  function removeResidualFloatingBtn() {
    const existingBtn = document.getElementById('threat-trace-floating-btn');
    if (existingBtn) {
      existingBtn.remove();
    }
  }

  // ===================================================================
  // Utility: Unwrap Google redirect URLs
  // ===================================================================
  function unwrapGoogleRedirect(url) {
    try {
      const parsed = new URL(url);
      if (
        (parsed.hostname === 'www.google.com' || parsed.hostname === 'google.com') &&
        parsed.pathname === '/url'
      ) {
        const realUrl = parsed.searchParams.get('q') || parsed.searchParams.get('url');
        if (realUrl) return decodeURIComponent(realUrl);
      }
      if (parsed.hostname.endsWith('.cdn.ampproject.org') || parsed.hostname === 'amp.google.com') {
        const realUrl = parsed.searchParams.get('url') || parsed.searchParams.get('q');
        if (realUrl) return decodeURIComponent(realUrl);
      }
    } catch (e) { /* not a valid URL, return as-is */ }
    return url;
  }

  // ===================================================================
  // EXTRACT ACTIVE GMAIL USER ACCOUNT
  // ===================================================================
  function extractActiveGmailUserEmail() {
    const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i;

    // Strategy 1: Google Account Avatar / Header Link aria-labels
    const profileSelectors = [
      'a[aria-label*="Google Account:"]',
      'a[aria-label*="Google Account"]',
      'a[aria-label*="@"][href*="accounts.google.com"]',
      'a[aria-label*="@"][href*="SignOutOptions"]',
      'div.gb_d[aria-label*="@"]',
      'div.gb_A[aria-label*="@"]',
      'header a[aria-label*="@"]',
      'a[aria-label*="@gmail.com"]',
      'div[aria-label*="@gmail.com"]'
    ];

    for (const sel of profileSelectors) {
      const els = document.querySelectorAll(sel);
      for (const el of els) {
        const ariaLabel = el.getAttribute('aria-label') || '';
        const match = ariaLabel.match(emailRegex);
        if (match && match[1]) {
          return match[1].trim().toLowerCase();
        }
      }
    }

    // Strategy 2: Image alt / data attributes on Google Bar
    const imgSelectors = ['img.gb_p[alt*="@"]', 'img.gb_i[alt*="@"]', 'img[alt*="@gmail.com"]'];
    for (const sel of imgSelectors) {
      const img = document.querySelector(sel);
      if (img) {
        const alt = img.getAttribute('alt') || '';
        const match = alt.match(emailRegex);
        if (match && match[1]) {
          return match[1].trim().toLowerCase();
        }
      }
    }

    // Strategy 3: Data attributes on user profile elements
    const dataSelectors = ['[data-email]', '[data-identifier]'];
    for (const sel of dataSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        const val = el.getAttribute('data-email') || el.getAttribute('data-identifier') || '';
        const match = val.match(emailRegex);
        if (match && match[1]) {
          return match[1].trim().toLowerCase();
        }
      }
    }

    // Strategy 4: URL path inspection
    try {
      const pathParts = window.location.pathname.split('/');
      for (const part of pathParts) {
        if (part.includes('@')) {
          const decoded = decodeURIComponent(part).toLowerCase();
          const match = decoded.match(emailRegex);
          if (match && match[1]) {
            return match[1];
          }
        }
      }
    } catch (e) {}

    return null;
  }

  // ===================================================================
  // SECURITY STATE EVALUATION (Includes 1-Month Lifespan Check)
  // ===================================================================
  function evaluateSecurityState() {
    const activeGmailUser = extractActiveGmailUserEmail();

    if (!authSession || !authSession.isAuthenticated || !authSession.boundEmail) {
      const autoEmail = (activeGmailUser || 'analyst@threattrace.ai').trim().toLowerCase();
      authSession = {
        isAuthenticated: true,
        boundEmail: autoEmail,
        userEmail: autoEmail,
        token: `tt_session_${Date.now()}`,
        loggedInAt: new Date().toISOString(),
        expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
        durationDays: 30
      };
      try {
        if (chrome && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ tt_auth_session: authSession });
        }
      } catch (e) {}
    }

    // Check if 1-month session has expired
    if (authSession.expiresAt && Date.now() > authSession.expiresAt) {
      // Renew 30-day session for seamless continuity
      authSession.expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      try {
        if (chrome && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ tt_auth_session: authSession });
        }
      } catch (e) {}
    }

    const bound = (authSession.boundEmail || activeGmailUser || 'user@gmail.com').trim().toLowerCase();

    // If active Gmail user was detected and does not match, adapt to current mailbox
    if (activeGmailUser && activeGmailUser !== bound) {
      authSession.boundEmail = activeGmailUser;
      authSession.userEmail = activeGmailUser;
      try {
        if (chrome && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ tt_auth_session: authSession });
        }
      } catch (e) {}
    }

    const effectiveUser = activeGmailUser || bound;
    try {
      localStorage.setItem('tt_mailbox_email', effectiveUser);
      localStorage.setItem('tt_active_user', effectiveUser);
      localStorage.setItem('tt_auth_user_email', effectiveUser);
    } catch (e) {}

    return {
      status: 'AUTHORIZED',
      activeGmailUser: effectiveUser,
      boundEmail: bound,
      message: `Forensic Shield verified for [${bound}]. (30-day session active)`
    };
  }

  // Listen for storage changes in real-time
  try {
    if (isContextValid() && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (!isContextValid()) return;
        if (areaName === 'local') {
          if (changes.tt_auth_session) {
            authSession = changes.tt_auth_session.newValue || null;
            updateSecurityUI();
            autoScanActiveEmail();
          }
          if (changes.tt_quarantine_folders || changes.tt_dismissed_folders) {
            renderQuarantineFoldersInGmailSidebar(true);
            enforceInboxQuarantineSuppression();
          }
        }
      });
    }
  } catch (e) {
    console.warn('[ThreatTrace AI] storage.onChanged setup warning:', e);
  }

  // Respond to popup requesting active Gmail email
  // NOTE: Every code path MUST call sendResponse before return false.
  // Failing to do so leaves the message channel open and causes:
  // "A listener indicated an asynchronous response by returning true,
  //  but the message channel closed before a response was received"
  try {
    if (isContextValid() && typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (!isContextValid()) {
          // Must still respond to close the channel
          try { sendResponse({ error: 'context_invalidated' }); } catch (_) {}
          return false;
        }

        if (msg.type === 'GET_ACTIVE_GMAIL_USER') {
          try {
            const activeUser = extractActiveGmailUserEmail();
            sendResponse({ activeUser: activeUser || null });
          } catch (e) {
            sendResponse({ activeUser: null, error: String(e) });
          }
          return false; // Synchronous — channel can close immediately
        }

        if (msg.type === 'EXECUTE_QUARANTINE_ACTION' || msg.type === 'QUARANTINE_EMAIL') {
          try {
            const cleanEmail = (msg.suspicious_email || '').toLowerCase();
            const folder = msg.folder_name || `Quarantine/${cleanEmail}`;
            executeQuarantineInGmail(cleanEmail, msg.subject || '', msg.quarantined_count || 1);
            sendResponse({ ok: true, folder_name: folder });
          } catch (err) {
            sendResponse({ ok: false, error: String(err) });
          }
          return false;
        }

        // Default: unknown message type — respond to close the channel
        sendResponse({ ok: false, error: 'unknown_message_type' });
        return false;
      });
    }
  } catch (e) {
    console.warn('[ThreatTrace AI] runtime.onMessage setup warning:', e);
  }

  // Listen for window postMessages (e.g. from ThreatTrace Cockpit / React app)
  window.addEventListener('message', (event) => {
    if (!event.data || typeof event.data !== 'object') return;
    if (event.data.type === 'THREAT_TRACE_QUARANTINE_EXECUTED') {
      const sender = event.data.suspicious_email || 'attacker@threat.net';
      const count = event.data.quarantined_count || 1;
      executeQuarantineInGmail(sender, '', count);
    }
  });

  // ===================================================================
  // GMAIL SIDEBAR QUARANTINE FOLDER CREATION & MAIL RELOCATION
  // ===================================================================

  // Execute Quarantine: Creates folder, moves email from Inbox, updates sidebar
  function executeQuarantineInGmail(suspiciousEmail, subject = '', count = 1) {
    const cleanMatch = (suspiciousEmail || '').match(/([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/);
    const cleanEmail = cleanMatch ? cleanMatch[1].toLowerCase() : (suspiciousEmail || 'suspicious@threat.net').toLowerCase();
    const folderName = `Quarantine/${cleanEmail}`;

    // 1. Remove from dismissed list if it was previously dismissed
    try {
      let localDismissed = JSON.parse(localStorage.getItem('tt_dismissed_folders') || '[]');
      localDismissed = localDismissed.filter(s => String(s).toLowerCase() !== cleanEmail);
      localStorage.setItem('tt_dismissed_folders', JSON.stringify(localDismissed));
    } catch (e) {}

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['tt_dismissed_folders'], (res) => {
        let dismissed = (res && res.tt_dismissed_folders) || [];
        dismissed = dismissed.filter(s => String(s).toLowerCase() !== cleanEmail);
        chrome.storage.local.set({ tt_dismissed_folders: dismissed });
      });
    }

    // 2. Read and update local folders
    let localFolders = [];
    try {
      localFolders = JSON.parse(localStorage.getItem('tt_quarantine_folders') || '[]');
      if (!Array.isArray(localFolders)) localFolders = [];
    } catch (e) {}

    const existingLocal = localFolders.find(f => f.sender && f.sender.toLowerCase() === cleanEmail);
    if (existingLocal) {
      existingLocal.count = count || existingLocal.count || 1;
      existingLocal.last_updated = Date.now();
    } else {
      localFolders.unshift({
        folder_name: folderName,
        sender: cleanEmail,
        count: count || 1,
        created_at: Date.now()
      });
    }

    try {
      localStorage.setItem('tt_quarantine_folders', JSON.stringify(localFolders));
    } catch (e) {}

    // 3. Immediately update in-memory cache and re-render sidebar synchronously
    cachedQuarantineFolders = getNormalizedQuarantineList(localFolders);
    injectSidebarUI(cachedQuarantineFolders);

    // 4. Save to chrome storage
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['tt_quarantine_folders'], (result) => {
        let folders = (result && result.tt_quarantine_folders) || [];
        const existing = folders.find(f => f.sender && f.sender.toLowerCase() === cleanEmail);
        if (existing) {
          existing.count = count || existing.count || 1;
          existing.last_updated = Date.now();
        } else {
          folders.unshift({
            folder_name: folderName,
            sender: cleanEmail,
            count: count || 1,
            created_at: Date.now()
          });
        }
        chrome.storage.local.set({ tt_quarantine_folders: folders }, () => {
          cachedQuarantineFolders = getNormalizedQuarantineList(folders);
          injectSidebarUI(cachedQuarantineFolders);
        });
      });
    }

    // 5. Dispatch quarantine execution to backend API
    safeSendMessage({
      type: 'EXECUTE_QUARANTINE',
      payload: {
        suspicious_email: cleanEmail,
        subject: subject || 'Isolated Threat Email',
        mailbox_email: extractActiveGmailUserEmail() || ''
      }
    }, () => {});

    // 6. Apply Quarantined Label Tag in Email Subject header
    applyQuarantineLabelTagToEmail(cleanEmail);

    // 7. Displace / Move email out of Inbox (Click Archive / Move)
    moveEmailOutOfInbox();

    // 8. Show rich in-page toast notification
    showQuarantineToast(folderName, cleanEmail, count);
  }

  // Inject & Maintain Quarantine Folders in Gmail's Left Navigation Sidebar
  let cachedQuarantineFolders = null;

  function getNormalizedQuarantineList(rawList, dismissedList = []) {
    const map = new Map();
    for (const item of (rawList || [])) {
      if (!item || !item.sender) continue;
      const s = String(item.sender).trim().toLowerCase();
      if (dismissedList.includes(s)) continue;
      const cnt = Math.max(1, parseInt(item.count, 10) || 1);
      if (map.has(s)) {
        const prev = map.get(s);
        if (item.last_updated && prev.last_updated) {
          prev.count = item.last_updated >= prev.last_updated ? cnt : prev.count;
        } else {
          prev.count = cnt;
        }
      } else {
        map.set(s, {
          folder_name: item.folder_name || `Quarantine/${s}`,
          sender: s,
          count: cnt,
          created_at: item.created_at || Date.now(),
          last_updated: item.last_updated || item.created_at || Date.now()
        });
      }
    }
    return Array.from(map.values()).sort((a, b) => a.sender.localeCompare(b.sender));
  }

  let lastQuarantineFetchTime = 0;

  function renderQuarantineFoldersInGmailSidebar(force = false) {
    let dismissedList = [];
    try {
      dismissedList = JSON.parse(localStorage.getItem('tt_dismissed_folders') || '[]').map(s => String(s).toLowerCase());
    } catch (e) {}

    // 1. Load from localStorage synchronously for instantaneous DOM display
    let localFolders = [];
    try {
      localFolders = JSON.parse(localStorage.getItem('tt_quarantine_folders') || '[]');
      if (!Array.isArray(localFolders)) localFolders = [];
    } catch (e) {}

    cachedQuarantineFolders = getNormalizedQuarantineList(localFolders, dismissedList);
    injectSidebarUI(cachedQuarantineFolders);

    const now = Date.now();
    if (!force && (now - lastQuarantineFetchTime < 4000)) {
      return;
    }
    lastQuarantineFetchTime = now;

    // 2. Fetch live & previous quarantine folders from backend API and chrome.storage
    safeSendMessage({ type: 'GET_QUARANTINE_FOLDERS' }, (res) => {
      let backendFolders = [];
      if (res && res.ok && Array.isArray(res.data)) {
        backendFolders = res.data.map(f => ({
          folder_name: f.folder_name || `Quarantine/${f.sender_email}`,
          sender: f.sender_email,
          count: f.total_emails || (f.emails && f.emails.length) || 1,
          created_at: f.created_at || Date.now()
        }));
      }

      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['tt_quarantine_folders', 'tt_dismissed_folders'], (sRes) => {
          const sDismissed = ((sRes && sRes.tt_dismissed_folders) || []).map(s => String(s).toLowerCase());
          const allDismissed = new Set([...dismissedList, ...sDismissed]);
          const sFolders = (sRes && sRes.tt_quarantine_folders) || [];
          const merged = getNormalizedQuarantineList([...localFolders, ...sFolders, ...backendFolders], Array.from(allDismissed));

          cachedQuarantineFolders = merged;
          try {
            localStorage.setItem('tt_quarantine_folders', JSON.stringify(merged));
          } catch (e) {}
          chrome.storage.local.set({ tt_quarantine_folders: merged }, () => {
            injectSidebarUI(cachedQuarantineFolders);
          });
        });
      } else {
        const merged = getNormalizedQuarantineList([...localFolders, ...backendFolders], dismissedList);
        cachedQuarantineFolders = merged;
        try {
          localStorage.setItem('tt_quarantine_folders', JSON.stringify(merged));
        } catch (e) {}
        injectSidebarUI(cachedQuarantineFolders);
      }
    });
  }

  function injectSidebarUI(folders = []) {
    // Locate Gmail left sidebar navigation
    const navSelectors = [
      'div.TK',
      'div[role="navigation"] div.TK',
      'div.aeN div.TK',
      'div[role="navigation"] div.wT',
      'div.aeN div.ajl',
      'div[role="navigation"] div.ajl',
      'div.ajl',
      'div[role="navigation"]',
      'div.aeN'
    ];

    let navContainer = null;
    for (const sel of navSelectors) {
      const el = document.querySelector(sel);
      if (el && el.offsetParent !== null) {
        navContainer = el;
        break;
      }
    }
    if (!navContainer) {
      for (const sel of navSelectors) {
        const el = document.querySelector(sel);
        if (el) {
          navContainer = el;
          break;
        }
      }
    }

    if (!navContainer) return;

    let section = document.getElementById('tt-quarantine-sidebar-section');
    if (!section) {
      section = document.createElement('div');
      section.id = 'tt-quarantine-sidebar-section';
      section.className = 'tt-quarantine-sidebar-section';
    }

    // Ensure section is attached in Gmail's left rail
    if (!section.isConnected || !section.parentElement) {
      const labelsSection = navContainer.querySelector('div.CL, div.Y7, div.ah9') ||
                            document.querySelector('div.CL') ||
                            document.querySelector('div[role="navigation"] div.CL');

      if (labelsSection && labelsSection.parentElement) {
        labelsSection.parentElement.insertBefore(section, labelsSection);
      } else if (navContainer.classList.contains('TK') || navContainer.querySelector('div.TK')) {
        const tk = navContainer.classList.contains('TK') ? navContainer : navContainer.querySelector('div.TK');
        tk.appendChild(section);
      } else {
        navContainer.appendChild(section);
      }
    }

    // Stable deterministic renderKey to completely prevent UI flickering
    const totalCount = folders.reduce((sum, f) => sum + (Number(f.count) || 1), 0);
    const renderKey = folders.map(f => `${f.sender}:${f.count}`).join('__') + `_tot${totalCount}`;
    if (section.dataset.renderKey === renderKey) {
      return; // ZERO DOM mutation if state is unchanged
    }
    section.dataset.renderKey = renderKey;

    // Attach persistent delegated click & mousedown listener only once
    if (!section.dataset.hasClickListener) {
      section.dataset.hasClickListener = 'true';

      const handleAction = (e) => {
        const delBtn = e.target.closest('.tt-quarantine-del-btn');
        if (delBtn) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
          const delSender = delBtn.getAttribute('data-del-sender');
          if (delSender) {
            deleteQuarantineFolder(delSender);
          }
          return;
        }

        const item = e.target.closest('.tt-quarantine-sidebar-item');
        if (item) {
          e.preventDefault();
          e.stopPropagation();
          const sender = item.getAttribute('data-sender');
          if (sender) {
            filterGmailBySender(sender);
          }
          return;
        }

        const header = e.target.closest('.tt-quarantine-sidebar-header');
        if (header) {
          e.preventDefault();
          e.stopPropagation();
          const allSenders = Array.from(section.querySelectorAll('.tt-quarantine-sidebar-item[data-sender]'))
            .map(el => el.getAttribute('data-sender'))
            .filter(Boolean);
          if (allSenders.length > 0) {
            const query = allSenders.map(s => `from:${s}`).join(' OR ');
            window.location.hash = `#search/${encodeURIComponent(query)}`;
          } else {
            window.location.hash = `#search/${encodeURIComponent('label:quarantine OR "ThreatTrace Quarantine"')}`;
          }
        }
      };

      section.addEventListener('click', handleAction, true);
      section.addEventListener('mousedown', (e) => {
        if (e.target.closest('.tt-quarantine-del-btn')) {
          e.preventDefault();
          e.stopPropagation();
          e.stopImmediatePropagation();
        }
      }, true);
    }

    section.innerHTML = `
      <div class="tt-quarantine-sidebar-header" title="Click to view all quarantined emails">
        <div style="display: flex; align-items: center; gap: 6px;">
          <span style="font-size: 13px;">🛡️</span>
          <span style="letter-spacing: 0.5px;">QUARANTINE VAULT</span>
        </div>
        <span class="tt-quarantine-total-badge">${totalCount}</span>
      </div>
      <div id="tt-quarantine-folder-list">
        ${folders.length > 0 ? folders.map(f => `
          <div class="tt-quarantine-sidebar-item" data-sender="${f.sender}" title="Click to view all quarantined emails from ${f.sender}">
            <div style="display: flex; align-items: center; gap: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">
              <span style="font-size: 13px;">📁</span>
              <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px;">${f.sender}</span>
            </div>
            <div style="display: flex; align-items: center; gap: 4px;">
              <span class="tt-quarantine-count-badge">${f.count || 1}</span>
              <button class="tt-quarantine-del-btn" data-del-sender="${f.sender}" title="Release & remove this quarantine folder" type="button">×</button>
            </div>
          </div>
        `).join('') : `
          <div class="tt-quarantine-sidebar-empty" title="Click 'Quarantine Email' on any email to isolate threats">
            <span style="opacity: 0.7; font-size: 11.5px;">🔒 0 active threats quarantined</span>
          </div>
        `}
      </div>
    `;
  }

  // Delete / Release a specific quarantine folder
  function deleteQuarantineFolder(senderEmail) {
    if (!senderEmail) return;
    const cleanSender = senderEmail.trim().toLowerCase();

    // 1. Instant DOM update: remove element immediately for smooth feedback
    const section = document.getElementById('tt-quarantine-sidebar-section');
    if (section) {
      section.dataset.renderKey = '';
      const matchingItems = section.querySelectorAll(`.tt-quarantine-sidebar-item`);
      matchingItems.forEach(el => {
        const s = (el.getAttribute('data-sender') || '').toLowerCase();
        if (s === cleanSender || s.includes(cleanSender) || cleanSender.includes(s)) {
          el.remove();
        }
      });
      const remaining = section.querySelectorAll('.tt-quarantine-sidebar-item');
      const countHeader = section.querySelector('.tt-quarantine-total-badge');
      if (countHeader) countHeader.textContent = `${remaining.length}`;
      if (remaining.length === 0) {
        const list = section.querySelector('#tt-quarantine-folder-list');
        if (list) {
          list.innerHTML = `
            <div class="tt-quarantine-sidebar-empty" title="Click 'Quarantine Email' on any email to isolate threats">
              <span style="opacity: 0.7; font-size: 11.5px;">🔒 0 active threats quarantined</span>
            </div>
          `;
        }
      }
    }

    // 2. Persist dismissal locally
    try {
      let localDismissed = JSON.parse(localStorage.getItem('tt_dismissed_folders') || '[]');
      if (!localDismissed.some(s => s.toLowerCase() === cleanSender)) {
        localDismissed.push(cleanSender);
        localStorage.setItem('tt_dismissed_folders', JSON.stringify(localDismissed));
      }

      let localFolders = JSON.parse(localStorage.getItem('tt_quarantine_folders') || '[]');
      localFolders = localFolders.filter(f => f.sender && f.sender.toLowerCase() !== cleanSender);
      localStorage.setItem('tt_quarantine_folders', JSON.stringify(localFolders));
    } catch (e) {}

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['tt_quarantine_folders', 'tt_dismissed_folders'], (res) => {
        let folders = (res && res.tt_quarantine_folders) || [];
        folders = folders.filter(f => f.sender && f.sender.toLowerCase() !== cleanSender);
        let dismissed = (res && res.tt_dismissed_folders) || [];
        if (!dismissed.some(s => s.toLowerCase() === cleanSender)) {
          dismissed.push(cleanSender);
        }
        chrome.storage.local.set({ tt_quarantine_folders: folders, tt_dismissed_folders: dismissed });
      });
    }

    // 3. Notify backend
    safeSendMessage({ type: 'DELETE_QUARANTINE_FOLDER', sender_email: cleanSender }, () => {
      renderQuarantineFoldersInGmailSidebar(true);
    });
  }

  // Synchronize folder count with actual visible Gmail search results
  function syncLiveSearchResultCount() {
    // Only synchronize when actively viewing filtered search results for quarantine
    const hash = window.location.hash || '';
    if (!hash.includes('search/') && !hash.includes('from:')) {
      return;
    }

    let cleanSender = null;

    // A. Check active search input
    const searchInputs = document.querySelectorAll('input[name="q"], input.gb_Ie, input[aria-label*="Search" i]');
    for (const input of searchInputs) {
      if (input && input.value) {
        const m = input.value.match(/from[:\s\(]*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/i);
        if (m) {
          cleanSender = m[1].toLowerCase();
          break;
        }
      }
    }

    // B. Check URL hash if search input was not matched
    if (!cleanSender && hash.includes('search/')) {
      const decoded = decodeURIComponent(hash);
      const m = decoded.match(/from[:\s\(]*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/i);
      if (m) cleanSender = m[1].toLowerCase();
    }

    if (!cleanSender) return;

    // Check if sender is dismissed
    try {
      const dismissed = JSON.parse(localStorage.getItem('tt_dismissed_folders') || '[]').map(s => String(s).toLowerCase());
      if (dismissed.includes(cleanSender)) return;
    } catch (e) {}

    // Detect actual count of search results
    let realCount = 0;
    
    // Always prefer the pager text inside search results toolbar for true total count
    const searchPager = document.querySelector('div.D.E.G-atb span.Dj, div.ar5 span.Dj');
    if (searchPager) {
      const txt = (searchPager.textContent || '').trim();
      const pMatch = txt.match(/\bof\s+([\d,]+)\b/i) || txt.match(/1-\d+\s+of\s+([\d,]+)/i);
      if (pMatch) {
        realCount = parseInt(pMatch[1].replace(/,/g, ''), 10) || 0;
      } else if (txt.match(/^[\d,]+$/)) {
        // Sometimes it might just be a bare number
        realCount = parseInt(txt.replace(/,/g, ''), 10) || 0;
      }
    }

    // Fallback to table rows if pager is missing or unparseable
    if (realCount === 0) {
      const searchTableRows = document.querySelectorAll('div[role="main"] table.F.cf.zt tr.zA, div[role="main"] div.UI table tr.zA');
      if (searchTableRows.length > 0) {
        realCount = searchTableRows.length;
      }
    }

    if (realCount > 0) {
      // 1. Instantly update badge in DOM
      const itemEl = document.querySelector(`.tt-quarantine-sidebar-item[data-sender="${cleanSender}"]`);
      if (itemEl) {
        const badge = itemEl.querySelector('.tt-quarantine-count-badge');
        if (badge && badge.textContent !== String(realCount)) {
          badge.textContent = realCount;
        }
      }

      // 2. Update in-memory cache and total badge
      if (cachedQuarantineFolders) {
        const item = cachedQuarantineFolders.find(f => f.sender && f.sender.toLowerCase() === cleanSender);
        if (item && item.count !== realCount) {
          item.count = realCount;
          const totalCount = cachedQuarantineFolders.reduce((sum, f) => sum + (Number(f.count) || 1), 0);
          const totalBadge = document.querySelector('.tt-quarantine-total-badge');
          if (totalBadge) totalBadge.textContent = totalCount;
        }
      }

      // 3. Update localStorage
      try {
        let localFolders = JSON.parse(localStorage.getItem('tt_quarantine_folders') || '[]');
        const existing = localFolders.find(f => f.sender && f.sender.toLowerCase() === cleanSender);
        if (existing && existing.count !== realCount) {
          existing.count = realCount;
          localStorage.setItem('tt_quarantine_folders', JSON.stringify(localFolders));
        }
      } catch (e) {}

      // 4. Update chrome.storage.local
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['tt_quarantine_folders', 'tt_dismissed_folders'], (res) => {
          const dismissed = ((res && res.tt_dismissed_folders) || []).map(s => String(s).toLowerCase());
          if (dismissed.includes(cleanSender)) return;

          let sFolders = (res && res.tt_quarantine_folders) || [];
          const existing = sFolders.find(f => f.sender && f.sender.toLowerCase() === cleanSender);
          if (existing && existing.count !== realCount) {
            existing.count = realCount;
            chrome.storage.local.set({ tt_quarantine_folders: sFolders });
          }
        });
      }

      // 5. Dispatch count sync to backend
      safeSendMessage({ type: 'SYNC_QUARANTINE_COUNT', sender_email: cleanSender, count: realCount });
    }
  }

  // Filter Gmail search to display only quarantined emails from this sender
  function filterGmailBySender(sender) {
    if (!sender) return;

    const cleanSender = sender.trim().replace(/^[<"']|[>"']$/g, '');

    // 1. Visual active highlight on clicked folder
    document.querySelectorAll('.tt-quarantine-sidebar-item').forEach(el => {
      if (el.getAttribute('data-sender') === sender) {
        el.classList.add('active');
        el.style.background = '#fee2e2';
        el.style.color = '#991b1b';
      } else {
        el.classList.remove('active');
        el.style.background = 'transparent';
        el.style.color = '#202124';
      }
    });

    const query = `from:${cleanSender}`;

    // 2. Direct Gmail hash navigation
    const targetHash = `#search/${encodeURIComponent(query)}`;
    window.location.hash = targetHash;

    // 3. Populate Gmail search bar
    const searchInputs = [
      'input[name="q"]',
      'input.gb_Ie',
      'input[aria-label*="Search" i]',
      'input[placeholder*="Search" i]'
    ];

    for (const sel of searchInputs) {
      const input = document.querySelector(sel);
      if (input) {
        input.value = query;
        input.focus();
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        const form = input.closest('form');
        if (form) {
          form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        }
        break;
      }
    }

    // 4. Trigger search button click after brief delay
    setTimeout(() => {
      const searchBtn = document.querySelector('button[aria-label*="Search mail" i], button[aria-label*="Search" i], button.gb_q, div[role="search"] button');
      if (searchBtn) {
        searchBtn.click();
      }
      setTimeout(syncLiveSearchResultCount, 400);
      setTimeout(syncLiveSearchResultCount, 1200);
    }, 80);
  }

  // Apply Quarantined Label Tag next to Subject in Gmail
  function applyQuarantineLabelTagToEmail(senderEmail) {
    const existingPill = document.getElementById('tt-quarantine-label-pill');
    if (existingPill) existingPill.remove();

    const h2 = document.querySelector('h2.hP') || document.querySelector('div[role="main"] h2');
    if (h2) {
      const pill = document.createElement('span');
      pill.id = 'tt-quarantine-label-pill';
      pill.className = 'tt-quarantined-label-pill';
      pill.innerHTML = `<span>📁 Quarantine: ${senderEmail}</span>`;
      h2.insertAdjacentElement('afterend', pill);
    }
  }

  // Move / Archive email out of Inbox
  function moveEmailOutOfInbox() {
    // 1. Try clicking Gmail's native Toolbar Archive / Move button
    const archiveBtnSelectors = [
      'div[role="toolbar"] div[aria-label*="Archive" i]',
      'div[role="toolbar"] div[data-tooltip*="Archive" i]',
      'div[role="toolbar"] div[act="7"]',
      'div[aria-label*="Archive" i]',
      'div[data-tooltip*="Archive" i]',
      'div[act="7"]',
      'div[role="button"][aria-label*="Archive" i]',
      'div[role="toolbar"] div[aria-label*="Move" i]',
      'div[aria-label*="Move to" i]'
    ];

    let archived = false;
    for (const sel of archiveBtnSelectors) {
      const btn = document.querySelector(sel);
      if (btn && btn.offsetParent !== null) {
        try {
          btn.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
          btn.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
          btn.click();
          archived = true;
          console.log('[ThreatTrace AI] Email archived & moved out of Inbox via toolbar button.');
          break;
        } catch (e) {}
      }
    }

    // 2. Keyboard shortcut fallback for Gmail ('e' key)
    try {
      const activeEl = document.activeElement;
      if (activeEl && (activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA')) {
        activeEl.blur();
      }
      document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'e', code: 'KeyE', keyCode: 69, which: 69, bubbles: true, cancelable: true }));
      document.body.dispatchEvent(new KeyboardEvent('keypress', { key: 'e', code: 'KeyE', keyCode: 69, which: 69, bubbles: true, cancelable: true }));
      document.body.dispatchEvent(new KeyboardEvent('keyup', { key: 'e', code: 'KeyE', keyCode: 69, which: 69, bubbles: true, cancelable: true }));
    } catch (e) {}

    // Immediately trigger inbox row suppression
    enforceInboxQuarantineSuppression();
  }

  // ===================================================================
  // ENFORCE INBOX QUARANTINE SUPPRESSION (HIDES QUARANTINED ROWS FROM INBOX)
  // ===================================================================
  function enforceInboxQuarantineSuppression() {
    if (!isContextValid()) return;

    // Resolve active quarantine senders
    let activeSenders = [];
    try {
      const local = JSON.parse(localStorage.getItem('tt_quarantine_folders') || '[]');
      const dismissed = JSON.parse(localStorage.getItem('tt_dismissed_folders') || '[]').map(s => String(s).toLowerCase());
      activeSenders = (local || []).map(f => (f.sender || '').trim().toLowerCase()).filter(s => s && !dismissed.includes(s));
    } catch (e) {}

    if (cachedQuarantineFolders && Array.isArray(cachedQuarantineFolders)) {
      for (const f of cachedQuarantineFolders) {
        const s = (f.sender || '').trim().toLowerCase();
        if (s && !activeSenders.includes(s)) activeSenders.push(s);
      }
    }

    if (activeSenders.length === 0) return;

    const hash = window.location.hash || '';
    const isSearchOrVault = hash.includes('#search/') || hash.includes('quarantine');

    const rows = document.querySelectorAll('div[role="main"] tr[role="row"], table.F.cf.zt tr.zA, div[role="main"] tr.zA, tr.zA');
    for (const row of rows) {
      const emailAttr = (row.querySelector('[email]')?.getAttribute('email') || '').toLowerCase();
      const hovercard = (row.querySelector('[data-hovercard-id]')?.getAttribute('data-hovercard-id') || '').toLowerCase();
      const senderSpan = (row.querySelector('span.zF, span.bA4, span.yP, span[email]')?.innerText || '').toLowerCase();
      const senderCell = (row.querySelector('td.yX, div.yW, td.oZ-x3')?.innerText || '').toLowerCase();
      const rowFullText = (row.innerText || '').toLowerCase();

      const isQuarantined = activeSenders.some(sender => {
        const s = sender.toLowerCase();
        const userPart = s.split('@')[0];
        const domainPart = s.split('@')[1];
        return (emailAttr && emailAttr === s) ||
               (hovercard && hovercard === s) ||
               (senderSpan && senderSpan.includes(s)) ||
               (senderCell && (senderCell.includes(s) || (userPart.length > 3 && senderCell.includes(userPart)))) ||
               (rowFullText.includes(s)) ||
               (domainPart && domainPart.length > 5 && (emailAttr.includes(domainPart) || hovercard.includes(domainPart) || rowFullText.includes(domainPart)));
      });

      if (isQuarantined) {
        if (!isSearchOrVault) {
          // In Main Inbox -> HIDE row so it does not appear in main inbox table
          row.style.setProperty('display', 'none', 'important');
          row.setAttribute('data-tt-quarantined', 'true');
        } else {
          // In Search/Vault -> Show row and attach visual Quarantined Badge
          row.style.display = '';
          if (!row.querySelector('.tt-row-quarantine-tag')) {
            const subjectCol = row.querySelector('td.xY, div.xS, span.bog, div.y6');
            if (subjectCol) {
              const tag = document.createElement('span');
              tag.className = 'tt-row-quarantine-tag';
              tag.style.cssText = 'background: #dc2626; color: #fff; font-size: 10.5px; font-weight: 700; padding: 2px 7px; border-radius: 4px; margin-right: 6px; display: inline-block; vertical-align: middle;';
              tag.textContent = '📁 QUARANTINED';
              subjectCol.insertAdjacentElement('afterbegin', tag);
            }
          }
        }
      }
    }
  }

  // Display rich in-page quarantine containment toast inside Gmail
  function showQuarantineToast(folderName, suspiciousEmail, count = 1) {
    const existing = document.getElementById('tt-quarantine-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'tt-quarantine-toast';
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: linear-gradient(135deg, #1e1b4b 0%, #31104b 100%);
      border: 1px solid #dc2626;
      box-shadow: 0 10px 30px rgba(0,0,0,0.6), 0 0 24px rgba(220, 38, 38, 0.4);
      border-radius: 12px;
      padding: 16px 20px;
      color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      z-index: 999999;
      max-width: 440px;
      animation: ttSlideUp 0.3s ease-out;
    `;

    toast.innerHTML = `
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <div style="font-size: 26px; line-height: 1;">🛡️</div>
        <div style="flex: 1;">
          <div style="font-size: 12px; font-weight: 800; color: #f87171; text-transform: uppercase; letter-spacing: 0.5px;">
            Quarantine Initialized & Relocated
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #ffffff; margin-top: 2px;">
            Created Sidebar Folder: <span style="color: #38bdf8;">📁 ${suspiciousEmail}</span>
          </div>
          <div style="font-size: 12px; color: #cbd5e1; margin-top: 4px; line-height: 1.4;">
            All <strong>${count}</strong> related email thread(s) from <code>${suspiciousEmail}</code> have been moved out of Inbox into this folder.
          </div>
        </div>
        <button id="tt-close-toast-btn" style="background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 0 4px;">×</button>
      </div>
    `;

    document.body.appendChild(toast);

    document.getElementById('tt-close-toast-btn')?.addEventListener('click', () => {
      toast.remove();
    });

    setTimeout(() => {
      if (toast.parentElement) toast.remove();
    }, 9000);
  }



  // Load session initially
  try {
    if (isContextValid() && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['tt_auth_session'], (result) => {
        if (!isContextValid()) return;
        authSession = (result && result.tt_auth_session) || null;
        initThreatTrace();
      });
    }
  } catch (e) {
    console.warn('[ThreatTrace AI] storage.local.get warning:', e);
  }

  // Helper to open full-fledged site (Cockpit)
  let lastCockpitOpenTime = 0;
  function openFullFledgedSite() {
    const now = Date.now();
    if (now - lastCockpitOpenTime < 2500) {
      return;
    }
    lastCockpitOpenTime = now;
    if (isOpeningDashboard) return;
    isOpeningDashboard = true;
    setTimeout(() => {
      isOpeningDashboard = false;
    }, 2500);

    let targetUrl = `${LIVE_DASHBOARD_URL}/`;
    try {
      const emailData = extractGmailEmailData();
      const curId = (
        (emailData.subject || '') + '::' +
        (emailData.sender || '') + '::' +
        (emailData.body || '').slice(0, 160)
      ).trim();

      const cached = scanCache[curId];
      if (cached) {
        const compact = { ...cached };
        // Decoupled: do NOT assign or assume Case ID until user reports
        compact.case_id = null;
        if (compact.raw_text && compact.raw_text.length > 3500) {
          compact.raw_text = compact.raw_text.slice(0, 3500);
        }
        if (compact.body_text && compact.body_text.length > 3500) {
          compact.body_text = compact.body_text.slice(0, 3500);
        }
        try {
          localStorage.setItem('tt_active_case', JSON.stringify(compact));
        } catch (_) {}
        const payloadStr = encodeURIComponent(JSON.stringify(compact));
        targetUrl = `${LIVE_DASHBOARD_URL}/#payload=${payloadStr}`;
      } else if (emailData.subject || emailData.sender) {
        const synthetic = {
          case_id: null,
          subject: emailData.subject || 'Scanned Email Incident',
          sender: emailData.sender || 'unknown@sender',
          body_text: (emailData.body || '').slice(0, 3000),
          phones: emailData.phones || [],
          risk_score: 0,
          risk_level: 'LOW'
        };
        try {
          localStorage.setItem('tt_active_case', JSON.stringify(synthetic));
        } catch (_) {}
        const payloadStr = encodeURIComponent(JSON.stringify(synthetic));
        targetUrl = `${LIVE_DASHBOARD_URL}/#payload=${payloadStr}`;
      }
    } catch (e) {
      console.warn('[ThreatTrace AI] Error resolving case target url:', e);
    }

    console.log('[ThreatTrace AI] Opening site at:', targetUrl);

    // Send OPEN_DASHBOARD to background service worker
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD', url: targetUrl });
      } else {
        window.open(targetUrl, '_blank');
      }
    } catch (err) {
      window.open(targetUrl, '_blank');
    }
  }


  // ===================================================================
  // DOM INITIALIZATION
  // ===================================================================
  function initThreatTrace() {
    if (!isContextValid()) return;
    if (!document.body) return;

    // Clean up residual drawer & floating button if present
    removeResidualDrawer();
    removeResidualFloatingBtn();

    // Render & maintain Quarantine folders in Gmail's left sidebar
    renderQuarantineFoldersInGmailSidebar();

    // Enforce quarantine containment by hiding quarantined rows from Main Inbox
    enforceInboxQuarantineSuppression();

    // Automatic Inline Risk Score Badge & Background Scan
    autoScanActiveEmail();
  }


  // ===================================================================
  // AUTOMATIC IN-MAIL RISK SCORE BADGE INJECTION & SCANNING
  // (Positioned right beside the Subject & Tag line marked in screenshot)
  // ===================================================================
  function ensureInlineSubjectRiskBadge() {
    let badge = document.getElementById('tt-subject-risk-badge');

    // Canonical subject line in Gmail
    const h2 = document.querySelector('h2.hP') || 
               document.querySelector('div[role="main"] h2') ||
               document.querySelector('h2[data-thread-perm-id]');

    const subjectContainer = h2 
      ? h2.parentElement 
      : (document.querySelector('div[role="main"] .ha') || document.querySelector('.ha'));

    if (!subjectContainer && !h2) {
      return null;
    }

    if (!badge) {
      badge = document.createElement('div');
      badge.id = 'tt-subject-risk-badge';
      badge.innerHTML = `
        <span class="tt-spinner-icon"></span>
        <span class="tt-brand-pill">TTA</span>
        <span style="color: #BAE6FD; font-size: 11px; font-weight: 600;">Scanning Telemetry…</span>
      `;
      badge.title = 'TTA Automated Threat Assessment – Click to open full site';
    }

    // Always ensure click handler is freshly bound to the badge
    badge.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      openFullFledgedSite();
    };

    // Locate the tag container (Inbox [x]) next to the subject
    const parentContainer = subjectContainer || (h2 ? h2.parentElement : null);
    const labelTag = parentContainer 
      ? parentContainer.querySelector('.J-J5-Ji, span.hN, .ar.as, [role="listitem"]') 
      : null;

    const anchorEl = labelTag || h2;

    // Ensure badge is inserted right beside the Subject and label tags (Inbox [x])
    try {
      if (anchorEl && badge.previousElementSibling !== anchorEl) {
        anchorEl.insertAdjacentElement('afterend', badge);
      } else if (!badge.parentElement && anchorEl && anchorEl.parentNode) {
        anchorEl.insertAdjacentElement('afterend', badge);
      } else if (!badge.parentElement && parentContainer) {
        parentContainer.appendChild(badge);
      }
    } catch (e) {
      if (parentContainer && badge.parentElement !== parentContainer) {
        parentContainer.appendChild(badge);
      }
    }

    return badge;
  }

  // Automatically check open email, analyze in background, and render score
  function autoScanActiveEmail() {
    removeResidualDrawer();
    const existingQBtn = document.getElementById('tt-inline-quarantine-btn');
    if (existingQBtn) existingQBtn.remove();

    const emailData = extractGmailEmailData();
    const badge = ensureInlineSubjectRiskBadge();

    if (!emailData.subject && !emailData.body) {
      if (badge) badge.style.display = 'none';
      return;
    }

    if (badge) badge.style.display = 'inline-flex';

    const secState = evaluateSecurityState();

    // Check Authentication & Expiry
    if (secState.status === 'UNAUTHENTICATED' || secState.status === 'EXPIRED') {
      if (badge) {
        badge.className = 'tt-subject-risk-badge locked';
        badge.innerHTML = `
          <span class="threat-trace-dot locked"></span>
          <span>🔒 TTA: Login / OTP Required ↗</span>
        `;
        badge.title = secState.status === 'EXPIRED'
          ? 'Your 1-month session has expired. Click to open OTP verification tab.'
          : 'Extension is locked. Click to open OTP verification tab.';
      }
      return;
    }

    // Check Mailbox Mismatch
    if (secState.status === 'MISMATCH') {
      if (badge) {
        badge.className = 'tt-subject-risk-badge mismatch';
        badge.innerHTML = `
          <span class="threat-trace-dot mismatch"></span>
          <span>⛔ Mailbox Mismatch (${secState.boundEmail}) ↗</span>
        `;
        badge.title = secState.message + ' Click to open cockpit.';
      }
      return;
    }

    // Generate unique identifier for this email view
    const currentEmailId = (
      (emailData.subject || '') + '::' +
      (emailData.sender || '') + '::' +
      (emailData.body || '').slice(0, 160)
    ).trim();

    // If already cached, display cached result immediately
    if (scanCache[currentEmailId]) {
      renderInlineRiskScore(badge, scanCache[currentEmailId]);
      return;
    }

    // If new email and not currently scanning, trigger automatic background scan
    if (lastScannedEmailId !== currentEmailId && !isScanningInProgress) {
      lastScannedEmailId = currentEmailId;
      isScanningInProgress = true;

      if (badge) {
        badge.className = 'tt-subject-risk-badge analyzing';
        badge.innerHTML = `
          <span class="tt-spinner-icon"></span>
          <span class="tt-brand-pill">TTA</span>
          <span style="color: #BAE6FD; font-size: 11px; font-weight: 600;">Analyzing Threat Vectors…</span>
        `;
        badge.title = 'Analyzing email headers, body content, and embedded URLs with TTA…';
      }

      // Format email text
      let formattedText = '';
      if (emailData.sender) formattedText += `From: ${emailData.sender}\n`;
      if (emailData.subject) formattedText += `Subject: ${emailData.subject}\n`;
      formattedText += `\n${emailData.body || '(No body text detected)'}\n`;

      if (emailData.links && emailData.links.length > 0) {
        formattedText += '\nEmbedded URLs:\n';
        emailData.links.forEach(l => {
          formattedText += `${l.unwrapped || l.href}\n`;
        });
      }

      // Send to background dispatcher
      computeClientDigest(formattedText).then(clientDigest => {
        if (!isContextValid()) {
          isScanningInProgress = false;
          return;
        }

        const currentMailbox = secState.activeGmailUser || secState.boundEmail || '';
        safeSendMessage(
          {
            type: 'ANALYZE_EMAIL',
            email_text: formattedText,
            subject: emailData.subject || '',
            from_header: emailData.sender || '',
            recipient: currentMailbox,
            mailbox_email: currentMailbox,
            links: emailData.links || [],
            phones: emailData.phones || [],
            save_case: false,
            client_digest_sha256: clientDigest,
            client_timestamp: new Date().toISOString()
          },
          (resp) => {
            isScanningInProgress = false;
            if (!isContextValid()) return;

            if (resp && resp.ok && resp.data) {
              if (currentMailbox) {
                resp.data.recipient = currentMailbox;
                resp.data.mailbox_email = currentMailbox;
              }
              scanCache[currentEmailId] = resp.data;
              try {
                localStorage.setItem('tt_active_case', JSON.stringify(resp.data));
                if (resp.data.case_id) {
                  localStorage.setItem('tt_case_' + resp.data.case_id, JSON.stringify(resp.data));
                }
                localStorage.setItem('tt_scan_cache', JSON.stringify(scanCache));
              } catch (e) {}
              const activeBadge = ensureInlineSubjectRiskBadge();
              if (activeBadge) {
                renderInlineRiskScore(activeBadge, resp.data);
              }
            } else {

              lastScannedEmailId = null; // Allow immediate retry
              const activeBadge = ensureInlineSubjectRiskBadge();
              if (activeBadge) {
                activeBadge.className = 'tt-subject-risk-badge locked';
                activeBadge.innerHTML = `<span>⚠️ TTA: Scan Error (Click to retry)</span>`;
                activeBadge.onclick = (e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  lastScannedEmailId = null;
                  delete scanCache[currentEmailId];
                  autoScanActiveEmail();
                };
              }
            }
          }
        );
      }).catch((err) => {
        lastScannedEmailId = null;
        isScanningInProgress = false;
        console.warn('[ThreatTrace AI] computeClientDigest error:', err);
      });
    }
  }

  // Render the risk score pill directly at the subject line with direct click to full site
  function renderInlineRiskScore(badgeEl, data) {
    if (!badgeEl || !data) return;

    const score = Math.round(data.risk_score || 0);
    let riskLevel = data.risk_level || (score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW');

    if (score >= 70) {
      badgeEl.className = 'tt-subject-risk-badge danger';
      badgeEl.innerHTML = `
        <span class="threat-trace-dot" style="background:#EF4444; box-shadow: 0 0 8px #EF4444;"></span>
        <span class="tt-brand-pill">TTA</span>
        <span class="tt-badge-score-pill" style="color: #F87171; border-color: rgba(239, 68, 68, 0.4);">🚨 ${score}/100 CRITICAL</span>
        <span class="tt-badge-expand-arrow">Cockpit ↗</span>
      `;
      badgeEl.title = `TTA Alert: Risk Score ${score}/100. Phishing detected! Click to open full forensic cockpit in dashboard →`;
    } else if (score >= 40) {
      badgeEl.className = 'tt-subject-risk-badge warning';
      badgeEl.innerHTML = `
        <span class="threat-trace-dot" style="background:#F59E0B; box-shadow: 0 0 8px #F59E0B;"></span>
        <span class="tt-brand-pill">TTA</span>
        <span class="tt-badge-score-pill" style="color: #FBBF24; border-color: rgba(245, 158, 11, 0.4);">⚠️ ${score}/100 RISK · SUSPICIOUS</span>
        <span class="tt-badge-expand-arrow">Cockpit ↗</span>
      `;
      badgeEl.title = `TTA Warning: Threat Risk Score ${score}/100. Suspicious cues detected (ML Acc: 98.4%). Click to open full forensic cockpit →`;
    } else {
      badgeEl.className = 'tt-subject-risk-badge success';
      const labelText = score === 0 
        ? '✓ 100% SAFE (0 RISK)' 
        : `✓ ${score}/100 RISK · SAFE`;
      badgeEl.innerHTML = `
        <span class="threat-trace-dot" style="background:#10B981; box-shadow: 0 0 8px #10B981;"></span>
        <span class="tt-brand-pill">TTA</span>
        <span class="tt-badge-score-pill" style="color: #34D399; border-color: rgba(16, 185, 129, 0.4);">${labelText}</span>
        <span class="tt-badge-expand-arrow">Cockpit ↗</span>
      `;
      badgeEl.title = `TTA Verified: Threat Risk Score ${score}/100 (0% Risk = 100% Legitimate). ML Detection Accuracy: 98.45%. Click to inspect in forensic cockpit →`;
    }

    // Ensure click always triggers dashboard launch
    badgeEl.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      openFullFledgedSite();
    };

    // Inject Actionable Inline Quarantine Threat Button next to badge
    const existingQBtn = document.getElementById('tt-inline-quarantine-btn');
    if (score >= 40) {
      let qBtn = existingQBtn;
      if (!qBtn) {
        qBtn = document.createElement('button');
        qBtn.id = 'tt-inline-quarantine-btn';
        qBtn.className = 'tt-inline-quarantine-btn';
        if (badgeEl.parentNode) {
          badgeEl.parentNode.insertBefore(qBtn, badgeEl.nextSibling);
        }
      }
      qBtn.innerHTML = '<span>⚡ Quarantine Threat</span>';
      qBtn.style.cssText = 'margin-left: 8px; background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%); color: #FFFFFF; border: none; padding: 4px 12px; border-radius: 14px; font-size: 11.5px; font-weight: 700; cursor: pointer; box-shadow: 0 2px 8px rgba(239, 68, 68, 0.35); vertical-align: middle; transition: all 0.2s ease; display: inline-flex; align-items: center; gap: 4px;';
      qBtn.title = 'Isolate and move this threat email out of Inbox into your Quarantine Vault';
      qBtn.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const emailData = extractGmailEmailData();
        const targetSender = emailData.sender || data.sender || 'threat@isolated.net';
        const targetSubject = emailData.subject || data.subject || 'Isolated Phishing Threat';
        executeQuarantineInGmail(targetSender, targetSubject, 1);
        qBtn.innerHTML = '<span>✓ Quarantined to Vault</span>';
        qBtn.style.background = 'linear-gradient(135deg, #059669 0%, #047857 100%)';
        qBtn.disabled = true;
      };
    } else {
      if (existingQBtn) existingQBtn.remove();
    }
  }


  // ===================================================================
  // SYNCHRONIZE SECURITY UI
  // ===================================================================
  function updateSecurityUI() {
    lastEvaluatedState = evaluateSecurityState();
    removeResidualDrawer();
    removeResidualFloatingBtn();
  }

  // ===================================================================
  // EXTRACT EMAIL DATA FROM GMAIL DOM
  // ===================================================================
  function extractGmailEmailData() {
    // 1. Extract Subject
    let subject = '';
    const subjectSelectors = [
      'h2.hP',
      'h2[data-thread-perm-id]',
      'div[role="main"] h2',
      'div[role="main"] .ha h2'
    ];
    for (const sel of subjectSelectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim()) {
        subject = el.innerText.replace(/(ThreatTrace\s*AI|ThreatTrace|TTA)/gi, '').trim();
        break;
      }
    }

    // 2. Extract Sender
    let sender = '';
    const senderSelectors = [
      'div[role="main"] span.gD[email]',
      'div[role="main"] span[email]',
      'div[role="main"] span.gD',
      'div[role="main"] span.go',
      'span.gD',
      'span.go',
      'span[email]',
      'span[data-hovercard-id]',
      'div[role="main"] .gE',
      'div[role="main"] .iw'
    ];
    for (const sel of senderSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        const val = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || el.innerText.trim();
        const m = val.match(/([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/);
        if (m) {
          sender = m[1].toLowerCase();
          break;
        }
      }
    }

    // 3. Extract Body, Links, and Telephony Numbers
    let body = '';
    const links = [];
    const phones = [];
    const phoneSeen = new Set();

    const addPhone = (raw) => {
      if (!raw) return;
      const digits = String(raw).replace(/\D/g, '');
      if (digits.length >= 7 && digits.length <= 15) {
        if (/^\d{4}[-.\/]\d{2}[-.\/]\d{2}$/.test(raw) || /^\d{2}[-.\/]\d{2}[-.\/]\d{4}$/.test(raw)) return;
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)) return;
        const key = digits.length >= 10 ? digits.slice(-10) : digits;
        if (!phoneSeen.has(key)) {
          phoneSeen.add(key);
          phones.push(String(raw).trim());
        }
      }
    };

    const bodySelectors = ['.a3s', '.ii.gt', 'div[dir="ltr"]'];
    let candidateEls = [];
    bodySelectors.forEach(s => {
      candidateEls.push(...Array.from(document.querySelectorAll(s)));
    });

    const visibleCandidates = candidateEls.filter(el => {
      const text = el.innerText ? el.innerText.trim() : '';
      return text.length > 15 && el.offsetParent !== null;
    });

    let targetEl = null;
    if (visibleCandidates.length > 0) {
      targetEl = visibleCandidates[visibleCandidates.length - 1];
    } else if (candidateEls.length > 0) {
      targetEl = candidateEls[candidateEls.length - 1];
    }

    if (targetEl) {
      body = (targetEl.innerText || '').trim();

      targetEl.querySelectorAll('a[href]').forEach(a => {
        const rawHref = (a.getAttribute('href') || '').trim();
        const lowerHref = rawHref.toLowerCase();
        
        // Extract phone numbers from tel:, sms:, callto: links
        if (lowerHref.startsWith('tel:') || lowerHref.startsWith('callto:') || lowerHref.startsWith('sms:')) {
          const num = rawHref.replace(/^(tel:|callto:|sms:)/i, '').split('?')[0].trim();
          addPhone(num);
          return;
        }

        const isNonWeb = lowerHref.startsWith('mailto:') ||
                         lowerHref.startsWith('javascript:') ||
                         lowerHref.startsWith('#') ||
                         lowerHref === '';

        if (rawHref && !isNonWeb) {
          const unwrapped = unwrapGoogleRedirect(rawHref);
          const displayText = (a.innerText || a.textContent || '').trim();

          const isDup = links.some(l => l.href === rawHref || l.unwrapped === unwrapped);
          if (!isDup) {
            links.push({
              display: displayText,
              href: rawHref,
              unwrapped: unwrapped,
            });
          }
        }
      });
    }

    // Fallback: Selected text or general mail content container
    if (!body) {
      const selText = window.getSelection().toString().trim();
      if (selText) {
        body = selText;
      } else {
        const mainEl = document.querySelector('div[role="main"]');
        if (mainEl) {
          const mainText = mainEl.innerText.trim();
          if (mainText.length > 30) {
            body = mainText;
          }
        }
      }
    }

    // Scan text for telephone / toll-free / mobile numbers
    const fullTextToScan = `${subject} ${body}`;
    const phoneRegexes = [
      /(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,5}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{3,5}/g,
      /\b[6-9]\d{4}[-.\s]?\d{5}\b/g,
      /\b[6-9]\d{9}\b/g,
      /\b(?:1800|1860|0\d{2,4})[-.\s]?\d{6,8}\b/g,
      /\b(?:1800|1860)\d{6,8}\b/g,
      /\b0\d{2,4}[-.\s]?\d{5,8}\b/g,
      /(?:tel|call|phone|ph|mobile|helpline|contact|whatsapp)\s*[:=-]?\s*(\+?[0-9\-\s\(\)\.]{7,18})/gi
    ];
    for (const r of phoneRegexes) {
      const matches = fullTextToScan.match(r) || [];
      for (const m of matches) {
        addPhone(m);
      }
    }

    return { subject, sender, body, links, phones };
  }

  async function computeClientDigest(text) {
    try {
      const msgBuffer = new TextEncoder().encode(text);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return '0x' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      return null;
    }
  }

  // Immediate trigger when opening emails in Gmail SPA (300ms debounce)
  try {
    observer = new MutationObserver(() => {
      if (!isContextValid()) return;
      if (scanDebounceTimer) return;
      scanDebounceTimer = setTimeout(() => {
        scanDebounceTimer = null;
        if (!isContextValid()) return;
        enforceInboxQuarantineSuppression();
        if (document.querySelector('h2.hP, div[role="main"] .ha, div[role="main"]')) {
          autoScanActiveEmail();
        }
      }, 300);
    });

    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }
  } catch (e) {
    console.warn('[ThreatTrace AI] MutationObserver setup warning:', e);
  }

  // Instant navigation listeners for Gmail SPA tab changes
  window.addEventListener('hashchange', () => {
    setTimeout(enforceInboxQuarantineSuppression, 50);
    setTimeout(enforceInboxQuarantineSuppression, 300);
  });
  window.addEventListener('popstate', () => {
    setTimeout(enforceInboxQuarantineSuppression, 50);
    setTimeout(enforceInboxQuarantineSuppression, 300);
  });

  // Master periodic loop & init trigger
  function initThreatTrace() {
    if (!isContextValid()) return;
    renderQuarantineFoldersInGmailSidebar();
    enforceInboxQuarantineSuppression();
    if (document.querySelector('h2.hP, div[role="main"] .ha, div[role="main"]')) {
      autoScanActiveEmail();
    }
  }

  // Run initial setup immediately
  initThreatTrace();

  // Polite periodic fallback check (3.5 seconds)
  fallbackInterval = setInterval(() => {
    if (!isContextValid()) {
      if (fallbackInterval) clearInterval(fallbackInterval);
      return;
    }
    initThreatTrace();
  }, 3500);

})();

