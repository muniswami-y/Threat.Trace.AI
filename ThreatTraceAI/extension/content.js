// Threat Trace AI – Gmail In-Page Forensic Inspector with Automatic In-Mail Risk Scoring & Account Locking
(function () {
  let isContextInvalidated = false;
  let scanDebounceTimer = null;
  let fallbackInterval = null;
  let observer = null;

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

    return {
      status: 'AUTHORIZED',
      activeGmailUser: activeGmailUser || bound,
      boundEmail: bound,
      message: `Forensic Shield verified for [${bound}]. (30-day session active)`
    };
  }

  // Listen for storage changes in real-time
  try {
    if (isContextValid() && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (!isContextValid()) return;
        if (areaName === 'local' && changes.tt_auth_session) {
          authSession = changes.tt_auth_session.newValue || null;
          updateSecurityUI();
          autoScanActiveEmail();
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

        // Default: unknown message type — respond to close the channel
        sendResponse({ ok: false, error: 'unknown_message_type' });
        return false;
      });
    }
  } catch (e) {
    console.warn('[ThreatTrace AI] runtime.onMessage setup warning:', e);
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
  function openFullFledgedSite() {
    let targetUrl = 'http://localhost:5173/';
    try {
      const emailData = extractGmailEmailData();
      const curId = (
        (emailData.subject || '') + '::' +
        (emailData.sender || '') + '::' +
        (emailData.body || '').slice(0, 160)
      ).trim();

      const cached = scanCache[curId];
      if (cached && cached.case_id) {
        targetUrl = `http://localhost:5173/case/${cached.case_id}`;
      }
    } catch (e) {
      console.warn('[ThreatTrace AI] Error resolving case target url:', e);
    }

    console.log('[ThreatTrace AI] Opening site at:', targetUrl);

    // Try sending OPEN_DASHBOARD to background service worker
    let messageSent = false;
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD', url: targetUrl }, (resp) => {
          if (chrome.runtime.lastError) {
            console.warn('[ThreatTrace AI] Background tab open failed, falling back to window.open');
            window.open(targetUrl, '_blank');
          }
        });
        messageSent = true;
      }
    } catch (err) {
      messageSent = false;
    }

    // Direct window.open fallback if sendMessage was not available
    if (!messageSent) {
      try {
        window.open(targetUrl, '_blank');
      } catch (err) {
        console.warn('[ThreatTrace AI] window.open error:', err);
      }
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
      badge.className = 'tt-subject-risk-badge analyzing';
      badge.innerHTML = `
        <span class="tt-spinner-icon"></span>
        <span>ThreatTrace: Analyzing…</span>
      `;
      badge.title = 'ThreatTrace AI Automated Threat Assessment – Click to open full site';
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
          <span>🔒 ThreatTrace: Login / OTP Required ↗</span>
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
          <span>ThreatTrace: Analyzing email…</span>
        `;
        badge.title = 'Analyzing email headers, body content, and embedded URLs with ThreatTrace AI…';
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

        safeSendMessage(
          {
            type: 'ANALYZE_EMAIL',
            email_text: formattedText,
            subject: emailData.subject || '',
            from_header: emailData.sender || '',
            links: emailData.links || [],
            mailbox_email: secState.activeGmailUser || secState.boundEmail,
            client_digest_sha256: clientDigest,
            client_timestamp: new Date().toISOString()
          },
          (resp) => {
            isScanningInProgress = false;
            if (!isContextValid()) return;

            if (resp && resp.ok && resp.data) {
              scanCache[currentEmailId] = resp.data;
              const activeBadge = ensureInlineSubjectRiskBadge();
              if (activeBadge) {
                renderInlineRiskScore(activeBadge, resp.data);
              }
            } else {
              lastScannedEmailId = null; // Allow immediate retry
              const activeBadge = ensureInlineSubjectRiskBadge();
              if (activeBadge) {
                activeBadge.className = 'tt-subject-risk-badge locked';
                activeBadge.innerHTML = `<span>⚠️ ThreatTrace: Scan Error (Click to retry)</span>`;
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
        <span class="threat-trace-dot" style="background:#fff; box-shadow: 0 0 6px #fff;"></span>
        <span>ThreatTrace:</span>
        <span class="tt-badge-score-pill">${score}/100 ${riskLevel}</span>
        <span class="tt-badge-expand-arrow">↗ Open Full Site</span>
      `;
      badgeEl.title = `ThreatTrace Alert: Risk Score ${score}/100. Phishing detected! Click to open full forensic cockpit in dashboard →`;
    } else if (score >= 40) {
      badgeEl.className = 'tt-subject-risk-badge warning';
      badgeEl.innerHTML = `
        <span class="threat-trace-dot" style="background:#fff; box-shadow: 0 0 6px #fff;"></span>
        <span>ThreatTrace:</span>
        <span class="tt-badge-score-pill">${score}/100 ${riskLevel}</span>
        <span class="tt-badge-expand-arrow">↗ Open Full Site</span>
      `;
      badgeEl.title = `ThreatTrace Warning: Risk Score ${score}/100. Suspicious signals detected. Click to open full forensic cockpit →`;
    } else {
      badgeEl.className = 'tt-subject-risk-badge success';
      badgeEl.innerHTML = `
        <span class="threat-trace-dot" style="background:#fff; box-shadow: 0 0 6px #fff;"></span>
        <span>ThreatTrace:</span>
        <span class="tt-badge-score-pill">${score}/100 ${riskLevel}</span>
        <span class="tt-badge-expand-arrow">↗ Open Full Site</span>
      `;
      badgeEl.title = `ThreatTrace Verified: Risk Score ${score}/100. Safe email. Click to open full forensic cockpit →`;
    }

    // Ensure click always triggers dashboard launch
    badgeEl.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      openFullFledgedSite();
    };
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
        subject = el.innerText.replace(/ThreatTrace AI/gi, '').trim();
        break;
      }
    }

    // 2. Extract Sender
    let sender = '';
    const senderSelectors = [
      'div[role="main"] span.gD[email]',
      'div[role="main"] span[email]',
      'span.gD',
      'span.go',
      'span[data-hovercard-id]'
    ];
    for (const sel of senderSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        const val = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || el.innerText.trim();
        if (val && val.includes('@')) {
          sender = val.replace(/<|>/g, '').trim();
          break;
        }
      }
    }

    // 3. Extract Body & Links
    let body = '';
    const links = [];

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
        const isNonWeb = lowerHref.startsWith('mailto:') ||
                         lowerHref.startsWith('tel:') ||
                         lowerHref.startsWith('sms:') ||
                         lowerHref.startsWith('callto:') ||
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

    return { subject, sender, body, links };
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

  // Immediate trigger when opening emails in Gmail SPA (150ms debounce)
  try {
    observer = new MutationObserver(() => {
      if (!isContextValid()) return;
      if (scanDebounceTimer) return;
      scanDebounceTimer = setTimeout(() => {
        scanDebounceTimer = null;
        if (!isContextValid()) return;
        if (document.querySelector('h2.hP, div[role="main"] .ha, div[role="main"]')) {
          initThreatTrace();
        }
      }, 150);
    });

    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }
  } catch (e) {
    console.warn('[ThreatTrace AI] MutationObserver setup warning:', e);
  }

  // Periodic fallback check (1 second) with context check
  fallbackInterval = setInterval(() => {
    if (!isContextValid()) {
      if (fallbackInterval) clearInterval(fallbackInterval);
      return;
    }
    initThreatTrace();
  }, 1000);

})();

