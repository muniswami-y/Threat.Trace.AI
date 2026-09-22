// ThreatTrace AI – Onboarding & OTP Auth Controller v1.2.0
document.addEventListener('DOMContentLoaded', () => {
  // Prevent any default form submission in compliant CSP manner
  document.querySelectorAll('form').forEach((f) => {
    f.addEventListener('submit', (e) => e.preventDefault());
  });

  // DOM Elements
  const statusChip = document.getElementById('statusChip');
  const statusChipText = document.getElementById('statusChipText');
  const alertBox = document.getElementById('alertBox');
  const authHeading = document.getElementById('authHeading');
  const authSubtitle = document.getElementById('authSubtitle');

  // Step Containers
  const step1Container = document.getElementById('step1Container');
  const step2Container = document.getElementById('step2Container');
  const step3Success = document.getElementById('step3Success');
  const directLoginContainer = document.getElementById('directLoginContainer');

  // Step 1 Elements
  const inputEmail = document.getElementById('inputEmail');
  const inputPassword = document.getElementById('inputPassword');
  const btnRequestOtp = document.getElementById('btnRequestOtp');
  const togglePwdBtn = document.getElementById('togglePwdBtn');
  const linkDirectLogin = document.getElementById('linkDirectLogin');

  // Step 2 Elements
  const otpSentTo = document.getElementById('otpSentTo');
  const inputOtp = document.getElementById('inputOtp');
  const btnVerifyOtp = document.getElementById('btnVerifyOtp');
  const btnBackToStep1 = document.getElementById('btnBackToStep1');
  const btnResendOtp = document.getElementById('btnResendOtp');
  const demoOtpDisplay = document.getElementById('demoOtpDisplay');
  const btnAutoFillOtp = document.getElementById('btnAutoFillOtp');
  const otpTimerText = document.getElementById('otpTimerText');

  // Step 3 Elements
  const successBoundEmail = document.getElementById('successBoundEmail');
  const successExpiryDate = document.getElementById('successExpiryDate');
  const btnOpenGmail = document.getElementById('btnOpenGmail');
  const btnCloseTab = document.getElementById('btnCloseTab');

  // Direct Login Elements
  const directLoginEmail = document.getElementById('directLoginEmail');
  const directLoginPassword = document.getElementById('directLoginPassword');
  const btnDirectLoginSubmit = document.getElementById('btnDirectLoginSubmit');
  const linkOtpSetup = document.getElementById('linkOtpSetup');

  let currentEmail = '';
  let currentPassword = '';
  let otpCountdownInterval = null;

  // 1. Initial State Check
  checkExistingSession();

  function checkExistingSession() {
    chrome.runtime.sendMessage({ type: 'GET_SESSION' }, (resp) => {
      // Always check lastError to prevent unchecked error warnings
      if (chrome.runtime.lastError) { return; }
      const session = resp && resp.session;
      if (session && session.isAuthenticated && !session.isExpired && session.boundEmail) {
        showSuccessState(session);
      } else {
        const urlParams = new URLSearchParams(window.location.search);
        const queryEmail = urlParams.get('email');
        if (queryEmail && inputEmail) {
          inputEmail.value = queryEmail;
        }
      }
    });
  }

  // 2. Password Visibility Toggle
  if (togglePwdBtn && inputPassword) {
    togglePwdBtn.addEventListener('click', () => {
      if (inputPassword.type === 'password') {
        inputPassword.type = 'text';
        togglePwdBtn.textContent = '🙈';
      } else {
        inputPassword.type = 'password';
        togglePwdBtn.textContent = '👁️';
      }
    });
  }

  // 3. Step 1: Request OTP
  btnRequestOtp.addEventListener('click', () => {
    const email = (inputEmail.value || '').trim().toLowerCase();
    const password = (inputPassword.value || '').trim();

    if (!email || !email.includes('@') || !email.includes('.')) {
      showAlert('danger', 'Please enter a valid email address.');
      inputEmail.focus();
      return;
    }

    if (!password || password.length < 4) {
      showAlert('danger', 'Password / security key must be at least 4 characters.');
      inputPassword.focus();
      return;
    }

    currentEmail = email;
    currentPassword = password;

    btnRequestOtp.disabled = true;
    btnRequestOtp.innerHTML = '<span>Sending Verification Code…</span>';
    hideAlert();

    chrome.runtime.sendMessage(
      {
        type: 'REQUEST_OTP',
        email: currentEmail,
        password: currentPassword
      },
      (resp) => {
        if (chrome.runtime.lastError) {
          btnRequestOtp.disabled = false;
          btnRequestOtp.innerHTML = '<span>Send 6-Digit Verification Code (OTP) →</span>';
          showAlert('danger', 'Extension error. Please reload and try again.');
          return;
        }
        btnRequestOtp.disabled = false;
        btnRequestOtp.innerHTML = '<span>Send 6-Digit Verification Code (OTP) →</span>';

        if (!resp || !resp.ok) {
          showAlert('danger', resp && resp.error ? resp.error : 'Failed to generate OTP. Please retry.');
          return;
        }

        transitionToStep2(resp.otpPreview || '123456');
      }
    );
  });

  // 4. Step 2 Transition & Countdown
  function transitionToStep2(previewOtp) {
    step1Container.style.display = 'none';
    step2Container.style.display = 'block';
    directLoginContainer.style.display = 'none';

    authHeading.textContent = 'Enter Verification Code';
    authSubtitle.textContent = `A 6-digit cryptographic verification code has been dispatched.`;
    otpSentTo.textContent = `Target account: ${currentEmail}`;

    if (demoOtpDisplay) {
      demoOtpDisplay.textContent = previewOtp || '123456';
    }

    startOtpCountdown(600); // 10 minutes

    setTimeout(() => {
      inputOtp.focus();
    }, 150);
  }

  function startOtpCountdown(durationSeconds) {
    if (otpCountdownInterval) clearInterval(otpCountdownInterval);
    let secondsLeft = durationSeconds;

    function updateDisplay() {
      const mins = Math.floor(secondsLeft / 60);
      const secs = secondsLeft % 60;
      if (otpTimerText) {
        otpTimerText.textContent = `Expires in ${mins}:${secs < 10 ? '0' : ''}${secs}`;
      }
      if (secondsLeft <= 0) {
        clearInterval(otpCountdownInterval);
        if (otpTimerText) otpTimerText.textContent = 'Code expired';
        showAlert('danger', 'OTP has expired. Please click "Resend OTP Code".');
      }
      secondsLeft--;
    }

    updateDisplay();
    otpCountdownInterval = setInterval(updateDisplay, 1000);
  }

  // Auto-Fill OTP Helper
  if (btnAutoFillOtp) {
    btnAutoFillOtp.addEventListener('click', () => {
      const code = demoOtpDisplay ? demoOtpDisplay.textContent : '123456';
      inputOtp.value = code;
      inputOtp.focus();
    });
  }

  // Back to Step 1
  btnBackToStep1.addEventListener('click', () => {
    if (otpCountdownInterval) clearInterval(otpCountdownInterval);
    step2Container.style.display = 'none';
    step1Container.style.display = 'block';
    authHeading.textContent = 'Account Setup & Verification';
    authSubtitle.textContent = 'Enter your authorized email and set your password to receive an OTP verification code.';
    hideAlert();
  });

  // Resend OTP
  btnResendOtp.addEventListener('click', () => {
    btnResendOtp.disabled = true;
    btnResendOtp.textContent = 'Sending…';

    chrome.runtime.sendMessage(
      {
        type: 'REQUEST_OTP',
        email: currentEmail,
        password: currentPassword
      },
      (resp) => {
        btnResendOtp.disabled = false;
        btnResendOtp.textContent = 'Resend OTP Code';
        if (resp && resp.ok) {
          showAlert('info', 'A new verification code has been dispatched.');
          if (demoOtpDisplay && resp.otpPreview) {
            demoOtpDisplay.textContent = resp.otpPreview;
          }
          startOtpCountdown(600);
        } else {
          showAlert('danger', 'Failed to resend code.');
        }
      }
    );
  });

  // 5. Verify OTP Button
  btnVerifyOtp.addEventListener('click', () => {
    const otp = (inputOtp.value || '').trim();
    if (!otp || otp.length < 4) {
      showAlert('danger', 'Please enter the 6-digit OTP verification code.');
      inputOtp.focus();
      return;
    }

    btnVerifyOtp.disabled = true;
    btnVerifyOtp.innerHTML = '<span>Verifying & Sealing Credentials…</span>';
    hideAlert();

    chrome.runtime.sendMessage(
      {
        type: 'VERIFY_OTP',
        email: currentEmail,
        password: currentPassword,
        otp: otp
      },
      (resp) => {
        if (chrome.runtime.lastError) {
          btnVerifyOtp.disabled = false;
          btnVerifyOtp.innerHTML = '<span>🔒 Verify OTP & Bind Extension (30 Days)</span>';
          showAlert('danger', 'Extension error. Please reload and retry.');
          return;
        }
        btnVerifyOtp.disabled = false;
        btnVerifyOtp.innerHTML = '<span>🔒 Verify OTP & Bind Extension (30 Days)</span>';

        if (!resp || !resp.ok) {
          showAlert('danger', resp && resp.error ? resp.error : 'Invalid OTP. Please check the code and try again.');
          return;
        }

        if (otpCountdownInterval) clearInterval(otpCountdownInterval);
        showSuccessState(resp.session);
      }
    );
  });

  // 6. Direct Login Toggle
  linkDirectLogin.addEventListener('click', (e) => {
    e.preventDefault();
    step1Container.style.display = 'none';
    step2Container.style.display = 'none';
    directLoginContainer.style.display = 'block';
    authHeading.textContent = 'Analyst Sign In';
    authSubtitle.textContent = 'Authenticate with your existing credentials to bind your 1-month session.';
    hideAlert();
    if (directLoginEmail && inputEmail.value) {
      directLoginEmail.value = inputEmail.value;
    }
  });

  linkOtpSetup.addEventListener('click', (e) => {
    e.preventDefault();
    directLoginContainer.style.display = 'none';
    step1Container.style.display = 'block';
    authHeading.textContent = 'Account Setup & Verification';
    authSubtitle.textContent = 'Enter your authorized email and set your password to receive an OTP verification code.';
    hideAlert();
  });

  // Direct Login Submit
  btnDirectLoginSubmit.addEventListener('click', () => {
    const email = (directLoginEmail.value || '').trim().toLowerCase();
    const password = (directLoginPassword.value || '').trim();

    if (!email || !email.includes('@')) {
      showAlert('danger', 'Please enter a valid email address.');
      return;
    }

    btnDirectLoginSubmit.disabled = true;
    btnDirectLoginSubmit.innerHTML = '<span>Authenticating…</span>';

    chrome.runtime.sendMessage({ type: 'LOGIN', email, password }, (resp) => {
      if (chrome.runtime.lastError) {
        btnDirectLoginSubmit.disabled = false;
        btnDirectLoginSubmit.innerHTML = '<span>Sign In & Bind for 30 Days</span>';
        showAlert('danger', 'Extension error. Please reload and retry.');
        return;
      }
      btnDirectLoginSubmit.disabled = false;
      btnDirectLoginSubmit.innerHTML = '<span>Sign In & Bind for 30 Days</span>';

      if (!resp || !resp.ok) {
        showAlert('danger', resp && resp.error ? resp.error : 'Sign in failed. Please check credentials.');
        return;
      }

      showSuccessState(resp.session);
    });
  });

  // 7. Success State Display
  function showSuccessState(session) {
    step1Container.style.display = 'none';
    step2Container.style.display = 'none';
    directLoginContainer.style.display = 'none';
    step3Success.style.display = 'block';

    statusChip.className = 'status-chip active';
    statusChipText.textContent = 'FORENSIC SHIELD ACTIVE';

    authHeading.textContent = 'Extension Verified & Ready';
    authSubtitle.textContent = 'Your forensic shield is fully active and automatically monitoring emails.';

    successBoundEmail.textContent = session.boundEmail || session.userEmail || currentEmail;

    // Calculate expiry date (30 days)
    const expiryTimestamp = session.expiresAt || (Date.now() + 30 * 24 * 60 * 60 * 1000);
    const expiryDateObj = new Date(expiryTimestamp);
    const options = { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    showAlert('success', `✓ Verified! Extension is locked to [${session.boundEmail}] with a 1-month active session.`);

    // Automatically trigger server-side quarantine filter & folder provisioning
    chrome.runtime.sendMessage({
      type: 'OAUTH_FLOW_COMPLETED',
      payload: {
        provider: 'google',
        userEmail: session.boundEmail || session.userEmail || currentEmail,
        token: session.token
      }
    }, (provResp) => {
      if (chrome.runtime.lastError) return;
      if (provResp && provResp.ok) {
        console.log('[ThreatTrace AI] Server-side Quarantine automatically provisioned:', provResp);
      }
    });
  }

  // 8. Open Dashboard & Gmail Buttons
  const btnOpenDashboard = document.getElementById('btnOpenDashboard');
  if (btnOpenDashboard) {
    btnOpenDashboard.addEventListener('click', () => {
      chrome.tabs.create({ url: 'http://localhost:5173/' });
    });
  }

  btnOpenGmail.addEventListener('click', () => {
    chrome.tabs.create({ url: 'https://mail.google.com' });
  });

  btnCloseTab.addEventListener('click', () => {
    window.close();
  });

  // Helpers
  function showAlert(type, message) {
    alertBox.className = `alert-box ${type}`;
    alertBox.textContent = message;
    alertBox.style.display = 'block';
  }

  function hideAlert() {
    alertBox.style.display = 'none';
  }
});
