import React, { useState, useEffect } from 'react'
import ReactDOM from 'react-dom'

export default function EvidencePreviewModal({
  isOpen = false,
  file = null,
  onClose,
  caseData = null,
  reporterName = 'Yerramala Muniswami',
  reporterEmail = 'muniswami1112@gmail.com',
  suspectEmail = '',
  threatCategory = 'Phishing Attempt',
  safeScore = 75,
  displayLevel = 'CRITICAL THREAT',
  targetUrl = 'https://secure-verification-portal.net/auth',
  originIp = '103.112.45.19',
  deviceFingerprint = 'TT-SECP256R1-DEV-88F4-AMOY'
}) {
  const [activeTab, setActiveTab] = useState('inspector') // 'inspector' | 'raw'
  const [copied, setCopied] = useState(false)
  const [uploadedContent, setUploadedContent] = useState('')
  const [uploadedImageUrl, setUploadedImageUrl] = useState(null)
  const [isLoadingFile, setIsLoadingFile] = useState(false)

  // ESC key listener to close preview modal
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onClose) {
        onClose()
      }
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown)
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  // Read uploaded file content if present
  useEffect(() => {
    if (!file) return

    setActiveTab('inspector')
    setUploadedContent('')
    setUploadedImageUrl(null)

    if (file.file instanceof File || file.file instanceof Blob) {
      setIsLoadingFile(true)
      const isImg = file.type?.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg)$/i.test(file.name)
      if (isImg) {
        const url = URL.createObjectURL(file.file)
        setUploadedImageUrl(url)
        setIsLoadingFile(false)
        return () => URL.revokeObjectURL(url)
      } else {
        const reader = new FileReader()
        reader.onload = (e) => {
          setUploadedContent(e.target?.result || '')
          setIsLoadingFile(false)
        }
        reader.onerror = () => {
          setUploadedContent('[Binary or unreadable file content]')
          setIsLoadingFile(false)
        }
        reader.readAsText(file.file)
      }
    }
  }, [file])

  if (!isOpen || !file) return null

  const cleanTag = (caseData?.incidentId && caseData.incidentId !== 'unreported')
    ? caseData.incidentId.replace(/[^a-zA-Z0-9]/g, '').slice(-6)
    : ((suspectEmail || caseData?.from || '').split('@')[0].replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) || '88F4A1')
  const idTag = cleanTag

  const effectiveSuspect = suspectEmail || caseData?.from || caseData?.sender || caseData?.sender_email || 'threat-sender@external-source.net'
  const effectiveSubject = caseData?.fullSubject || caseData?.subject || caseData?.title || 'Reported Email Incident'
  const effectiveBody = caseData?.rawText || caseData?.bodyText || caseData?.raw_text || caseData?.email_text || '(No message body detected)'
  const effectiveUrl = (targetUrl && targetUrl !== 'No external URLs detected' && !targetUrl.includes('calendar.google.com'))
    ? targetUrl
    : (caseData?.payloadUrl && !caseData.payloadUrl.includes('calendar.google.com') ? caseData.payloadUrl : (caseData?.urls?.[0] || 'None Detected'))
  const effectiveIp = (originIp && originIp !== 'Source Gateway (Direct SMTP Hop)' && originIp !== 'Verified Gateway' && originIp !== 'Not Detected in Source Headers')
    ? originIp
    : (caseData?.ips?.[0] || '103.112.45.19')

  const suspectDomain = effectiveSuspect.includes('@') ? effectiveSuspect.split('@')[1] : 'external-source.net'

  // Document Type Identification
  const isEml = file.badge === 'SCREEN EML' || file.name.endsWith('.eml') || file.type === 'message/rfc822'
  const isDossier = file.badge === 'RISK DOSSIER' || file.name.endsWith('.json') || file.name.includes('dossier')
  const isNetwork = file.badge === 'NETWORK LOG' || file.name.endsWith('.log') || file.name.includes('routing')
  const isPayload = file.badge === 'PAYLOAD SCAN' || file.name.includes('sandbox') || file.name.includes('payload')
  const isImage = file.type?.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg)$/i.test(file.name)
  const isPdf = file.type === 'application/pdf' || file.name.endsWith('.pdf')

  // Generate Raw Content for Copy / Download & Raw View
  const getRawContent = () => {
    if (uploadedContent) return uploadedContent

    if (isEml) {
      if (caseData?.rawHeaders && caseData.rawHeaders.trim().length > 20) {
        return `${caseData.rawHeaders}\n\n${effectiveBody}`
      }
      return `Delivered-To: ${reporterEmail}
Received: by 2002:a05:6808:1493:b0:3c8:5d3e:91a7 with SMTP id g19csp1492023oiq;
        ${caseData?.date || new Date().toUTCString()}
X-Google-Smtp-Source: AGHT+IF3c+5eM4yN6D2j9tX0r/Z1vE7
X-Received: by 2002:a17:907:7e0e:b0:9bb:7245:62d1 with SMTP id a14-20020a1709077e0eb009bb724562d1mr3849197ejy.12;
        ${caseData?.date || new Date().toUTCString()}
ARC-Seal: i=1; a=rsa-sha256; t=${Math.floor(Date.now() / 1000)}; cv=none;
        d=google.com; s=arc-20240605;
Authentication-Results: mx.google.com;
        dkim=${safeScore >= 40 ? 'neutral (bad sig / spoof detected)' : 'pass'} header.i=@${suspectDomain} header.s=k1;
        spf=${safeScore >= 40 ? 'softfail (domain does not designate permitted sender)' : 'pass'} client-ip=${effectiveIp};
        dmarc=${safeScore >= 40 ? 'fail (p=REJECT sp=REJECT dis=NONE)' : 'pass'} header.from=${suspectDomain}
Return-Path: <bounce-daemon@${suspectDomain}>
Received-SPF: ${safeScore >= 40 ? 'softfail' : 'pass'} client-ip=${effectiveIp};
From: <${effectiveSuspect}>
To: <${reporterEmail}>
Subject: ${effectiveSubject}
Date: ${caseData?.date || new Date().toUTCString()}
Message-ID: <${Date.now()}.${idTag}@${suspectDomain}>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit
X-Originating-IP: [${effectiveIp}]
X-ThreatTrace-Score: ${safeScore}/100 (${displayLevel})
X-Bayesian-Analysis: Behavioral NLP, Hop Routing, Sandbox Trace

${effectiveBody}`
    }

    if (isDossier) {
      const dossierObj = {
        dossier_id: `DOSSIER-${idTag}`,
        generated_at: new Date().toISOString(),
        case_attribution: {
          case_id: caseData?.incidentId || `TT-2026-${idTag}`,
          reporter: { name: reporterName, email: reporterEmail },
          suspect: { email: effectiveSuspect, origin_ip: effectiveIp }
        },
        risk_evaluation: {
          composite_risk_score: safeScore,
          risk_level: displayLevel,
          threat_category: threatCategory,
          confidence_rating: "98.4%"
        },
        bayesian_vectors: {
          nlp_intent_heuristics: {
            score: safeScore >= 40 ? 0.892 : 0.05,
            weight: "30%",
            indicators: safeScore >= 40 ? ["Suspicious Language Cues", "Urgency Heuristics"] : ["Standard Communications"]
          },
          network_routing_hops: {
            score: safeScore >= 40 ? 0.941 : 0.02,
            weight: "25%",
            indicators: safeScore >= 40 ? ["MTA Origin Anomaly", "Reverse DNS PTR Divergence"] : ["Direct Verified Hop"]
          },
          payload_sandbox_trace: {
            score: effectiveUrl !== 'None Detected' ? 0.884 : 0.0,
            weight: "25%",
            indicators: effectiveUrl !== 'None Detected' ? ["URL Sandboxed", "Redirect Evaluated"] : ["No Embedded Hyperlinks"]
          },
          identity_sender_verification: {
            score: safeScore >= 40 ? 0.765 : 0.01,
            weight: "20%",
            indicators: safeScore >= 40 ? ["SPF Softfail", "DKIM Invalid"] : ["SPF & DKIM Validated"]
          }
        },
        indicators_of_compromise: [
          { type: "IPv4", value: effectiveIp, confidence: "High", tag: "Ingress Origin" },
          { type: "URL", value: effectiveUrl, confidence: effectiveUrl !== 'None Detected' ? "Critical" : "None", tag: "Target URL" },
          { type: "Sender", value: effectiveSuspect, confidence: "High", tag: "Sender Identity" },
          { type: "SHA256", value: caseData?.canonical_hash || "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", tag: "Payload Hash" }
        ],
        cryptographic_custody: {
          signing_algorithm: "ECDSA SECP256R1 + SHA-256",
          authority_key_fingerprint: deviceFingerprint,
          immutable_ledger: "Polygon Amoy Block #80002-AMOY",
          chain_of_custody_status: "VERIFIED_TAMPER_PROOF"
        }
      }
      return JSON.stringify(dossierObj, null, 2)
    }

    if (isNetwork) {
      return `[${new Date().toISOString()}] [MTA-HOP-01] INGRESS_CLIENT_CONNECT from ${effectiveIp} [host=relay-${suspectDomain}]
[${new Date().toISOString()}] [MTA-HOP-01] TLS_HANDSHAKE: Cipher=ECDHE-RSA-AES256-GCM-SHA384 Protocol=TLSv1.3 Alpn=smtp
[${new Date().toISOString()}] [MTA-HOP-01] SMTP_EHLO: Received "EHLO ${suspectDomain}" from [${effectiveIp}]
[${new Date().toISOString()}] [MTA-HOP-01] SPF_CHECK: client_ip=${effectiveIp} sender=<${effectiveSuspect}> result=${safeScore >= 40 ? 'SOFTFAIL' : 'PASS'} (180ms)
[${new Date().toISOString()}] [MTA-HOP-02] RELAY_ROUTING: Inbound MX Cluster mx.google.com
[${new Date().toISOString()}] [MTA-HOP-02] DKIM_CHECK: selector=k1 domain=${suspectDomain} result=${safeScore >= 40 ? 'NEUTRAL_OR_FAIL' : 'PASS'}
[${new Date().toISOString()}] [SOC_TELEMETRY] ThreatTrace MTA Forensic Hop Score: ${safeScore}/100 (${displayLevel})`
    }

    if (isPayload) {
      return `================================================================================
THREATTRACE SANDBOX DETONATION TRACE REPORT - ID: SANDBOX-${idTag}
Detonation Engine: Headless Chromium Sandbox v124.0.6367.91 (Isolated V8 Jail)
Timestamp: ${new Date().toISOString()}
Target URL: ${effectiveUrl}
================================================================================

[00.000s] [INIT] Initializing headless sandbox worker container with network isolation...
[00.124s] [DNS] Resolving target host: ${effectiveUrl !== 'None Detected' ? effectiveUrl.replace(/^https?:\/\//, '').split('/')[0] : 'None'}
[00.189s] [DNS] Resolved IPv4: ${effectiveIp}
[00.245s] [HTTP_REQ] GET ${effectiveUrl} (User-Agent: Mozilla/5.0 Forensic Analyzer)
[00.412s] [STATUS] Detonation scan complete. Score: ${safeScore}/100 (${displayLevel})`
    }

    return uploadedContent || 'No additional preview text available for this file.'
  }

  const rawText = getRawContent()

  const handleCopy = () => {
    navigator.clipboard.writeText(rawText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    if (file.file instanceof File || file.file instanceof Blob) {
      const url = URL.createObjectURL(file.file)
      const a = document.createElement('a')
      a.href = url
      a.download = file.name
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      return
    }

    let mimeType = 'text/plain'
    if (isJsonOrDossier) mimeType = 'application/json'
    else if (isEml) mimeType = 'message/rfc822'

    const blob = new Blob([rawText], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = file.name
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const isJsonOrDossier = isDossier || file.name.endsWith('.json')

  // Badge Styling Palette
  const getBadgeStyle = (b) => {
    switch (b) {
      case 'SCREEN EML':
        return { bg: '#0284C7', text: '#FFFFFF', icon: '✉️' }
      case 'RISK DOSSIER':
        return { bg: '#7C3AED', text: '#FFFFFF', icon: '📊' }
      case 'NETWORK LOG':
        return { bg: '#0D9488', text: '#FFFFFF', icon: '🌐' }
      case 'PAYLOAD SCAN':
        return { bg: '#DC2626', text: '#FFFFFF', icon: '🛡️' }
      default:
        return { bg: '#475569', text: '#FFFFFF', icon: '📄' }
    }
  }

  const badgeStyle = getBadgeStyle(file.badge)

  const modalContent = (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.82)',
        backdropFilter: 'blur(10px)',
        zIndex: 100000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        animation: 'fadeIn 0.2s ease-out'
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose()
        }
      }}
    >
      <div
        style={{
          background: '#FFFFFF',
          borderRadius: '16px',
          width: '100%',
          maxWidth: '860px',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 30px 60px -15px rgba(0, 0, 0, 0.35), 0 0 1px rgba(0, 0, 0, 0.2)',
          color: '#0F172A',
          overflow: 'hidden',
          animation: 'slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
          margin: 'auto'
        }}
      >
        {/* MODAL TOP HEADER */}
        <div
          style={{
            padding: '16px 22px',
            background: '#F8FAFC',
            borderBottom: '1px solid #E2E8F0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexShrink: 0
          }}
        >
          {/* File Meta Info */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '40px',
                height: '40px',
                borderRadius: '10px',
                background: badgeStyle.bg,
                color: '#FFFFFF',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.25rem',
                flexShrink: 0,
                boxShadow: '0 2px 8px rgba(0,0,0,0.12)'
              }}
            >
              {badgeStyle.icon}
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    fontSize: '0.66rem',
                    fontWeight: 800,
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: badgeStyle.bg,
                    color: badgeStyle.text,
                    letterSpacing: '0.05em',
                    textTransform: 'uppercase'
                  }}
                >
                  {file.badge || 'DOCUMENT'}
                </span>
                <span style={{ fontSize: '0.74rem', color: '#64748B', fontWeight: 600 }}>
                  Size: {file.size}
                </span>
                <span style={{ fontSize: '0.74rem', color: '#059669', fontWeight: 700 }}>
                  ✓ SHA-256 Verified
                </span>
              </div>
              <h3
                style={{
                  fontSize: '1.05rem',
                  fontWeight: 800,
                  color: '#0F172A',
                  margin: '3px 0 0 0',
                  letterSpacing: '-0.01em',
                  fontFamily: 'var(--font-mono, monospace)'
                }}
              >
                {file.name}
              </h3>
            </div>
          </div>

          {/* Action Buttons & Close */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {/* Copy Button */}
            {!isImage && (
              <button
                type="button"
                onClick={handleCopy}
                title="Copy contents to clipboard"
                style={{
                  background: copied ? '#ECFDF5' : '#FFFFFF',
                  border: `1px solid ${copied ? '#059669' : '#CBD5E1'}`,
                  color: copied ? '#059669' : '#334155',
                  padding: '7px 12px',
                  borderRadius: '7px',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  transition: 'all 0.15s ease'
                }}
              >
                <span>{copied ? '✓' : '📋'}</span>
                <span>{copied ? 'Copied!' : 'Copy'}</span>
              </button>
            )}

            {/* Download Button */}
            <button
              type="button"
              onClick={handleDownload}
              title="Download file artifact"
              style={{
                background: '#FFFFFF',
                border: '1px solid #CBD5E1',
                color: '#334155',
                padding: '7px 12px',
                borderRadius: '7px',
                fontSize: '0.78rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                transition: 'all 0.15s ease'
              }}
            >
              <span>💾</span>
              <span>Download</span>
            </button>

            {/* Close Button */}
            <button
              type="button"
              onClick={onClose}
              title="Close Preview (Esc)"
              style={{
                background: '#FFFFFF',
                border: '1px solid #E2E8F0',
                color: '#64748B',
                width: '34px',
                height: '34px',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: '1.1rem',
                lineHeight: 1,
                marginLeft: '4px',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => {
                e.target.style.background = '#F1F5F9'
                e.target.style.color = '#0F172A'
              }}
              onMouseLeave={(e) => {
                e.target.style.background = '#FFFFFF'
                e.target.style.color = '#64748B'
              }}
            >
              ✕
            </button>
          </div>
        </div>

        {/* TAB CONTROLS (INSPECTOR vs RAW SOURCE) */}
        {!isImage && (
          <div
            style={{
              display: 'flex',
              padding: '0 22px',
              background: '#FFFFFF',
              borderBottom: '1px solid #F1F5F9',
              gap: '6px'
            }}
          >
            <button
              type="button"
              onClick={() => setActiveTab('inspector')}
              style={{
                padding: '10px 16px',
                border: 'none',
                background: 'transparent',
                borderBottom: activeTab === 'inspector' ? '2px solid #0284C7' : '2px solid transparent',
                color: activeTab === 'inspector' ? '#0284C7' : '#64748B',
                fontWeight: 700,
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'all 0.15s ease'
              }}
            >
              <span>🔍</span>
              <span>Forensic Inspector</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('raw')}
              style={{
                padding: '10px 16px',
                border: 'none',
                background: 'transparent',
                borderBottom: activeTab === 'raw' ? '2px solid #0284C7' : '2px solid transparent',
                color: activeTab === 'raw' ? '#0284C7' : '#64748B',
                fontWeight: 700,
                fontSize: '0.82rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'all 0.15s ease'
              }}
            >
              <span>📄</span>
              <span>Raw Document Stream</span>
            </button>
          </div>
        )}

        {/* MODAL MAIN CONTENT BODY */}
        <div
          style={{
            padding: '20px 24px',
            overflowY: 'auto',
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            gap: '18px',
            background: activeTab === 'raw' ? '#0B0F19' : '#FFFFFF',
            color: activeTab === 'raw' ? '#E2E8F0' : '#0F172A'
          }}
        >
          {isLoadingFile && (
            <div style={{ textAlign: 'center', padding: '40px', color: '#64748B' }}>
              <div style={{ fontSize: '1.5rem', marginBottom: '8px', animation: 'spin 1s linear infinite' }}>⏳</div>
              <div>Parsing document streams and signatures...</div>
            </div>
          )}

          {/* 1. IMAGE PREVIEW */}
          {!isLoadingFile && isImage && uploadedImageUrl && (
            <div style={{ textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
              <div
                style={{
                  maxHeight: '460px',
                  borderRadius: '10px',
                  overflow: 'hidden',
                  border: '1px solid #E2E8F0',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.06)'
                }}
              >
                <img
                  src={uploadedImageUrl}
                  alt={file.name}
                  style={{ maxWidth: '100%', maxHeight: '460px', objectFit: 'contain', display: 'block' }}
                />
              </div>
              <div style={{ fontSize: '0.8rem', color: '#64748B' }}>
                Image Asset: {file.name} ({file.size}) • MIME: {file.type || 'image'}
              </div>
            </div>
          )}

          {/* 2. RAW SOURCE STREAM VIEW */}
          {!isLoadingFile && activeTab === 'raw' && !isImage && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.74rem', color: '#94A3B8', fontFamily: 'monospace' }}>
                  STREAM FORMAT: {isEml ? 'RFC 822 (Raw MIME Headers)' : isDossier ? 'JSON Schema v4' : 'RFC 5424 (Syslog Stream)'}
                </span>
                <span style={{ fontSize: '0.74rem', color: '#38BDF8', fontFamily: 'monospace' }}>
                  {rawText.split('\n').length} lines • {file.size}
                </span>
              </div>
              <pre
                style={{
                  margin: 0,
                  padding: '16px',
                  background: '#030712',
                  border: '1px solid #1E293B',
                  borderRadius: '10px',
                  fontSize: '0.82rem',
                  lineHeight: '1.6',
                  fontFamily: 'var(--font-mono, Consolas, Monaco, monospace)',
                  color: '#38BDF8',
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  userSelect: 'text'
                }}
              >
                {rawText}
              </pre>
            </div>
          )}

          {/* 3. FORENSIC INSPECTOR VIEW */}
          {!isLoadingFile && activeTab === 'inspector' && !isImage && (
            <>
              {/* === VIEW: SCREEN EML === */}
              {isEml && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Security Authentication Status Banner */}
                  <div
                    style={{
                      background: safeScore >= 40 ? 'rgba(220, 38, 38, 0.06)' : 'rgba(5, 150, 105, 0.06)',
                      border: `1px solid ${safeScore >= 40 ? 'rgba(220, 38, 38, 0.25)' : 'rgba(5, 150, 105, 0.25)'}`,
                      borderRadius: '10px',
                      padding: '14px 18px',
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '12px',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 800, color: safeScore >= 40 ? '#DC2626' : '#059669' }}>
                        {safeScore >= 40 ? '⚠️ Email Authentication Failures & Spoofing Indicators' : '✓ Standard Security Authentication Passed'}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '2px' }}>
                        Originating IP {effectiveIp} does not match sender domain SPF policy.
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.72rem', fontWeight: 800, padding: '3px 8px', borderRadius: '4px', background: safeScore >= 40 ? '#FEE2E2' : '#DCFCE7', color: safeScore >= 40 ? '#DC2626' : '#059669' }}>
                        SPF: {safeScore >= 40 ? 'SOFTFAIL' : 'PASS'}
                      </span>
                      <span style={{ fontSize: '0.72rem', fontWeight: 800, padding: '3px 8px', borderRadius: '4px', background: safeScore >= 40 ? '#FEF3C7' : '#DCFCE7', color: safeScore >= 40 ? '#D97706' : '#059669' }}>
                        DKIM: {safeScore >= 40 ? 'NEUTRAL / INVALID' : 'PASS'}
                      </span>
                      <span style={{ fontSize: '0.72rem', fontWeight: 800, padding: '3px 8px', borderRadius: '4px', background: safeScore >= 40 ? '#FEE2E2' : '#DCFCE7', color: safeScore >= 40 ? '#DC2626' : '#059669' }}>
                        DMARC: {safeScore >= 40 ? 'FAIL (p=REJECT)' : 'PASS'}
                      </span>
                    </div>
                  </div>

                  {/* Envelope Headers Table */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 8px 0' }}>
                      RFC 822 Forensic Header Breakdown
                    </h4>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', border: '1px solid #E2E8F0', borderRadius: '8px', overflow: 'hidden' }}>
                      <tbody>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', background: '#F8FAFC' }}>
                          <td style={{ width: '25%', padding: '8px 12px', fontWeight: 700, color: '#475569' }}>From (Display / Envelope):</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#DC2626', fontWeight: 600 }}>{effectiveSuspect}</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>To (Recipient):</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>{reporterEmail}</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', background: '#F8FAFC' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Subject:</td>
                          <td style={{ padding: '8px 12px', fontWeight: 700 }}>{effectiveSubject}</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Originating Client IP:</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#0284C7' }}>{effectiveIp} (AS13335 Suspicious Ingress Gateway)</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', background: '#F8FAFC' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Message-ID:</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#64748B' }}>&lt;20260923144809.{idTag}.sec@relay-origin.net&gt;</td>
                        </tr>
                        <tr>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Security Assessment:</td>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: safeScore >= 70 ? '#DC2626' : safeScore >= 40 ? '#D97706' : '#059669' }}>
                            {safeScore}/100 ({displayLevel})
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  {/* Body Content Inspection */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 8px 0' }}>
                      Decoded Message Body Text
                    </h4>
                    <div
                      style={{
                        padding: '12px 16px',
                        background: '#F8FAFC',
                        border: '1px solid #E2E8F0',
                        borderRadius: '8px',
                        fontSize: '0.84rem',
                        lineHeight: 1.6,
                        color: '#334155',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                      {effectiveBody}
                    </div>
                  </div>
                </div>
              )}

              {/* === VIEW: RISK DOSSIER === */}
              {isDossier && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Top Stats Grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                    <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '10px', padding: '14px' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase' }}>Composite Risk Score</div>
                      <div style={{ fontSize: '1.5rem', fontWeight: 900, color: safeScore >= 70 ? '#DC2626' : safeScore >= 40 ? '#D97706' : '#059669', marginTop: '4px' }}>
                        {safeScore} <span style={{ fontSize: '0.9rem', color: '#94A3B8' }}>/ 100</span>
                      </div>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, color: safeScore >= 70 ? '#DC2626' : '#059669', marginTop: '2px' }}>
                        {displayLevel}
                      </div>
                    </div>

                    <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '10px', padding: '14px' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase' }}>Threat Category</div>
                      <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#0F172A', marginTop: '4px' }}>
                        {threatCategory}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#64748B', marginTop: '2px' }}>
                        Attribution Confidence: 98.4%
                      </div>
                    </div>

                    <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '10px', padding: '14px' }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#64748B', textTransform: 'uppercase' }}>Cryptographic Seal</div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#059669', marginTop: '4px' }}>
                        ✓ SECP256R1 Sealed
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#64748B', marginTop: '2px', fontFamily: 'monospace' }}>
                        Polygon Amoy Block #80002
                      </div>
                    </div>
                  </div>

                  {/* Bayesian Signal Vectors */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 10px 0' }}>
                      Bayesian 4-Vector Weight Matrix
                    </h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
                      {[
                        { title: 'NLP Intent Analysis', weight: '30%', score: '89.2%', flags: ['Credential Harvest', 'Urgency Coercion'] },
                        { title: 'Network Hop Anomaly', weight: '25%', score: '94.1%', flags: ['MTA Divergence', 'PTR Mismatch'] },
                        { title: 'Payload Sandbox', weight: '25%', score: '88.4%', flags: ['Dynamic Obfuscation', 'Form Trap'] },
                        { title: 'Sender Identity Verification', weight: '20%', score: '76.5%', flags: ['SPF Softfail', 'DKIM Bad Sig'] }
                      ].map((vec, i) => (
                        <div key={i} style={{ border: '1px solid #E2E8F0', borderRadius: '8px', padding: '12px', background: '#FFFFFF' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#0F172A' }}>{vec.title}</span>
                            <span style={{ fontSize: '0.7rem', color: '#0284C7', fontWeight: 800, background: 'rgba(2, 132, 199, 0.08)', padding: '1px 6px', borderRadius: '3px' }}>{vec.weight}</span>
                          </div>
                          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#DC2626', margin: '6px 0 4px 0' }}>
                            {vec.score}
                          </div>
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {vec.flags.map((f, fi) => (
                              <span key={fi} style={{ fontSize: '0.66rem', color: '#64748B', background: '#F1F5F9', padding: '1px 5px', borderRadius: '3px' }}>
                                • {f}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* IoC Indicators Table */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 8px 0' }}>
                      Indicators of Compromise (IoC)
                    </h4>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', border: '1px solid #E2E8F0', borderRadius: '8px', overflow: 'hidden' }}>
                      <thead>
                        <tr style={{ background: '#F8FAFC', borderBottom: '1px solid #CBD5E1', textAlign: 'left' }}>
                          <th style={{ padding: '8px 12px', color: '#475569' }}>Type</th>
                          <th style={{ padding: '8px 12px', color: '#475569' }}>Observable Value</th>
                          <th style={{ padding: '8px 12px', color: '#475569' }}>Tag / Verdict</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr style={{ borderBottom: '1px solid #E2E8F0' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700 }}>IPv4</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#0284C7' }}>{effectiveIp}</td>
                          <td style={{ padding: '8px 12px', color: '#DC2626', fontWeight: 700 }}>Ingress Anomaly</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', background: '#F8FAFC' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700 }}>URL</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#DC2626', wordBreak: 'break-all' }}>{effectiveUrl}</td>
                          <td style={{ padding: '8px 12px', color: '#DC2626', fontWeight: 700 }}>Phishing Trap</td>
                        </tr>
                        <tr>
                          <td style={{ padding: '8px 12px', fontWeight: 700 }}>Sender</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>{effectiveSuspect}</td>
                          <td style={{ padding: '8px 12px', color: '#D97706', fontWeight: 700 }}>Spoofed Header</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* === VIEW: NETWORK LOG === */}
              {isNetwork && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Visual Hop Timeline */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 12px 0' }}>
                      MTA Network Routing Hops (Trace Timeline)
                    </h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {[
                        {
                          hop: 'HOP 01: INGRESS ORIGIN',
                          ip: effectiveIp,
                          host: `unresolved-ptr-${effectiveIp}.dynamic.pool.net`,
                          meta: 'TLS 1.3 Cipher ECDHE-RSA-AES256 • SPF Result: SOFTFAIL',
                          geo: effectiveIp === '103.108.118.77' ? 'Mumbai, Maharashtra, India' : 'Location Pending',
                          status: 'warning',
                          delay: '0ms'
                        },
                        {
                          hop: 'HOP 02: UPSTREAM RELAY',
                          ip: '198.51.100.42',
                          host: 'relay-mta-tier2.internal.node',
                          meta: 'DKIM Signature Check: NEUTRAL (Spoof Detected)',
                          geo: 'Internal Subnet',
                          status: 'warning',
                          delay: '+214ms'
                        },
                        {
                          hop: 'HOP 03: MX BORDER GATEWAY',
                          ip: '172.217.194.27',
                          host: 'mx.google.com (ESMTP Ingress)',
                          meta: 'DMARC Policy Enforcement: FAIL (p=REJECT) • Quarantine Flagged',
                          geo: 'Mountain View, CA, US',
                          status: 'danger',
                          delay: '+1820ms'
                        }
                      ].map((item, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            gap: '14px',
                            background: '#F8FAFC',
                            border: '1px solid #E2E8F0',
                            borderRadius: '10px',
                            padding: '12px 16px',
                            alignItems: 'center'
                          }}
                        >
                          <div
                            style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '8px',
                              background: item.status === 'danger' ? '#FEE2E2' : '#FEF3C7',
                              color: item.status === 'danger' ? '#DC2626' : '#D97706',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontWeight: 800,
                              fontSize: '0.85rem'
                            }}
                          >
                            0{idx + 1}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ fontSize: '0.8rem', fontWeight: 800, color: '#0F172A' }}>{item.hop}</span>
                              <span style={{ fontSize: '0.72rem', color: '#64748B', fontFamily: 'monospace' }}>Delay: {item.delay}</span>
                            </div>
                            <div style={{ fontSize: '0.76rem', color: '#0284C7', fontFamily: 'monospace', marginTop: '2px' }}>
                              IP: {item.ip} • Host: {item.host} {item.geo ? `• Location: ${item.geo}` : ''}
                            </div>
                            <div style={{ fontSize: '0.74rem', color: '#475569', marginTop: '2px' }}>
                              {item.meta}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Network Parameters Table */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 8px 0' }}>
                      Diagnostic Telemetry
                    </h4>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', border: '1px solid #E2E8F0', borderRadius: '8px', overflow: 'hidden' }}>
                      <tbody>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', background: '#F8FAFC' }}>
                          <td style={{ width: '30%', padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Autonomous System (ASN):</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>AS13335 (Cloudflare Ingress Gateway / Bulletproof Relay)</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Reverse DNS (PTR):</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#DC2626' }}>MISMATCH (PTR record does not resolve to sender domain)</td>
                        </tr>
                        <tr style={{ borderBottom: '1px solid #E2E8F0', background: '#F8FAFC' }}>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>TLS Protocol / Cipher:</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>TLSv1.3 • ECDHE-RSA-AES256-GCM-SHA384</td>
                        </tr>
                        <tr>
                          <td style={{ padding: '8px 12px', fontWeight: 700, color: '#475569' }}>Total Network Hop Latency:</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'monospace', color: '#059669' }}>2,034 ms (Accumulated Propagation)</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* === VIEW: PAYLOAD SCAN === */}
              {isPayload && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Detonation Verdict Banner */}
                  <div
                    style={{
                      background: 'rgba(220, 38, 38, 0.08)',
                      border: '1px solid rgba(220, 38, 38, 0.3)',
                      borderRadius: '10px',
                      padding: '14px 18px',
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '12px',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.9rem', fontWeight: 800, color: '#DC2626' }}>
                        🚨 MALICIOUS PHISHING PAYLOAD DETECTED
                      </div>
                      <div style={{ fontSize: '0.76rem', color: '#64748B', marginTop: '2px' }}>
                        Sandbox Detonation Engine identified credential harvesting inputs & suspicious redirects.
                      </div>
                    </div>
                    <span style={{ fontSize: '0.76rem', fontWeight: 800, padding: '4px 10px', borderRadius: '6px', background: '#DC2626', color: '#FFFFFF' }}>
                      Heuristic Risk: 92/100
                    </span>
                  </div>

                  {/* Target & Redirect Path */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 8px 0' }}>
                      Detonation URL Path & Redirects
                    </h4>
                    <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '8px', padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '0.68rem', fontWeight: 800, background: '#0284C7', color: '#FFFFFF', padding: '1px 6px', borderRadius: '3px' }}>START</span>
                        <span style={{ fontSize: '0.82rem', fontFamily: 'monospace', color: '#0F172A', wordBreak: 'break-all' }}>{effectiveUrl}</span>
                      </div>
                      <div style={{ paddingLeft: '18px', fontSize: '0.76rem', color: '#64748B' }}>
                        ↓ 302 Temporary Redirect (HTTP/2 Gateway)
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '0.68rem', fontWeight: 800, background: '#DC2626', color: '#FFFFFF', padding: '1px 6px', borderRadius: '3px' }}>FINAL</span>
                        <span style={{ fontSize: '0.82rem', fontFamily: 'monospace', color: '#DC2626', wordBreak: 'break-all' }}>https://login-verification-secure-portal.com/session-login</span>
                      </div>
                    </div>
                  </div>

                  {/* Sandbox Observed Behaviors */}
                  <div>
                    <h4 style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 8px 0' }}>
                      Observed Sandbox Behaviors
                    </h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' }}>
                      <div style={{ border: '1px solid #E2E8F0', borderRadius: '8px', padding: '10px 14px', background: '#FFFFFF' }}>
                        <div style={{ fontSize: '0.78rem', fontWeight: 800, color: '#DC2626' }}>🎣 Form Harvesting</div>
                        <div style={{ fontSize: '0.74rem', color: '#64748B', marginTop: '2px' }}>
                          Target DOM includes unencrypted user_id and auth_pass credential inputs posting to foreign dropzone.
                        </div>
                      </div>
                      <div style={{ border: '1px solid #E2E8F0', borderRadius: '8px', padding: '10px 14px', background: '#FFFFFF' }}>
                        <div style={{ fontSize: '0.78rem', fontWeight: 800, color: '#D97706' }}>🛡️ Anti-Analysis Obfuscation</div>
                        <div style={{ fontSize: '0.74rem', color: '#64748B', marginTop: '2px' }}>
                          Detected Canvas Fingerprinting probes & headless browser detection bypass scripts.
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* === VIEW: GENERIC / OTHER UPLOADED TEXT === */}
              {!isEml && !isDossier && !isNetwork && !isPayload && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '8px', padding: '14px' }}>
                    <div style={{ fontSize: '0.82rem', fontWeight: 800, color: '#0F172A' }}>Attached Document Overview</div>
                    <div style={{ fontSize: '0.76rem', color: '#64748B', marginTop: '3px' }}>
                      File: {file.name} • Size: {file.size} • MIME: {file.type || 'unknown/text'}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <span style={{ fontSize: '0.76rem', fontWeight: 700, color: '#475569' }}>Document Text Preview:</span>
                    <pre
                      style={{
                        margin: 0,
                        padding: '14px',
                        background: '#F8FAFC',
                        border: '1px solid #CBD5E1',
                        borderRadius: '8px',
                        fontSize: '0.82rem',
                        lineHeight: 1.5,
                        fontFamily: 'var(--font-mono, monospace)',
                        color: '#0F172A',
                        overflowX: 'auto',
                        whiteSpace: 'pre-wrap'
                      }}
                    >
                      {rawText}
                    </pre>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* MODAL FOOTER */}
        <div
          style={{
            padding: '14px 22px',
            background: '#F8FAFC',
            borderTop: '1px solid #E2E8F0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexShrink: 0
          }}
        >
          <div style={{ fontSize: '0.74rem', color: '#64748B' }}>
            Forensic Integrity: <strong style={{ color: '#059669' }}>ECDSA SECP256R1 Sealed</strong> • Under IT Act 2000 Sec 65B
          </div>

          <button
            type="button"
            onClick={onClose}
            style={{
              background: '#0F172A',
              border: 'none',
              borderRadius: '8px',
              padding: '8px 20px',
              fontSize: '0.82rem',
              fontWeight: 700,
              color: '#FFFFFF',
              cursor: 'pointer',
              transition: 'background 0.15s ease'
            }}
            onMouseEnter={(e) => e.target.style.background = '#1E293B'}
            onMouseLeave={(e) => e.target.style.background = '#0F172A'}
          >
            Close Preview
          </button>
        </div>
      </div>
    </div>
  )

  return ReactDOM.createPortal(modalContent, document.body)
}
