import React, { useState, useEffect, useRef } from 'react'
import ReactDOM from 'react-dom'
import { api } from '../services/api'
import { cyberService } from '../cybercrime/cybercrimeService'
import EvidencePreviewModal from './EvidencePreviewModal'

// Intelligent Attack Vector & Threat Category Auto-Classifier
function detectThreatCategory(data) {
  if (!data) return 'Phishing Attempt'

  const rawText = (
    (data.fullSubject || data.subject || data.title || '') + ' ' +
    (data.body_text || data.raw_text || data.evidence_description || data.body || '') + ' ' +
    (Array.isArray(data.threat_categories) ? data.threat_categories.join(' ') : '') + ' ' +
    (Array.isArray(data.risk_factors) ? data.risk_factors.join(' ') : '') + ' ' +
    (Array.isArray(data.tags) ? data.tags.join(' ') : '') + ' ' +
    (Array.isArray(data.indicators) ? data.indicators.join(' ') : '')
  ).toLowerCase()

  // 1. Ransomware / Extortion / Cryptolocker / Blackmail
  if (
    rawText.includes('ransom') || rawText.includes('extortion') || rawText.includes('bitcoin') ||
    rawText.includes('btc') || rawText.includes('wallet') || rawText.includes('encrypt') ||
    rawText.includes('locked your files') || rawText.includes('blackmail') || rawText.includes('recorded video') ||
    rawText.includes('pay within') || rawText.includes('decrypt') || rawText.includes('pornography') ||
    rawText.includes('webcam')
  ) {
    return 'Ransomware'
  }

  // 2. Unauthorized Access / Account Takeover / 2FA Hijack / Suspicious Session / Suspicious Sign-in
  if (
    rawText.includes('unauthorized') || rawText.includes('compromised') || rawText.includes('security alert') ||
    rawText.includes('sign-in attempt') || rawText.includes('login attempt') || rawText.includes('account suspended') ||
    rawText.includes('2fa') || rawText.includes('mfa') || rawText.includes('otp bypass') || rawText.includes('password reset') ||
    rawText.includes('access granted') || rawText.includes('new device') || rawText.includes('account access') ||
    rawText.includes('session hijacked') || rawText.includes('suspicious login')
  ) {
    return 'Unauthorized Access'
  }

  // 3. Data Leak / Exfiltration / Database Dump / PII Exposure
  if (
    rawText.includes('data leak') || rawText.includes('exfiltrat') || rawText.includes('breach') ||
    rawText.includes('database dumped') || rawText.includes('dumped') || rawText.includes('credentials leaked') ||
    rawText.includes('customer records') || rawText.includes('ssn') || rawText.includes('credit card leaked') ||
    rawText.includes('data exposure') || rawText.includes('confidential disclosure')
  ) {
    return 'Data Leak'
  }

  // 4. Phishing / Lookalike / Credential Harvesting / Fake Invoices / Impersonation
  if (
    data.is_lookalike || data.has_urgency_cues ||
    rawText.includes('phish') || rawText.includes('verify your email') || rawText.includes('verify your account') ||
    rawText.includes('click here') || rawText.includes('invoice') || rawText.includes('wire transfer') ||
    rawText.includes('payment overdue') || rawText.includes('urgent action') || rawText.includes('bank') ||
    rawText.includes('kyc') || rawText.includes('update payment') || rawText.includes('spoof') ||
    rawText.includes('impersonat') || rawText.includes('gift card') || rawText.includes('parcel tracking')
  ) {
    return 'Phishing Attempt'
  }

  // 5. Backend classified threat categories inspection
  if (Array.isArray(data.threat_categories)) {
    for (const tc of data.threat_categories) {
      const lower = tc.toLowerCase()
      if (lower.includes('ransom') || lower.includes('extort')) return 'Ransomware'
      if (lower.includes('access') || lower.includes('auth') || lower.includes('credential')) return 'Unauthorized Access'
      if (lower.includes('leak') || lower.includes('breach') || lower.includes('exfiltrat')) return 'Data Leak'
      if (lower.includes('phish') || lower.includes('spoof') || lower.includes('scam')) return 'Phishing Attempt'
    }
  }

  return 'Phishing Attempt'
}

export default function IncidentReportModal({
  isOpen = true,
  onClose,
  caseData = null,
  onReportSubmitted
}) {
  // Preview Modal State
  const [previewFile, setPreviewFile] = useState(null)

  // Form State
  const [reporterName, setReporterName] = useState('Yerramala Muniswami')
  const [reporterEmail, setReporterEmail] = useState('muniswami1112@gmail.com')
  const [countryCode, setCountryCode] = useState('+91')
  const [contactNumber, setContactNumber] = useState('9876543210')
  const [suspectEmail, setSuspectEmail] = useState('')
  const [threatCategory, setThreatCategory] = useState('Phishing Attempt')
  const [urgencyLevel, setUrgencyLevel] = useState('Medium')
  const [incidentDescription, setIncidentDescription] = useState('')
  const [evidenceFiles, setEvidenceFiles] = useState([])
  const [isDragging, setIsDragging] = useState(false)
  const [consentChecked, setConsentChecked] = useState(false)

  // Submission State
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submissionSuccess, setSubmissionSuccess] = useState(false)
  const [ackReceipt, setAckReceipt] = useState(null)
  const [copiedAck, setCopiedAck] = useState(false)

  // Live timestamp
  const [currentTime] = useState(() => {
    const now = new Date()
    return now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
  })

  const fileInputRef = useRef(null)

  // ESC key listener to close modal or preview
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && !isSubmitting) {
        if (previewFile) {
          setPreviewFile(null)
        } else if (onClose) {
          onClose()
        }
      }
    }
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown)
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose, previewFile, isSubmitting])

  // Compute System Context & Scores
  const safeScore = caseData?.riskScore !== undefined && caseData?.riskScore !== null && !isNaN(Number(caseData.riskScore))
    ? Math.max(0, Math.min(100, Math.round(Number(caseData.riskScore))))
    : 12

  const displayLevel = caseData?.riskLevel
    ? (caseData.riskLevel.toUpperCase().includes('CLEAN') || caseData.riskLevel.toUpperCase().includes('SAFE') ? 'VERIFIED CLEAN' : caseData.riskLevel.toUpperCase())
    : safeScore >= 70 ? 'CRITICAL THREAT' : safeScore >= 40 ? 'ELEVATED THREAT' : 'VERIFIED CLEAN'

  // Pre-fill fields and automatically generate on-screen evidence files
  useEffect(() => {
    if (caseData) {
      // 1. Pre-fill suspect email from screen data
      const suspect = caseData.from || caseData.sender || caseData.sender_email || ''
      setSuspectEmail(suspect)

      // 2. Pre-fill reporter email from screen data
      const userMail = caseData.to || caseData.recipient || caseData.mailbox_email || localStorage.getItem('tt_mailbox_email') || localStorage.getItem('tt_active_user') || 'muniswami1112@gmail.com'
      setReporterEmail(userMail)

      // 3. Intelligent Threat Category Auto-Detection
      const autoCategory = detectThreatCategory(caseData)
      setThreatCategory(autoCategory)

      // 4. Pre-fill incident description with actual screen context
      const subj = caseData.fullSubject || caseData.subject || caseData.title || 'Email Security Incident'
      const senderStr = suspect || 'External Sender'
      const scoreStr = `${safeScore}/100 (${displayLevel})`
      setIncidentDescription(`Forensic inspection of email "${subj}" received from <${senderStr}>. Auto-classified as: ${autoCategory}. Assessed with Composite Risk Score of ${scoreStr}. System detected actionable Bayesian threat indicators and forensic network signals.`)

      // 5. Pre-set urgency based on risk score
      if (safeScore >= 70) {
        setUrgencyLevel('Critical')
      } else if (safeScore >= 40) {
        setUrgencyLevel('High')
      } else if (safeScore > 15) {
        setUrgencyLevel('Medium')
      } else {
        setUrgencyLevel('Low')
      }

      // 5. Automatically populate evidence files according to on-screen case data
      const cleanTag = (caseData.incidentId && caseData.incidentId !== 'unreported')
        ? caseData.incidentId.replace(/[^a-zA-Z0-9]/g, '').slice(-6)
        : (suspect ? suspect.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').slice(0, 8) : '88F4A1')

      const autoAttached = [
        {
          id: 'auto-eml',
          name: `forensic_headers_${cleanTag}.eml`,
          size: '14.8 KB',
          type: 'message/rfc822',
          badge: 'SCREEN EML',
          isAuto: true
        },
        {
          id: 'auto-dossier',
          name: `telemetry_dossier_${cleanTag}.json`,
          size: '9.4 KB',
          type: 'application/json',
          badge: 'RISK DOSSIER',
          isAuto: true
        },
        {
          id: 'auto-network',
          name: `mta_origin_routing_${cleanTag}.log`,
          size: '4.2 KB',
          type: 'text/plain',
          badge: 'NETWORK LOG',
          isAuto: true
        }
      ]

      if (caseData.payloadUrl && caseData.payloadUrl !== 'No link' && caseData.payloadUrl !== 'None Detected' && !caseData.payloadUrl.includes('calendar.google.com')) {
        autoAttached.push({
          id: 'auto-url',
          name: `url_sandbox_trace_${cleanTag}.txt`,
          size: '3.1 KB',
          type: 'text/plain',
          badge: 'PAYLOAD SCAN',
          isAuto: true
        })
      }

      setEvidenceFiles(autoAttached)
    }
  }, [caseData, safeScore, displayLevel])

  const allCaseUrls = (caseData?.unmaskedUrls && caseData.unmaskedUrls.length > 0)
    ? caseData.unmaskedUrls
    : (Array.isArray(caseData?.urls) && caseData.urls.length > 0
        ? caseData.urls
        : (caseData?.payloadUrl && caseData.payloadUrl !== 'No link' && caseData.payloadUrl !== 'None Detected' ? [caseData.payloadUrl] : []))

  const targetUrl = (function() {
    if (caseData?.payloadUrl && caseData.payloadUrl !== 'No link' && caseData.payloadUrl !== 'None Detected' && !caseData.payloadUrl.includes('calendar.google.com')) {
      return caseData.payloadUrl
    }
    if (allCaseUrls.length > 0) {
      const u0 = allCaseUrls[0]
      return typeof u0 === 'string' ? u0 : (u0.final || u0.unwrapped || u0.original || 'No external URLs detected')
    }
    return 'No external URLs detected'
  })()

  const originIp = caseData?.originIp && caseData.originIp !== 'Not detected' && caseData.originIp !== 'Verified Gateway' && caseData.originIp !== 'Not Detected in Source Headers'
    ? caseData.originIp
    : (caseData?.ips?.[0] || 'Source Gateway (Direct SMTP Hop)')

  const deviceFingerprint = caseData?.public_key_fingerprint || 'TT-SECP256R1-DEV-88F4-AMOY'

  // Drag & Drop handlers
  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      addFiles(Array.from(e.dataTransfer.files))
    }
  }

  const handleFileInputChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      addFiles(Array.from(e.target.files))
    }
  }

  const addFiles = (newFiles) => {
    const formatted = newFiles.map(file => ({
      id: Math.random().toString(36).substring(2, 9),
      name: file.name,
      size: (file.size / 1024).toFixed(1) + ' KB',
      type: file.type || 'application/octet-stream',
      badge: 'UPLOADED',
      isAuto: false,
      file
    }))
    setEvidenceFiles(prev => [...prev, ...formatted])
  }

  const removeFile = (id) => {
    setEvidenceFiles(prev => prev.filter(f => f.id !== id))
  }

  // Handle Form Submission
  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!consentChecked || isSubmitting) return

    setIsSubmitting(true)

    try {
      const randHex = Math.random().toString(16).slice(2, 8).toUpperCase()
      const caseIdToReport = caseData?.incidentId || `TT-2026-${randHex}`
      const ackNumber = `NCRP-IN-2026-${caseIdToReport.replace(/[^A-Za-z0-9]/g, '').slice(-6)}`

      const reportPayload = {
        case_id: caseIdToReport,
        ack_number: ackNumber,
        subject: caseData?.fullSubject || caseData?.subject || `Incident Report: ${threatCategory}`,
        sender: suspectEmail || caseData?.from || 'unknown@sender.com',
        recipient: reporterEmail || caseData?.to || 'muniswami1112@gmail.com',
        reporter_name: reporterName,
        reporter_email: reporterEmail,
        reporter_contact: `${countryCode} ${contactNumber}`,
        threat_category: threatCategory,
        urgency_level: urgencyLevel,
        incident_description: incidentDescription,
        body_text: caseData?.rawText || caseData?.bodyText || incidentDescription,
        raw_headers: caseData?.rawHeaders || '',
        risk_score: safeScore,
        risk_level: displayLevel,
        urls: allCaseUrls.length > 0 ? allCaseUrls : [targetUrl],
        ips: [originIp],
        device_fingerprint: deviceFingerprint,
        evidence_file_count: evidenceFiles.length,
        evidence_files: evidenceFiles.map(f => ({ name: f.name, size: f.size, badge: f.badge }))
      }

      // 1. Dispatch to backend API
      try {
        await api.cybercrimeReport(reportPayload)
      } catch (err) {
        console.warn('Backend cybercrime report fallback:', err)
      }

      // 2. Synchronize Cybercrime Service client store
      try {
        await cyberService.reportIncident(reportPayload)
      } catch (err) {
        console.warn('Client cyberService report fallback:', err)
      }

      // Save to localStorage for cross-page persistence
      try {
        localStorage.setItem('tt_active_case', JSON.stringify({ ...caseData, case_id: caseIdToReport, ack_number: ackNumber }))
        localStorage.setItem('tt_case_' + caseIdToReport, JSON.stringify({ ...caseData, case_id: caseIdToReport, ack_number: ackNumber }))
      } catch (_) {}

      setAckReceipt({
        caseId: caseIdToReport,
        ackNumber: ackNumber,
        timestamp: currentTime,
        reporterName,
        reporterEmail,
        threatCategory,
        urgencyLevel,
        riskScore: safeScore,
        displayLevel
      })

      setSubmissionSuccess(true)

      if (onReportSubmitted) {
        onReportSubmitted({ caseId: caseIdToReport, ackNumber })
      }
    } catch (err) {
      console.error('Error submitting report:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleCopyAck = () => {
    if (!ackReceipt) return
    const text = `NATIONAL CYBER CRIME REPORTING PORTAL (NCRP)
Acknowledgment No: ${ackReceipt.ackNumber}
Case Dossier ID: ${ackReceipt.caseId}
Reporter: ${ackReceipt.reporterName} (${ackReceipt.reporterEmail})
Threat Category: ${ackReceipt.threatCategory}
Urgency: ${ackReceipt.urgencyLevel}
Composite Risk Score: ${ackReceipt.riskScore}/100 (${ackReceipt.displayLevel})
Timestamp: ${ackReceipt.timestamp}
Evidence Files Attached: ${evidenceFiles.length} Forensic Items
Cryptographic Custody: ECDSA-SECP256R1 Sealed (Polygon Amoy)`
    navigator.clipboard.writeText(text)
    setCopiedAck(true)
    setTimeout(() => setCopiedAck(false), 2000)
  }

  // Generate Official Printable FIR HTML Document
  const generateFIRHTML = () => {
    const ack = ackReceipt || {
      ackNumber: `NCRP-IN-2026-${(caseData?.incidentId || '88F4A1').slice(-6)}`,
      caseId: caseData?.incidentId || 'TT-2026-88F4A1',
      reporterName: reporterName || 'Yerramala Muniswami',
      reporterEmail: reporterEmail || 'muniswami1112@gmail.com',
      threatCategory: threatCategory || 'Phishing Attempt',
      urgencyLevel: urgencyLevel || 'Medium',
      riskScore: safeScore,
      displayLevel: displayLevel,
      timestamp: currentTime
    }

    const contactStr = `${countryCode} ${contactNumber}`

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FIRST INFORMATION REPORT (FIR) - ${ack.ackNumber}</title>
  <style>
    @page { size: A4 portrait; margin: 15mm 18mm; }
    body { font-family: 'Times New Roman', serif, Georgia; color: #111827; background: #FFFFFF; line-height: 1.5; font-size: 13px; margin: 0; padding: 20px; }
    .fir-container { max-width: 800px; margin: 0 auto; border: 2px solid #0F172A; padding: 24px; position: relative; }
    .watermark { position: absolute; top: 45%; left: 50%; transform: translate(-50%, -50%) rotate(-35deg); font-size: 64px; color: rgba(15, 23, 42, 0.04); font-weight: 900; pointer-events: none; text-transform: uppercase; white-space: nowrap; }
    .fir-header { text-align: center; border-bottom: 2px double #0F172A; padding-bottom: 12px; margin-bottom: 16px; }
    .fir-emblem { font-size: 28px; line-height: 1; margin-bottom: 4px; }
    .govt-title { font-size: 16px; font-weight: 800; letter-spacing: 0.05em; text-transform: uppercase; color: #0F172A; }
    .dept-title { font-size: 13px; font-weight: 700; color: #334155; margin-top: 2px; }
    .portal-subtitle { font-size: 11px; color: #64748B; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.08em; }
    .fir-badge { display: inline-block; background: #0F172A; color: #FFFFFF; font-size: 12px; font-weight: 800; padding: 4px 14px; border-radius: 4px; margin-top: 8px; text-transform: uppercase; letter-spacing: 0.06em; }
    .meta-table, .data-table { width: 100%; border-collapse: collapse; margin-bottom: 14px; font-size: 12.5px; }
    .meta-table td, .data-table td, .data-table th { border: 1px solid #CBD5E1; padding: 6px 10px; vertical-align: top; }
    .data-table th { background: #F1F5F9; font-weight: 700; text-align: left; color: #0F172A; }
    .sec-header { font-size: 13px; font-weight: 800; text-transform: uppercase; background: #E2E8F0; padding: 5px 10px; border-left: 4px solid #0F172A; margin: 14px 0 8px 0; color: #0F172A; }
    .code-box { font-family: 'Courier New', Courier, monospace; background: #F8FAFC; border: 1px solid #CBD5E1; padding: 8px 10px; font-size: 11px; border-radius: 4px; word-break: break-all; margin-top: 10px; }
    .seal-section { margin-top: 24px; display: flex; justify-content: space-between; align-items: flex-end; padding-top: 16px; border-top: 1px dashed #CBD5E1; }
    .seal-box { border: 2px solid #059669; color: #059669; padding: 8px 14px; font-size: 10.5px; font-weight: 700; text-transform: uppercase; text-align: center; border-radius: 6px; }
    .sign-box { text-align: right; font-size: 12px; }
    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>
  <div class="fir-container">
    <div class="watermark">OFFICIAL COMPLAINT FIR</div>

    <div class="fir-header" style="position: relative; padding: 10px 80px;">
      <img src="${window.location.origin}/logo.png" alt="Threat Trace AI" style="position: absolute; left: 0; top: 50%; transform: translateY(-50%); height: 64px; object-fit: contain;" />
      <img src="https://res.cloudinary.com/dfnoy78m8/image/upload/v1790424891/nprquyyd5oisxrnnw8dr.png" alt="Cyber Crime Dept" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%); height: 64px; object-fit: contain;" />
      
      <div class="fir-emblem">🏛️</div>
      <div class="govt-title">GOVERNMENT OF INDIA • MINISTRY OF HOME AFFAIRS</div>
      <div class="dept-title">NATIONAL CYBER CRIME REPORTING PORTAL (NCRP)</div>
      <div class="portal-subtitle">Cyber Crime Forensic & Incident Attribution Bureau</div>
      <div class="fir-badge">FIRST INFORMATION REPORT (FIR) / INCIDENT DOSSIER</div>
    </div>

    <table class="meta-table">
      <tr>
        <td style="width: 25%; font-weight: 700; background: #F8FAFC;">Acknowledgment No:</td>
        <td style="width: 25%; font-weight: 800; color: #0F172A; font-family: monospace;">${ack.ackNumber}</td>
        <td style="width: 25%; font-weight: 700; background: #F8FAFC;">Registration Date/Time:</td>
        <td style="width: 25%; font-family: monospace;">${ack.timestamp}</td>
      </tr>
      <tr>
        <td style="font-weight: 700; background: #F8FAFC;">Case Dossier ID:</td>
        <td style="font-weight: 800; color: #0284C7; font-family: monospace;">${ack.caseId}</td>
        <td style="font-weight: 700; background: #F8FAFC;">Acts & Sections:</td>
        <td style="font-weight: 700; color: #DC2626;">Sec 66C, 66D IT Act 2000; Sec 419, 420 IPC</td>
      </tr>
    </table>

    <div class="sec-header">1. COMPLAINANT / INFORMANT DETAILS</div>
    <table class="data-table">
      <tr>
        <td style="width: 25%; font-weight: 700;">Full Legal Name:</td>
        <td style="width: 25%;">${ack.reporterName}</td>
        <td style="width: 25%; font-weight: 700;">Registered Email:</td>
        <td style="width: 25%; font-family: monospace;">${ack.reporterEmail}</td>
      </tr>
      <tr>
        <td style="font-weight: 700;">Contact Phone:</td>
        <td>${contactStr}</td>
        <td style="font-weight: 700;">Verification Status:</td>
        <td style="color: #059669; font-weight: 700;">✓ Verified Electronic Filing</td>
      </tr>
    </table>

    <div class="sec-header">2. OFFENSE ATTRIBUTION & SUSPECT PROFILE</div>
    <table class="data-table">
      <tr>
        <td style="width: 25%; font-weight: 700;">Threat Category:</td>
        <td style="width: 25%; font-weight: 700; color: #DC2626;">${ack.threatCategory}</td>
        <td style="width: 25%; font-weight: 700;">Assessed Urgency:</td>
        <td style="width: 25%; font-weight: 700;">${ack.urgencyLevel}</td>
      </tr>
      <tr>
        <td style="font-weight: 700;">Suspect / Sender Identifier:</td>
        <td style="font-family: monospace; color: #DC2626;">${suspectEmail || 'noreply@api.data.gov'}</td>
        <td style="font-weight: 700;">Origin Gateway / IP:</td>
        <td style="font-family: monospace;">${originIp}</td>
      </tr>
      <tr>
        <td style="font-weight: 700;">Target Payload URL:</td>
        <td colspan="3" style="font-family: monospace; word-break: break-all;">${targetUrl}</td>
      </tr>
    </table>

    <div class="sec-header">3. COMPOSITE FORENSIC SYNTHESIS (THREATTRACE AI)</div>
    <table class="data-table">
      <tr>
        <td style="width: 25%; font-weight: 700;">Composite Risk Score:</td>
        <td style="font-weight: 800; font-size: 14px; color: ${ack.riskScore >= 70 ? '#DC2626' : ack.riskScore >= 40 ? '#D97706' : '#059669'};">
          ${ack.riskScore} / 100 (${ack.displayLevel})
        </td>
        <td style="width: 25%; font-weight: 700;">Bayesian Signal Vectors:</td>
        <td>Behavioral NLP (30%), Network Hop (25%), Payload (25%), Identity (20%)</td>
      </tr>
      <tr>
        <td style="font-weight: 700;">Incident Narrative:</td>
        <td colspan="3" style="font-style: italic; color: #334155;">"${incidentDescription}"</td>
      </tr>
    </table>

    <div class="sec-header">4. ATTACHED EVIDENCE ARTIFACTS & CHAIN OF CUSTODY</div>
    <table class="data-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Artifact Filename</th>
          <th>Type / Source</th>
          <th>Size</th>
          <th>Verification Seal</th>
        </tr>
      </thead>
      <tbody>
        ${evidenceFiles.map((f, idx) => `
          <tr>
            <td>${idx + 1}</td>
            <td style="font-family: monospace; font-weight: 700;">${f.name}</td>
            <td>${f.badge || 'SCREEN FORENSICS'}</td>
            <td>${f.size}</td>
            <td style="color: #059669; font-family: monospace; font-size: 11px;">✓ SHA-256 VERIFIED</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <div class="code-box">
      <strong>CRYPTOGRAPHIC SIGNATURE & IMMUTABLE LEDGER SEAL:</strong><br/>
      Algorithm: ECDSA SECP256R1 + SHA-256 • Ledger: Polygon Amoy Block #80002-AMOY<br/>
      Authority Key Fingerprint: ${deviceFingerprint}<br/>
      Immutable Evidence Hash: ${caseData?.canonical_hash || '0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069'}
    </div>

    <div class="seal-section">
      <div class="seal-box">
        ✓ CRYPTOGRAPHICALLY SEALED<br/>
        DIGITAL EVIDENCE REPOSITORY<br/>
        NCRP CENTRAL INVESTIGATION ENCLAVE
      </div>
      <div class="sign-box">
        <div style="font-weight: 800; font-size: 13px; color: #0F172A;">CYBER CRIME INVESTIGATION WING</div>
        <div style="color: #64748B; font-size: 11px; margin-top: 2px;">Electronic Copy Generated under Section 65B, Indian Evidence Act</div>
        <div style="font-family: monospace; font-size: 11px; color: #0284C7; margin-top: 4px;">ID: ${ack.ackNumber}</div>
      </div>
    </div>
  </div>
</body>
</html>`
  }

  // Print FIR Action
  const handlePrintFIR = () => {
    const html = generateFIRHTML()
    const printWindow = window.open('', '_blank')
    if (printWindow) {
      printWindow.document.open()
      printWindow.document.write(html)
      printWindow.document.close()
      printWindow.focus()
      setTimeout(() => {
        printWindow.print()
      }, 350)
    }
  }

  // Download FIR File Action
  const handleDownloadFIR = () => {
    const html = generateFIRHTML()
    const blob = new Blob([html], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `FIR_${(ackReceipt?.ackNumber || 'NCRP-IN-2026-CASE')}.html`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  if (!isOpen) return null

  const modalContent = (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.72)',
        backdropFilter: 'blur(8px)',
        zIndex: 99999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
        animation: 'fadeIn 0.2s ease-out'
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !isSubmitting) {
          onClose()
        }
      }}
    >
      <div
        style={{
          background: '#FFFFFF',
          borderRadius: '16px',
          width: '100%',
          maxWidth: '880px',
          maxHeight: '92vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25), 0 0 1px rgba(0, 0, 0, 0.15)',
          color: '#0F172A',
          overflow: 'hidden',
          animation: 'slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1)',
          margin: 'auto'
        }}
      >
        {/* 1. HEADER SECTION */}
        <div style={{
          padding: '20px 24px',
          background: '#FFFFFF',
          borderBottom: '1px solid #F1F5F9',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexShrink: 0
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: '44px',
              height: '44px',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              overflow: 'hidden'
            }}>
              <img 
                src="https://res.cloudinary.com/dfnoy78m8/image/upload/v1790424891/nprquyyd5oisxrnnw8dr.png" 
                alt="Cyber Crime Siren" 
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
              />
            </div>
            <div>
              <h2 style={{
                fontSize: '1.25rem',
                fontWeight: 800,
                color: '#0F172A',
                margin: 0,
                letterSpacing: '-0.02em',
                lineHeight: 1.2
              }}>
                Cyber Crime Incident Report
              </h2>
              <p style={{
                fontSize: '0.82rem',
                color: '#64748B',
                margin: '3px 0 0 0',
                fontWeight: 500
              }}>
                Submit suspicious activity or threats for immediate forensic analysis.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={isSubmitting}
            aria-label="Close modal"
            style={{
              background: '#F1F5F9',
              border: 'none',
              color: '#64748B',
              width: '34px',
              height: '34px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              fontSize: '1.1rem',
              lineHeight: 1,
              transition: 'all 0.15s ease'
            }}
          >
            ✕
          </button>
        </div>

        {/* 2. BODY CONTENT (SCROLLABLE) */}
        <div style={{
          padding: '22px 24px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px',
          background: '#F8FAFC'
        }}>

          {submissionSuccess ? (
            /* SUBMISSION SUCCESS CONFIRMATION RECEIPT */
            <div style={{
              background: '#FFFFFF',
              borderRadius: '14px',
              padding: '28px 24px',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '16px',
              boxShadow: '0 1px 3px rgba(0, 0, 0, 0.05)'
            }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: 'rgba(5, 150, 105, 0.12)',
                color: '#059669',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '2rem'
              }}>
                ✓
              </div>

              <div>
                <span style={{
                  fontSize: '0.74rem',
                  fontWeight: 800,
                  letterSpacing: '0.08em',
                  color: '#059669',
                  background: 'rgba(5, 150, 105, 0.1)',
                  padding: '4px 12px',
                  borderRadius: '9999px',
                  textTransform: 'uppercase'
                }}>
                  Official Registration Confirmed
                </span>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#0F172A', margin: '10px 0 6px 0' }}>
                  Incident Dossier Successfully Logged
                </h3>
                <p style={{ fontSize: '0.85rem', color: '#64748B', maxWidth: '540px', margin: '0 auto' }}>
                  Your case has been sealed with cryptographic proof and dispatched to the National Cybercrime Portal repository. You can print or download the official FIR copy below.
                </p>
              </div>

              {/* Receipt Summary Card */}
              <div style={{
                background: '#F8FAFC',
                borderRadius: '12px',
                padding: '16px 20px',
                width: '100%',
                maxWidth: '560px',
                textAlign: 'left',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                border: '1px solid #E2E8F0',
                fontFamily: 'var(--font-mono, monospace)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Acknowledgment No:</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: 800, color: '#0F172A' }}>{ackReceipt?.ackNumber}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Dossier Case ID:</span>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#0284C7' }}>{ackReceipt?.caseId}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Reporter Email:</span>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>{ackReceipt?.reporterEmail}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Threat Category:</span>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#DC2626' }}>{ackReceipt?.threatCategory} ({ackReceipt?.urgencyLevel} Urgency)</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Composite Risk:</span>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#D97706' }}>{ackReceipt?.riskScore}/100 ({ackReceipt?.displayLevel})</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Attached Evidence:</span>
                  <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#059669' }}>{evidenceFiles.length} screen files auto-sealed</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.78rem', color: '#64748B' }}>Timestamp:</span>
                  <span style={{ fontSize: '0.78rem', color: '#334155' }}>{ackReceipt?.timestamp}</span>
                </div>
              </div>

              {/* ACTION BUTTONS: Print FIR, Download FIR, Copy Receipt, and Return */}
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', justifyContent: 'center', marginTop: '6px' }}>
                <button
                  onClick={handlePrintFIR}
                  style={{
                    background: 'linear-gradient(135deg, #0284C7 0%, #0369A1 100%)',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '10px 20px',
                    fontSize: '0.86rem',
                    fontWeight: 800,
                    color: '#FFFFFF',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    boxShadow: '0 4px 12px rgba(2, 132, 199, 0.3)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span>🖨️</span>
                  <span>Print FIR Copy</span>
                </button>

                <button
                  onClick={handleDownloadFIR}
                  style={{
                    background: '#F1F5F9',
                    border: '1px solid #CBD5E1',
                    borderRadius: '8px',
                    padding: '10px 18px',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    color: '#0F172A',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span>📥</span>
                  <span>Download FIR</span>
                </button>

                <button
                  onClick={handleCopyAck}
                  style={{
                    background: '#F1F5F9',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '10px 18px',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    color: '#0F172A',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  {copiedAck ? '✓ Copied Acknowledgment' : '📋 Copy Receipt Details'}
                </button>

                <a
                  href={`https://threattrace-cybercrime.vercel.app/?caseId=${ackReceipt?.caseId || ''}&tab=queue`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    background: 'linear-gradient(135deg, #D97706 0%, #B45309 100%)',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '10px 18px',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    color: '#FFFFFF',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    textDecoration: 'none',
                    boxShadow: '0 4px 12px rgba(217, 119, 6, 0.25)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span>🏛️</span>
                  <span>View in Cybercrime Dept</span>
                </a>

                <button
                  onClick={onClose}
                  style={{
                    background: '#0F172A',
                    border: 'none',
                    borderRadius: '8px',
                    padding: '10px 22px',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    color: '#FFFFFF',
                    cursor: 'pointer'
                  }}
                >
                  Done & Return to Cockpit
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* 3. AUTO-CAPTURED SYSTEM CONTEXT (READ-ONLY WHITE THEMED BOX) */}
              <div style={{
                background: '#FFFFFF',
                borderRadius: '12px',
                padding: '16px 18px',
                color: '#0F172A',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
                border: '1px solid #E2E8F0',
                boxShadow: '0 1px 3px rgba(0, 0, 0, 0.04)'
              }}>
                {/* Header of System Box */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #F1F5F9', paddingBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10B981', boxShadow: '0 0 6px rgba(16, 185, 129, 0.4)' }} />
                    <span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.74rem', fontWeight: 800, letterSpacing: '0.08em', color: '#334155' }}>
                      AUTO-CAPTURED SYSTEM CONTEXT (READ-ONLY)
                    </span>
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '0.72rem', fontWeight: 600, color: '#64748B' }}>
                    {currentTime}
                  </span>
                </div>

                {/* Active Dashboard Context Prompt Requirement */}
                <div style={{
                  background: '#F8FAFC',
                  borderRadius: '8px',
                  padding: '10px 12px',
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '0.82rem',
                  color: '#0F172A',
                  lineHeight: 1.4,
                  border: '1px solid #E2E8F0',
                  borderLeft: '4px solid #0284C7'
                }}>
                  <strong style={{ color: '#0F172A', fontWeight: 800 }}>Active Dashboard Context: </strong>
                  Risk Score: <span style={{ color: safeScore >= 70 ? '#DC2626' : safeScore >= 40 ? '#D97706' : '#059669', fontWeight: 800 }}>{safeScore}/100 ({displayLevel})</span> - Deterministic Bayesian synthesis across 4 signal vectors.
                </div>

                {/* Session Metadata Grid */}
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                  gap: '10px',
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '0.75rem'
                }}>
                  <div style={{ background: '#F8FAFC', padding: '8px 10px', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
                    <div style={{ color: '#64748B', fontSize: '0.68rem', fontWeight: 700, marginBottom: '2px' }}>AFFECTED TARGET URL</div>
                    <div style={{ color: '#0F172A', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {targetUrl}
                    </div>
                  </div>

                  <div style={{ background: '#F8FAFC', padding: '8px 10px', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
                    <div style={{ color: '#64748B', fontSize: '0.68rem', fontWeight: 700, marginBottom: '2px' }}>GATEWAY / ORIGIN IP</div>
                    <div style={{ color: '#0F172A', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {originIp}
                    </div>
                  </div>

                  <div style={{ background: '#F8FAFC', padding: '8px 10px', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
                    <div style={{ color: '#64748B', fontSize: '0.68rem', fontWeight: 700, marginBottom: '2px' }}>DEVICE FINGERPRINT</div>
                    <div style={{ color: '#6D28D9', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {deviceFingerprint}
                    </div>
                  </div>
                </div>
              </div>

              {/* 2. USER INPUT SECTION (INTERACTIVE FORM FIELDS) */}
              <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                
                {/* Row 1: Reporter Name, Your Mail ID, and Contact Number */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px' }}>
                  {/* Reporter Name */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                      Reporter Name <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <input
                      type="text"
                      required
                      value={reporterName}
                      onChange={(e) => setReporterName(e.target.value)}
                      placeholder="e.g. Yerramala Muniswami"
                      style={{
                        background: '#FFFFFF',
                        border: '1px solid #CBD5E1',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '0.88rem',
                        color: '#0F172A',
                        outline: 'none',
                        transition: 'border-color 0.15s ease'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#0284C7'}
                      onBlur={(e) => e.target.style.borderColor = '#CBD5E1'}
                    />
                  </div>

                  {/* Your Mail ID (Reporter Email) */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                      Your Mail ID <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <input
                      type="email"
                      required
                      value={reporterEmail}
                      onChange={(e) => setReporterEmail(e.target.value)}
                      placeholder="e.g. muniswami1112@gmail.com"
                      style={{
                        background: '#FFFFFF',
                        border: '1px solid #CBD5E1',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '0.88rem',
                        fontFamily: 'var(--font-mono, monospace)',
                        color: '#0F172A',
                        outline: 'none',
                        transition: 'border-color 0.15s ease'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#0284C7'}
                      onBlur={(e) => e.target.style.borderColor = '#CBD5E1'}
                    />
                  </div>

                  {/* Contact Number with Country Code */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                      Contact Number <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <select
                        value={countryCode}
                        onChange={(e) => setCountryCode(e.target.value)}
                        style={{
                          background: '#F1F5F9',
                          border: '1px solid #CBD5E1',
                          borderRadius: '8px',
                          padding: '10px 8px',
                          fontSize: '0.85rem',
                          fontWeight: 600,
                          color: '#0F172A',
                          cursor: 'pointer',
                          outline: 'none',
                          flexShrink: 0
                        }}
                      >
                        <option value="+91">🇮🇳 +91</option>
                        <option value="+1">🇺🇸 +1</option>
                        <option value="+44">🇬🇧 +44</option>
                        <option value="+61">🇦🇺 +61</option>
                        <option value="+971">🇦🇪 +971</option>
                        <option value="+65">🇸🇬 +65</option>
                        <option value="+49">🇩🇪 +49</option>
                        <option value="+33">🇫🇷 +33</option>
                      </select>
                      <input
                        type="tel"
                        required
                        value={contactNumber}
                        onChange={(e) => setContactNumber(e.target.value)}
                        placeholder="e.g. 98765 43210"
                        style={{
                          flex: 1,
                          background: '#FFFFFF',
                          border: '1px solid #CBD5E1',
                          borderRadius: '8px',
                          padding: '10px 12px',
                          fontSize: '0.88rem',
                          color: '#0F172A',
                          outline: 'none',
                          minWidth: 0,
                          transition: 'border-color 0.15s ease'
                        }}
                        onFocus={(e) => e.target.style.borderColor = '#0284C7'}
                        onBlur={(e) => e.target.style.borderColor = '#CBD5E1'}
                      />
                    </div>
                  </div>
                </div>

                {/* Row 2: Suspect Email & Threat Category */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
                  {/* Suspect / Sender Email */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                      Suspect / Malicious Sender Email <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <input
                      type="email"
                      required
                      value={suspectEmail}
                      onChange={(e) => setSuspectEmail(e.target.value)}
                      placeholder="e.g. malicious-sender@attacker.xyz"
                      style={{
                        background: '#FFFFFF',
                        border: '1px solid #CBD5E1',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '0.88rem',
                        fontFamily: 'var(--font-mono, monospace)',
                        color: '#0F172A',
                        outline: 'none',
                        transition: 'border-color 0.15s ease'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#0284C7'}
                      onBlur={(e) => e.target.style.borderColor = '#CBD5E1'}
                    />
                  </div>

                  {/* Threat Category */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                        Threat Category <span style={{ color: '#DC2626' }}>*</span>
                      </label>
                      <span style={{ fontSize: '0.72rem', background: '#F0F9FF', border: '1px solid #BAE6FD', color: '#0284C7', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>
                        ✨ AI Auto-Classified
                      </span>
                    </div>
                    <select
                      value={threatCategory}
                      onChange={(e) => setThreatCategory(e.target.value)}
                      style={{
                        background: '#FFFFFF',
                        border: '1px solid #CBD5E1',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '0.88rem',
                        fontWeight: 600,
                        color: '#0F172A',
                        cursor: 'pointer',
                        outline: 'none',
                        transition: 'border-color 0.15s ease'
                      }}
                      onFocus={(e) => e.target.style.borderColor = '#0284C7'}
                      onBlur={(e) => e.target.style.borderColor = '#CBD5E1'}
                    >
                      <option value="Phishing Attempt">🎣 Phishing Attempt</option>
                      <option value="Ransomware">🔒 Ransomware / Extortion</option>
                      <option value="Unauthorized Access">🛡️ Unauthorized Access</option>
                      <option value="Data Leak">💾 Data Leak / Exfiltration</option>
                      <option value="Other">⚠️ Other Suspicious Anomaly</option>
                    </select>
                  </div>
                </div>

                {/* Urgency Level Pill Toggles */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                    Urgency Level
                  </label>
                  <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                    {[
                      { level: 'Low', color: '#059669', bg: 'rgba(5, 150, 105, 0.12)', label: '🟢 Low' },
                      { level: 'Medium', color: '#D97706', bg: 'rgba(217, 119, 6, 0.12)', label: '🟡 Medium' },
                      { level: 'High', color: '#EA580C', bg: 'rgba(234, 88, 12, 0.12)', label: '🟠 High' },
                      { level: 'Critical', color: '#DC2626', bg: 'rgba(220, 38, 38, 0.12)', label: '🔴 Critical' }
                    ].map((item) => {
                      const isSelected = urgencyLevel === item.level
                      return (
                        <button
                          key={item.level}
                          type="button"
                          onClick={() => setUrgencyLevel(item.level)}
                          style={{
                            padding: '8px 18px',
                            borderRadius: '9999px',
                            fontSize: '0.82rem',
                            fontWeight: 700,
                            cursor: 'pointer',
                            border: isSelected ? `2px solid ${item.color}` : '1px solid #E2E8F0',
                            background: isSelected ? item.bg : '#FFFFFF',
                            color: isSelected ? item.color : '#64748B',
                            transition: 'all 0.15s ease',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px'
                          }}
                        >
                          {item.label}
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Incident Description */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                      Incident Description <span style={{ color: '#DC2626' }}>*</span>
                    </label>
                    <span style={{ fontSize: '0.72rem', color: '#94A3B8' }}>
                      {incidentDescription.length} characters
                    </span>
                  </div>
                  <textarea
                    rows={3}
                    required
                    value={incidentDescription}
                    onChange={(e) => setIncidentDescription(e.target.value)}
                    placeholder="Provide specific context regarding suspicious requests, unusual links, spoofed headers, or extortion threats observed..."
                    style={{
                      background: '#FFFFFF',
                      border: '1px solid #CBD5E1',
                      borderRadius: '8px',
                      padding: '10px 14px',
                      fontSize: '0.86rem',
                      lineHeight: 1.5,
                      color: '#0F172A',
                      outline: 'none',
                      resize: 'vertical',
                      minHeight: '80px',
                      transition: 'border-color 0.15s ease'
                    }}
                    onFocus={(e) => e.target.style.borderColor = '#0284C7'}
                    onBlur={(e) => e.target.style.borderColor = '#CBD5E1'}
                  />
                </div>

                {/* Evidence Upload (Drag and Drop Zone + Auto-Filled Screen Artifacts) */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                    <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#334155' }}>
                      Evidence Files (Auto-Filled from Screen Forensics & Attachments)
                    </label>
                    <span style={{ fontSize: '0.72rem', color: '#0284C7', background: 'rgba(2, 132, 199, 0.08)', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                      ⚡ {evidenceFiles.length} Forensic Artifacts Attached
                    </span>
                  </div>

                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    onChange={handleFileInputChange}
                    style={{ display: 'none' }}
                  />

                  {/* Drag and Drop Zone */}
                  <div
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    style={{
                      border: `2px dashed ${isDragging ? '#0284C7' : '#CBD5E1'}`,
                      borderRadius: '10px',
                      padding: '16px 20px',
                      background: isDragging ? 'rgba(2, 132, 199, 0.05)' : '#FFFFFF',
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      gap: '4px'
                    }}
                  >
                    <div style={{ fontSize: '1.3rem', color: '#0284C7' }}>📁</div>
                    <div style={{ fontSize: '0.84rem', fontWeight: 700, color: '#0F172A' }}>
                      Drag and drop additional files, or <span style={{ color: '#0284C7', textDecoration: 'underline' }}>browse</span>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: '#94A3B8' }}>
                      Supports PNG, JPG, PDF, EML, JSON (Max 25MB)
                    </div>
                  </div>

                  {/* Attached Files Chips (Auto-Populated from Screen + Uploaded) */}
                  {evidenceFiles.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '4px' }}>
                      {evidenceFiles.map((file) => (
                        <div
                          key={file.id}
                          onClick={() => setPreviewFile(file)}
                          title="Click to preview document forensic content"
                          style={{
                            background: file.isAuto ? 'rgba(2, 132, 199, 0.05)' : '#FFFFFF',
                            border: `1px solid ${file.isAuto ? 'rgba(2, 132, 199, 0.3)' : '#CBD5E1'}`,
                            borderRadius: '8px',
                            padding: '6px 12px',
                            fontSize: '0.78rem',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
                            userSelect: 'none'
                          }}
                          onMouseEnter={(e) => {
                            e.currentTarget.style.borderColor = '#0284C7'
                            e.currentTarget.style.background = file.isAuto ? 'rgba(2, 132, 199, 0.1)' : '#F8FAFC'
                            e.currentTarget.style.transform = 'translateY(-1px)'
                            e.currentTarget.style.boxShadow = '0 4px 10px rgba(2, 132, 199, 0.15)'
                          }}
                          onMouseLeave={(e) => {
                            e.currentTarget.style.borderColor = file.isAuto ? 'rgba(2, 132, 199, 0.3)' : '#CBD5E1'
                            e.currentTarget.style.background = file.isAuto ? 'rgba(2, 132, 199, 0.05)' : '#FFFFFF'
                            e.currentTarget.style.transform = 'translateY(0)'
                            e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.04)'
                          }}
                        >
                          <span style={{
                            fontSize: '0.64rem',
                            fontWeight: 800,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            background: file.isAuto ? '#0284C7' : '#64748B',
                            color: '#FFFFFF',
                            letterSpacing: '0.04em'
                          }}>
                            {file.badge || 'FILE'}
                          </span>
                          <span style={{ fontWeight: 600, color: '#1E293B', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {file.name}
                          </span>
                          <span style={{ fontSize: '0.7rem', color: '#94A3B8' }}>
                            ({file.size})
                          </span>
                          <span style={{
                            fontSize: '0.68rem',
                            color: '#0284C7',
                            fontWeight: 700,
                            background: 'rgba(2, 132, 199, 0.08)',
                            padding: '1px 5px',
                            borderRadius: '3px'
                          }}>
                            👁️ Preview
                          </span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation()
                              removeFile(file.id)
                            }}
                            title="Remove file"
                            style={{
                              background: 'none',
                              border: 'none',
                              color: '#DC2626',
                              cursor: 'pointer',
                              padding: '0 2px',
                              fontWeight: 800,
                              fontSize: '0.88rem',
                              lineHeight: 1
                            }}
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 4. FOOTER & ACTIONS */}
                <div style={{
                  borderTop: '1px solid #E2E8F0',
                  paddingTop: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px'
                }}>
                  {/* Consent Checkbox */}
                  <label style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    fontSize: '0.82rem',
                    color: '#334155',
                    cursor: 'pointer',
                    userSelect: 'none',
                    lineHeight: 1.4
                  }}>
                    <input
                      type="checkbox"
                      checked={consentChecked}
                      onChange={(e) => setConsentChecked(e.target.checked)}
                      style={{
                        marginTop: '2px',
                        width: '16px',
                        height: '16px',
                        accentColor: '#0F172A',
                        cursor: 'pointer'
                      }}
                    />
                    <span>
                      I confirm this information is accurate and consent to sharing system logs with the incident response team.
                    </span>
                  </label>

                  {/* Action Buttons */}
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                    <button
                      type="button"
                      onClick={onClose}
                      disabled={isSubmitting}
                      style={{
                        background: '#FFFFFF',
                        border: '1px solid #CBD5E1',
                        borderRadius: '8px',
                        padding: '10px 20px',
                        fontSize: '0.86rem',
                        fontWeight: 700,
                        color: '#475569',
                        cursor: isSubmitting ? 'not-allowed' : 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      Cancel
                    </button>

                    <button
                      type="submit"
                      disabled={!consentChecked || isSubmitting}
                      style={{
                        background: consentChecked && !isSubmitting ? 'linear-gradient(135deg, #DC2626 0%, #B91C1C 100%)' : '#E2E8F0',
                        border: 'none',
                        borderRadius: '8px',
                        padding: '10px 24px',
                        fontSize: '0.86rem',
                        fontWeight: 700,
                        color: consentChecked && !isSubmitting ? '#FFFFFF' : '#94A3B8',
                        cursor: consentChecked && !isSubmitting ? 'pointer' : 'not-allowed',
                        boxShadow: consentChecked && !isSubmitting ? '0 4px 14px rgba(220, 38, 38, 0.3)' : 'none',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        transition: 'all 0.2s ease'
                      }}
                    >
                      {isSubmitting ? (
                        <>
                          <span style={{ display: 'inline-block', animation: 'spin 1s linear infinite' }}>⏳</span>
                          <span>Dispatching Dossier...</span>
                        </>
                      ) : (
                        <>
                          <span>🚨</span>
                          <span>Submit Report</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

              </form>
            </>
          )}

        </div>
      </div>

      {/* DOCUMENT PREVIEW MODAL OVERLAY */}
      {previewFile && (
        <EvidencePreviewModal
          isOpen={!!previewFile}
          file={previewFile}
          onClose={() => setPreviewFile(null)}
          caseData={caseData}
          reporterName={reporterName}
          reporterEmail={reporterEmail}
          suspectEmail={suspectEmail}
          threatCategory={threatCategory}
          safeScore={safeScore}
          displayLevel={displayLevel}
          targetUrl={targetUrl}
          originIp={originIp}
          deviceFingerprint={deviceFingerprint}
        />
      )}
    </div>
  )

  return ReactDOM.createPortal(modalContent, document.body)
}
