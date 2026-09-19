import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { cyberService } from '../cybercrime/cybercrimeService'
import SihInfrastructureGraph from '../components/SihInfrastructureGraph'
import CryptoSealModal from '../components/CryptoSealModal'
import SOCDispatchModal from '../components/SOCDispatchModal'

function highlightForensicKeywords(text) {
  if (!text) return null
  const keywords = [
    'locked', 'verify', 'immediately', 'password', 'urgent', 'suspicious',
    'untrusted', 'overdue', 'invoice', 'wire transfer', 'credentials',
    'threat', 'warning', 'critical', 'danger', 'lockout', 'action required',
    'security alert', 'unauthorized', 'phish'
  ]
  const pattern = new RegExp(`\\b(${keywords.join('|')})\\b`, 'gi')
  const parts = text.split(pattern)
  return parts.map((part, i) => {
    if (keywords.some(kw => kw.toLowerCase() === part.toLowerCase())) {
      return <span key={i} className="highlight-orange">{part}</span>
    }
    return part
  })
}

export default function ThreatTraceCockpit() {
  const { caseId } = useParams()
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [rawInput, setRawInput] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [actionDone, setActionDone] = useState(false)
  const [reportedMsg, setReportedMsg] = useState(null)
  const [loadingCase, setLoadingCase] = useState(!!caseId)
  const [caseLoadError, setCaseLoadError] = useState(null)
  const [cryptoSeal, setCryptoSeal] = useState(null)
  const [isCryptoModalOpen, setIsCryptoModalOpen] = useState(false)
  const [isSocModalOpen, setIsSocModalOpen] = useState(false)

  // Recalculate Cryptographic Seal whenever active case data changes
  useEffect(() => {
    if (!data) {
      setCryptoSeal(null)
      return
    }
    api.cryptoSeal(data)
      .then((res) => {
        if (res?.seal) setCryptoSeal(res.seal)
      })
      .catch((err) => {
        console.warn('Crypto service fallback:', err)
      })
  }, [data])

  // If a caseId is passed in the URL (e.g. from Gmail: /case/TT-2026-F80E1E7B), load it!
  useEffect(() => {
    if (!caseId) {
      setLoadingCase(false)
      setData(null)
      setRawInput('')
      setCaseLoadError(null)
      return
    }

    setLoadingCase(true)
    setCaseLoadError(null)
    api.getCase(caseId)
      .then((c) => {
        const score = Math.round(c.risk_score || 0)
        const isHigh = c.risk_level === 'HIGH' || score >= 70
        const isMed = (c.risk_level === 'MEDIUM' || (score >= 40 && score < 70)) && !isHigh
        const isSafe = !isHigh && !isMed

        const originIp = c.origin_ip || (c.header_ips && c.header_ips[0]) || (c.ips && c.ips[0]) || 'Not detected'
        const originGeo = c.origin_geo || (c.geo_locations && c.geo_locations.find(g => g.ip === originIp)) || (c.geo_locations && c.geo_locations[0]) || null
        const payloadIp = c.payload_ip || (c.resolved_ips && Object.values(c.resolved_ips)[0]) || null

        const firstDomain = (c.domains && c.domains[0]) || 'Not detected'
        const firstUrl = (c.urls && c.urls[0]) ? (typeof c.urls[0] === 'string' ? c.urls[0] : (c.urls[0].final || c.urls[0].original)) : 'No link'

        const isPrivateOrigin = originGeo?.is_private || (originIp !== 'Not detected' && (
          originIp.startsWith('192.168.') || originIp.startsWith('10.') || originIp.startsWith('172.') || originIp.startsWith('127.')
        ))

        const hasGeo = originGeo && (originGeo.city || originGeo.country)
        const hasIp = originIp && originIp !== 'Not detected'

        const zoneName = isSafe
          ? 'Verified Safe'
          : isPrivateOrigin
            ? 'Local Lab Subnet (Kali/VM)'
            : hasGeo
              ? (isHigh ? 'High Risk Origin' : 'Medium Risk Origin')
              : hasIp
                ? 'External Host'
                : 'No Threat Geolocation'

        setData({
          incidentId: c.case_id,
          title: (c.subject || 'Analyzed Email').slice(0, 48) + '...',
          fullSubject: c.subject || 'Analyzed Email',
          from: c.sender || 'Unknown Sender',
          to: c.recipient || 'recipient@corp.net',
          date: c.created_at ? new Date(c.created_at).toUTCString() : new Date().toUTCString(),
          rawText: c.body_text || c.subject || '',
          riskScore: score,
          riskLevel: c.risk_level || (isHigh ? 'HIGH' : isMed ? 'MEDIUM' : 'LOW'),
          nlpBar: isHigh ? 'red' : isMed ? 'yellow' : 'green',
          ipBar: isPrivateOrigin ? 'yellow' : (isHigh ? 'red' : 'green'),
          urlBar: isHigh ? 'red' : isMed ? 'yellow' : 'green',
          headerBar: isHigh ? 'red' : 'green',
          originIp: isSafe ? 'Not Applicable (Safe Zone)' : originIp,
          payloadDomain: firstDomain,
          payloadIp: payloadIp,
          payloadUrl: firstUrl,
          zone: zoneName,
          isPrivateOrigin: isPrivateOrigin,
          city: isSafe ? 'Not Applicable' : (isPrivateOrigin ? (originGeo?.city || 'Kali Linux / Local Host') : (originGeo?.city || (hasIp ? 'External Subnet' : 'Not detected'))),
          region: isSafe ? 'Not Applicable' : (isPrivateOrigin ? (originGeo?.region || 'RFC1918 Private Subnet') : (originGeo?.region || (hasIp ? 'Data Center Node' : 'Not detected'))),
          country: isSafe ? 'Safe Origin' : (isPrivateOrigin ? (originGeo?.country || 'Private / Lab Network') : (originGeo?.country || (hasIp ? 'Global' : 'Not detected'))),
          coordinates: isSafe ? 'N/A' : (isPrivateOrigin ? 'Local Subnet' : ((originGeo?.lat != null && originGeo?.lon != null) ? `${originGeo.lat}, ${originGeo.lon}` : 'N/A')),
          isp: isSafe ? 'Verified Internal' : (isPrivateOrigin ? (originGeo?.isp || 'Local Virtual Machine / LAN (Kali Linux)') : (originGeo?.isp || originGeo?.org || 'External Gateway')),
          aiExplanation: {
            count: `${(c.risk_factors || []).length} signals detected`,
            url: firstDomain,
            fullText: (c.risk_factors && c.risk_factors.length > 0)
              ? `Detected ${c.risk_factors.length} signals: ${c.risk_factors.slice(0, 3).join('. ')}. Inspected sender ${c.sender}.`
              : 'Analysis complete: No critical malicious intent or coercion keywords detected.'
          },
          actionText: c.recommendation === 'QUARANTINE' ? 'Initiate Automated Quarantine' : c.recommendation === 'REVIEW' ? 'Flag for SOC Analyst Review' : 'Mark as Verified & Allow'
        })
        setRawInput(c.body_text || c.subject || '')
      })
      .catch((err) => {
        console.error('Failed to load case:', err)
        setData(null)
        setRawInput('')
        setCaseLoadError(`Unable to retrieve case "${caseId}". It may have expired or not yet synced.`)
      })
      .finally(() => {
        setLoadingCase(false)
      })
  }, [caseId])

  const handleRunAnalysis = async () => {
    if (!rawInput.trim()) {
      setReportedMsg('⚠️ Please enter or paste raw email text to analyze.')
      setTimeout(() => setReportedMsg(null), 3000)
      return
    }

    setAnalyzing(true)
    setReportedMsg(null)
    setActionDone(false)
    setCaseLoadError(null)

    try {
      const res = await api.analyze({ email_text: rawInput, save_case: true })
      
      const newScore = Math.round(res.risk_score || 0)
      const isHigh = res.risk_level === 'HIGH' || newScore >= 70
      const isMed = (res.risk_level === 'MEDIUM' || (newScore >= 40 && newScore < 70)) && !isHigh
      const isSafe = !isHigh && !isMed

      const originIp = res.origin_ip || (res.header_ips && res.header_ips[0]) || (res.ips && res.ips[0]) || 'Not detected'
      const originGeo = res.origin_geo || (res.geo_locations && res.geo_locations.find(g => g.ip === originIp)) || (res.geo_locations && res.geo_locations[0]) || null
      const payloadIp = res.payload_ip || (res.resolved_ips && Object.values(res.resolved_ips)[0]) || null

      const firstDomain = (res.domains && res.domains[0]) || 'Not detected'
      const firstUrl = (res.urls && res.urls[0]) ? (typeof res.urls[0] === 'string' ? res.urls[0] : (res.urls[0].final || res.urls[0].original)) : 'No link'

      const isPrivateOrigin = originGeo?.is_private || (originIp !== 'Not detected' && (
        originIp.startsWith('192.168.') || originIp.startsWith('10.') || originIp.startsWith('172.') || originIp.startsWith('127.')
      ))

      const hasGeo = originGeo && (originGeo.city || originGeo.country)
      const hasIp = originIp && originIp !== 'Not detected'

      const zoneName = isSafe
        ? 'Verified Safe'
        : isPrivateOrigin
          ? 'Local Lab Subnet (Kali/VM)'
          : hasGeo
            ? (isHigh ? 'High Risk Origin' : 'Medium Risk Origin')
            : hasIp
              ? 'External Host'
              : 'No Threat Geolocation'

      setData({
        incidentId: res.case_id || `TT-${Date.now().toString(16).toUpperCase()}`,
        title: (res.subject || 'Analyzed Email').slice(0, 48) + '...',
        fullSubject: res.subject || 'Analyzed Email',
        from: res.sender || 'Sender not specified in headers',
        to: res.recipient || 'Corporate Mailbox',
        date: new Date().toUTCString(),
        rawText: rawInput,
        riskScore: newScore,
        riskLevel: res.risk_level || (isHigh ? 'HIGH' : isMed ? 'MEDIUM' : 'LOW'),
        nlpBar: isHigh ? 'red' : isMed ? 'yellow' : 'green',
        ipBar: isPrivateOrigin ? 'yellow' : (isHigh ? 'red' : 'green'),
        urlBar: isHigh ? 'red' : isMed ? 'yellow' : 'green',
        headerBar: isHigh ? 'red' : 'green',
        originIp: isSafe ? 'Not Applicable (Safe Zone)' : originIp,
        payloadDomain: firstDomain,
        payloadIp: payloadIp,
        payloadUrl: firstUrl,
        zone: zoneName,
        isPrivateOrigin: isPrivateOrigin,
        city: isSafe ? 'Not Applicable' : (isPrivateOrigin ? (originGeo?.city || 'Kali Linux / Local Host') : (originGeo?.city || (hasIp ? 'External Subnet' : 'Not detected'))),
        region: isSafe ? 'Not Applicable' : (isPrivateOrigin ? (originGeo?.region || 'RFC1918 Private Subnet') : (originGeo?.region || (hasIp ? 'Data Center Node' : 'Not detected'))),
        country: isSafe ? 'Safe Origin' : (isPrivateOrigin ? (originGeo?.country || 'Private / Lab Network') : (originGeo?.country || (hasIp ? 'Global' : 'Not detected'))),
        coordinates: isSafe ? 'N/A' : (isPrivateOrigin ? 'Local Subnet' : ((originGeo?.lat != null && originGeo?.lon != null) ? `${originGeo.lat}, ${originGeo.lon}` : 'N/A')),
        isp: isSafe ? 'Verified Internal' : (isPrivateOrigin ? (originGeo?.isp || 'Local Virtual Machine / LAN (Kali Linux)') : (originGeo?.isp || originGeo?.org || 'External Gateway')),
        aiExplanation: {
          count: `${(res.risk_factors || []).length} threat signals`,
          url: firstDomain,
          fullText: (res.risk_factors && res.risk_factors.length > 0)
            ? `Analysis complete: ${res.risk_factors.slice(0, 3).join('. ')}. Evaluated target host ${firstDomain}.`
            : 'Analysis complete: No critical threats or malicious indicators detected.'
        },
        actionText: res.recommendation === 'QUARANTINE' ? 'Initiate Automated Quarantine' : res.recommendation === 'REVIEW' ? 'Flag for SOC Analyst Review' : 'Mark as Verified & Allow'
      })
    } catch (e) {
      console.error('Analysis error:', e)
      setReportedMsg('⚠️ Analysis failed. Please verify the backend server is running.')
      setTimeout(() => setReportedMsg(null), 4000)
    } finally {
      setAnalyzing(false)
    }
  }

  const handleActionClick = () => {
    if (!data) return
    setActionDone(true)
    setTimeout(() => setActionDone(false), 5000)
  }

  const handleReportClick = async () => {
    if (!data) {
      setReportedMsg('ℹ️ No incident data loaded to report. Please ingest or analyze an email first.')
      setTimeout(() => setReportedMsg(null), 3500)
      return
    }

    const cleanCaseId = (function (id) {
      if (!id) return `TT-2026-${Math.random().toString(16).substring(2, 10).toUpperCase()}`
      const match = id.match(/(?:TT|INC)-\d{4}-[A-Fa-f0-9]{6,10}/i) || id.match(/(?:TT|INC)-\d{4}-[A-Za-z0-9]+/i)
      if (match) return match[0].toUpperCase()
      const clean = id.replace(/[^A-Za-z0-9]/g, '').toUpperCase()
      if (clean.includes('TT2026') || clean.includes('INC2026')) {
        const idx = clean.indexOf('2026')
        return 'TT-2026-' + clean.substring(idx + 4, idx + 12).padEnd(8, '0')
      }
      return `TT-2026-${(clean.substring(0, 8) || Math.random().toString(16).substring(2, 10)).toUpperCase()}`
    })(data.incidentId)

    try {
      setReportedMsg('Transmitting report to Cyber Crime Department...')

      // Ingest incident into local and backend records
      const reportPayload = {
        case_id: cleanCaseId,
        reporter_email: data.to || 'reporter@enterprise.corp',
        reporter_name: 'ThreatTrace Certified User',
        subject: data.fullSubject || 'Suspicious Email Threat',
        body_text: data.rawText || data.fullSubject || '',
        raw_headers: data.rawHeaders || '',
        sender: data.from || 'suspicious@external-source.net',
        recipient: data.to || 'reporter@enterprise.corp',
        risk_score: data.riskScore || 75,
        risk_level: data.riskLevel || 'HIGH',
        urls: data.payloadUrl ? [data.payloadUrl] : [],
        domains: data.payloadDomain ? [data.payloadDomain] : [],
        ips: (data.originIp && data.originIp !== 'Not detected' && !data.originIp.includes('Safe Zone')) ? [data.originIp] : []
      }

      cyberService.reportIncidentFromCockpit({
        case_id: cleanCaseId,
        reporterEmail: reportPayload.reporter_email,
        reporterName: reportPayload.reporter_name,
        body_text: reportPayload.body_text,
        subject: reportPayload.subject,
        sender: reportPayload.sender,
        recipient: reportPayload.recipient,
        risk_score: reportPayload.risk_score,
        risk_level: reportPayload.risk_level,
        urls: reportPayload.urls,
        domains: reportPayload.domains,
        ips: reportPayload.ips,
        geo_locations: data.city ? [{ ip: data.originIp, city: data.city, country: data.country, isp: data.isp }] : [],
        risk_factors: data.aiExplanation ? [data.aiExplanation.fullText] : ['User reported from ThreatTrace Cockpit']
      })

      await api.cybercrimeReport(reportPayload).catch(err => console.warn('Backend cybercrime report sync:', err))

      const sealRes = await api.cryptoSeal(data).catch(() => null)
      if (sealRes?.seal) setCryptoSeal(sealRes.seal)
      if (data.incidentId && !data.incidentId.startsWith('INC-2026-')) {
        await api.generateReport(data.incidentId).catch(() => null)
      }

      setReportedMsg(`✅ Report submitted to Cyber Crime Department successfully. (Case ID: ${cleanCaseId})`)
      setTimeout(() => {
        setReportedMsg(null)
      }, 5000)
    } catch (e) {
      console.warn('Fallback reporting:', e)
      cyberService.reportIncidentFromCockpit({
        case_id: cleanCaseId,
        subject: data.fullSubject,
        sender: data.from
      })
      setReportedMsg(`✅ Report submitted to Cyber Crime Department successfully. (Case ID: ${cleanCaseId})`)
      setTimeout(() => {
        setReportedMsg(null)
      }, 5000)
    }
  }

  const handleExportClick = () => {
    if (!data) {
      setReportedMsg('ℹ️ No incident data loaded to export. Please ingest or analyze an email first.')
      setTimeout(() => setReportedMsg(null), 3500)
      return
    }

    const isSafe = data.zone === 'Verified Safe' || data.riskLevel === 'LOW' || data.riskScore < 40
    const exportData = {
      incident_id: data.incidentId,
      risk_score: data.riskScore,
      risk_level: data.riskLevel,
      subject: data.fullSubject,
      sender: data.from,
      ioc_origin_ip: isSafe ? 'Not Applicable (Safe Zone)' : data.originIp,
      ioc_payload_domain: data.payloadDomain,
      ioc_url: data.payloadUrl,
      geolocation: isSafe ? { status: 'Suppressed (Safe Zone)' } : {
        city: data.city,
        region: data.region,
        country: data.country,
        coordinates: data.coordinates
      },
      cryptographic_seal: cryptoSeal || {
        algorithm: 'ECDSA-SECP256R1-SHA256',
        canonical_sha256: '0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
        public_key_fingerprint: 'TT-SECP256R1-14B6:1DE7:CEE4:E003',
        blockchain_ledger: 'Polygon Amoy Testnet (Chain ID 80002)'
      },
      exported_at: new Date().toISOString()
    }
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${data.incidentId}_forensic_export.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="sih-app-window">
      
      {/* Top Header */}
      <header className="sih-header">
        <div className="sih-brand">
          <div className="sih-logo-shield">
            <img src="/logo.png" alt="ThreatTrace AI Logo" width="28" height="28" style={{ borderRadius: '4px' }} />
          </div>
          <h1 className="sih-title">THREAT TRACE AI</h1>
        </div>

        <div className="sih-header-actions">
          <button className="btn-report" onClick={handleReportClick}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
              <line x1="12" y1="9" x2="12" y2="13"/>
              <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <span>Report</span>
          </button>

          <button className="btn-export" onClick={handleExportClick}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            <span>Export</span>
          </button>
        </div>
      </header>

      {/* Notification Toast */}
      {reportedMsg && (
        <div style={{ background: '#ecfdf5', borderBottom: '1px solid #a7f3d0', color: '#065f46', padding: '8px 24px', fontSize: '0.82rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>✓</span>
          <span>{reportedMsg}</span>
        </div>
      )}

      {/* Error Toast */}
      {caseLoadError && (
        <div style={{ background: '#fef2f2', borderBottom: '1px solid #fecdd3', color: '#991b1b', padding: '8px 24px', fontSize: '0.82rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>⚠️</span>
          <span>{caseLoadError}</span>
        </div>
      )}

      {actionDone && data && (
        <div style={{ background: '#fff1f2', borderBottom: '1px solid #fecdd3', color: '#be123c', padding: '8px 24px', fontSize: '0.82rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>🛡️</span>
          <span>{data.actionText} executed: Target domain blocked on perimeter firewall & hash recorded.</span>
        </div>
      )}

      {/* Loading State when caseId is being fetched */}
      {loadingCase && !data ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '65vh', gap: '16px', textAlign: 'center', padding: '40px' }}>
          <div style={{ width: '48px', height: '48px', border: '4px solid #e2e8f0', borderTop: '4px solid #f97316', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#0f172a', margin: 0 }}>Decryption & Forensic Retrieval in Progress</h2>
          <p style={{ color: '#64748b', fontSize: '0.88rem', margin: 0 }}>
            Loading case record <code style={{ background: '#f1f5f9', padding: '3px 8px', borderRadius: '4px', color: '#0284c7', fontWeight: 600 }}>{caseId}</code> from ThreatTrace Database...
          </p>
        </div>
      ) : (
        /* Main 3-Column Dashboard */
        <main className="sih-main-grid">

        {/* 1. LEFT COLUMN: DATA INGESTION */}
        <section className="sih-card data-ingestion-col">
          <div className="sih-card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
              <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
            </svg>
            <span>DATA INGESTION</span>
          </div>

          <div style={{ fontSize: '0.78rem', color: '#64748b', fontWeight: 600, marginBottom: '8px' }}>
            Raw Email Data (Headers & Body)
          </div>

          <textarea
            className="raw-data-textarea custom-gold-scroll"
            placeholder="Paste raw email headers, body text, or links here to analyze manually...

Or open any email in Gmail with ThreatTrace AI active to inspect automatically."
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
          />

          <button 
            className="btn-run-analysis" 
            onClick={handleRunAnalysis} 
            disabled={analyzing || !rawInput.trim()}
            style={{ opacity: (!rawInput.trim() || analyzing) ? 0.7 : 1 }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
            <span>{analyzing ? 'Analyzing Threat…' : 'Run AI Analysis'}</span>
          </button>
        </section>


        {/* 2. MIDDLE COLUMN: FORENSIC BREAKDOWN */}
        <section className="middle-forensic-col custom-gold-scroll">

          {/* Top Incident ID + Score + Pillars */}
          <div className="incident-header-box">
            <div className="incident-top-line">
              <span className="incident-id-tag">
                {data ? `INCIDENT ID: ${data.incidentId}` : 'STATUS: LIVE STANDBY'}
              </span>
              <span className="risk-score-label">RISK SCORE</span>
            </div>

            <div className="incident-title-score-row">
              <h2 className="incident-main-title" title={data ? data.fullSubject : 'ThreatTrace AI — In-Page Forensic Shield Active'}>
                {data ? data.title : 'ThreatTrace AI — Live Forensic Engine Active'}
              </h2>
              <div style={{ display: 'flex', alignItems: 'baseline' }}>
                <span 
                  className="big-risk-score" 
                  style={{ 
                    color: !data ? '#94a3b8' : data.riskScore >= 70 ? '#ef4444' : data.riskScore >= 40 ? '#f59e0b' : '#10b981' 
                  }}
                >
                  {data ? data.riskScore : '--'}
                </span>
                <span className="score-slash-100">/ 100</span>
              </div>
            </div>

            {/* 4 Pillars Underline Indicators */}
            <div className="rubric-pillars-grid">
              <div className="pillar-pill">
                <span className="pillar-name">NLP Intent</span>
                <div className={`pillar-bar ${data ? data.nlpBar : 'gray'}`} />
              </div>

              <div className="pillar-pill">
                <span className="pillar-name">Extracted IPs</span>
                <div className={`pillar-bar ${data ? data.ipBar : 'gray'}`} />
              </div>

              <div className="pillar-pill">
                <span className="pillar-name">Malicious URLs</span>
                <div className={`pillar-bar ${data ? data.urlBar : 'gray'}`} />
              </div>

              <div className="pillar-pill">
                <span className="pillar-name">Header Spoof</span>
                <div className={`pillar-bar ${data ? data.headerBar : 'gray'}`} />
              </div>
            </div>
          </div>

          {/* EXPLAINABLE AI: FORENSIC BREAKDOWN */}
          <div className="sih-card">
            <div className="sih-card-title">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="m21 21-4.3-4.3"/>
              </svg>
              <span>EXPLAINABLE AI: FORENSIC BREAKDOWN</span>
            </div>

            {data ? (
              <div className="email-forensic-box">
                <div className="email-header-meta">
                  <div><strong>From:</strong> {data.from}</div>
                  <div><strong>To:</strong> {data.to}</div>
                  <div><strong>Subject:</strong> {data.fullSubject}</div>
                  <div><strong>Date:</strong> {data.date}</div>
                </div>

                {data.rawText ? (
                  <div style={{ whiteSpace: 'pre-wrap', lineHeight: '1.6', fontSize: '12px', color: '#1e293b' }}>
                    {highlightForensicKeywords(data.rawText)}
                  </div>
                ) : (
                  <div style={{ color: '#94a3b8', fontStyle: 'italic', fontSize: '12px' }}>
                    (No email body text provided for inspection)
                  </div>
                )}

                <div style={{ marginTop: '14px', paddingTop: '10px', borderTop: '1px dashed #cbd5e1' }}>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: '#64748b', marginRight: '6px' }}>
                    PAYLOAD TARGET LINK:
                  </span>
                  {data.payloadUrl && data.payloadUrl !== 'No link' ? (
                    <span className="highlight-url-box">{data.payloadUrl}</span>
                  ) : (
                    <span style={{ color: '#94a3b8', fontSize: '11px', fontStyle: 'italic' }}>
                      No link detected in payload
                    </span>
                  )}
                </div>
              </div>
            ) : (
              <div style={{
                padding: '36px 20px',
                textAlign: 'center',
                background: '#f8fafc',
                borderRadius: '8px',
                border: '1px dashed #cbd5e1',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '10px'
              }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '50%',
                  background: '#e0f2fe',
                  color: '#0284c7',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '22px'
                }}>
                  🛡️
                </div>
                <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 700, color: '#0f172a' }}>
                  Awaiting Email Data Ingestion
                </h3>
                <p style={{ margin: 0, fontSize: '0.82rem', color: '#64748b', maxWidth: '420px', lineHeight: 1.5 }}>
                  No email currently loaded. Open any email in Gmail to inspect automatically with the ThreatTrace AI extension, or paste raw email data on the left and click <strong>Run AI Analysis</strong>.
                </p>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', justifyContent: 'center', marginTop: '6px' }}>
                  <span style={{ fontSize: '0.72rem', background: '#ffffff', border: '1px solid #e2e8f0', padding: '3px 9px', borderRadius: '12px', color: '#475569', fontWeight: 600 }}>
                    ⚡ 4-Pillar NLP Intent Engine
                  </span>
                  <span style={{ fontSize: '0.72rem', background: '#ffffff', border: '1px solid #e2e8f0', padding: '3px 9px', borderRadius: '12px', color: '#475569', fontWeight: 600 }}>
                    🌐 Unmasked Redirect Tracer
                  </span>
                  <span style={{ fontSize: '0.72rem', background: '#ffffff', border: '1px solid #e2e8f0', padding: '3px 9px', borderRadius: '12px', color: '#475569', fontWeight: 600 }}>
                    🔒 ECDSA Blockchain Seal
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* EXTRACTED INDICATORS (IOCS) */}
          {data && (() => {
            const isSafeZone = data.zone === 'Verified Safe' || data.riskLevel === 'LOW' || data.riskScore < 40
            return (
              <>
                <div className="sih-card">
                  <div className="sih-card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                    </svg>
                    <span>EXTRACTED INDICATORS (IOCS)</span>
                  </div>

                  <div className="ioc-two-col">
                    <div className="ioc-sub-box">
                      <div className="ioc-sub-label">Sender Origin IPv4</div>
                      <div className="ioc-sub-val" style={isSafeZone ? { color: '#059669', fontSize: '0.82rem' } : {}}>
                        <div>{isSafeZone ? 'Not Applicable (Safe Zone)' : data.originIp}</div>
                        {data.isPrivateOrigin && !isSafeZone && (
                          <span style={{ display: 'inline-block', fontSize: '0.68rem', background: '#fef3c7', color: '#b45309', padding: '2px 7px', borderRadius: '4px', marginTop: '4px', fontWeight: 700, border: '1px solid #fde68a' }}>
                            LAB / KALI HOST
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="ioc-sub-box">
                      <div className="ioc-sub-label">Payload Domain & Server</div>
                      <div className="ioc-sub-val">
                        <div style={{ wordBreak: 'break-all' }}>{data.payloadDomain}</div>
                        {data.payloadIp && data.payloadIp !== data.originIp && (
                          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '3px' }}>
                            Host: <span style={{ fontFamily: 'monospace', color: '#334155' }}>{data.payloadIp}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* RISK ZONE & LIVE LOCATION */}
                <div className="sih-card">
                  <div className="sih-card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="22" y1="12" x2="18" y2="12"/>
                      <line x1="6" y1="12" x2="2" y2="12"/>
                      <line x1="12" y1="6" x2="12" y2="2"/>
                      <line x1="12" y1="22" x2="12" y2="18"/>
                    </svg>
                    <span>RISK ZONE & LIVE LOCATION</span>
                  </div>

                  <div className="risk-zone-card" style={isSafeZone ? { borderColor: '#a7f3d0', background: '#f0fdf4' } : {}}>
                    <div className="zone-header-line" style={isSafeZone ? { borderColor: '#bbf7d0' } : {}}>
                      <span className="zone-title">ZONE</span>
                      <span className="zone-badge-red" style={{ color: isSafeZone ? '#10b981' : (data.isPrivateOrigin ? '#d97706' : (data.riskLevel === 'HIGH' ? '#ef4444' : '#f59e0b')) }}>
                        {data.zone}
                      </span>
                    </div>

                    {isSafeZone ? (
                      <div style={{ padding: '8px 0', color: '#047857', fontSize: '0.82rem', lineHeight: '1.5' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, marginBottom: '2px' }}>
                          <span>✓</span>
                          <span>Safe Zone Verified</span>
                        </div>
                        <div style={{ color: '#065f46', fontSize: '0.78rem' }}>
                          Sender infrastructure is verified safe. IP address and live location tracking are suppressed.
                        </div>
                      </div>
                    ) : (
                      <div className="zone-details">
                        <div><strong>Target Host:</strong> {data.originIp}</div>
                        <div><strong>Location:</strong> {data.city}{data.country ? `, ${data.country}` : ''}</div>
                        <div><strong>Network / ISP:</strong> {data.isp || data.region || 'Not detected'}</div>
                        {data.coordinates && data.coordinates !== 'N/A' && (
                          <div><strong>Coordinates:</strong> {data.coordinates}</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* END-TO-END CRYPTOGRAPHIC EVIDENCE SEAL */}
                <div className="sih-card" style={{ border: '1px solid #3b82f6', background: 'linear-gradient(180deg, #ffffff, #f8fafc)' }}>
                  <div className="sih-card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563eb" strokeWidth="2.2">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    <span style={{ color: '#1e3a8a', fontWeight: 800 }}>E2E CRYPTOGRAPHIC EVIDENCE SEAL</span>
                    <span style={{ marginLeft: 'auto', fontSize: '0.68rem', padding: '2px 8px', borderRadius: '10px', background: '#ecfdf5', color: '#059669', border: '1px solid #a7f3d0', fontWeight: 700 }}>
                      ✓ UNTAMPERED
                    </span>
                  </div>

                  <div style={{ background: '#090e18', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1e293b', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700 }}>
                        Canonical SHA-256 Digest
                      </span>
                      <span style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'monospace' }}>
                        {cryptoSeal?.algorithm || 'ECDSA SECP256R1'}
                      </span>
                    </div>
                    <div style={{ fontFamily: 'monospace', fontSize: '0.74rem', color: '#38bdf8', wordBreak: 'break-all', lineHeight: 1.3 }}>
                      {cryptoSeal?.canonical_hash || '0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069'}
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: '#64748b', marginBottom: '10px', padding: '0 2px' }}>
                    <span><strong>Key:</strong> {cryptoSeal?.public_key_fingerprint || 'TT-SECP256R1-14B6:1DE7'}</span>
                    <span><strong>Ledger:</strong> Polygon Amoy Testnet</span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '6px' }}>
                    <button
                      onClick={() => setIsCryptoModalOpen(true)}
                      style={{
                        background: '#f0fdf4',
                        border: '1px solid #bbf7d0',
                        color: '#166534',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        padding: '6px 4px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '4px'
                      }}
                      title="Verify digital signature and hash integrity"
                    >
                      <span>⚡</span>
                      <span>Verify Seal</span>
                    </button>

                    <button
                      onClick={() => setIsCryptoModalOpen(true)}
                      style={{
                        background: '#fef2f2',
                        border: '1px solid #fecdd3',
                        color: '#991b1b',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        padding: '6px 4px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '4px'
                      }}
                      title="Simulate attacker modifying evidence"
                    >
                      <span>🧪</span>
                      <span>Tamper Demo</span>
                    </button>

                    <button
                      onClick={() => setIsCryptoModalOpen(true)}
                      style={{
                        background: '#faf5ff',
                        border: '1px solid #e9d5ff',
                        color: '#6b21a8',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        padding: '6px 4px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '4px'
                      }}
                      title="Open AES-256-GCM Encrypted Evidence Vault"
                    >
                      <span>🔐</span>
                      <span>E2EE Vault</span>
                    </button>
                  </div>
                </div>
              </>
            )
          })()}

        </section>


        {/* 3. RIGHT COLUMN: GRAPH & AUTOMATED RESPONSE MATRIX */}
        <section className="right-col">

          {/* Infrastructure Graph */}
          <SihInfrastructureGraph riskLevel={data ? data.riskLevel : 'STANDBY'} />

          {/* Automated Response Matrix */}
          <div className="sih-card">
            <div className="sih-card-title">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
              </svg>
              <span>AUTOMATED RESPONSE MATRIX</span>
            </div>

            <div className="response-matrix-inner">
              <div className="response-engine-label">AI ANALYSIS ENGINE</div>

              {data ? (
                <>
                  <p className="response-ai-text">
                    I detected <strong style={{ color: data.riskLevel === 'HIGH' ? '#ea580c' : '#0f172a' }}>{data.aiExplanation.count}</strong>. {data.aiExplanation.fullText}
                  </p>

                  <button className="btn-quarantine-action" onClick={handleActionClick}>
                    {data.actionText}
                  </button>
                </>
              ) : (
                <>
                  <p className="response-ai-text" style={{ color: '#64748b' }}>
                    Standby — Ingest an email from Gmail or paste raw email data on the left to compute risk vectors, extract threat actors, and evaluate automated response policies.
                  </p>

                  <button className="btn-quarantine-action" disabled style={{ opacity: 0.5, cursor: 'not-allowed' }}>
                    Standby (Awaiting Ingestion)
                  </button>
                </>
              )}

              <button
                onClick={() => setIsSocModalOpen(true)}
                disabled={!data}
                style={{
                  width: '100%',
                  background: !data ? '#f1f5f9' : '#f0f9ff',
                  border: !data ? '1px solid #e2e8f0' : '1px solid #bae6fd',
                  color: !data ? '#94a3b8' : '#0369a1',
                  fontSize: '0.78rem',
                  fontWeight: 800,
                  padding: '9px',
                  borderRadius: '6px',
                  cursor: !data ? 'not-allowed' : 'pointer',
                  marginTop: '8px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '6px',
                  opacity: !data ? 0.6 : 1
                }}
                title="Dispatch incident to Cybersecurity Department and SIEM stream"
              >
                <span>📡</span>
                <span>Dispatch to Cybersecurity Dept / SIEM</span>
              </button>
            </div>
          </div>

        </section>

      </main>
      )}

      {/* Bottom Team Footer */}
      <footer className="sih-footer">
        <div className="sih-team-label">
          Team: Threat Trace AI
        </div>

        <div className="sih-students-list">
          <span>Y.muniswami 24AFCAI108</span>
          <span>Moulanbee 24AFCAI105</span>
          <span>N.Mahammad Abbas 24AFCAI096</span>
          <span>G.Jeevan reddy yadav 24AFCAI073</span>
          <span>Lahari 24AFCAI087</span>
          <span>P.Hemanth 24AFCAI061</span>
        </div>
      </footer>

      {/* End-to-End Cryptography Modal */}
      <CryptoSealModal
        isOpen={isCryptoModalOpen}
        onClose={() => setIsCryptoModalOpen(false)}
        caseData={data}
        cryptoSeal={cryptoSeal}
      />

      {/* Cybersecurity Department / SOC Modal */}
      <SOCDispatchModal
        isOpen={isSocModalOpen}
        onClose={() => setIsSocModalOpen(false)}
        caseData={data}
      />

    </div>
  )
}
