import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import RiskScore from '../components/RiskScore'
import RiskFactors from '../components/RiskFactors'
import IOCPanel from '../components/IOCPanel'
import IPGeolocation from '../components/IPGeolocation'
import InfrastructureGraph from '../components/InfrastructureGraph'
import ResponseMatrix from '../components/ResponseMatrix'
import ReportPanel from '../components/ReportPanel'

const PRESETS = [
  {
    id: 'banking',
    title: '🚨 Banking Phishing',
    subtitle: 'Credential lure, spoofed auth headers',
    text: `From: security@fake-bank-login.com
To: victim@example.com
Subject: Urgent: Your account will be locked within 24 hours
Date: Fri, 11 Sep 2026 10:00:00 +0000
Message-ID: <fake123@fake-bank-login.com>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail

Dear valued customer,

We have detected unusual sign-in activity on your account.
To protect your funds you must verify your password immediately 
by visiting the secure link below. Failure to do so within 24 hours 
will result in permanent account suspension.

https://urgent-verify-now.net/login?user=victim

Thank you,
Security Team
Fake Bank`
  },
  {
    id: 'ceo_wire',
    title: '💼 CEO Wire Fraud',
    subtitle: 'Urgent invoice, changed wire details',
    text: `From: billing@acme-supplies-intl.com
To: finance@company.com
Subject: Invoice #INV-98421 – Urgent Payment Overdue
Date: Fri, 11 Sep 2026 09:30:00 +0000

Please find attached the overdue invoice.
Wire transfer details have changed.
Kindly process payment to the new account within 48 hours to avoid late fees.

Click here to download the invoice: http://acme-supplies-intl.com/invoice/INV-98421

Regards,
Accounts Payable`
  },
  {
    id: 'courier',
    title: '📦 Delivery Tracking Link',
    subtitle: 'Short call-to-action redirect link',
    text: `From: notification@courier-fast-track.com
To: recipient@corp.net
Subject: Your package could not be delivered

Your parcel #GB-99214 is pending delivery fees.
Please update your address immediately:
http://bit.ly/fake-courier-update-99`
  },
  {
    id: 'safe_github',
    title: '🛡️ Legitimate Security Email',
    subtitle: 'Passing SPF/DKIM/DMARC headers',
    text: `From: noreply@github.com
To: developer@example.com
Subject: [GitHub] Please reset your password
Date: Fri, 11 Sep 2026 08:00:00 +0000
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

We received a request to reset the password for your GitHub account.

If you requested this, click the link below:
https://github.com/password_reset/token/abc123

If you did not request a password reset, you can safely ignore this email.

Thanks,
The GitHub Team`
  }
]

export default function Investigation() {
  const [text, setText] = useState(PRESETS[0].text)
  const [loading, setLoading] = useState(false)
  const [scanStep, setScanStep] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (event) => {
      setText(event.target?.result || '')
    }
    reader.readAsText(file)
  }

  async function runAnalysis() {
    if (!text.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    setScanStep(1)

    // Simulate cyber telemetry scanning steps
    const stepInterval = setInterval(() => {
      setScanStep(prev => (prev < 4 ? prev + 1 : prev))
    }, 450)

    try {
      const data = await api.analyze({ email_text: text, save_case: true })
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      clearInterval(stepInterval)
      setLoading(false)
      setScanStep(0)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Forensic Studio Input Card */}
      <div className="card scanner-container">
        {loading && <div className="scanner-overlay" />}

        <div className="card-header">
          <div className="card-title">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.3-4.3"/>
            </svg>
            <span>Live Forensic Analysis Studio</span>
          </div>
          <span className="badge badge-cyan">RFC-822 MIME Parser</span>
        </div>

        {/* Preset scenario bar */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em', marginBottom: '0.6rem' }}>
            Quick Load Attack Scenarios:
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.6rem' }}>
            {PRESETS.map(p => (
              <button
                key={p.id}
                className="secondary"
                style={{
                  textAlign: 'left',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'flex-start',
                  padding: '0.65rem 0.85rem',
                  gap: '2px',
                  borderColor: text === p.text ? '#38bdf8' : ''
                }}
                onClick={() => setText(p.text)}
              >
                <strong style={{ fontSize: '0.85rem', color: '#fff' }}>{p.title}</strong>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{p.subtitle}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Text Area */}
        <div style={{ position: 'relative' }}>
          <textarea
            rows={10}
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder="Paste raw email content with headers (or standard plain text) here…"
            style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', lineHeight: 1.5 }}
          />
        </div>

        {/* Action bar */}
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <label className="btn btn-secondary" style={{ fontSize: '0.82rem', padding: '0.55rem 0.95rem', cursor: 'pointer', margin: 0 }}>
              📁 Upload .eml File
              <input type="file" accept=".eml,.txt,.msg" style={{ display: 'none' }} onChange={handleFileUpload} />
            </label>
            <button className="ghost" onClick={() => setText('')} style={{ fontSize: '0.82rem' }}>
              Clear Input
            </button>
          </div>

          <button onClick={runAnalysis} disabled={loading || !text.trim()} style={{ minWidth: '220px' }}>
            {loading ? (
              <>
                <span className="status-dot online" style={{ background: '#fff' }} />
                <span>
                  {scanStep === 1 && 'Extracting MIME Headers…'}
                  {scanStep === 2 && 'Tracing Live Redirects…'}
                  {scanStep === 3 && 'Checking OpenPhish Feeds…'}
                  {scanStep >= 4 && 'Computing Risk Rubric…'}
                  {scanStep === 0 && 'Analyzing…'}
                </span>
              </>
            ) : (
              <>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polygon points="5 3 19 12 5 21 5 3"/>
                </svg>
                <span>Execute Deep Forensic Analysis</span>
              </>
            )}
          </button>
        </div>

        {error && (
          <div style={{ background: 'rgba(244,63,94,0.12)', border: '1px solid #f43f5e', color: '#f43f5e', padding: '0.85rem', borderRadius: '10px', marginTop: '1rem', fontSize: '0.85rem' }}>
            {error}
          </div>
        )}
      </div>

      {/* Forensic Results Section */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Top Verdict Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
            <RiskScore
              score={result.risk_score}
              level={result.risk_level}
              recommendation={result.recommendation}
            />

            <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div className="card-header" style={{ marginBottom: '0.75rem' }}>
                  <div className="card-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                      <rect width="18" height="18" x="3" y="3" rx="2"/>
                      <line x1="9" y1="3" x2="9" y2="21"/>
                    </svg>
                    <span>Attributed Incident Summary</span>
                  </div>
                  <span className="mono" style={{ color: '#38bdf8', fontSize: '0.85rem', fontWeight: 700 }}>
                    {result.case_id}
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.88rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Subject: </span>
                    <strong style={{ color: '#fff' }}>{result.subject || '(None)'}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Sender: </span>
                    <strong style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{result.sender}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Recipient: </span>
                    <span style={{ color: '#cbd5e1' }}>{result.recipient || 'Not specified'}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Threat Intelligence Status: </span>
                    <span style={{ color: '#10b981', fontWeight: 600 }}>{result.message}</span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                <button className="secondary" style={{ padding: '0.45rem 0.85rem', fontSize: '0.82rem' }} onClick={() => navigate(`/case/${result.case_id}`)}>
                  Open Dedicated Case Dossier →
                </button>
              </div>
            </div>
          </div>

          {/* Explainable Rubric */}
          <RiskFactors factors={result.risk_factors || []} />

          {/* Infrastructure Topology Graph */}
          <InfrastructureGraph graph={result.graph} />

          {/* IOC Vault */}
          <IOCPanel
            urls={result.urls || []}
            domains={result.domains || []}
            ips={result.ips || []}
          />

          {/* IP Geolocation Telemetry */}
          <IPGeolocation locations={result.geo_locations || []} />

          {/* Automated Response Playbook */}
          <ResponseMatrix
            recommendation={result.recommendation}
            factors={result.risk_factors || []}
          />

          {/* Chain-of-Custody & Reporting */}
          <ReportPanel caseId={result.case_id} />

        </div>
      )}

    </div>
  )
}
