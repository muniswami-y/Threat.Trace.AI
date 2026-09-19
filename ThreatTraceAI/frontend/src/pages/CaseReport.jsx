import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../services/api'
import RiskScore from '../components/RiskScore'
import RiskFactors from '../components/RiskFactors'
import IOCPanel from '../components/IOCPanel'
import IPGeolocation from '../components/IPGeolocation'
import InfrastructureGraph from '../components/InfrastructureGraph'
import ResponseMatrix from '../components/ResponseMatrix'
import ReportPanel from '../components/ReportPanel'

export default function CaseReport() {
  const { caseId } = useParams()
  const [c, setC] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    setLoading(true)
    api.getCase(caseId)
      .then(setC)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [caseId])

  const handleCopyId = () => {
    navigator.clipboard.writeText(caseId)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (loading) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '4rem 1rem' }}>
        <div className="status-dot online" style={{ width: '16px', height: '16px', marginBottom: '1rem' }} />
        <div style={{ color: 'var(--text-muted)' }}>Retrieving forensic dossier for {caseId}…</div>
      </div>
    )
  }

  if (error || !c) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
        <div style={{ color: '#f43f5e', fontSize: '1.2rem', fontWeight: 700, marginBottom: '0.5rem' }}>
          Case Record Not Found
        </div>
        <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
          {error || `Unable to load case record with identifier "${caseId}".`}
        </p>
        <Link to="/"><button className="secondary">← Return to Case History</button></Link>
      </div>
    )
  }

  // Construct graph if not explicitly provided
  const graph = c.graph || {
    nodes: [
      { id: c.sender || 'sender', type: 'sender', label: c.sender || 'Sender' },
      ...(c.domains || []).map(d => ({ id: d, type: 'domain', label: d })),
      ...(c.ips || []).map(ip => ({ id: ip, type: 'ip', label: ip })),
      ...(c.urls || []).map(u => {
        const val = typeof u === 'string' ? u : (u.final || u.original)
        return { id: val, type: 'url', label: val ? val.slice(0, 50) : 'link' }
      })
    ],
    edges: [
      ...(c.domains || []).map(d => ({ from: c.sender, to: d, label: 'uses domain' })),
      ...(c.ips || []).map(ip => ({ from: c.sender, to: ip, label: 'resolved / relay' })),
      ...(c.urls || []).map(u => {
        const val = typeof u === 'string' ? u : (u.final || u.original)
        return { from: c.sender, to: val, label: 'contains link' }
      })
    ]
  }

  const BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Breadcrumb Navigation */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.88rem' }}>
          <Link to="/" style={{ color: 'var(--text-muted)' }}>Cases</Link>
          <span style={{ color: 'var(--text-dim)' }}>/</span>
          <span style={{ color: '#38bdf8', fontWeight: 700 }} className="mono">{caseId}</span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }} onClick={handleCopyId}>
            {copied ? '✓ Copied ID' : '📋 Copy Case ID'}
          </button>
          {c.report_id && (
            <a
              href={`${BASE}/api/reports/${c.report_id}/download?format=html`}
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
            >
              📄 Printable Dossier
            </a>
          )}
        </div>
      </div>

      {/* Top Header Card */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <RiskScore
          score={c.risk_score}
          level={c.risk_level}
          recommendation={c.recommendation}
        />

        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div className="card-header" style={{ marginBottom: '0.75rem' }}>
              <div className="card-title">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                </svg>
                <span>Forensic Case Dossier</span>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <span className="badge badge-purple">{c.risk_level}</span>
                {c.blockchain_hash && <span className="badge badge-cyan">CHAIN SEALED</span>}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.88rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)' }}>Subject: </span>
                <strong style={{ color: '#fff' }}>{c.subject || '(None)'}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)' }}>Sender: </span>
                <strong style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{c.sender}</strong>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)' }}>Recipient: </span>
                <span style={{ color: '#cbd5e1' }}>{c.recipient || 'None specified'}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-dim)' }}>Registered Timestamp: </span>
                <span style={{ color: '#cbd5e1' }}>{c.created_at ? new Date(c.created_at).toLocaleString() : 'N/A'}</span>
              </div>
              {c.report_id && (
                <div>
                  <span style={{ color: 'var(--text-dim)' }}>Dossier ID: </span>
                  <span style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{c.report_id}</span>
                </div>
              )}
            </div>
          </div>

          {c.blockchain_hash && (
            <div style={{ marginTop: '1rem', padding: '0.65rem 0.85rem', background: '#070b14', borderRadius: '8px', border: '1px solid rgba(99, 102, 241, 0.3)', fontSize: '0.78rem' }}>
              <div style={{ color: '#a5b4fc', fontWeight: 700, marginBottom: '2px' }}>🔒 Blockchain Fingerprint:</div>
              <div className="mono" style={{ color: '#e2e8f0', wordBreak: 'break-all' }}>{c.blockchain_hash}</div>
            </div>
          )}
        </div>
      </div>

      {/* Explainable Threat Rubric */}
      <RiskFactors factors={c.risk_factors || []} />

      {/* Infrastructure Topology Graph */}
      <InfrastructureGraph graph={graph} />

      {/* Indicators of Compromise */}
      <IOCPanel
        urls={c.urls || []}
        domains={c.domains || []}
        ips={c.ips || []}
      />

      {/* IP Geolocation Telemetry */}
      <IPGeolocation locations={c.geo_locations || []} />

      {/* Automated Response Playbook */}
      <ResponseMatrix
        recommendation={c.recommendation}
        factors={c.risk_factors || []}
      />

      {/* Chain-of-Custody & Reporting */}
      <ReportPanel
        caseId={c.case_id}
        initialReportId={c.report_id}
        initialHash={c.blockchain_hash}
        initialTx={c.blockchain_tx}
      />

    </div>
  )
}
