import { useState } from 'react'
import { api } from '../services/api'

export default function ReportPanel({ caseId, initialReportId = null, initialHash = null, initialTx = null }) {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(initialReportId ? {
    report_id: initialReportId,
    blockchain: {
      case_hash: initialHash,
      tx_hash: initialTx,
      simulated: !initialTx
    }
  } : null)
  const [error, setError] = useState(null)

  async function handleReport() {
    if (!caseId) return
    setLoading(true)
    setError(null)
    try {
      const data = await api.generateReport(caseId)
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

  return (
    <div className="card" style={{ background: 'linear-gradient(135deg, rgba(14, 22, 40, 0.95), rgba(20, 15, 38, 0.95))', border: '1px solid #4f46e555' }}>
      <div className="card-header" style={{ borderBottomColor: '#4f46e533' }}>
        <div className="card-title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <circle cx="12" cy="11" r="3"/>
          </svg>
          <span style={{ background: 'linear-gradient(135deg, #a5b4fc, #38bdf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Chain-of-Custody & Law Enforcement Reporting
          </span>
        </div>
        <span className="badge badge-purple">Polygon Amoy Testnet</span>
      </div>

      <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem', marginBottom: '1.25rem', lineHeight: 1.5 }}>
        Finalizing this forensic record generates an immutable cryptographic SHA-256 digest of all IOCs, header telemetry, and evidence points. The hash is sealed to the Polygon blockchain to provide tamper-proof provenance for judicial presentation.
      </p>

      {!result && (
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button className="danger" onClick={handleReport} disabled={loading || !caseId}>
            {loading ? (
              <>
                <span className="status-dot online" style={{ background: '#fff' }} />
                <span>Hashing & Generating Dossier…</span>
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span>Report Case & Seal Hash On-Chain</span>
              </>
            )}
          </button>
        </div>
      )}

      {error && (
        <div style={{ color: '#f43f5e', background: 'rgba(244,63,94,0.1)', padding: '0.75rem', borderRadius: '8px', marginTop: '1rem', border: '1px solid rgba(244,63,94,0.3)', fontSize: '0.85rem' }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
            <div style={{ background: '#090e18', padding: '0.75rem 1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Dossier ID</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#38bdf8', fontSize: '0.95rem' }}>
                {result.report_id}
              </div>
            </div>

            <div style={{ background: '#090e18', padding: '0.75rem 1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Blockchain Ledger State</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, fontSize: '0.9rem', color: result.blockchain?.tx_hash ? '#10b981' : '#a855f7' }}>
                <span className="status-dot chain" style={result.blockchain?.tx_hash ? { background: '#10b981' } : {}} />
                {result.blockchain?.tx_hash ? 'On-Chain Block Confirmed' : 'Cryptographic Hash Ready (Simulation)'}
              </div>
            </div>
          </div>

          {result.blockchain?.case_hash && (
            <div style={{ background: '#070b14', padding: '0.85rem 1rem', borderRadius: '8px', border: '1px solid rgba(99, 102, 241, 0.3)' }}>
              <div style={{ fontSize: '0.75rem', color: '#a5b4fc', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>
                SHA-256 Canonical Forensic Hash
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#e2e8f0', wordBreak: 'break-all' }}>
                {result.blockchain.case_hash}
              </div>
            </div>
          )}

          {result.blockchain?.tx_hash && (
            <div style={{ background: '#070b14', padding: '0.85rem 1rem', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
              <div style={{ fontSize: '0.75rem', color: '#6ee7b7', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>
                Polygon Transaction Receipt
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#a7f3d0', wordBreak: 'break-all' }}>
                {result.blockchain.tx_hash}
              </div>
            </div>
          )}

          {/* Action links */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
            <a
              href={`${BASE}/api/reports/${result.report_id}/download?format=html`}
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ fontSize: '0.82rem', padding: '0.5rem 1rem' }}
            >
              📄 Open Printable HTML Dossier
            </a>
            <a
              href={`${BASE}/api/reports/${result.report_id}/download?format=json`}
              download={`${result.report_id}.json`}
              className="btn btn-secondary"
              style={{ fontSize: '0.82rem', padding: '0.5rem 1rem' }}
            >
              💾 Download Raw JSON Report
            </a>
          </div>
        </div>
      )}
    </div>
  )
}
