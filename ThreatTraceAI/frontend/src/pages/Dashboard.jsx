import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api'

export default function Dashboard() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [seeding, setSeeding] = useState(false)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('ALL')

  const fetchCases = () => {
    setLoading(true)
    api.listCases()
      .then(data => {
        setCases(data)
        setError(null)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchCases()
  }, [])

  const handleSeed = async () => {
    setSeeding(true)
    try {
      await api.seedCases()
      fetchCases()
    } catch (e) {
      setError('Seed failed: ' + e.message)
    } finally {
      setSeeding(false)
    }
  }

  // Stats calculation
  const totalCount = cases.length
  const criticalCount = cases.filter(c => c.risk_level === 'HIGH' || c.risk_score >= 70).length
  const chainCount = cases.filter(c => c.blockchain_hash || c.blockchain_tx).length
  const avgScore = totalCount > 0 ? Math.round(cases.reduce((a, b) => a + (b.risk_score || 0), 0) / totalCount) : 0

  // Filtering
  const filteredCases = cases.filter(c => {
    const matchesSearch = (c.subject || '').toLowerCase().includes(search.toLowerCase()) ||
                          (c.sender || '').toLowerCase().includes(search.toLowerCase()) ||
                          (c.case_id || '').toLowerCase().includes(search.toLowerCase())
    
    if (!matchesSearch) return false
    if (filterSeverity === 'HIGH') return c.risk_level === 'HIGH' || c.risk_score >= 70
    if (filterSeverity === 'MEDIUM') return c.risk_level === 'MEDIUM' || (c.risk_score >= 40 && c.risk_score < 70)
    if (filterSeverity === 'LOW') return c.risk_level === 'LOW' && c.risk_score < 40
    return true
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      
      {/* Top Banner / Metrics */}
      <div className="grid grid-4">
        <div className="kpi-card">
          <div className="kpi-icon" style={{ color: '#38bdf8' }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
          </div>
          <div>
            <div className="kpi-value">{totalCount}</div>
            <div className="kpi-label">Incidents Triaged</div>
          </div>
        </div>

        <div className="kpi-card" style={{ '--accent-gradient': 'linear-gradient(135deg, #f43f5e, #be123c)' }}>
          <div className="kpi-icon" style={{ background: 'rgba(244, 63, 94, 0.1)', borderColor: 'rgba(244, 63, 94, 0.3)', color: '#f43f5e' }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 9v4"/>
              <path d="M12 17h.01"/>
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
            </svg>
          </div>
          <div>
            <div className="kpi-value">{criticalCount}</div>
            <div className="kpi-label">Critical Threats</div>
          </div>
        </div>

        <div className="kpi-card" style={{ '--accent-gradient': 'linear-gradient(135deg, #a855f7, #6366f1)' }}>
          <div className="kpi-icon" style={{ background: 'rgba(168, 85, 247, 0.1)', borderColor: 'rgba(168, 85, 247, 0.3)', color: '#a855f7' }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect width="18" height="18" x="3" y="3" rx="2"/>
              <path d="M7 7h10"/>
              <path d="M7 12h10"/>
              <path d="M7 17h10"/>
            </svg>
          </div>
          <div>
            <div className="kpi-value">{chainCount}</div>
            <div className="kpi-label">Chain Hashes Sealed</div>
          </div>
        </div>

        <div className="kpi-card" style={{ '--accent-gradient': 'linear-gradient(135deg, #fbbf24, #d97706)' }}>
          <div className="kpi-icon" style={{ background: 'rgba(251, 191, 36, 0.1)', borderColor: 'rgba(251, 191, 36, 0.3)', color: '#fbbf24' }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <path d="M12 6v6l4 2"/>
            </svg>
          </div>
          <div>
            <div className="kpi-value">{avgScore}<span style={{ fontSize: '1rem', color: 'var(--text-dim)' }}>/100</span></div>
            <div className="kpi-label">Avg Threat Severity</div>
          </div>
        </div>
      </div>

      {/* Action and Filter Toolbar */}
      <div className="card" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '1rem' }}>
          
          {/* Search Box */}
          <div style={{ flex: '1 1 280px', maxWidth: '420px', position: 'relative' }}>
            <input
              type="text"
              placeholder="Search Case ID, sender email, or subject line…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ paddingLeft: '2.5rem', fontSize: '0.88rem' }}
            />
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="2" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }}>
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.3-4.3"/>
            </svg>
          </div>

          {/* Severity Filter Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <button
              className={filterSeverity === 'ALL' ? '' : 'ghost'}
              style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
              onClick={() => setFilterSeverity('ALL')}
            >
              All ({cases.length})
            </button>
            <button
              className={filterSeverity === 'HIGH' ? 'danger' : 'ghost'}
              style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
              onClick={() => setFilterSeverity('HIGH')}
            >
              High ({criticalCount})
            </button>
            <button
              className={filterSeverity === 'MEDIUM' ? 'secondary' : 'ghost'}
              style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', color: filterSeverity === 'MEDIUM' ? '#fbbf24' : '' }}
              onClick={() => setFilterSeverity('MEDIUM')}
            >
              Medium
            </button>
            <button
              className={filterSeverity === 'LOW' ? 'secondary' : 'ghost'}
              style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem', color: filterSeverity === 'LOW' ? '#10b981' : '' }}
              onClick={() => setFilterSeverity('LOW')}
            >
              Low / Safe
            </button>
          </div>

          {/* Action CTAs */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button className="secondary" onClick={handleSeed} disabled={seeding}>
              {seeding ? 'Seeding Data…' : '⚡ Load Demo Threats'}
            </button>
            <Link to="/investigate">
              <button>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <line x1="12" y1="5" x2="12" y2="19"/>
                  <line x1="5" y1="12" x2="19" y2="12"/>
                </svg>
                <span>New Investigation</span>
              </button>
            </Link>
          </div>

        </div>
      </div>

      {error && (
        <div style={{ background: 'rgba(244,63,94,0.12)', border: '1px solid #f43f5e', color: '#f43f5e', padding: '1rem', borderRadius: '10px' }}>
          {error}
        </div>
      )}

      {/* Case List Grid */}
      {loading ? (
        <div className="card" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
          <div className="status-dot online" style={{ width: '14px', height: '14px', marginBottom: '1rem' }} />
          <div style={{ color: 'var(--text-muted)' }}>Loading threat intelligence cases from local SQLite ledger…</div>
        </div>
      ) : filteredCases.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1rem' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🛡️</div>
          <h3 style={{ marginBottom: '0.5rem' }}>No incident cases matching criteria</h3>
          <p style={{ color: 'var(--text-muted)', maxWidth: '440px', margin: '0 auto 1.5rem auto', fontSize: '0.9rem' }}>
            Click &ldquo;Load Demo Threats&rdquo; to populate realistic sample cases, or paste a phishing email into the Forensic Studio.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem' }}>
            <button className="secondary" onClick={handleSeed} disabled={seeding}>
              ⚡ Load Demo Threats
            </button>
            <Link to="/investigate"><button>Start Investigation</button></Link>
          </div>
        </div>
      ) : (
        <div className="grid">
          {filteredCases.map(c => {
            const isHigh = c.risk_level === 'HIGH' || c.risk_score >= 70
            const isMed = (c.risk_level === 'MEDIUM' || (c.risk_score >= 40 && c.risk_score < 70)) && !isHigh
            const badgeCls = isHigh ? 'badge-critical' : isMed ? 'badge-warning' : 'badge-safe'
            const scoreColor = isHigh ? '#f43f5e' : isMed ? '#fbbf24' : '#10b981'

            return (
              <div key={c.case_id} className="card" style={{ padding: '1.25rem 1.5rem', position: 'relative' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                  
                  {/* Left: Metadata */}
                  <div style={{ flex: '1 1 340px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                      <span className="mono" style={{ fontSize: '0.85rem', color: '#38bdf8', fontWeight: 700 }}>
                        {c.case_id}
                      </span>
                      <span className={`badge ${badgeCls}`}>{c.risk_level || 'LOW'}</span>
                      {c.recommendation && (
                        <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>
                          ACTION: {c.recommendation}
                        </span>
                      )}
                      {c.blockchain_hash && (
                        <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }} title={`SHA-256: ${c.blockchain_hash}`}>
                          ⛓️ CHAIN SEALED
                        </span>
                      )}
                    </div>

                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
                      {c.subject || '(no subject line)'}
                    </div>

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                      <div>Sender: <strong style={{ color: '#cbd5e1' }}>{c.sender}</strong></div>
                      {c.created_at && (
                        <div>Timestamp: <span>{new Date(c.created_at).toLocaleString()}</span></div>
                      )}
                    </div>
                  </div>

                  {/* Right: Score & CTA */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '1.8rem', fontWeight: 900, color: scoreColor, lineHeight: 1, fontFamily: 'var(--font-mono)' }}>
                        {Math.round(c.risk_score || 0)}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700 }}>
                        Risk Score
                      </div>
                    </div>

                    <Link to={`/case/${c.case_id}`}>
                      <button className="secondary" style={{ padding: '0.55rem 1rem', fontSize: '0.82rem' }}>
                        <span>Inspect Dossier</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M5 12h14"/>
                          <path d="m12 5 7 7-7 7"/>
                        </svg>
                      </button>
                    </Link>
                  </div>

                </div>
              </div>
            )
          })}
        </div>
      )}

    </div>
  )
}
