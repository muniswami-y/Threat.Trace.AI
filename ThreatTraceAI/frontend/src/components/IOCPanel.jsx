import { useState } from 'react'

export default function IOCPanel({ urls = [], domains = [], ips = [] }) {
  const [activeTab, setActiveTab] = useState('urls')
  const [copied, setCopied] = useState(false)

  const defangUrl = (u) => {
    if (!u) return ''
    return u.replace(/http/gi, 'hxxp').replace(/\./g, '[.]')
  }

  const handleCopyDefanged = () => {
    const list = [
      '=== THREAT TRACE AI DEFANGED IOCS ===',
      '',
      '-- URLs --',
      ...urls.map(u => typeof u === 'string' ? defangUrl(u) : `${defangUrl(u.original)} -> ${defangUrl(u.final)}`),
      '',
      '-- Domains --',
      ...domains.map(d => d.replace(/\./g, '[.]')),
      '',
      '-- IP Addresses --',
      ...ips.map(ip => ip.replace(/\./g, '[.]'))
    ].join('\n')

    navigator.clipboard.writeText(list)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
          <span>Forensic Indicators of Compromise (IOC Vault)</span>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="secondary" style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }} onClick={handleCopyDefanged}>
            {copied ? '✓ Copied Defanged IOCs' : '📋 Copy Defanged IOCs'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '0.5rem' }}>
        <button
          className={activeTab === 'urls' ? '' : 'ghost'}
          style={{ padding: '0.4rem 0.85rem', fontSize: '0.82rem' }}
          onClick={() => setActiveTab('urls')}
        >
          URLs ({urls.length})
        </button>
        <button
          className={activeTab === 'domains' ? '' : 'ghost'}
          style={{ padding: '0.4rem 0.85rem', fontSize: '0.82rem' }}
          onClick={() => setActiveTab('domains')}
        >
          Domains ({domains.length})
        </button>
        <button
          className={activeTab === 'ips' ? '' : 'ghost'}
          style={{ padding: '0.4rem 0.85rem', fontSize: '0.82rem' }}
          onClick={() => setActiveTab('ips')}
        >
          IP Addresses ({ips.length})
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'urls' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
          {urls.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>No hyperlinks extracted from body.</div>
          ) : (
            urls.map((u, i) => {
              const orig = typeof u === 'string' ? u : u.original
              const final = typeof u === 'string' ? u : (u.final || u.original)
              const hasRedirect = typeof u !== 'string' && u.redirect_count > 0

              return (
                <div key={i} style={{ background: '#090e18', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '10px', padding: '0.85rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span className="badge badge-purple" style={{ fontSize: '0.7rem' }}>
                      {hasRedirect ? `UNMASKED REDIRECT (${u.redirect_count} hops)` : 'DIRECT LINK'}
                    </span>
                    {typeof u !== 'string' && u.status && (
                      <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>HTTP {u.status}</span>
                    )}
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#38bdf8', wordBreak: 'break-all' }}>
                    {orig}
                  </div>
                  {hasRedirect && (
                    <div style={{ marginTop: '6px', paddingTop: '6px', borderTop: '1px dashed rgba(255,255,255,0.06)', fontSize: '0.82rem' }}>
                      <span style={{ color: '#f43f5e', fontWeight: 600 }}>Final Destination Landing: </span>
                      <code style={{ color: '#fca5a5', wordBreak: 'break-all' }}>{final}</code>
                    </div>
                  )}
                </div>
              )
            })
          )}
        </div>
      )}

      {activeTab === 'domains' && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem' }}>
          {domains.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>No domains identified.</div>
          ) : (
            domains.map((d, i) => (
              <div key={i} style={{ background: '#090e18', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '0.5rem 0.85rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ color: '#818cf8' }}>🌐</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem', color: '#f1f5f9' }}>{d}</span>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'ips' && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.6rem' }}>
          {ips.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>No standalone IPs extracted.</div>
          ) : (
            ips.map((ip, i) => (
              <div key={i} style={{ background: '#090e18', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '0.5rem 0.85rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ color: '#fbbf24' }}>🖥️</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem', color: '#f1f5f9' }}>{ip}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}
