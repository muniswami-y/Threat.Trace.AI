export default function RiskFactors({ factors = [] }) {
  if (!factors.length) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>Explainable Threat Rubric</span>
          </div>
          <span className="badge badge-safe">Clean Record</span>
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          No threat or spoofing indicators detected in headers or body text.
        </div>
      </div>
    )
  }

  const getFactorMeta = (text) => {
    const t = text.toLowerCase()
    if (t.includes('spf') || t.includes('dkim') || t.includes('dmarc') || t.includes('header') || t.includes('return-path')) {
      return {
        category: 'HEADER / AUTH',
        icon: '🛡️',
        color: '#f43f5e',
        weight: t.includes('fail') ? '+25 pts' : '+8 pts'
      }
    }
    if (t.includes('url') || t.includes('phishing') || t.includes('feed')) {
      return {
        category: 'INTEL BLACKLIST',
        icon: '⚡',
        color: '#ef4444',
        weight: '+30 pts'
      }
    }
    if (t.includes('credential') || t.includes('password') || t.includes('login') || t.includes('otp')) {
      return {
        category: 'CREDENTIAL HARVEST',
        icon: '🔑',
        color: '#f59e0b',
        weight: '+18 pts'
      }
    }
    if (t.includes('urgency') || t.includes('threat') || t.includes('short body')) {
      return {
        category: 'SOCIAL ENGINEERING',
        icon: '⚠️',
        color: '#fbbf24',
        weight: '+12 pts'
      }
    }
    if (t.includes('financial') || t.includes('payment') || t.includes('wire')) {
      return {
        category: 'FINANCIAL FRAUD',
        icon: '💳',
        color: '#ec4899',
        weight: '+15 pts'
      }
    }
    return {
      category: 'FORENSIC SIGNAL',
      icon: '🔍',
      color: '#38bdf8',
      weight: '+10 pts'
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
            <polyline points="10 9 9 9 8 9"/>
          </svg>
          <span>Explainable Threat Rubric ({factors.length} Signals)</span>
        </div>
        <span className="badge badge-purple">Transparent Attribution</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
        {factors.map((factor, i) => {
          const meta = getFactorMeta(factor)
          return (
            <div key={i} className="factor-card" style={{ borderLeft: `3px solid ${meta.color}` }}>
              <div style={{ fontSize: '1.2rem', lineHeight: 1 }}>{meta.icon}</div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                  <span className="factor-badge" style={{ background: `${meta.color}22`, color: meta.color, border: `1px solid ${meta.color}44` }}>
                    {meta.category}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    {meta.weight}
                  </span>
                </div>
                <div style={{ color: '#e2e8f0', fontWeight: 500 }}>
                  {factor}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
