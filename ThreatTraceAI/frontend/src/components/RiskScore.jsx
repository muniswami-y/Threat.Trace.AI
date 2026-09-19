export default function RiskScore({ score = 0, level = 'LOW', recommendation = '' }) {
  const rounded = Math.round(score)
  
  // Visual config based on level
  const isHigh = level === 'HIGH' || rounded >= 70
  const isMed = (level === 'MEDIUM' || (rounded >= 40 && rounded < 70)) && !isHigh
  
  const color = isHigh ? '#f43f5e' : isMed ? '#fbbf24' : '#10b981'
  const glow = isHigh ? 'rgba(244, 63, 94, 0.4)' : isMed ? 'rgba(251, 191, 36, 0.4)' : 'rgba(16, 185, 129, 0.4)'
  const badgeClass = isHigh ? 'badge-critical' : isMed ? 'badge-warning' : 'badge-safe'
  
  // Radial SVG calculation
  const radius = 64
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (rounded / 100) * circumference

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', position: 'relative', overflow: 'hidden' }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '3px', background: color, boxShadow: `0 0 12px ${color}` }} />
      
      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700, marginBottom: '0.75rem' }}>
        Forensic Threat Score
      </div>

      <div className="gauge-wrapper" style={{ width: '160px', height: '160px', position: 'relative' }}>
        <svg className="gauge-svg" width="160" height="160" viewBox="0 0 160 160">
          <circle
            className="gauge-bg"
            cx="80"
            cy="80"
            r={radius}
            strokeWidth="12"
            fill="none"
          />
          <circle
            className="gauge-progress"
            cx="80"
            cy="80"
            r={radius}
            strokeWidth="12"
            fill="none"
            stroke={color}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 8px ${glow})` }}
          />
        </svg>

        <div className="gauge-inner-text">
          <div className="gauge-num" style={{ color: '#fff', textShadow: `0 0 15px ${glow}` }}>
            {rounded}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>
            / 100 MAX
          </div>
        </div>
      </div>

      <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.4rem' }}>
        <span className={`badge ${badgeClass}`} style={{ fontSize: '0.82rem', padding: '0.35rem 0.85rem' }}>
          {level} SEVERITY
        </span>
        {recommendation && (
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Action: <strong style={{ color: color }}>{recommendation}</strong>
          </div>
        )}
      </div>
    </div>
  )
}
