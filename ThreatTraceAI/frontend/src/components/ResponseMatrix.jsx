export default function ResponseMatrix({ recommendation = 'ALLOW', factors = [] }) {
  const isQuarantine = recommendation === 'QUARANTINE'
  const isReview = recommendation === 'REVIEW'

  const matrixConfig = {
    QUARANTINE: {
      title: 'Automated Containment: Immediate Quarantine',
      color: '#f43f5e',
      badge: 'badge-critical',
      actions: [
        { label: 'Message Purge / Quarantine', desc: 'Isolate message from recipient mailbox across Google Workspace / Exchange tenant.' },
        { label: 'Domain & IP Perimeter Block', desc: 'Push sender domain and redirect landing host to enterprise firewall / DNS sinkhole.' },
        { label: 'SOC Escalation & Ticket Creation', desc: 'Dispatch priority P1 security ticket with full IOC dossier and hash chain.' },
        { label: 'Credential Invalidation Check', desc: 'Trigger automated password reset if recipient visited link within last 2 hours.' }
      ]
    },
    REVIEW: {
      title: 'Automated Containment: Analyst Triage Required',
      color: '#fbbf24',
      badge: 'badge-warning',
      actions: [
        { label: 'Temporary Link Neutralization', desc: 'Rewrite links to caution splash page while sandbox evaluation completes.' },
        { label: 'Flag in Security Queue', desc: 'Mark as suspicious awaiting human verification of invoice / payment instructions.' },
        { label: 'Sender Reputation Challenge', desc: 'Request out-of-band verification via corporate Slack or Teams.' }
      ]
    },
    ALLOW: {
      title: 'Standard Delivery: Verified Safe',
      color: '#10b981',
      badge: 'badge-safe',
      actions: [
        { label: 'Standard Inbox Delivery', desc: 'Email meets domain alignment, SPF/DKIM verification, and clean URL inspection.' },
        { label: 'Passive Telemetry Logging', desc: 'Log forensic signature for internal baseline model training.' }
      ]
    }
  }

  const current = matrixConfig[recommendation] || matrixConfig.ALLOW

  return (
    <div className="card" style={{ borderTop: `3px solid ${current.color}` }}>
      <div className="card-header">
        <div className="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={current.color} strokeWidth="2">
            <rect width="18" height="18" x="3" y="3" rx="2"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
          <span>Automated SOC Playbook Matrix</span>
        </div>
        <span className={`badge ${current.badge}`}>{recommendation}</span>
      </div>

      <div style={{ marginBottom: '1rem', fontWeight: 600, color: '#fff', fontSize: '0.95rem' }}>
        {current.title}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
        {current.actions.map((act, i) => (
          <div key={i} style={{ background: '#090e18', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '10px', padding: '0.85rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
              <span style={{ color: current.color, fontWeight: 700 }}>✓</span>
              <strong style={{ fontSize: '0.88rem', color: '#f1f5f9' }}>{act.label}</strong>
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
              {act.desc}
            </div>
          </div>
        ))}
      </div>

      {factors.length > 0 && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.6rem' }}>
          <strong>Playbook Trigger Traces:</strong> {factors.slice(0, 3).join(' • ')}
        </div>
      )}
    </div>
  )
}
