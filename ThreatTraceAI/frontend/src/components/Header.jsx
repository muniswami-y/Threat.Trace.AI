import { useState, useEffect } from 'react'
import { NavLink, Link } from 'react-router-dom'
import { api } from '../services/api'

export default function Header() {
  const [backendStatus, setBackendStatus] = useState('checking')
  const [time, setTime] = useState('')

  useEffect(() => {
    // Check backend health
    api.health()
      .then(() => setBackendStatus('online'))
      .catch(() => setBackendStatus('offline'))

    const timer = setInterval(() => {
      const now = new Date()
      setTime(now.toUTCString().slice(17, 25) + ' UTC')
    }, 1000)

    return () => clearInterval(timer)
  }, [])

  return (
    <header className="site-header">
      <div className="site-brand">
        <div className="logo-icon" style={{ width: 62, height: 62, background: 'transparent', border: 'none', padding: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <img 
            src="/logo.png" 
            alt="Threat Trace AI Logo" 
            style={{ 
              width: '100%', 
              height: '100%', 
              objectFit: 'contain',
              filter: 'drop-shadow(0 2px 8px rgba(14, 165, 233, 0.35))'
            }} 
          />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 className="title">THREAT TRACE AI</h1>
          </div>
          <div className="subtitle">
            <span>Intelligent Email Forensics & Attribution</span>
            <span>•</span>
            <span style={{ color: '#38bdf8' }}>Polygon Amoy Custody</span>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div className="sys-status-bar" style={{ display: 'none', '@media (min-width: 800px)': { display: 'flex' } }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <span className={`status-dot ${backendStatus === 'online' ? 'online' : ''}`} style={backendStatus !== 'online' ? { background: '#ef4444' } : {}} />
            <span style={{ color: backendStatus === 'online' ? '#10b981' : '#f43f5e' }}>
              API {backendStatus.toUpperCase()}
            </span>
          </div>
          <div style={{ color: '#64748b' }}>|</div>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <span className="status-dot chain" />
            <span style={{ color: '#c084fc' }}>AMOY TESTNET</span>
          </div>
          {time && (
            <>
              <div style={{ color: '#64748b' }}>|</div>
              <div style={{ color: '#94a3b8' }}>{time}</div>
            </>
          )}
        </div>

        <nav className="site-nav">
          <NavLink to="/" end className={({ isActive }) => isActive ? 'active' : ''}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect width="7" height="9" x="3" y="3" rx="1"/>
              <rect width="7" height="5" x="14" y="3" rx="1"/>
              <rect width="7" height="9" x="14" y="12" rx="1"/>
              <rect width="7" height="5" x="3" y="16" rx="1"/>
            </svg>
            <span>Cases</span>
          </NavLink>
          <NavLink to="/investigate" className={({ isActive }) => isActive ? 'active' : ''}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.3-4.3"/>
            </svg>
            <span>Forensic Studio</span>
          </NavLink>
        </nav>
      </div>
    </header>
  )
}
