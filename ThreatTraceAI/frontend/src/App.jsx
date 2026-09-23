import React from 'react'
import { Routes, Route } from 'react-router-dom'
import ThreatTraceCockpit from './pages/ThreatTraceCockpit'
import CybercrimeAdminDashboard from './cybercrime/CybercrimeAdminDashboard'
import PrivacyPolicy from './pages/PrivacyPolicy'
import TermsOfService from './pages/TermsOfService'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ThreatTrace AI] Render Error Caught:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          background: '#0F172A',
          color: '#F8FAFC',
          fontFamily: 'system-ui, sans-serif',
          padding: '24px',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '12px' }}>🚨</div>
          <p style={{ color: '#94A3B8', fontSize: '0.88rem', maxWidth: '480px', marginBottom: '14px' }}>
            A rendering exception occurred while parsing live email streams. Click below to safely reset and launch the Cockpit.
          </p>
          {this.state.error && (
            <div style={{
              background: '#030712',
              border: '1px solid #DC2626',
              borderRadius: '8px',
              padding: '10px 16px',
              color: '#F87171',
              fontFamily: 'monospace',
              fontSize: '0.78rem',
              maxWidth: '680px',
              overflowX: 'auto',
              marginBottom: '18px',
              textAlign: 'left'
            }}>
              <strong>Error:</strong> {String(this.state.error?.message || this.state.error)}
            </div>
          )}
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={() => {
                localStorage.removeItem('tt_active_case')
                window.location.href = '/'
              }}
              style={{
                background: '#0284C7',
                color: '#FFFFFF',
                border: 'none',
                padding: '10px 20px',
                borderRadius: '8px',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Reset to Clean Cockpit
            </button>
            <button
              onClick={() => window.location.reload()}
              style={{
                background: '#334155',
                color: '#FFFFFF',
                border: 'none',
                padding: '10px 18px',
                borderRadius: '8px',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Reload Page
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/" element={<ThreatTraceCockpit />} />
        <Route path="/case/:caseId" element={<ThreatTraceCockpit />} />
        <Route path="/cybercrime" element={<CybercrimeAdminDashboard />} />
        <Route path="/cybercrime/admin" element={<CybercrimeAdminDashboard />} />
        <Route path="/privacy" element={<PrivacyPolicy />} />
        <Route path="/terms" element={<TermsOfService />} />
        <Route path="*" element={<ThreatTraceCockpit />} />
      </Routes>
    </ErrorBoundary>
  )
}


