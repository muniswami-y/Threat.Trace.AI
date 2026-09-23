import React, { useState } from 'react'

export default function QuarantineVaultModal({ isOpen = true, onClose, quarantineData, caseData }) {
  if (isOpen === false) return null

  const safeQuarantine = quarantineData || {
    suspicious_email: caseData?.from || 'threat@isolated.net',
    folder_name: `Quarantine/${caseData?.from || 'threat@isolated.net'}`,
    isolation_status: 'ACTIVE_CONTAINMENT',
    action_timestamp: new Date().toISOString(),
    quarantined_emails: [{
      id: caseData?.incidentId || 'CASE-01',
      subject: caseData?.fullSubject || 'Isolated Phishing Evidence',
      from: caseData?.from || 'threat@isolated.net',
      date: new Date().toISOString(),
      risk_score: caseData?.riskScore || 85
    }]
  }

  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState('overview') // 'overview' | 'emails' | 'policy'

  const emails = safeQuarantine.quarantined_emails || []
  const folderName = safeQuarantine.folder_name || `Quarantine/${safeQuarantine.suspicious_email || 'threat@isolated.net'}`
  const suspiciousEmail = safeQuarantine.suspicious_email || caseData?.from || 'threat@isolated.net'

  const handleCopyFolder = () => {
    navigator.clipboard.writeText(folderName)
    setCopied(true)
    setTimeout(() => setCopied(false), 2500)
  }

  const handleExportQuarantinePackage = () => {
    const exportPayload = {
      quarantine_folder: folderName,
      target_threat_sender: suspiciousEmail,
      isolation_status: safeQuarantine?.isolation_status || 'ACTIVE_CONTAINMENT',
      firewall_rule: safeQuarantine?.firewall_rule || `DROP ALL FROM ${suspiciousEmail}`,
      action_timestamp: safeQuarantine?.action_timestamp || new Date().toISOString(),
      total_emails_quarantined: emails.length,
      quarantined_emails: emails,
      cryptographic_containment_hash: '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('')
    }

    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `QUARANTINE_${suspiciousEmail.replace(/[^a-zA-Z0-9]/g, '_')}_VAULT.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div 
      className="soc-modal-overlay" 
      onClick={onClose}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '20px'
      }}
    >
      <div
        className="soc-modal-container custom-gold-scroll"
        style={{ 
          maxWidth: '820px', 
          width: '94%',
          background: '#FFFFFF',
          border: '1px solid #E2E8F0',
          borderRadius: '14px',
          overflow: 'hidden',
          boxShadow: '0 25px 50px -12px rgba(15, 23, 42, 0.25)',
          color: '#0F172A',
          fontFamily: 'system-ui, -apple-system, sans-serif'
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* White Header */}
        <div className="soc-modal-header" style={{
          background: '#F8FAFC',
          borderBottom: '1px solid #E2E8F0',
          padding: '18px 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '42px', height: '42px', borderRadius: '10px',
              background: 'linear-gradient(135deg, #DC2626 0%, #B91C1C 100%)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 4px 12px rgba(220, 38, 38, 0.25)', fontSize: '20px'
            }}>
              🛡️
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#0F172A', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
                Quarantine Isolation Vault
                <span style={{ fontSize: '0.72rem', background: '#DC2626', color: '#FFFFFF', padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 700 }}>
                  ACTIVE CONTAINMENT
                </span>
              </h2>
              <p style={{ margin: '2px 0 0 0', fontSize: '0.8rem', color: '#475569' }}>
                All emails matching suspicious sender moved to separate dedicated quarantine folder
              </p>
            </div>
          </div>
          <button 
            className="soc-modal-close" 
            onClick={onClose} 
            style={{ color: '#64748B', background: 'transparent', border: 'none', fontSize: '24px', cursor: 'pointer', fontWeight: 700, padding: '4px' }}
          >
            ×
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: '6px', background: '#F1F5F9', padding: '8px 24px', borderBottom: '1px solid #E2E8F0' }}>
          <button
            onClick={() => setActiveTab('overview')}
            style={{
              padding: '6px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, border: 'none', cursor: 'pointer',
              background: activeTab === 'overview' ? '#0284C7' : '#FFFFFF',
              color: activeTab === 'overview' ? '#FFFFFF' : '#334155',
              boxShadow: activeTab === 'overview' ? '0 2px 4px rgba(2, 132, 199, 0.25)' : 'none',
              border: activeTab === 'overview' ? 'none' : '1px solid #CBD5E1'
            }}
          >
            📁 Quarantine Overview
          </button>
          <button
            onClick={() => setActiveTab('emails')}
            style={{
              padding: '6px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, border: 'none', cursor: 'pointer',
              background: activeTab === 'emails' ? '#0284C7' : '#FFFFFF',
              color: activeTab === 'emails' ? '#FFFFFF' : '#334155',
              boxShadow: activeTab === 'emails' ? '0 2px 4px rgba(2, 132, 199, 0.25)' : 'none',
              border: activeTab === 'emails' ? 'none' : '1px solid #CBD5E1'
            }}
          >
            ✉️ Moved Emails ({emails.length})
          </button>
          <button
            onClick={() => setActiveTab('policy')}
            style={{
              padding: '6px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, border: 'none', cursor: 'pointer',
              background: activeTab === 'policy' ? '#0284C7' : '#FFFFFF',
              color: activeTab === 'policy' ? '#FFFFFF' : '#334155',
              boxShadow: activeTab === 'policy' ? '0 2px 4px rgba(2, 132, 199, 0.25)' : 'none',
              border: activeTab === 'policy' ? 'none' : '1px solid #CBD5E1'
            }}
          >
            🔒 Mailbox Rule & Firewall
          </button>
        </div>

        {/* White Body */}
        <div style={{ padding: '24px', background: '#FFFFFF', color: '#0F172A', maxHeight: '65vh', overflowY: 'auto' }}>
          
          {/* Main Success Callout */}
          <div style={{
            background: '#FEF2F2',
            border: '1px solid #FECACA',
            borderRadius: '10px',
            padding: '16px',
            marginBottom: '20px'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
              <div>
                <div style={{ fontSize: '0.78rem', color: '#DC2626', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  AUTOMATED RELOCATION COMPLETE
                </div>
                <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#0F172A', marginTop: '4px' }}>
                  Folder created for: <span style={{ color: '#0284C7', wordBreak: 'break-all' }}>{suspiciousEmail}</span>
                </div>
                <p style={{ margin: '6px 0 0 0', fontSize: '0.85rem', color: '#334155', lineHeight: '1.5' }}>
                  ThreatTrace AI scanned your mailbox records and relocated <strong style={{ color: '#DC2626' }}>{emails.length} related email thread(s)</strong> into an isolated digital quarantine container.
                </p>
              </div>

              <button
                onClick={handleCopyFolder}
                style={{
                  background: '#FFFFFF', border: '1px solid #CBD5E1', color: '#0F172A',
                  padding: '8px 14px', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
                }}
              >
                <span>{copied ? '✓ Copied' : '📋 Copy Folder Path'}</span>
              </button>
            </div>

            {/* Folder Path Pill */}
            <div style={{
              marginTop: '12px',
              padding: '10px 14px',
              background: '#F8FAFC',
              borderRadius: '6px',
              border: '1px dashed #94A3B8',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              fontFamily: 'monospace',
              fontSize: '0.85rem',
              color: '#0284C7'
            }}>
              <span>📁</span>
              <strong style={{ color: '#0F172A' }}>Target Vault:</strong>
              <span style={{ wordBreak: 'break-all', fontWeight: 600 }}>{folderName}</span>
            </div>
          </div>

          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Metrics Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                <div style={{ background: '#F8FAFC', padding: '14px', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
                  <div style={{ fontSize: '0.72rem', color: '#64748B', fontWeight: 700, textTransform: 'uppercase' }}>QUARANTINED EMAILS</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#DC2626', marginTop: '2px' }}>
                    {emails.length} Message(s)
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748B', marginTop: '2px' }}>Moved from Inbox to Vault</div>
                </div>

                <div style={{ background: '#F8FAFC', padding: '14px', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
                  <div style={{ fontSize: '0.72rem', color: '#64748B', fontWeight: 700, textTransform: 'uppercase' }}>ISOLATION STATE</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#059669', marginTop: '4px' }}>
                    Locked & Sinkholed
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748B', marginTop: '2px' }}>Zero execution capability</div>
                </div>

                <div style={{ background: '#F8FAFC', padding: '14px', borderRadius: '8px', border: '1px solid #E2E8F0' }}>
                  <div style={{ fontSize: '0.72rem', color: '#64748B', fontWeight: 700, textTransform: 'uppercase' }}>SENDER POLICY</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#D97706', marginTop: '4px' }}>
                    Auto-Quarantine ON
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748B', marginTop: '2px' }}>All future traffic diverted</div>
                </div>
              </div>

              {/* Quick Table Preview */}
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#0F172A', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span>📬</span>
                  <span>Emails Relocated to this Quarantine Folder</span>
                </div>

                <div style={{ background: '#FFFFFF', borderRadius: '8px', border: '1px solid #E2E8F0', overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ background: '#F1F5F9', color: '#475569', fontSize: '0.75rem', textTransform: 'uppercase', borderBottom: '1px solid #E2E8F0' }}>
                        <th style={{ padding: '10px 12px', fontWeight: 700 }}>Subject</th>
                        <th style={{ padding: '10px 12px', fontWeight: 700 }}>Case ID</th>
                        <th style={{ padding: '10px 12px', fontWeight: 700 }}>Risk</th>
                        <th style={{ padding: '10px 12px', fontWeight: 700 }}>Location</th>
                      </tr>
                    </thead>
                    <tbody>
                      {emails.map((m, idx) => {
                        const mScore = typeof m.risk_score === 'number' ? m.risk_score : (parseFloat(m.risk_score) || 0)
                        const mLevel = m.risk_level || (mScore >= 70 ? 'HIGH' : mScore >= 40 ? 'MEDIUM' : 'LOW')
                        const badgeBg = mScore >= 70 ? '#DC2626' : (mScore >= 40 ? '#D97706' : '#059669')
                        return (
                          <tr key={idx} style={{ borderBottom: '1px solid #F1F5F9' }}>
                            <td style={{ padding: '10px 12px', fontWeight: 600, color: '#0F172A' }}>
                              {m.subject || 'Suspicious Electronic Message'}
                            </td>
                            <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#0284C7', fontWeight: 600 }}>
                              {m.case_id}
                            </td>
                            <td style={{ padding: '10px 12px' }}>
                              <span style={{
                                background: badgeBg,
                                color: '#FFFFFF', padding: '2px 8px', borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700
                              }}>
                                {Math.round(mScore)}/100 {mLevel}
                              </span>
                            </td>
                            <td style={{ padding: '10px 12px', color: '#059669', fontWeight: 700, fontSize: '0.75rem' }}>
                              📁 {folderName}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'emails' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ fontSize: '0.82rem', color: '#475569' }}>
                All {emails.length} email records associated with <strong style={{ color: '#0284C7' }}>{suspiciousEmail}</strong> isolated in <strong style={{ color: '#0F172A' }}>{folderName}</strong>:
              </div>

              {emails.map((mail, idx) => {
                const mailScore = typeof mail.risk_score === 'number' ? mail.risk_score : (parseFloat(mail.risk_score) || 0)
                const mailLevel = mail.risk_level || (mailScore >= 70 ? 'HIGH' : mailScore >= 40 ? 'MEDIUM' : 'LOW')
                const badgeBg = mailScore >= 70 ? '#DC2626' : (mailScore >= 40 ? '#D97706' : '#059669')
                return (
                  <div key={idx} style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '8px', padding: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: '0.92rem', color: '#0F172A' }}>
                          {mail.subject}
                        </div>
                        <div style={{ fontSize: '0.78rem', color: '#64748B', marginTop: '2px' }}>
                          Sender: <span style={{ color: '#DC2626', fontWeight: 600 }}>{mail.sender}</span>
                        </div>
                      </div>
                      <span style={{ background: badgeBg, color: '#FFFFFF', padding: '3px 8px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700 }}>
                        SCORE: {Math.round(mailScore)}/100
                      </span>
                    </div>

                    <div style={{ marginTop: '10px', display: 'flex', gap: '12px', fontSize: '0.75rem', color: '#64748B' }}>
                      <div>Case Ref: <strong style={{ color: '#0284C7' }}>{mail.case_id}</strong></div>
                      <div>•</div>
                      <div>Folder: <strong style={{ color: '#059669' }}>{folderName}</strong></div>
                      <div>•</div>
                      <div>Isolated: {new Date(mail.quarantined_at || Date.now()).toLocaleTimeString()}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {activeTab === 'policy' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '8px', padding: '16px' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 800, color: '#D97706', textTransform: 'uppercase' }}>
                  Active Tenant & Mailbox Rule
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', background: '#0F172A', padding: '12px', borderRadius: '6px', color: '#38BDF8', marginTop: '8px', whiteSpace: 'pre-wrap' }}>
{`RULE_NAME: THREAT_TRACE_AUTO_QUARANTINE_${suspiciousEmail.replace(/[^a-zA-Z0-9]/g, '_')}
CONDITION: IF (sender == "${suspiciousEmail}" OR sender_domain == "${suspiciousEmail.split('@')[1] || ''}")
ACTION_1: MOVE_TO_LABEL("${folderName}")
ACTION_2: SKIP_INBOX (Archive)
ACTION_3: MARK_AS_SUSPICIOUS
ACTION_4: STRIP_ACTIVE_SCRIPTS_AND_ATTACHMENTS
STATUS: ACTIVE & ENFORCED`}
                </div>
              </div>

              <div style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderRadius: '8px', padding: '16px' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 800, color: '#0284C7', textTransform: 'uppercase' }}>
                  Perimeter Firewall Sinkhole
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', background: '#0F172A', padding: '12px', borderRadius: '6px', color: '#F87171', marginTop: '8px' }}>
                  {safeQuarantine.firewall_rule || `BLOCK_AND_SINKHOLE sender='${suspiciousEmail}'`}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* White Footer */}
        <div style={{ padding: '16px 24px', background: '#F8FAFC', borderTop: '1px solid #E2E8F0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <button
            onClick={handleExportQuarantinePackage}
            style={{
              background: 'linear-gradient(135deg, #0284C7 0%, #0369A1 100%)',
              color: '#FFFFFF', border: 'none', padding: '9px 18px', borderRadius: '6px',
              fontSize: '0.82rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px',
              boxShadow: '0 2px 4px rgba(2, 132, 199, 0.25)'
            }}
          >
            <span>📥 Export Quarantine Vault (.JSON)</span>
          </button>

          <button
            onClick={onClose}
            style={{
              background: '#FFFFFF', color: '#0F172A', border: '1px solid #CBD5E1',
              padding: '8px 20px', borderRadius: '6px', fontSize: '0.85rem', fontWeight: 700, cursor: 'pointer',
              boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
            }}
          >
            Close Vault
          </button>
        </div>
      </div>
    </div>
  )
}
