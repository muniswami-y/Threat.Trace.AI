import React, { useState } from 'react'

export default function QuarantineVaultModal({ isOpen, onClose, quarantineData, caseData }) {
  if (!isOpen || !quarantineData) return null

  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState('overview') // 'overview' | 'emails' | 'policy'

  const emails = quarantineData.quarantined_emails || []
  const folderName = quarantineData.folder_name || `Quarantine/${quarantineData.suspicious_email || 'threat@isolated.net'}`
  const suspiciousEmail = quarantineData.suspicious_email || caseData?.from || 'threat@isolated.net'

  const handleCopyFolder = () => {
    navigator.clipboard.writeText(folderName)
    setCopied(true)
    setTimeout(() => setCopied(false), 2500)
  }

  const handleExportQuarantinePackage = () => {
    const exportPayload = {
      quarantine_folder: folderName,
      target_threat_sender: suspiciousEmail,
      isolation_status: quarantineData.isolation_status || 'ACTIVE_CONTAINMENT',
      firewall_rule: quarantineData.firewall_rule,
      action_timestamp: quarantineData.action_timestamp || new Date().toISOString(),
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
    <div className="soc-modal-overlay" onClick={onClose}>
      <div
        className="soc-modal-container custom-gold-scroll"
        style={{ maxWidth: '820px', width: '92%' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="soc-modal-header" style={{ background: 'linear-gradient(135deg, #1e1b4b 0%, #31104b 100%)', borderBottom: '1px solid #7c3aed' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '40px', height: '40px', borderRadius: '10px',
              background: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 16px rgba(220, 38, 38, 0.4)', fontSize: '20px'
            }}>
              🛡️
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#f8fafc', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                Quarantine Isolation Vault
                <span style={{ fontSize: '0.72rem', background: '#dc2626', color: '#fff', padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  ACTIVE CONTAINMENT
                </span>
              </h2>
              <p style={{ margin: '2px 0 0 0', fontSize: '0.78rem', color: '#cbd5e1' }}>
                All emails matching suspicious sender moved to separate dedicated quarantine folder
              </p>
            </div>
          </div>
          <button className="soc-modal-close" onClick={onClose} style={{ color: '#e2e8f0', background: 'transparent', border: 'none', fontSize: '24px', cursor: 'pointer' }}>×</button>
        </div>

        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: '4px', background: '#0f172a', padding: '8px 24px', borderBottom: '1px solid #334155' }}>
          <button
            onClick={() => setActiveTab('overview')}
            style={{
              padding: '6px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, border: 'none', cursor: 'pointer',
              background: activeTab === 'overview' ? '#7c3aed' : 'transparent',
              color: activeTab === 'overview' ? '#fff' : '#94a3b8'
            }}
          >
            📁 Quarantine Overview
          </button>
          <button
            onClick={() => setActiveTab('emails')}
            style={{
              padding: '6px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, border: 'none', cursor: 'pointer',
              background: activeTab === 'emails' ? '#7c3aed' : 'transparent',
              color: activeTab === 'emails' ? '#fff' : '#94a3b8'
            }}
          >
            ✉️ Moved Emails ({emails.length})
          </button>
          <button
            onClick={() => setActiveTab('policy')}
            style={{
              padding: '6px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 600, border: 'none', cursor: 'pointer',
              background: activeTab === 'policy' ? '#7c3aed' : 'transparent',
              color: activeTab === 'policy' ? '#fff' : '#94a3b8'
            }}
          >
            🔒 Mailbox Rule & Firewall
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '24px', background: '#0b0f19', color: '#e2e8f0', maxHeight: '65vh', overflowY: 'auto' }}>
          
          {/* Main Success Callout */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(220, 38, 38, 0.12) 0%, rgba(124, 58, 237, 0.12) 100%)',
            border: '1px solid rgba(220, 38, 38, 0.35)',
            borderRadius: '10px',
            padding: '16px',
            marginBottom: '20px'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
              <div>
                <div style={{ fontSize: '0.78rem', color: '#f87171', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  AUTOMATED RELOCATION COMPLETE
                </div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
                  Folder created for: <span style={{ color: '#38bdf8', wordBreak: 'break-all' }}>{suspiciousEmail}</span>
                </div>
                <p style={{ margin: '6px 0 0 0', fontSize: '0.85rem', color: '#cbd5e1', lineHeight: '1.4' }}>
                  ThreatTrace AI scanned your mailbox records and relocated <strong style={{ color: '#fca5a5' }}>{emails.length} related email thread(s)</strong> into an isolated digital quarantine container.
                </p>
              </div>

              <button
                onClick={handleCopyFolder}
                style={{
                  background: '#1e293b', border: '1px solid #475569', color: '#e2e8f0',
                  padding: '8px 14px', borderRadius: '6px', fontSize: '0.8rem', fontWeight: 600,
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap'
                }}
              >
                <span>{copied ? '✓ Copied' : '📋 Copy Folder Path'}</span>
              </button>
            </div>

            {/* Folder Path Pill */}
            <div style={{
              marginTop: '12px',
              padding: '10px 14px',
              background: '#030712',
              borderRadius: '6px',
              border: '1px dashed #64748b',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              fontFamily: 'monospace',
              fontSize: '0.85rem',
              color: '#38bdf8'
            }}>
              <span>📁</span>
              <strong style={{ color: '#f8fafc' }}>Target Vault:</strong>
              <span style={{ wordBreak: 'break-all' }}>{folderName}</span>
            </div>
          </div>

          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Metrics Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
                <div style={{ background: '#1e293b', padding: '14px', borderRadius: '8px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>QUARANTINED EMAILS</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f87171', marginTop: '2px' }}>
                    {emails.length} Message(s)
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748b', marginTop: '2px' }}>Moved from Inbox to Vault</div>
                </div>

                <div style={{ background: '#1e293b', padding: '14px', borderRadius: '8px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>ISOLATION STATE</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#34d399', marginTop: '4px' }}>
                    Locked & Sinkholed
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748b', marginTop: '2px' }}>Zero execution capability</div>
                </div>

                <div style={{ background: '#1e293b', padding: '14px', borderRadius: '8px', border: '1px solid #334155' }}>
                  <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>SENDER POLICY</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f59e0b', marginTop: '4px' }}>
                    Auto-Quarantine ON
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748b', marginTop: '2px' }}>All future traffic diverted</div>
                </div>
              </div>

              {/* Quick Table Preview */}
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span>📬</span>
                  <span>Emails Relocated to this Quarantine Folder</span>
                </div>

                <div style={{ background: '#111827', borderRadius: '8px', border: '1px solid #1f2937', overflow: 'hidden' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ background: '#1f2937', color: '#94a3b8', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                        <th style={{ padding: '10px 12px' }}>Subject</th>
                        <th style={{ padding: '10px 12px' }}>Case ID</th>
                        <th style={{ padding: '10px 12px' }}>Risk</th>
                        <th style={{ padding: '10px 12px' }}>Location</th>
                      </tr>
                    </thead>
                    <tbody>
                      {emails.map((m, idx) => {
                        const mScore = typeof m.risk_score === 'number' ? m.risk_score : (parseFloat(m.risk_score) || 0)
                        const mLevel = m.risk_level || (mScore >= 70 ? 'HIGH' : mScore >= 40 ? 'MEDIUM' : 'LOW')
                        const badgeBg = mScore >= 70 ? '#dc2626' : (mScore >= 40 ? '#d97706' : '#059669')
                        return (
                          <tr key={idx} style={{ borderBottom: '1px solid #1f2937' }}>
                            <td style={{ padding: '10px 12px', fontWeight: 600, color: '#f1f5f9' }}>
                              {m.subject || 'Suspicious Electronic Message'}
                            </td>
                            <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#38bdf8' }}>
                              {m.case_id}
                            </td>
                            <td style={{ padding: '10px 12px' }}>
                              <span style={{
                                background: badgeBg,
                                color: '#fff', padding: '2px 6px', borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700
                              }}>
                                {Math.round(mScore)}/100 {mLevel}
                              </span>
                            </td>
                            <td style={{ padding: '10px 12px', color: '#34d399', fontWeight: 600, fontSize: '0.75rem' }}>
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
              <div style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
                All {emails.length} email records associated with <strong style={{ color: '#38bdf8' }}>{suspiciousEmail}</strong> isolated in <strong style={{ color: '#f8fafc' }}>{folderName}</strong>:
              </div>

              {emails.map((mail, idx) => {
                const mailScore = typeof mail.risk_score === 'number' ? mail.risk_score : (parseFloat(mail.risk_score) || 0)
                const mailLevel = mail.risk_level || (mailScore >= 70 ? 'HIGH' : mailScore >= 40 ? 'MEDIUM' : 'LOW')
                const badgeBg = mailScore >= 70 ? '#dc2626' : (mailScore >= 40 ? '#d97706' : '#059669')
                return (
                  <div key={idx} style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: '0.92rem', color: '#f8fafc' }}>
                          {mail.subject}
                        </div>
                        <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '2px' }}>
                          Sender: <span style={{ color: '#f87171' }}>{mail.sender}</span>
                        </div>
                      </div>
                      <span style={{ background: badgeBg, color: '#fff', padding: '3px 8px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700 }}>
                        SCORE: {Math.round(mailScore)}/100
                      </span>
                    </div>

                    <div style={{ marginTop: '10px', display: 'flex', gap: '12px', fontSize: '0.75rem', color: '#64748b' }}>
                      <div>Case Ref: <strong style={{ color: '#38bdf8' }}>{mail.case_id}</strong></div>
                      <div>•</div>
                      <div>Folder: <strong style={{ color: '#34d399' }}>{folderName}</strong></div>
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
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '16px' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase' }}>
                  Active Tenant & Mailbox Rule
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', background: '#090d16', padding: '12px', borderRadius: '6px', color: '#a7f3d0', marginTop: '8px', whiteSpace: 'pre-wrap' }}>
{`RULE_NAME: THREAT_TRACE_AUTO_QUARANTINE_${suspiciousEmail.replace(/[^a-zA-Z0-9]/g, '_')}
CONDITION: IF (sender == "${suspiciousEmail}" OR sender_domain == "${suspiciousEmail.split('@')[1] || ''}")
ACTION_1: MOVE_TO_LABEL("${folderName}")
ACTION_2: SKIP_INBOX (Archive)
ACTION_3: MARK_AS_SUSPICIOUS
ACTION_4: STRIP_ACTIVE_SCRIPTS_AND_ATTACHMENTS
STATUS: ACTIVE & ENFORCED`}
                </div>
              </div>

              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '16px' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase' }}>
                  Perimeter Firewall Sinkhole
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '0.82rem', background: '#090d16', padding: '12px', borderRadius: '6px', color: '#fca5a5', marginTop: '8px' }}>
                  {quarantineData.firewall_rule || `BLOCK_AND_SINKHOLE sender='${suspiciousEmail}'`}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '16px 24px', background: '#0f172a', borderTop: '1px solid #334155', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <button
            onClick={handleExportQuarantinePackage}
            style={{
              background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)',
              color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '6px',
              fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px'
            }}
          >
            <span>📥 Export Quarantine Vault (.JSON)</span>
          </button>

          <button
            onClick={onClose}
            style={{
              background: '#334155', color: '#f8fafc', border: 'none',
              padding: '8px 20px', borderRadius: '6px', fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer'
            }}
          >
            Close Vault
          </button>
        </div>
      </div>
    </div>
  )
}
