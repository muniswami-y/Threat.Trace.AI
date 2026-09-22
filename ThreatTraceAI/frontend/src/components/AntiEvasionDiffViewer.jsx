import React, { useState } from 'react'

export default function AntiEvasionDiffViewer({ rawText = '', cleanText = '' }) {
  const [activeTab, setActiveTab] = useState('split') // 'split' | 'raw' | 'clean'
  const [copied, setCopied] = useState(false)

  // Detect zero-width characters or evasion artifacts
  const evasionRegex = /[\u200B-\u200D\uFEFF\u00A0\u202A-\u202E]/g
  const evasionMatches = rawText ? (rawText.match(evasionRegex) || []).length : 0
  
  // Synthetic clean text if not provided
  const normalizedStream = cleanText || (rawText ? rawText.replace(evasionRegex, '').trim() : '')

  const handleCopyClean = () => {
    if (!normalizedStream) return
    navigator.clipboard.writeText(normalizedStream)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{ background: 'var(--bg-surface-1)', padding: '20px', borderRadius: 'var(--radius-lg)', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div className="section-heading">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
            <polyline points="10 9 9 9 8 9"/>
          </svg>
          <span>ANTI-EVASION NORMALIZATION STREAM</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.74rem',
            fontWeight: 700,
            background: 'var(--bg-surface-2)',
            padding: '4px 10px',
            borderRadius: '9999px',
            color: 'var(--text-secondary)'
          }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: evasionMatches > 0 ? '#EF4444' : '#10B981' }} />
            {evasionMatches > 0 ? `${evasionMatches} Hidden Evasion Bytes Stripped` : 'Zero Hidden Bytes Detected'}
          </span>
          <span style={{
            fontSize: '0.74rem',
            fontWeight: 700,
            background: 'rgba(16, 185, 129, 0.12)',
            color: '#34D399',
            padding: '4px 10px',
            borderRadius: '9999px'
          }}>
            Confidence: +34%
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ display: 'flex', background: 'var(--bg-surface-2)', padding: '3px', borderRadius: 'var(--radius-sm)' }}>
          <button 
            style={{
              background: activeTab === 'split' ? 'var(--bg-surface-3)' : 'transparent',
              color: activeTab === 'split' ? 'var(--text-primary)' : 'var(--text-muted)',
              border: 'none',
              padding: '5px 12px',
              borderRadius: '4px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
            onClick={() => setActiveTab('split')}
          >
            Side-by-Side Diff
          </button>
          <button 
            style={{
              background: activeTab === 'raw' ? 'var(--bg-surface-3)' : 'transparent',
              color: activeTab === 'raw' ? 'var(--text-primary)' : 'var(--text-muted)',
              border: 'none',
              padding: '5px 12px',
              borderRadius: '4px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
            onClick={() => setActiveTab('raw')}
          >
            Raw Obfuscated
          </button>
          <button 
            style={{
              background: activeTab === 'clean' ? 'var(--bg-surface-3)' : 'transparent',
              color: activeTab === 'clean' ? 'var(--text-primary)' : 'var(--text-muted)',
              border: 'none',
              padding: '5px 12px',
              borderRadius: '4px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
            onClick={() => setActiveTab('clean')}
          >
            Clean NLP Stream
          </button>
        </div>

        <button className="btn-secondary-sm" onClick={handleCopyClean}>
          {copied ? '✓ Copied Stream' : 'Copy Normalized'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: activeTab === 'split' ? '1fr 1fr' : '1fr', gap: '12px' }}>
        {(activeTab === 'split' || activeTab === 'raw') && (
          <div style={{ background: 'var(--bg-terminal)', borderRadius: 'var(--radius-md)', padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#EF4444' }} />
              <span>RAW INGESTION (OBFUSCATION STREAM)</span>
            </div>
            <div style={{ maxHeight: '160px', overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeigth: 1.6 }}>
              {rawText ? (
                rawText.split('\n').slice(0, 15).map((line, idx) => (
                  <div key={idx} style={{ display: 'flex', gap: '12px' }}>
                    <span style={{ color: 'var(--text-faint)', width: '22px', textAlign: 'right', userSelect: 'none' }}>{idx + 1}</span>
                    <span style={{ color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{line || ' '}</span>
                  </div>
                ))
              ) : (
                <div style={{ color: 'var(--text-faint)', fontStyle: 'italic', padding: '8px 0', fontSize: '0.8rem' }}>No raw stream ingested</div>
              )}
            </div>
          </div>
        )}

        {(activeTab === 'split' || activeTab === 'clean') && (
          <div style={{ background: 'var(--bg-terminal)', borderRadius: 'var(--radius-md)', padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10B981' }} />
              <span>NORMALIZED TOKENIZED STREAM</span>
            </div>
            <div style={{ maxHeight: '160px', overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', lineHeight: 1.6 }}>
              {normalizedStream ? (
                normalizedStream.split('\n').slice(0, 15).map((line, idx) => (
                  <div key={idx} style={{ display: 'flex', gap: '12px' }}>
                    <span style={{ color: 'var(--text-faint)', width: '22px', textAlign: 'right', userSelect: 'none' }}>{idx + 1}</span>
                    <span style={{ color: '#34D399', wordBreak: 'break-all' }}>{line || ' '}</span>
                  </div>
                ))
              ) : (
                <div style={{ color: 'var(--text-faint)', fontStyle: 'italic', padding: '8px 0', fontSize: '0.8rem' }}>No normalized stream generated</div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
