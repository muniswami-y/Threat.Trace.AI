import { useState } from 'react'

export default function InfrastructureGraph({ graph }) {
  const [selectedNode, setSelectedNode] = useState(null)

  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
              <circle cx="18" cy="5" r="3"/>
              <circle cx="6" cy="12" r="3"/>
              <circle cx="18" cy="19" r="3"/>
              <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
              <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
            </svg>
            <span>Infrastructure Attribution Topology</span>
          </div>
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          No infrastructure nodes linked to this incident.
        </div>
      </div>
    )
  }

  const nodes = graph.nodes || []
  const edges = graph.edges || []

  const getNodeColor = (type) => {
    switch (type) {
      case 'sender': return { bg: 'rgba(56, 189, 248, 0.15)', border: '#38bdf8', text: '#38bdf8', icon: '👤' }
      case 'domain': return { bg: 'rgba(129, 140, 248, 0.15)', border: '#818cf8', text: '#818cf8', icon: '🌐' }
      case 'ip': return { bg: 'rgba(251, 191, 36, 0.15)', border: '#fbbf24', text: '#fbbf24', icon: '🖥️' }
      case 'url': return { bg: 'rgba(244, 63, 94, 0.15)', border: '#f43f5e', text: '#f43f5e', icon: '🎯' }
      default: return { bg: 'rgba(148, 163, 184, 0.15)', border: '#94a3b8', text: '#94a3b8', icon: '📌' }
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
            <circle cx="18" cy="5" r="3"/>
            <circle cx="6" cy="12" r="3"/>
            <circle cx="18" cy="19" r="3"/>
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
          </svg>
          <span>Infrastructure Attribution Topology ({nodes.length} Nodes • {edges.length} Links)</span>
        </div>
        <div style={{ display: 'flex', gap: '6px' }}>
          <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}>Sender</span>
          <span className="badge" style={{ background: 'rgba(129, 140, 248, 0.1)', color: '#818cf8', border: '1px solid rgba(129, 140, 248, 0.3)' }}>Domain</span>
          <span className="badge" style={{ background: 'rgba(251, 191, 36, 0.1)', color: '#fbbf24', border: '1px solid rgba(251, 191, 36, 0.3)' }}>IP</span>
          <span className="badge" style={{ background: 'rgba(244, 63, 94, 0.1)', color: '#f43f5e', border: '1px solid rgba(244, 63, 94, 0.3)' }}>URL</span>
        </div>
      </div>

      {/* Visual interactive graph map */}
      <div className="graph-container">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '0.85rem' }}>
          {nodes.map((node) => {
            const style = getNodeColor(node.type)
            const isSelected = selectedNode?.id === node.id

            return (
              <div
                key={node.id}
                onClick={() => setSelectedNode(node)}
                className="graph-node"
                style={{
                  background: isSelected ? style.bg : '#0b1220',
                  borderColor: isSelected ? style.border : 'rgba(255, 255, 255, 0.08)',
                  cursor: 'pointer',
                  boxShadow: isSelected ? `0 0 16px ${style.border}44` : 'none'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '1rem' }}>{style.icon}</span>
                  <span className="badge" style={{ background: style.bg, color: style.text, border: `1px solid ${style.border}44`, fontSize: '0.7rem' }}>
                    {node.type.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#f1f5f9', wordBreak: 'break-all', fontFamily: node.type !== 'sender' ? 'var(--font-mono)' : 'inherit' }}>
                  {node.label || node.id}
                </div>
              </div>
            )
          })}
        </div>

        {/* Edges representation */}
        {edges.length > 0 && (
          <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.6rem', fontWeight: 700 }}>
              Observed Correlation Vectors
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {edges.map((edge, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    padding: '4px 10px',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                    fontFamily: 'var(--font-mono)'
                  }}
                >
                  <span style={{ color: '#38bdf8' }}>{edge.from.slice(0, 20)}</span>
                  <span style={{ color: 'var(--text-dim)' }}>→</span>
                  <span style={{ color: '#f43f5e' }}>{edge.to.slice(0, 24)}</span>
                  <span style={{ color: '#a855f7', fontSize: '0.7rem', background: '#a855f715', padding: '1px 5px', borderRadius: '4px' }}>
                    ({edge.label})
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {selectedNode && (
          <div style={{ marginTop: '1rem', padding: '0.85rem', background: '#060a12', borderRadius: '10px', border: '1px solid #38bdf855' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <strong style={{ color: '#38bdf8', fontSize: '0.85rem' }}>SELECTED ARTIFACT</strong>
              <button className="ghost" style={{ padding: '2px 6px', fontSize: '0.75rem' }} onClick={() => setSelectedNode(null)}>Dismiss</button>
            </div>
            <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: '#e2e8f0', wordBreak: 'break-all' }}>
              Type: <strong>{selectedNode.type}</strong> | Value: <strong>{selectedNode.label || selectedNode.id}</strong>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
