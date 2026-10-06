import React, { useState } from 'react'
import ThreatGlobe3D from './ThreatGlobe3D'

export default function IPGeolocation({ locations = [] }) {
  const [viewMode, setViewMode] = useState('3d') // '3d' | 'grid'

  if (!locations || locations.length === 0) return null

  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
          <span>3D Geographical Threat Attribution ({locations.length} Origin Coordinates)</span>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ display: 'flex', background: 'rgba(255, 255, 255, 0.05)', padding: '2px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <button
              onClick={() => setViewMode('3d')}
              style={{
                background: viewMode === '3d' ? '#0284c7' : 'transparent',
                color: viewMode === '3d' ? '#fff' : '#94a3b8',
                border: 'none',
                padding: '3px 10px',
                borderRadius: '4px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              🌐 3D Globe
            </button>
            <button
              onClick={() => setViewMode('grid')}
              style={{
                background: viewMode === 'grid' ? '#0284c7' : 'transparent',
                color: viewMode === 'grid' ? '#fff' : '#94a3b8',
                border: 'none',
                padding: '3px 10px',
                borderRadius: '4px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              📋 Coordinates
            </button>
          </div>
          <span className="badge badge-cyan">Live 3D Telemetry</span>
        </div>
      </div>

      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
        Interactive 3D WebGL GeoIP telemetry tracking: drag to rotate the globe in 3D space, inspect origin coordinates, and trace multi-hop relay hops.
      </div>

      {/* 3D WebGL Globe View */}
      {viewMode === '3d' && (
        <div style={{ marginBottom: '1.2rem' }}>
          <ThreatGlobe3D locations={locations} height={340} />
        </div>
      )}

      {/* Origin IP Cards Grid */}
      <div className="grid grid-2">
        {locations.map((geo, idx) => {
          const isSuccess = geo.status === 'success'
          
          return (
            <div
              key={idx}
              style={{
                background: '#0a101d',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '12px',
                padding: '1.2rem',
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              <div style={{ position: 'absolute', top: 0, left: 0, width: '3px', height: '100%', background: isSuccess ? '#38bdf8' : '#f43f5e' }} />

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.95rem', color: '#fff' }}>
                  {geo.ip}
                </div>
                <span className={`badge ${isSuccess ? 'badge-cyan' : 'badge-critical'}`}>
                  {isSuccess ? 'RESOLVED' : 'UNRESOLVED'}
                </span>
              </div>

              {isSuccess ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.85rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#f1f5f9' }}>
                    <span style={{ fontSize: '1.1rem' }}>📍</span>
                    <strong>{geo.city || 'Unknown City'}, {geo.region || ''}</strong> ({geo.country || 'Unknown'})
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    Lat: {geo.lat} • Lon: {geo.lon}
                  </div>
                  <div style={{ color: '#cbd5e1', fontSize: '0.82rem', background: 'rgba(255, 255, 255, 0.03)', padding: '4px 8px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                    ISP / ASN: <strong>{geo.isp || geo.org || 'Unknown Provider'}</strong>
                  </div>
                </div>
              ) : (
                <div style={{ color: '#f43f5e', fontSize: '0.82rem', marginTop: '4px' }}>
                  {geo.error || 'Private IP / internal relay address or lookup timeout.'}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
