import React, { useState } from 'react'
import ThreatGlobe3D from './ThreatGlobe3D'
import RealWorldMap from './RealWorldMap'

export default function IPGeolocation({ locations = [] }) {
  const [viewMode, setViewMode] = useState('map') // 'map' | '3d' | 'grid'

  if (!locations || locations.length === 0) return null

  return (
    <div className="card" style={{ overflow: 'hidden', background: '#FFFFFF', border: '1px solid #E2E8F0', boxShadow: '0 1px 3px rgba(0,0,0,0.04)' }}>
      <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#0284C7" strokeWidth="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
          <span style={{ color: '#0F172A', fontWeight: 800 }}>Geographical Threat Attribution ({locations.length} Origin Coordinates)</span>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ display: 'flex', background: '#F1F5F9', padding: '2px', borderRadius: '6px', border: '1px solid #E2E8F0' }}>
            <button
              type="button"
              onClick={() => setViewMode('map')}
              style={{
                background: viewMode === 'map' ? '#0284C7' : 'transparent',
                color: viewMode === 'map' ? '#fff' : '#64748B',
                border: 'none',
                padding: '3px 10px',
                borderRadius: '4px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              🗺️ Real Map
            </button>
            <button
              type="button"
              onClick={() => setViewMode('3d')}
              style={{
                background: viewMode === '3d' ? '#0284C7' : 'transparent',
                color: viewMode === '3d' ? '#fff' : '#64748B',
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
              type="button"
              onClick={() => setViewMode('grid')}
              style={{
                background: viewMode === 'grid' ? '#0284C7' : 'transparent',
                color: viewMode === 'grid' ? '#fff' : '#64748B',
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
          <span className="badge badge-cyan">Live GPS Telemetry</span>
        </div>
      </div>

      <div style={{ fontSize: '0.82rem', color: '#64748B', marginBottom: '1rem' }}>
        Real-world IP coordinate tracking: inspect precise street/city GPS coordinates on interactive map tiles, or switch to the 3D globe to trace multi-hop trajectory arcs.
      </div>

      {/* Real-World Leaflet Map View */}
      {viewMode === 'map' && (
        <div style={{ marginBottom: '1.2rem' }}>
          <RealWorldMap locations={locations} height={320} />
        </div>
      )}

      {/* 3D WebGL Globe View */}
      {viewMode === '3d' && (
        <div style={{ marginBottom: '1.2rem' }}>
          <ThreatGlobe3D locations={locations} height={320} theme="white" />
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
                background: '#F8FAFC',
                border: '1px solid #E2E8F0',
                boxShadow: '0 1px 3px rgba(0, 0, 0, 0.03)',
                borderRadius: '12px',
                padding: '1.2rem',
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              <div style={{ position: 'absolute', top: 0, left: 0, width: '4px', height: '100%', background: isSuccess ? '#0284C7' : '#EF4444' }} />

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.95rem', color: '#0F172A' }}>
                  {geo.ip}
                </div>
                <span className={`badge ${isSuccess ? 'badge-cyan' : 'badge-critical'}`}>
                  {isSuccess ? 'RESOLVED' : 'UNRESOLVED'}
                </span>
              </div>

              {isSuccess ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.85rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#1E293B' }}>
                    <span style={{ fontSize: '1.1rem' }}>📍</span>
                    <strong>{geo.city || 'Unknown City'}, {geo.region || ''}</strong> ({geo.country || 'Unknown'})
                  </div>
                  <div style={{ color: '#64748B', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    Lat: {geo.lat} • Lon: {geo.lon}
                  </div>
                  <div style={{ color: '#1E40AF', fontSize: '0.82rem', background: '#EFF6FF', padding: '4px 8px', borderRadius: '6px', border: '1px solid #DBEAFE' }}>
                    ISP / ASN: <strong>{geo.isp || geo.org || 'Unknown Provider'}</strong>
                  </div>
                </div>
              ) : (
                <div style={{ color: '#EF4444', fontSize: '0.82rem', marginTop: '4px' }}>
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
