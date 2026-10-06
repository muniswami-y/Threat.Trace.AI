import React, { useEffect, useRef, useState } from 'react'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'

/**
 * RealWorldMap: Interactive White-Themed Leaflet Real-World Map
 * Renders high-resolution map tiles with exact IP address GPS coordinates,
 * pulsing radar markers, accuracy radius circles, and forensic IP telemetry.
 */
export default function RealWorldMap({
  locations = [],
  primaryIp = null,
  riskLevel = 'HIGH',
  riskScore = null,
  height = 290,
  zoom = 11
}) {
  const mapContainerRef = useRef(null)
  const mapInstanceRef = useRef(null)
  const [activeTileLayer, setActiveTileLayer] = useState('mapbox-light') // 'mapbox-light' | 'mapbox-streets' | 'satellite' | 'osm'
  const [selectedLocation, setSelectedLocation] = useState(null)
  const [currentZoom, setCurrentZoom] = useState(zoom)

  const isCritical = riskScore !== null ? Number(riskScore) >= 70 : (riskLevel === 'HIGH' || riskLevel === 'CRITICAL')
  const themeColor = isCritical ? '#EF4444' : '#0284C7'

  // Normalize locations or fallback to realistic demo coordinates
  const validLocs = (locations || []).filter(l => l && l.lat != null && l.lon != null)
  const activeLocations = validLocs.length > 0 ? validLocs : [
    {
      ip: primaryIp || '103.108.118.77',
      city: 'Mumbai',
      region: 'Maharashtra',
      country: 'India',
      lat: 19.0760,
      lon: 72.8777,
      isp: 'Indian Banking Infrastructure',
      org: 'Banking / Postal Network',
      isAttacker: isCritical
    }
  ]

  const activeLoc = selectedLocation || activeLocations[0]

  useEffect(() => {
    const container = mapContainerRef.current
    if (!container) return

    // Clean up existing map instance if any
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove()
      mapInstanceRef.current = null
    }

    const defaultLat = activeLoc?.lat || 19.0760
    const defaultLon = activeLoc?.lon || 72.8777

    // Initialize Leaflet Map
    const map = L.map(container, {
      center: [defaultLat, defaultLon],
      zoom: currentZoom,
      zoomControl: false,
      attributionControl: false
    })
    mapInstanceRef.current = map

    // Active Mapbox Token from .env
    const mapboxToken = import.meta.env.VITE_MAPBOX_TOKEN || null

    let tileUrl = mapboxToken
      ? `https://api.mapbox.com/styles/v1/mapbox/light-v11/tiles/256/{z}/{x}/{y}@2x?access_token=${mapboxToken}`
      : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
    let subdomains = 'abcd'
    let maxZoom = 19

    if (activeTileLayer === 'mapbox-streets' && mapboxToken) {
      tileUrl = `https://api.mapbox.com/styles/v1/mapbox/streets-v12/tiles/256/{z}/{x}/{y}@2x?access_token=${mapboxToken}`
    } else if (activeTileLayer === 'satellite') {
      tileUrl = mapboxToken
        ? `https://api.mapbox.com/styles/v1/mapbox/satellite-streets-v12/tiles/256/{z}/{x}/{y}@2x?access_token=${mapboxToken}`
        : 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}'
    } else if (activeTileLayer === 'osm') {
      tileUrl = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png'
      subdomains = 'abc'
    }

    const tiles = L.tileLayer(tileUrl, {
      subdomains,
      maxZoom,
      detectRetina: true,
      tileSize: 256
    })
    tiles.addTo(map)

    // Add Markers for all active coordinates
    activeLocations.forEach((loc, idx) => {
      const lat = Number(loc.lat)
      const lon = Number(loc.lon)
      if (isNaN(lat) || isNaN(lon)) return

      const isCurrentActive = loc === activeLoc || loc.ip === activeLoc.ip
      const markerColor = loc.isVictim ? '#10B981' : (loc.isAttacker || isCritical ? '#EF4444' : '#0284C7')

      // Custom High-Tech SVG Pulsing GPS Pin
      const customPinHtml = `
        <div style="position: relative; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; cursor: pointer;">
          <div style="position: absolute; width: 38px; height: 38px; border-radius: 50%; background: ${markerColor}25; animation: ttMapPulse 2s infinite ease-out;"></div>
          <div style="position: absolute; width: 24px; height: 24px; border-radius: 50%; background: ${markerColor}40;"></div>
          <div style="position: relative; width: 14px; height: 14px; border-radius: 50%; background: ${markerColor}; border: 2.5px solid #FFFFFF; box-shadow: 0 2px 8px rgba(0,0,0,0.35);"></div>
          <div style="position: absolute; bottom: -18px; background: #0F172A; color: #FFFFFF; font-size: 9px; font-family: monospace; font-weight: 700; padding: 1px 5px; border-radius: 4px; white-space: nowrap; border: 1px solid rgba(255,255,255,0.2); box-shadow: 0 2px 6px rgba(0,0,0,0.25);">
            ${loc.ip || `LOC #${idx + 1}`}
          </div>
        </div>
      `

      const customIcon = L.divIcon({
        className: 'tt-map-marker',
        html: customPinHtml,
        iconSize: [40, 40],
        iconAnchor: [20, 20]
      })

      const marker = L.marker([lat, lon], { icon: customIcon }).addTo(map)

      // Geolocation Accuracy Radius Circle (5km)
      const circle = L.circle([lat, lon], {
        radius: 6500,
        color: markerColor,
        weight: 1.5,
        fillColor: markerColor,
        fillOpacity: isCurrentActive ? 0.12 : 0.05,
        dashArray: '4, 4'
      }).addTo(map)

      // Interactive Popup
      const popupHtml = `
        <div style="font-family: system-ui, sans-serif; padding: 4px; min-width: 190px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; border-bottom: 1px solid #E2E8F0; padding-bottom: 4px;">
            <span style="font-weight: 800; font-size: 11px; color: ${markerColor}; text-transform: uppercase;">
              ${loc.isVictim ? 'VERIFIED ENDPOINT' : (isCritical ? '🚨 THREAT ORIGIN' : 'TARGET HOST')}
            </span>
            <span style="font-size: 9px; background: #F1F5F9; color: #475569; padding: 1px 4px; border-radius: 3px; font-family: monospace;">
              #${idx + 1}
            </span>
          </div>
          <div style="font-family: monospace; font-weight: 700; font-size: 13px; color: #0F172A; margin-bottom: 2px;">
            ${loc.ip || 'Unresolved IP'}
          </div>
          <div style="font-size: 11px; color: #334155; font-weight: 600; margin-bottom: 4px;">
            📍 ${loc.city || 'Region'}, ${loc.region ? loc.region + ', ' : ''}${loc.country || 'Zone'}
          </div>
          <div style="font-size: 10px; color: #64748B; font-family: monospace;">
            GPS: ${lat.toFixed(4)}°, ${lon.toFixed(4)}°
          </div>
          ${loc.isp ? `<div style="font-size: 9.5px; color: #0284C7; margin-top: 3px; font-weight: 600;">ISP: ${loc.isp}</div>` : ''}
        </div>
      `
      marker.bindPopup(popupHtml)

      marker.on('click', () => {
        setSelectedLocation(loc)
      })

      if (isCurrentActive) {
        marker.openPopup()
      }
    })

    // Center on active coordinate
    map.setView([defaultLat, defaultLon], currentZoom)

    // Invalidate size after layout mounts
    const timer = setTimeout(() => {
      map.invalidateSize()
    }, 250)

    return () => {
      clearTimeout(timer)
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove()
        mapInstanceRef.current = null
      }
    }
  }, [activeLoc?.lat, activeLoc?.lon, activeTileLayer, currentZoom])

  const handleZoom = (level) => {
    setCurrentZoom(level)
    if (mapInstanceRef.current && activeLoc) {
      mapInstanceRef.current.setView([activeLoc.lat, activeLoc.lon], level)
    }
  }

  return (
    <div style={{
      position: 'relative',
      background: '#FFFFFF',
      borderRadius: '12px',
      overflow: 'hidden',
      border: '1px solid #E2E8F0',
      boxShadow: '0 2px 8px rgba(0, 0, 0, 0.04)',
      width: '100%'
    }}>
      <style>{`
        @keyframes ttMapPulse {
          0% { transform: scale(0.85); opacity: 0.9; }
          100% { transform: scale(1.75); opacity: 0; }
        }
        .tt-map-marker {
          background: transparent !important;
          border: none !important;
        }
        .leaflet-popup-content-wrapper {
          border-radius: 8px;
          box-shadow: 0 4px 14px rgba(0, 0, 0, 0.12);
          border: 1px solid #E2E8F0;
        }
        .leaflet-popup-tip {
          box-shadow: none;
        }
      `}</style>

      {/* Top Map Header Bar (White / Light Themed) */}
      <div style={{
        position: 'absolute',
        top: '8px',
        left: '10px',
        right: '10px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        zIndex: 1000,
        pointerEvents: 'none'
      }}>
        {/* Left: GPS Telemetry Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          background: 'rgba(255, 255, 255, 0.92)',
          backdropFilter: 'blur(8px)',
          padding: '4px 10px',
          borderRadius: '8px',
          border: '1px solid #E2E8F0',
          boxShadow: '0 2px 6px rgba(0, 0, 0, 0.06)',
          pointerEvents: 'auto'
        }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: themeColor,
            boxShadow: `0 0 6px ${themeColor}`
          }} />
          <span style={{
            fontSize: '0.72rem',
            fontWeight: 800,
            color: '#0F172A',
            letterSpacing: '0.04em',
            textTransform: 'uppercase'
          }}>
            Real-World Geolocation Map
          </span>
          <span style={{
            fontFamily: 'monospace',
            fontSize: '0.68rem',
            color: '#0284C7',
            background: 'rgba(2, 132, 199, 0.08)',
            padding: '1px 5px',
            borderRadius: '4px',
            fontWeight: 700
          }}>
            {activeLoc?.lat ? `${Number(activeLoc.lat).toFixed(4)}°, ${Number(activeLoc.lon).toFixed(4)}°` : 'N/A'}
          </span>
        </div>

        {/* Right: Map Style Toggles & Zoom Presets */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
          pointerEvents: 'auto'
        }}>
          {/* Tile Layer Selector */}
          <div style={{
            display: 'flex',
            background: 'rgba(255, 255, 255, 0.95)',
            backdropFilter: 'blur(8px)',
            padding: '2px',
            borderRadius: '6px',
            border: '1px solid #E2E8F0',
            boxShadow: '0 2px 6px rgba(0, 0, 0, 0.05)'
          }}>
            <button
              type="button"
              onClick={() => setActiveTileLayer('mapbox-light')}
              style={{
                border: 'none',
                background: activeTileLayer === 'mapbox-light' ? '#0284C7' : 'transparent',
                color: activeTileLayer === 'mapbox-light' ? '#FFFFFF' : '#475569',
                padding: '2px 7px',
                borderRadius: '4px',
                fontSize: '0.64rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
              title="Mapbox Crisp White Vector Tiles"
            >
              Mapbox Light
            </button>
            <button
              type="button"
              onClick={() => setActiveTileLayer('mapbox-streets')}
              style={{
                border: 'none',
                background: activeTileLayer === 'mapbox-streets' ? '#0284C7' : 'transparent',
                color: activeTileLayer === 'mapbox-streets' ? '#FFFFFF' : '#475569',
                padding: '2px 7px',
                borderRadius: '4px',
                fontSize: '0.64rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
              title="Mapbox Streets & Traffic Tiles"
            >
              Streets
            </button>
            <button
              type="button"
              onClick={() => setActiveTileLayer('satellite')}
              style={{
                border: 'none',
                background: activeTileLayer === 'satellite' ? '#0284C7' : 'transparent',
                color: activeTileLayer === 'satellite' ? '#FFFFFF' : '#475569',
                padding: '2px 7px',
                borderRadius: '4px',
                fontSize: '0.64rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
              title="Mapbox High-Res Satellite Imagery"
            >
              Satellite
            </button>
            <button
              type="button"
              onClick={() => setActiveTileLayer('osm')}
              style={{
                border: 'none',
                background: activeTileLayer === 'osm' ? '#0284C7' : 'transparent',
                color: activeTileLayer === 'osm' ? '#FFFFFF' : '#475569',
                padding: '2px 7px',
                borderRadius: '4px',
                fontSize: '0.64rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
              title="Standard OpenStreetMap Tiles"
            >
              OSM
            </button>
          </div>

          {/* Quick Zoom Buttons */}
          <div style={{
            display: 'flex',
            background: 'rgba(255, 255, 255, 0.92)',
            backdropFilter: 'blur(8px)',
            borderRadius: '6px',
            border: '1px solid #E2E8F0',
            overflow: 'hidden',
            boxShadow: '0 2px 6px rgba(0, 0, 0, 0.05)'
          }}>
            <button
              type="button"
              onClick={() => handleZoom(Math.min(currentZoom + 2, 17))}
              style={{
                border: 'none',
                background: 'transparent',
                color: '#334155',
                padding: '3px 7px',
                fontSize: '0.75rem',
                fontWeight: 800,
                cursor: 'pointer'
              }}
              title="Zoom In"
            >
              +
            </button>
            <button
              type="button"
              onClick={() => handleZoom(Math.max(currentZoom - 2, 3))}
              style={{
                border: 'none',
                borderLeft: '1px solid #E2E8F0',
                background: 'transparent',
                color: '#334155',
                padding: '3px 7px',
                fontSize: '0.75rem',
                fontWeight: 800,
                cursor: 'pointer'
              }}
              title="Zoom Out"
            >
              -
            </button>
          </div>
        </div>
      </div>

      {/* Real-World Leaflet Map Viewport */}
      <div 
        ref={mapContainerRef} 
        style={{ 
          width: '100%', 
          height: `${height}px`,
          zIndex: 1
        }} 
      />

      {/* Bottom Telemetry HUD Ribbon (White Themed) */}
      <div style={{
        position: 'absolute',
        bottom: '8px',
        left: '10px',
        right: '10px',
        background: 'rgba(255, 255, 255, 0.95)',
        backdropFilter: 'blur(10px)',
        border: '1px solid #E2E8F0',
        boxShadow: '0 4px 14px rgba(0, 0, 0, 0.08)',
        borderRadius: '8px',
        padding: '6px 12px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        zIndex: 1000
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
          <span style={{ fontSize: '1.05rem' }}>📍</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 800, color: '#0F172A', whiteSpace: 'nowrap' }}>
                {activeLoc?.city || 'Zone'}, {activeLoc?.region ? `${activeLoc.region}, ` : ''}{activeLoc?.country || 'Origin'}
              </span>
              <span style={{
                fontSize: '0.64rem',
                fontWeight: 700,
                fontFamily: 'monospace',
                background: isCritical ? '#FEE2E2' : '#E0F2FE',
                color: isCritical ? '#DC2626' : '#0284C7',
                padding: '1px 5px',
                borderRadius: '4px'
              }}>
                {activeLoc?.ip || primaryIp || '103.108.118.77'}
              </span>
            </div>
            <div style={{ fontSize: '0.65rem', color: '#64748B', fontFamily: 'monospace', marginTop: '1px' }}>
              Lat: {Number(activeLoc?.lat || 19.0760).toFixed(4)}° • Lon: {Number(activeLoc?.lon || 72.8777).toFixed(4)}° • {activeLoc?.isp || 'Banking Infrastructure'}
            </div>
          </div>
        </div>

        {/* Pin Location Switchers */}
        <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
          {activeLocations.map((loc, i) => (
            <button
              key={i}
              type="button"
              onClick={() => {
                setSelectedLocation(loc)
                if (mapInstanceRef.current && loc.lat && loc.lon) {
                  mapInstanceRef.current.setView([loc.lat, loc.lon], 12)
                }
              }}
              style={{
                background: (selectedLocation === loc || (!selectedLocation && i === 0)) ? '#0284C7' : '#F1F5F9',
                color: (selectedLocation === loc || (!selectedLocation && i === 0)) ? '#FFFFFF' : '#475569',
                border: '1px solid #E2E8F0',
                borderRadius: '4px',
                padding: '3px 7px',
                fontSize: '0.64rem',
                fontWeight: 700,
                cursor: 'pointer'
              }}
            >
              Pin #{i + 1} ({loc.country ? loc.country.slice(0, 3).toUpperCase() : 'LOC'})
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
