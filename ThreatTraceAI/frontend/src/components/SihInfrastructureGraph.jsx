import React from 'react'

export default function SihInfrastructureGraph({ riskLevel = 'HIGH' }) {
  const isStandby = riskLevel === 'STANDBY' || !riskLevel
  const isSafe = riskLevel === 'LOW'
  const isMed = riskLevel === 'MEDIUM'
  const isHigh = !isStandby && !isSafe && !isMed

  const targetColor = isStandby ? '#475569' : isSafe ? '#10B981' : isMed ? '#F59E0B' : '#EF4444'
  const targetGlow = isStandby ? 'rgba(71, 85, 105, 0.2)' : isSafe ? 'rgba(16, 185, 129, 0.4)' : isMed ? 'rgba(245, 158, 11, 0.4)' : 'rgba(239, 68, 68, 0.5)'
  const targetLabel = isStandby ? 'Target Domain' : isSafe ? 'Verified Org' : isMed ? 'Suspicious Domain' : 'High Risk Host'
  const campaignLabel = isStandby ? 'Campaign Node' : isSafe ? 'Clean Record' : isMed ? 'Unverified Relay' : 'Known Campaign'

  return (
    <div className="attack-graph-card">
      <div className="section-label-group">
        <div className="section-heading">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
            <circle cx="18" cy="5" r="3"/>
            <circle cx="6" cy="12" r="3"/>
            <circle cx="18" cy="19" r="3"/>
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
          </svg>
          <span>ATTACK INFRASTRUCTURE GRAPH</span>
        </div>
        <div className="radar-badge">
          <span className="radar-badge-dot" />
          RADAR ACTIVE
        </div>
      </div>

      <div className="graph-canvas-container">
        <svg width="100%" height="190" viewBox="0 0 320 180" style={{ overflow: 'visible' }}>
          <defs>
            {/* Dynamic radar wave gradient */}
            <radialGradient id="radarGlowGradient" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor={targetColor} stopOpacity="0.4" />
              <stop offset="100%" stopColor={targetColor} stopOpacity="0" />
            </radialGradient>
            <filter id="graphGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Background constellation dots */}
          <pattern id="gridConstellation" width="20" height="20" patternUnits="userSpaceOnUse">
            <circle cx="2" cy="2" r="0.75" fill="rgba(255, 255, 255, 0.05)" />
          </pattern>
          <rect width="320" height="180" fill="url(#gridConstellation)" rx="8" />

          {/* Pulsating radar sweep on active host */}
          {!isStandby && (
            <circle
              cx="210"
              cy="70"
              r="28"
              fill="url(#radarGlowGradient)"
              style={{
                animation: 'radarRipple 2s ease-out infinite',
                transformOrigin: '210px 70px'
              }}
            />
          )}

          {/* Edge 1: Sender -> Entry Gateway */}
          <line
            x1="50"
            y1="85"
            x2="130"
            y2="115"
            stroke="rgba(255, 255, 255, 0.15)"
            strokeWidth="1.8"
            strokeDasharray="4,4"
            style={{ animation: 'flowDash 1s linear infinite' }}
          />

          {/* Edge 2: Entry Gateway -> Target Domain */}
          <line
            x1="130"
            y1="115"
            x2="210"
            y2="70"
            stroke={targetColor}
            strokeWidth="2.8"
            filter="url(#graphGlow)"
          />

          {/* Edge 3: Target Domain -> Campaign Node */}
          <line
            x1="210"
            y1="70"
            x2="275"
            y2="115"
            stroke={targetColor}
            strokeWidth="1.8"
            strokeDasharray="4,4"
            style={{ animation: 'flowDash 1s linear infinite' }}
          />

          {/* Node 1: Origin Sender */}
          <g>
            <circle
              cx="50"
              cy="85"
              r="14"
              fill="#14151C"
              stroke="rgba(255, 255, 255, 0.2)"
              strokeWidth="1.5"
            />
            <text
              x="50"
              y="89"
              textAnchor="middle"
              fill="#CBD5E1"
              fontSize="8.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              SRC
            </text>
            <text
              x="50"
              y="112"
              textAnchor="middle"
              fill="#94A3B8"
              fontSize="9"
              fontWeight="600"
              fontFamily="var(--font-sans)"
            >
              Sender
            </text>
          </g>

          {/* Node 2: Entry MX Gateway */}
          <g>
            <circle
              cx="130"
              cy="115"
              r="16"
              fill="#14151C"
              stroke="#F59E0B"
              strokeWidth="2"
              filter="drop-shadow(0 0 8px rgba(245, 158, 11, 0.35))"
            />
            <text
              x="130"
              y="119"
              textAnchor="middle"
              fill="#F59E0B"
              fontSize="9"
              fontWeight="800"
              fontFamily="var(--font-sans)"
            >
              MX
            </text>
            <text
              x="130"
              y="144"
              textAnchor="middle"
              fill="#F8FAFC"
              fontSize="8.5"
              fontWeight="700"
              letterSpacing="0.04em"
              fontFamily="var(--font-sans)"
            >
              ENTRY GATEWAY
            </text>
          </g>

          {/* Node 3: Target Domain / Host */}
          <g>
            <circle
              cx="210"
              cy="70"
              r="17"
              fill={targetColor}
              stroke="#FFFFFF"
              strokeWidth="1.5"
              filter={`drop-shadow(0 0 12px ${targetGlow})`}
            />
            <text
              x="210"
              y="74"
              textAnchor="middle"
              fill="#FFFFFF"
              fontSize="9"
              fontWeight="800"
              fontFamily="var(--font-sans)"
            >
              HOST
            </text>
            <text
              x="210"
              y="99"
              textAnchor="middle"
              fill={targetColor}
              fontSize="8.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              {targetLabel}
            </text>
          </g>

          {/* Node 4: Campaign / C2 Record */}
          <g>
            <circle
              cx="275"
              cy="115"
              r="14"
              fill="#14151C"
              stroke={targetColor}
              strokeWidth="1.5"
              strokeDasharray="3,3"
            />
            <text
              x="275"
              y="119"
              textAnchor="middle"
              fill={targetColor}
              fontSize="8"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              C2
            </text>
            <text
              x="275"
              y="140"
              textAnchor="middle"
              fill={targetColor}
              fontSize="8.5"
              fontWeight="700"
              fontFamily="var(--font-sans)"
            >
              {campaignLabel}
            </text>
          </g>
        </svg>
      </div>

      {/* Telemetry Status Triad */}
      <div className="graph-status-triad">
        <div className="graph-status-item">
          <span className="graph-status-k">LATENCY</span>
          <span className="graph-status-v">24ms</span>
        </div>
        <div style={{ width: '1px', background: 'rgba(255, 255, 255, 0.05)' }} />
        <div className="graph-status-item">
          <span className="graph-status-k">LEDGER</span>
          <span className="graph-status-v" style={{ color: '#34D399' }}>SYNCED</span>
        </div>
        <div style={{ width: '1px', background: 'rgba(255, 255, 255, 0.05)' }} />
        <div className="graph-status-item">
          <span className="graph-status-k">NODES</span>
          <span className="graph-status-v">4 ACTIVE</span>
        </div>
      </div>
    </div>
  )
}
