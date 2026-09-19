export default function SihInfrastructureGraph({ riskLevel = 'HIGH' }) {
  const isStandby = riskLevel === 'STANDBY' || !riskLevel
  const isSafe = riskLevel === 'LOW'
  const isMed = riskLevel === 'MEDIUM'

  const targetColor = isStandby ? '#94a3b8' : isSafe ? '#10b981' : isMed ? '#f59e0b' : '#ef4444'
  const targetLabel = isStandby ? 'Target Domain' : isSafe ? 'Verified Org' : isMed ? 'Suspicious Domain' : 'High Risk Node'
  const campaignLabel = isStandby ? 'Campaign Node' : isSafe ? 'Clean Record' : isMed ? 'Unverified Relay' : 'Known Campaign'


  return (
    <div className="sih-card">
      <div className="sih-card-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="18" cy="5" r="3"/>
          <circle cx="6" cy="12" r="3"/>
          <circle cx="18" cy="19" r="3"/>
          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
        </svg>
        <span>INFRASTRUCTURE GRAPH</span>
      </div>

      <div className="graph-canvas-box">
        <svg width="100%" height="100%" viewBox="0 0 320 180" style={{ overflow: 'visible' }}>
          {/* Edge 1: Sender to Email Entry (gray dashed) */}
          <line
            x1="50"
            y1="85"
            x2="130"
            y2="115"
            stroke="#94a3b8"
            strokeWidth="2"
            strokeDasharray="4,4"
          />

          {/* Edge 2: Email Entry to Target Domain (solid red/targetColor) */}
          <line
            x1="130"
            y1="115"
            x2="210"
            y2="70"
            stroke={targetColor}
            strokeWidth="3"
          />

          {/* Edge 3: Target Domain to Known Campaign (dashed red/targetColor) */}
          <line
            x1="210"
            y1="70"
            x2="275"
            y2="115"
            stroke={targetColor}
            strokeWidth="2"
            strokeDasharray="4,4"
          />

          {/* Node 1: Sender */}
          <circle
            cx="50"
            cy="85"
            r="12"
            fill="#ffffff"
            stroke="#94a3b8"
            strokeWidth="2"
          />
          <text
            x="50"
            y="108"
            textAnchor="middle"
            fill="#94a3b8"
            fontSize="9"
            fontWeight="600"
            fontFamily="var(--font-sans)"
          >
            Sender
          </text>

          {/* Node 2: Email Entry */}
          <circle
            cx="130"
            cy="115"
            r="14"
            fill="#ffffff"
            stroke="#eab308"
            strokeWidth="4"
          />
          <text
            x="130"
            y="142"
            textAnchor="middle"
            fill="#475569"
            fontSize="8.5"
            fontWeight="700"
            letterSpacing="0.05em"
            fontFamily="var(--font-sans)"
          >
            EMAIL ENTRY
          </text>

          {/* Node 3: Target Domain / High Risk Node */}
          <circle
            cx="210"
            cy="70"
            r="14"
            fill={targetColor}
            stroke="#ffffff"
            strokeWidth="2"
          />
          <text
            x="210"
            y="73"
            textAnchor="middle"
            fill="#ffffff"
            fontSize="7"
            fontWeight="700"
            fontFamily="var(--font-sans)"
          >
            Domain
          </text>
          <text
            x="210"
            y="94"
            textAnchor="middle"
            fill={targetColor}
            fontSize="8"
            fontWeight="700"
            fontFamily="var(--font-sans)"
          >
            {targetLabel}
          </text>

          {/* Node 4: Known Campaign */}
          <circle
            cx="275"
            cy="115"
            r="12"
            fill="#ffffff"
            stroke={targetColor}
            strokeWidth="2"
            strokeDasharray="3,3"
          />
          <text
            x="275"
            y="138"
            textAnchor="middle"
            fill={targetColor}
            fontSize="7.5"
            fontWeight="700"
            fontFamily="var(--font-sans)"
          >
            {campaignLabel}
          </text>
        </svg>
      </div>
    </div>
  )
}
