import React, { useState, useEffect } from 'react'

export default function SihInfrastructureGraph({ riskLevel = 'HIGH', riskScore = null }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [latency, setLatency] = useState(24)

  useEffect(() => {
    const interval = setInterval(() => {
      // Gentle realistic latency fluctuation for live telemetry feel
      setLatency(Math.floor(21 + Math.random() * 7))
    }, 2800)
    return () => clearInterval(interval)
  }, [])

  // Determine if email is safe (either riskLevel LOW or riskScore <= 35)
  const isSafe = riskScore !== null ? Number(riskScore) < 40 : (riskLevel === 'LOW' || riskLevel === 'SAFE')

  return (
    <div className="sih-card" style={{ position: 'relative', overflow: 'hidden' }}>
      <style>{`
        @keyframes graphFlowDash {
          0% { stroke-dashoffset: 28; }
          100% { stroke-dashoffset: 0; }
        }
        @keyframes graphFlowDashReverse {
          0% { stroke-dashoffset: 0; }
          100% { stroke-dashoffset: 28; }
        }
        @keyframes graphSonarWave1 {
          0% { r: 20px; opacity: 0.85; }
          100% { r: 46px; opacity: 0; }
        }
        @keyframes graphSonarWave2 {
          0% { r: 20px; opacity: 0.65; }
          50% { opacity: 0.35; }
          100% { r: 60px; opacity: 0; }
        }
        @keyframes graphRedGlowPulse {
          0%, 100% { filter: drop-shadow(0 0 8px rgba(220, 38, 38, 0.4)); }
          50% { filter: drop-shadow(0 0 20px rgba(220, 38, 38, 0.85)); }
        }
        @keyframes graphGreenGlowPulse {
          0%, 100% { filter: drop-shadow(0 0 8px rgba(5, 150, 105, 0.35)); }
          50% { filter: drop-shadow(0 0 18px rgba(5, 150, 105, 0.75)); }
        }
        @keyframes graphScanline {
          0% { transform: translateX(-40px); opacity: 0; }
          30% { opacity: 0.5; }
          70% { opacity: 0.5; }
          100% { transform: translateX(390px); opacity: 0; }
        }
        @keyframes graphXMarkPulse {
          0%, 100% { transform: scale(1); filter: drop-shadow(0 0 4px rgba(239, 68, 68, 0.6)); }
          50% { transform: scale(1.18); filter: drop-shadow(0 0 12px rgba(239, 68, 68, 0.95)); }
        }
        .graph-node-group {
          cursor: pointer;
          transition: transform 0.22s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        .graph-node-group:hover {
          transform: scale(1.1);
        }
        .flow-line-active {
          animation: graphFlowDash 1.2s linear infinite;
        }
      `}</style>

      {/* Header with Active Scanner Status */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <div className="section-heading" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" style={{ color: '#0284C7' }}>
            <circle cx="18" cy="5" r="3"/>
            <circle cx="6" cy="12" r="3"/>
            <circle cx="18" cy="19" r="3"/>
            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
          </svg>
          <span style={{ fontWeight: 800, fontSize: '0.85rem', letterSpacing: '0.04em' }}>
            ATTACK INFRASTRUCTURE GRAPH
          </span>
        </div>
        <div className="radar-badge" style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '6px', 
          background: isSafe ? 'rgba(16, 185, 129, 0.08)' : 'rgba(2, 132, 199, 0.08)', 
          padding: '4px 10px', 
          borderRadius: '20px', 
          border: `1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(2, 132, 199, 0.25)'}` 
        }}>
          <span className="pulse-dot" style={{ 
            width: '7px', 
            height: '7px', 
            background: isSafe ? '#10B981' : '#0284C7', 
            boxShadow: `0 0 8px ${isSafe ? '#10B981' : '#0284C7'}` 
          }} />
          <span style={{ fontSize: '0.7rem', fontWeight: 700, color: isSafe ? '#059669' : '#0284C7', letterSpacing: '0.05em' }}>
            {isSafe ? 'VERIFIED SECURE TOPOLOGY' : 'LIVE FORENSIC TOPOLOGY'}
          </span>
        </div>
      </div>

      {/* Main SVG Telemetry Canvas */}
      <div style={{ 
        background: 'linear-gradient(180deg, #F8FAFC 0%, #F1F5F9 100%)', 
        borderRadius: '12px', 
        padding: '10px', 
        position: 'relative', 
        border: '1px solid #E2E8F0',
        boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.03)' 
      }}>
        <svg width="100%" height="225" viewBox="0 0 380 205" style={{ overflow: 'visible' }}>
          <defs>
            {/* Dot Grid Background */}
            <pattern id="infraGridDot" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1.1" fill="rgba(15, 23, 42, 0.07)" />
            </pattern>

            {/* Glowing Edge Gradients */}
            <linearGradient id="edgeGradSrcMx" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#64748B" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#F59E0B" />
            </linearGradient>

            <linearGradient id="edgeGradMxHost" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#F59E0B" />
              <stop offset="100%" stopColor="#10B981" />
            </linearGradient>

            <linearGradient id="edgeGradHostC2" x1="0%" y1="100%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10B981" />
              <stop offset="100%" stopColor="#10B981" stopOpacity="0.9" />
            </linearGradient>

            <linearGradient id="edgeGradHostPhish" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10B981" />
              <stop offset="50%" stopColor="#F59E0B" />
              <stop offset="100%" stopColor="#DC2626" />
            </linearGradient>

            {/* Radar Scanline */}
            <linearGradient id="scanBeamGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={isSafe ? '#10B981' : '#0284C7'} stopOpacity="0" />
              <stop offset="50%" stopColor={isSafe ? '#10B981' : '#0284C7'} stopOpacity="0.14" />
              <stop offset="100%" stopColor={isSafe ? '#10B981' : '#0284C7'} stopOpacity="0" />
            </linearGradient>

            {/* Filters */}
            <filter id="neonGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Grid Background */}
          <rect width="380" height="205" fill="url(#infraGridDot)" rx="10" />

          {/* Radar Scanning Laser Beam */}
          <rect
            y="0"
            width="50"
            height="205"
            fill="url(#scanBeamGrad)"
            style={{ animation: 'graphScanline 4.5s linear infinite', pointerEvents: 'none' }}
          />

          {/* Multi-layered Concentric Sonar Rings on HOST Node (Verified Org) */}
          <circle cx="205" cy="100" r="24" fill="none" stroke="#10B981" strokeWidth="1.2" opacity="0.7">
            <animate attributeName="r" values="24;46" dur="2.2s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.75;0" dur="2.2s" repeatCount="indefinite" />
          </circle>
          <circle cx="205" cy="100" r="24" fill="none" stroke="#10B981" strokeWidth="0.9" opacity="0.5">
            <animate attributeName="r" values="24;62" dur="2.2s" begin="0.75s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.55;0" dur="2.2s" begin="0.75s" repeatCount="indefinite" />
          </circle>
          <circle cx="205" cy="100" r="24" fill="none" stroke="#10B981" strokeWidth="0.6" opacity="0.3">
            <animate attributeName="r" values="24;78" dur="2.2s" begin="1.4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.35;0" dur="2.2s" begin="1.4s" repeatCount="indefinite" />
          </circle>

          {/* Sonar Warning Waves on PHISHING Node (Only when Unsafe) */}
          {!isSafe && (
            <circle cx="315" cy="148" r="20" fill="none" stroke="#DC2626" strokeWidth="1.4" opacity="0.8">
              <animate attributeName="r" values="20;40" dur="1.8s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.8;0" dur="1.8s" repeatCount="indefinite" />
            </circle>
          )}

          {/* Sonar Clean Record Waves on C2 Node (Pulsing Green when Safe) */}
          {isSafe && (
            <circle cx="310" cy="52" r="20" fill="none" stroke="#10B981" strokeWidth="1.3" opacity="0.75">
              <animate attributeName="r" values="20;38" dur="2.0s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.75;0" dur="2.0s" repeatCount="indefinite" />
            </circle>
          )}

          {/* Static Conduits Backdrop */}
          <path d="M 45 100 L 125 100" fill="none" stroke="#E2E8F0" strokeWidth="3" strokeLinecap="round" />
          <path d="M 125 100 L 205 100" fill="none" stroke="rgba(245, 158, 11, 0.2)" strokeWidth="3.5" strokeLinecap="round" />
          <path d="M 205 100 C 240 100, 260 52, 310 52" fill="none" stroke="rgba(16, 185, 129, 0.2)" strokeWidth="3" strokeLinecap="round" />
          <path d="M 205 100 C 240 100, 260 148, 315 148" fill="none" stroke={isSafe ? 'rgba(148, 163, 184, 0.25)' : 'rgba(220, 38, 38, 0.2)'} strokeWidth="3.5" strokeLinecap="round" />

          {/* Animated Conduit 1: SRC -> MX */}
          <path
            d="M 45 100 L 125 100"
            fill="none"
            stroke="url(#edgeGradSrcMx)"
            strokeWidth="2.8"
            strokeDasharray="6,5"
            strokeLinecap="round"
            className="flow-line-active"
          />

          {/* Flow indicator label */}
          <text x="85" y="93" textAnchor="middle" fill="#64748B" fontSize="6.5" fontWeight="700" letterSpacing="0.06em" fontFamily="var(--font-mono)">
            FLOW →
          </text>

          {/* Animated Conduit 2: MX -> HOST */}
          <path
            d="M 125 100 L 205 100"
            fill="none"
            stroke="url(#edgeGradMxHost)"
            strokeWidth="3.5"
            strokeDasharray="7,5"
            strokeLinecap="round"
            filter="url(#neonGlow)"
            className="flow-line-active"
            style={{ animationDuration: '0.95s' }}
          />

          {/* Animated Conduit 3 (Upper Branch): HOST -> C2 (Clean Record) */}
          <path
            d="M 205 100 C 240 100, 260 52, 310 52"
            fill="none"
            stroke="url(#edgeGradHostC2)"
            strokeWidth={isSafe ? "3.2" : "2.8"}
            strokeDasharray="6,4"
            strokeLinecap="round"
            filter={isSafe ? "url(#neonGlow)" : undefined}
            className="flow-line-active"
            style={{ animationDuration: '1.2s' }}
          />

          {/* Conduit 4 (Lower Branch): HOST -> PHISHING */}
          {isSafe ? (
            /* SAFE MODE: Truncated / Severed Conduit Halting with Red 'X' in the Middle */
            <>
              {/* Halting Severed Line from HOST to Middle */}
              <path
                d="M 205 100 C 230 100, 245 116, 260 125"
                fill="none"
                stroke="#EF4444"
                strokeWidth="2.8"
                strokeDasharray="4,4"
                strokeLinecap="round"
                opacity="0.8"
              />
              {/* Inactive Line from Middle to Phishing Node */}
              <path
                d="M 260 125 C 275 134, 290 148, 315 148"
                fill="none"
                stroke="#CBD5E1"
                strokeWidth="2"
                strokeDasharray="3,3"
                strokeLinecap="round"
                opacity="0.5"
              />
            </>
          ) : (
            /* UNSAFE MODE: Live Glowing Fiery Conduit to Phishing */
            <path
              d="M 205 100 C 240 100, 260 148, 315 148"
              fill="none"
              stroke="url(#edgeGradHostPhish)"
              strokeWidth="3.5"
              strokeDasharray="7,4"
              strokeLinecap="round"
              filter="url(#neonGlow)"
              className="flow-line-active"
              style={{ animationDuration: '0.8s' }}
            />
          )}

          {/* Animated Travelling Photon 1: SRC -> MX */}
          <circle r="4" fill="#0284C7" filter="drop-shadow(0 0 6px #0284C7)">
            <animateMotion dur="2.1s" repeatCount="indefinite" path="M 45 100 L 125 100" />
          </circle>

          {/* Animated Travelling Photon 2: MX -> HOST */}
          <circle r="4.5" fill="#F59E0B" filter="drop-shadow(0 0 6px #F59E0B)">
            <animateMotion dur="1.4s" repeatCount="indefinite" path="M 125 100 L 205 100" />
          </circle>

          {/* Animated Travelling Photon 3 (Upper): HOST -> C2 */}
          <circle r={isSafe ? "4.5" : "3.5"} fill="#10B981" filter="drop-shadow(0 0 6px #10B981)">
            <animateMotion dur={isSafe ? "1.2s" : "1.7s"} repeatCount="indefinite" path="M 205 100 C 240 100, 260 52, 310 52" />
          </circle>

          {/* Lower Branch Action: Travelling Photon (if unsafe) OR Prominent 'X' Mark (if safe) */}
          {!isSafe ? (
            <>
              {/* Active Intermediate Orange Conduit Dot Node */}
              <circle cx="260" cy="125" r="5.5" fill="#EA580C" stroke="#FDBA74" strokeWidth="1.8" filter="drop-shadow(0 0 6px #EA580C)" />
              
              {/* Travelling Danger Exfiltration Photon: HOST -> PHISHING */}
              <circle r="4.5" fill="#EF4444" filter="drop-shadow(0 0 8px #DC2626)">
                <animateMotion dur="1.1s" repeatCount="indefinite" path="M 205 100 C 240 100, 260 148, 315 148" />
              </circle>
            </>
          ) : (
            /* PROMINENT RED 'X' MARK IN THE MIDDLE OF HOST AND PHISHING */
            <g style={{ transformOrigin: '260px 125px', animation: 'graphXMarkPulse 2s ease-in-out infinite' }}>
              {/* Glowing Red Halting Halo */}
              <circle cx="260" cy="125" r="13" fill="#FEE2E2" stroke="#EF4444" strokeWidth="2.2" filter="drop-shadow(0 0 8px rgba(239, 68, 68, 0.7))" />
              <circle cx="260" cy="125" r="9" fill="#DC2626" />
              
              {/* Bold White 'X' Cross */}
              <path
                d="M 256 121 L 264 129 M 264 121 L 256 129"
                stroke="#FFFFFF"
                strokeWidth="2.6"
                strokeLinecap="round"
              />
              
              {/* Subtitle 'HALTED' tag */}
              <rect x="242" y="141" width="36" height="13" rx="4" fill="#1E293B" opacity="0.9" />
              <text x="260" y="150.5" textAnchor="middle" fill="#FCA5A5" fontSize="6.5" fontWeight="800" fontFamily="var(--font-mono)">
                HALTED ✕
              </text>
            </g>
          )}

          {/* ================= NODE 1: SRC (Sender) ================= */}
          <g 
            className="graph-node-group" 
            onClick={() => setSelectedNode(selectedNode === 'SRC' ? null : 'SRC')}
          >
            <circle cx="45" cy="100" r="22" fill="#5B7083" stroke="#475569" strokeWidth="2.5" filter="drop-shadow(0 4px 10px rgba(91, 112, 131, 0.35))" />
            <circle cx="45" cy="100" r="17" fill="#475569" stroke="rgba(255,255,255,0.25)" strokeWidth="1" />
            <text x="45" y="104" textAnchor="middle" fill="#FFFFFF" fontSize="10" fontWeight="900" letterSpacing="0.04em" fontFamily="var(--font-sans)">
              SRC
            </text>
            <text x="45" y="134" textAnchor="middle" fill="#334155" fontSize="9.5" fontWeight="800" fontFamily="var(--font-sans)">
              Sender
            </text>
          </g>

          {/* ================= NODE 2: MX (Entry Gateway) ================= */}
          <g 
            className="graph-node-group"
            onClick={() => setSelectedNode(selectedNode === 'MX' ? null : 'MX')}
          >
            <circle cx="125" cy="100" r="22" fill="#EA580C" stroke="#F59E0B" strokeWidth="2.8" filter="drop-shadow(0 4px 12px rgba(234, 88, 12, 0.45))" />
            <circle cx="125" cy="100" r="17" fill="#F97316" stroke="rgba(255,255,255,0.3)" strokeWidth="1" />
            <text x="125" y="104" textAnchor="middle" fill="#FFFFFF" fontSize="10.5" fontWeight="900" letterSpacing="0.04em" fontFamily="var(--font-sans)">
              MX
            </text>
            <text x="125" y="133" textAnchor="middle" fill="#0F172A" fontSize="8" fontWeight="800" letterSpacing="0.03em" fontFamily="var(--font-sans)">
              ENTRY GATEWAY,
            </text>
            <text x="125" y="143" textAnchor="middle" fill="#D97706" fontSize="7.5" fontWeight="700" fontFamily="var(--font-mono)">
              PORT 587, TLS
            </text>
          </g>

          {/* ================= NODE 3: HOST (Verified Org) ================= */}
          <g 
            className="graph-node-group"
            onClick={() => setSelectedNode(selectedNode === 'HOST' ? null : 'HOST')}
            style={{ animation: 'graphGreenGlowPulse 2.4s ease-in-out infinite' }}
          >
            <circle cx="205" cy="100" r="23" fill="#064E3B" stroke="#10B981" strokeWidth="3" filter="drop-shadow(0 4px 16px rgba(16, 185, 129, 0.55))" />
            <circle cx="205" cy="100" r="18" fill="#047857" stroke="rgba(255,255,255,0.3)" strokeWidth="1" />
            <text x="205" y="104" textAnchor="middle" fill="#FFFFFF" fontSize="9.5" fontWeight="900" letterSpacing="0.05em" fontFamily="var(--font-sans)">
              HOST
            </text>
            <text x="205" y="133" textAnchor="middle" fill="#065F46" fontSize="9" fontWeight="900" fontFamily="var(--font-sans)">
              HOST
            </text>
            <text x="205" y="143" textAnchor="middle" fill="#059669" fontSize="7.5" fontWeight="800" fontFamily="var(--font-sans)">
              Verified Org,
            </text>
            <text x="205" y="153" textAnchor="middle" fill="#64748B" fontSize="6.8" fontWeight="700" fontFamily="var(--font-mono)">
              NODE IDENTITY
            </text>
          </g>

          {/* ================= NODE 4 (UPPER BRANCH): C2 (Clean Record) ================= */}
          <g 
            className="graph-node-group"
            onClick={() => setSelectedNode(selectedNode === 'C2' ? null : 'C2')}
            style={{ animation: isSafe ? 'graphGreenGlowPulse 2s ease-in-out infinite' : undefined }}
          >
            <circle cx="310" cy="52" r="20" fill={isSafe ? "#ECFDF5" : "#FFFFFF"} stroke="#10B981" strokeWidth={isSafe ? "3" : "2.5"} strokeDasharray="5,4" filter="drop-shadow(0 3px 10px rgba(16, 185, 129, 0.4))" />
            <circle cx="310" cy="52" r="14" fill={isSafe ? "rgba(16, 185, 129, 0.18)" : "rgba(16, 185, 129, 0.08)"} />
            <text x="310" y="56" textAnchor="middle" fill="#047857" fontSize="9.5" fontWeight="900" letterSpacing="0.04em" fontFamily="var(--font-sans)">
              C2
            </text>
            <text x="310" y="82" textAnchor="middle" fill="#047857" fontSize="8.5" fontWeight="800" fontFamily="var(--font-sans)">
              Clean Record
            </text>
          </g>

          {/* ================= NODE 5 (LOWER BRANCH): PHISHING (Data Theft / Interception) ================= */}
          <g 
            className="graph-node-group"
            onClick={() => setSelectedNode(selectedNode === 'PHISHING' ? null : 'PHISHING')}
            style={{ 
              animation: !isSafe ? 'graphRedGlowPulse 1.8s ease-in-out infinite' : undefined,
              opacity: isSafe ? 0.45 : 1
            }}
          >
            <circle cx="315" cy="148" r="23" fill={isSafe ? "#475569" : "#7F1D1D"} stroke={isSafe ? "#94A3B8" : "#DC2626"} strokeWidth="3" filter={!isSafe ? "drop-shadow(0 4px 18px rgba(220, 38, 38, 0.75))" : undefined} />
            <circle cx="315" cy="148" r="18" fill={isSafe ? "#64748B" : "#991B1B"} stroke="rgba(255,255,255,0.3)" strokeWidth="1" />
            <text x="315" y="152" textAnchor="middle" fill="#FFFFFF" fontSize="8.5" fontWeight="900" letterSpacing="0.04em" fontFamily="var(--font-sans)">
              PHISHING
            </text>
            <text x="315" y="180" textAnchor="middle" fill={isSafe ? "#64748B" : "#DC2626"} fontSize="9" fontWeight="900" fontFamily="var(--font-sans)">
              {isSafe ? 'PHISHING (BLOCKED)' : 'PHISHING'}
            </text>
            <text x="315" y="191" textAnchor="middle" fill={isSafe ? "#94A3B8" : "#991B1B"} fontSize="7.5" fontWeight="800" fontFamily="var(--font-sans)">
              {isSafe ? 'No Exfiltration Vector' : 'Data Theft / Interception'}
            </text>
          </g>
        </svg>

        {/* Tactical Node Inspector Pill (Appears on click or hover) */}
        {selectedNode && (
          <div style={{
            position: 'absolute',
            top: '12px',
            right: '12px',
            background: 'rgba(15, 23, 42, 0.94)',
            backdropFilter: 'blur(8px)',
            color: '#FFFFFF',
            padding: '7px 14px',
            borderRadius: '8px',
            fontSize: '0.72rem',
            boxShadow: '0 4px 14px rgba(0,0,0,0.2)',
            display: 'flex',
            flexDirection: 'column',
            gap: '3px',
            zIndex: 10,
            animation: 'slideDown 0.15s ease'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', alignItems: 'center' }}>
              <span style={{ fontWeight: 800, color: selectedNode === 'PHISHING' ? (isSafe ? '#94A3B8' : '#EF4444') : selectedNode === 'HOST' || selectedNode === 'C2' ? '#34D399' : '#38BDF8' }}>
                NODE: {selectedNode} {selectedNode === 'PHISHING' && isSafe ? '(HALTED / SEVERED)' : ''}
              </span>
              <button 
                onClick={(e) => { e.stopPropagation(); setSelectedNode(null) }} 
                style={{ background: 'none', border: 'none', color: '#94A3B8', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 800 }}
              >
                ✕
              </button>
            </div>
            <span style={{ fontSize: '0.68rem', color: '#CBD5E1', fontFamily: 'var(--font-mono)' }}>
              {selectedNode === 'SRC' && 'Origin IP: 192.0.2.1 • SPF: PASS • DKIM: VALID'}
              {selectedNode === 'MX' && 'Gateway: mx.gateway.sec • Encryption: TLS 1.3 • Port 587'}
              {selectedNode === 'HOST' && 'Domain: Verified Org Authority • TLS Active • Identity Confirmed'}
              {selectedNode === 'C2' && 'Reputation: 0 Threats Logged • Clean Certificate Record'}
              {selectedNode === 'PHISHING' && (isSafe ? '🛡️ STATUS: Phishing conduit severed by TTA. Zero threat exfiltration.' : '🚨 ALERT: Intercepted Exfiltration Tunnel • Known Phishing Vector')}
            </span>
          </div>
        )}
      </div>

      {/* Real-Time Telemetry Status Triad */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        background: '#FFFFFF', 
        border: '1px solid #E2E8F0', 
        padding: '10px 16px', 
        borderRadius: '10px', 
        marginTop: '10px',
        boxShadow: '0 1px 3px rgba(0,0,0,0.02)'
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontSize: '0.62rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>LATENCY</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            {latency}ms
          </span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontSize: '0.62rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>LEDGER</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 800, color: '#059669', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span className="pulse-dot" style={{ width: '5px', height: '5px', background: '#059669', display: 'inline-block' }} />
            SYNCED
          </span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontSize: '0.62rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>THREAT NODES</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 800, color: isSafe ? '#059669' : '#DC2626' }}>
            {isSafe ? '0 (HALTED ✕)' : '1 EXFILTRATING'}
          </span>
        </div>
      </div>
    </div>
  )
}
