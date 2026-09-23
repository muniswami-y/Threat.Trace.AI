import React, { useEffect, useState, useId } from 'react'
import RiskScoreExplanationModal from './RiskScoreExplanationModal'

/**
 * Cyber Threat Risk Score Radial Gauge Component
 * High-performance, SVG-based radial gauge with multi-zone trigonometric tracking,
 * radar sonar aura, and cubic ease-out animation.
 */
export default function RiskScoreCircle({ 
  score = null, 
  riskLevel = null, 
  caseData = null, 
  interactive = true,
  onClick = null,
  onInspect = null
}) {
  const filterId = useId()
  const isLoaded = score !== null && score !== undefined && score !== '--' && !isNaN(Number(score))
  const targetScore = isLoaded ? Math.min(100, Math.max(0, Math.round(Number(score)))) : 0
  
  const [animatedScore, setAnimatedScore] = useState(0)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isHovered, setIsHovered] = useState(false)

  // Step 2: Smooth Easing Count-Up Animation (1100ms cubic ease-out)
  useEffect(() => {
    if (!isLoaded) {
      setAnimatedScore(0)
      return
    }

    let startTimestamp = null
    const duration = 1100 // ms
    const target = targetScore

    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp
      const progress = Math.min((timestamp - startTimestamp) / duration, 1)
      const easeOut = 1 - Math.pow(1 - progress, 3)
      setAnimatedScore(Math.round(target * easeOut))

      if (progress < 1) {
        window.requestAnimationFrame(step)
      }
    }

    const animId = window.requestAnimationFrame(step)
    return () => window.cancelAnimationFrame(animId)
  }, [targetScore, isLoaded])

  // Dynamic Tri-Tier Severity Classification
  const normalizedLevel = (riskLevel || '').toUpperCase()
  const isCritical = isLoaded && (normalizedLevel === 'CRITICAL' || normalizedLevel === 'HIGH' || targetScore >= 70)
  const isMedium = isLoaded && !isCritical && (normalizedLevel === 'MEDIUM' || normalizedLevel === 'SUSPICIOUS' || (targetScore >= 40 && targetScore < 70))
  const isSafe = isLoaded && !isCritical && !isMedium

  const activeColor = !isLoaded 
    ? '#94A3B8' 
    : isCritical 
      ? '#EF4444' 
      : isMedium 
        ? '#F59E0B' 
        : '#10B981'

  const glowColor = !isLoaded
    ? 'rgba(148, 163, 184, 0.15)'
    : isCritical
      ? 'rgba(239, 68, 68, 0.55)'
      : isMedium
        ? 'rgba(245, 158, 11, 0.45)'
        : 'rgba(16, 185, 129, 0.45)'

  const statusLabel = !isLoaded 
    ? 'STANDBY' 
    : isCritical 
      ? 'CRITICAL DANGER' 
      : isMedium 
        ? 'SUSPICIOUS / MEDIUM' 
        : 'VERIFIED SAFE'

  // Step 1: SVG Geometry & Arc Math
  const size = 200
  const center = size / 2
  const strokeWidth = 12
  const radius = center - strokeWidth - 6 // 82px
  const circumference = 2 * Math.PI * radius

  const progressDashoffset = circumference - (isLoaded ? animatedScore / 100 : 0) * circumference

  // Step 5: Orbital Tracer Needle Node (Knob) Coordinates
  const angle = ((isLoaded ? animatedScore : 0) / 100) * 360 - 90
  const rad = (angle * Math.PI) / 180
  const tracerX = center + radius * Math.cos(rad)
  const tracerY = center + radius * Math.sin(rad)

  const handleCardClick = (e) => {
    if (onClick) onClick(e)
    if (onInspect) onInspect(targetScore)
    if (interactive) {
      setIsModalOpen(true)
    }
  }

  return (
    <>
      <div 
        onClick={handleCardClick}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        role={interactive ? 'button' : 'region'}
        tabIndex={interactive ? 0 : -1}
        onKeyDown={(e) => {
          if (interactive && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault()
            handleCardClick(e)
          }
        }}
        title="Click to view comprehensive Bayesian multi-vector calculation"
        style={{
          background: 'transparent',
          borderRadius: '0px',
          border: 'none',
          padding: '0px',
          width: '100%',
          maxWidth: '260px',
          boxSizing: 'border-box',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '12px',
          cursor: interactive ? 'pointer' : 'default',
          boxShadow: 'none',
          transition: 'all 0.25s ease',
          userSelect: 'none',
          margin: '0 auto'
        }}
      >
        {/* Top Header + Dynamic Severity Pill */}
        <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ 
            fontSize: '11px', 
            fontWeight: 800, 
            letterSpacing: '0.08em', 
            textTransform: 'uppercase', 
            color: 'var(--text-muted, #64748B)' 
          }}>
            RISK SCORE
          </span>

          <span style={{
            fontSize: '9.5px',
            fontWeight: 800,
            padding: '3px 8px',
            borderRadius: '9999px',
            color: activeColor,
            background: `${activeColor}1A`,
            border: `1px solid ${activeColor}4D`,
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            boxShadow: `0 0 10px ${activeColor}22`
          }}>
            {statusLabel}
          </span>
        </div>

        {/* SVG Radial Gauge Container */}
        <div style={{ position: 'relative', width: `${size}px`, height: `${size}px` }}>
          <svg 
            width={size} 
            height={size} 
            viewBox={`0 0 ${size} ${size}`}
            style={{ overflow: 'visible' }}
          >
            <defs>
              {/* Dynamic Neon Glow Filter */}
              <filter id={`neonGlow-${filterId}`} x="-50%" y="-50%" width="200%" height="200%">
                <feDropShadow dx="0" dy="0" stdDeviation="6" floodColor={activeColor} floodOpacity="0.65" />
              </filter>

              {/* Radial Radar Gradient */}
              <radialGradient id={`radarAura-${filterId}`} cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor={activeColor} stopOpacity="0.22" />
                <stop offset="60%" stopColor={activeColor} stopOpacity="0.06" />
                <stop offset="100%" stopColor={activeColor} stopOpacity="0" />
              </radialGradient>
            </defs>

            {/* Layer 1: Pulsing Radar Aura Disk */}
            <circle
              cx={center}
              cy={center}
              r={radius - 14}
              fill={`url(#radarAura-${filterId})`}
              style={{
                transformOrigin: 'center',
                animation: isCritical 
                  ? 'pulseDiskFast 1.4s ease-in-out infinite' 
                  : 'pulseDisk 2.8s ease-in-out infinite'
              }}
            />

            {/* Layer 2: Expanding Radar Sonar Ripple */}
            {isLoaded && animatedScore > 0 && (
              <circle
                cx={center}
                cy={center}
                fill="none"
                stroke={activeColor}
                style={{
                  transformOrigin: 'center',
                  animation: 'innerRadarRipple 2.4s cubic-bezier(0.1, 0.8, 0.3, 1) infinite'
                }}
              />
            )}

            {/* Layer 3: Background Base Track */}
            <circle
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke="rgba(148, 163, 184, 0.18)"
              strokeWidth={strokeWidth}
            />

            {/* Layer 4: Neon Active Progress Arc */}
            <circle
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke={activeColor}
              strokeWidth={strokeWidth}
              strokeDasharray={circumference}
              strokeDashoffset={progressDashoffset}
              strokeLinecap="round"
              filter={`url(#neonGlow-${filterId})`}
              style={{
                transform: 'rotate(-90deg)',
                transformOrigin: 'center',
                transition: 'stroke-dashoffset 0.15s linear, stroke 0.3s ease'
              }}
            />

            {/* Layer 5: Orbital Tracer Needle Node (Knob) */}
            {isLoaded && animatedScore > 0 && (
              <g style={{ transformOrigin: `${tracerX}px ${tracerY}px` }}>
                {/* Outer Halo with Breathing Pulse */}
                <circle
                  cx={tracerX}
                  cy={tracerY}
                  r={11}
                  fill={activeColor}
                  fillOpacity={0.25}
                  style={{
                    transformOrigin: `${tracerX}px ${tracerY}px`,
                    animation: 'tracerHaloPulse 2s ease-in-out infinite'
                  }}
                />
                {/* Inner Core */}
                <circle
                  cx={tracerX}
                  cy={tracerY}
                  r={7}
                  fill="#FFFFFF"
                  stroke={activeColor}
                  strokeWidth={3.5}
                  filter={`url(#neonGlow-${filterId})`}
                />
              </g>
            )}
          </svg>

          {/* Layer 6: Center HTML Typography & Micro-Interactions */}
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            pointerEvents: 'none'
          }}>
            <div 
              style={{ 
                fontSize: '2.5rem', 
                fontWeight: 900, 
                lineHeight: 1, 
                color: activeColor,
                letterSpacing: '-0.03em',
                fontFamily: 'var(--font-sans, "Inter", sans-serif)',
                textShadow: `0 0 16px ${activeColor}66`,
                transform: isHovered ? 'scale(1.08)' : 'scale(1)',
                transition: 'transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1)'
              }}
            >
              {isLoaded ? animatedScore : '--'}
            </div>

            <div style={{ 
              fontSize: '0.72rem', 
              fontWeight: 600, 
              color: '#94A3B8', 
              marginTop: '4px' 
            }}>
              / 100
            </div>

            <div style={{
              marginTop: '6px',
              fontSize: '0.68rem',
              fontWeight: 800,
              padding: '2px 8px',
              borderRadius: '9999px',
              color: activeColor,
              background: `${activeColor}1A`,
              border: `1px solid ${activeColor}33`,
              letterSpacing: '0.04em',
              textTransform: 'uppercase'
            }}>
              {isCritical ? 'CRITICAL' : isMedium ? 'SUSPICIOUS' : isSafe ? 'CLEAN' : 'STANDBY'}
            </div>
          </div>
        </div>

        {/* Interactive Click Hint */}
        {interactive && (
          <div style={{
            fontSize: '0.68rem',
            fontWeight: 600,
            color: '#38BDF8',
            background: 'rgba(56, 189, 248, 0.1)',
            padding: '4px 10px',
            borderRadius: '6px',
            border: '1px dashed rgba(56, 189, 248, 0.35)',
            display: 'flex',
            alignItems: 'center',
            gap: '5px',
            marginTop: '2px'
          }}>
            <span>🔍 Click for forensic synthesis breakdown</span>
          </div>
        )}
      </div>

      {/* Forensic Breakdown Modal */}
      {isModalOpen && (
        <RiskScoreExplanationModal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          score={targetScore || 12}
          riskLevel={statusLabel}
          caseData={caseData}
        />
      )}
    </>
  )
}
