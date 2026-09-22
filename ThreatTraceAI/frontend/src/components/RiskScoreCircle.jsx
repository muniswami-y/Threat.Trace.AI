import React, { useEffect, useState } from 'react'

export default function RiskScoreCircle({ score = null, riskLevel = 'STANDBY' }) {
  const isLoaded = score !== null && score !== undefined && score !== '--'
  const numericScore = isLoaded ? Math.min(100, Math.max(0, Math.round(Number(score)))) : 0
  
  const [displayScore, setDisplayScore] = useState(0)

  // Smooth easing count-up animation
  useEffect(() => {
    if (!isLoaded) {
      setDisplayScore(0)
      return
    }
    let start = 0
    const end = numericScore
    const duration = 650
    const stepTime = 16
    const totalSteps = Math.ceil(duration / stepTime)
    let currentStep = 0

    const timer = setInterval(() => {
      currentStep++
      const progress = currentStep / totalSteps
      const current = Math.round(end * (1 - Math.pow(1 - progress, 3)))
      setDisplayScore(current)
      if (currentStep >= totalSteps) {
        clearInterval(timer)
        setDisplayScore(end)
      }
    }, stepTime)

    return () => clearInterval(timer)
  }, [numericScore, isLoaded])

  // Threat taxonomy mapping
  const isHigh = isLoaded && (riskLevel === 'HIGH' || numericScore >= 70)
  const isMed = isLoaded && !isHigh && (riskLevel === 'MEDIUM' || (numericScore >= 40 && numericScore < 70))
  const isSafe = isLoaded && !isHigh && !isMed

  const color = !isLoaded 
    ? '#475569' 
    : isHigh 
      ? '#EF4444' 
      : isMed 
        ? '#F59E0B' 
        : '#10B981'

  const glowColor = !isLoaded
    ? 'rgba(71, 85, 105, 0.15)'
    : isHigh
      ? 'rgba(239, 68, 68, 0.35)'
      : isMed
        ? 'rgba(245, 158, 11, 0.35)'
        : 'rgba(16, 185, 129, 0.35)'

  const statusLabel = !isLoaded 
    ? 'STANDBY' 
    : isHigh 
      ? 'CRITICAL THREAT' 
      : isMed 
        ? 'SUSPICIOUS' 
        : 'VERIFIED CLEAN'

  const radius = 50
  const strokeWidth = 9
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (circumference * (isLoaded ? displayScore : 0)) / 100

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px', width: '100%' }}>
      <div 
        style={{ 
          position: 'relative', 
          width: '140px', 
          height: '140px', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          filter: `drop-shadow(0 0 24px ${glowColor})`
        }}
      >
        <svg width="140" height="140" viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
          {/* Background track */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth={strokeWidth}
          />
          {/* Active progress arc */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 0.6s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.3s ease'
            }}
          />
        </svg>

        {/* Center metric */}
        <div style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div 
            style={{ 
              fontSize: '2.5rem', 
              fontWeight: 800, 
              lineHeight: 1, 
              fontFamily: 'var(--font-sans)',
              color: color,
              letterSpacing: '-0.03em'
            }}
          >
            {isLoaded ? displayScore : '--'}
          </div>
          <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)', marginTop: '4px' }}>
            / 100
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px' }}>
        <div style={{ fontSize: '0.74rem', fontWeight: 800, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
          COMPOSITE RISK SCORE
        </div>
        <div 
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.78rem',
            fontWeight: 700,
            padding: '4px 12px',
            borderRadius: '9999px',
            color: color,
            background: `${color}18`
          }}
        >
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: color }} />
          {statusLabel}
        </div>
      </div>
    </div>
  )
}
