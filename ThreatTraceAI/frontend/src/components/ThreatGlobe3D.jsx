import React, { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'

/**
 * ThreatGlobe3D: Interactive WebGL 3D Cyber Threat Globe
 * Renders a high-tech 3D Earth with rotating continents, glowing atmosphere,
 * pulsating threat markers at lat/lon coordinates, and 3D attack trajectory arcs.
 */
export default function ThreatGlobe3D({ 
  locations = [], 
  riskLevel = 'HIGH', 
  riskScore = null,
  height = 320,
  showControls = true 
}) {
  const mountRef = useRef(null)
  const [isRotating, setIsRotating] = useState(true)
  const [selectedLoc, setSelectedLoc] = useState(null)
  const [cameraView, setCameraView] = useState('auto') // 'auto' | 'top' | 'threat'
  const sceneRef = useRef(null)
  const globeGroupRef = useRef(null)
  const cameraRef = useRef(null)
  const rendererRef = useRef(null)
  const animFrameId = useRef(null)
  const isDraggingRef = useRef(false)
  const mousePosRef = useRef({ x: 0, y: 0 })

  const isCritical = riskScore !== null ? Number(riskScore) >= 70 : (riskLevel === 'HIGH' || riskLevel === 'CRITICAL')
  const themeColor = isCritical ? 0xef4444 : 0x10b981
  const hexColorStr = isCritical ? '#ef4444' : '#10b981'

  // Normalize locations or fallback to realistic default
  const validLocations = locations.filter(l => l && l.lat != null && l.lon != null)
  const activeLocations = validLocations.length > 0 ? validLocations : [
    { ip: '185.220.101.5', city: 'Moscow', country: 'Russia', lat: 55.7558, lon: 37.6173, isAttacker: true },
    { ip: '103.108.118.77', city: 'Mumbai', country: 'India', lat: 19.0760, lon: 72.8777, isAttacker: isCritical },
    { ip: '142.250.190.46', city: 'Mountain View', country: 'United States', lat: 37.3861, lon: -122.0839, isVictim: true }
  ]

  // Coordinate conversion: Lat/Lon -> 3D Vector
  const latLonToVector3 = (lat, lon, radius) => {
    const phi = (90 - lat) * (Math.PI / 180)
    const theta = (lon + 180) * (Math.PI / 180)
    const x = -(radius * Math.sin(phi) * Math.cos(theta))
    const z = (radius * Math.sin(phi) * Math.sin(theta))
    const y = (radius * Math.cos(phi))
    return new THREE.Vector3(x, y, z)
  }

  useEffect(() => {
    const container = mountRef.current
    if (!container) return

    const width = container.clientWidth || 400
    const currentHeight = height

    // 1. Scene setup
    const scene = new THREE.Scene()
    sceneRef.current = scene

    // 2. Camera setup - Centered right on the globe
    const camera = new THREE.PerspectiveCamera(45, width / currentHeight, 0.1, 1000)
    camera.position.set(0, 0.6, 16.5)
    camera.lookAt(0, 0.6, 0)
    cameraRef.current = camera

    // 3. Renderer setup
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(width, currentHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    rendererRef.current = renderer
    container.innerHTML = ''
    container.appendChild(renderer.domElement)

    // 4. Globe Root Group - Elevated slightly for beautiful composition
    const globeGroup = new THREE.Group()
    globeGroup.position.set(0, 0.6, 0)
    scene.add(globeGroup)
    globeGroupRef.current = globeGroup

    const RADIUS = 5.2

    // 5. Base Dark Sphere (Ocean)
    const sphereGeo = new THREE.SphereGeometry(RADIUS, 48, 48)
    const sphereMat = new THREE.MeshBasicMaterial({
      color: 0x050b14,
      transparent: true,
      opacity: 0.92
    })
    const baseSphere = new THREE.Mesh(sphereGeo, sphereMat)
    globeGroup.add(baseSphere)

    // 6. Glowing Latitude & Longitude Wireframe Cage
    const wireframeMat = new THREE.MeshBasicMaterial({
      color: 0x0284c7,
      wireframe: true,
      transparent: true,
      opacity: 0.18
    })
    const wireframeSphere = new THREE.Mesh(sphereGeo, wireframeMat)
    globeGroup.add(wireframeSphere)

    // 7. Outer Atmospheric Glow Halo
    const haloGeo = new THREE.SphereGeometry(RADIUS * 1.15, 32, 32)
    const haloMat = new THREE.ShaderMaterial({
      vertexShader: `
        varying vec3 vNormal;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        varying vec3 vNormal;
        uniform vec3 glowColor;
        void main() {
          float intensity = pow(0.65 - dot(vNormal, vec3(0, 0, 1.0)), 2.2);
          gl_FragColor = vec4(glowColor, intensity * 0.45);
        }
      `,
      uniforms: {
        glowColor: { value: new THREE.Color(isCritical ? 0xef4444 : 0x0284c7) }
      },
      side: THREE.BackSide,
      blending: THREE.AdditiveBlending,
      transparent: true
    })
    const haloMesh = new THREE.Mesh(haloGeo, haloMat)
    globeGroup.add(haloMesh)

    // 8. Procedural Particle Continents (High-Tech Cyber Dots)
    const pointCount = 1400
    const pointPositions = new Float32Array(pointCount * 3)
    const pointColors = new Float32Array(pointCount * 3)
    const cyanColor = new THREE.Color(0x38bdf8)
    const mutedColor = new THREE.Color(0x1e293b)

    for (let i = 0; i < pointCount; i++) {
      // Golden spiral distribution on sphere
      const phi = Math.acos(-1 + (2 * i) / pointCount)
      const theta = Math.sqrt(pointCount * Math.PI) * phi

      const x = -(RADIUS * 1.008 * Math.sin(phi) * Math.cos(theta))
      const y = (RADIUS * 1.008 * Math.cos(phi))
      const z = (RADIUS * 1.008 * Math.sin(phi) * Math.sin(theta))

      pointPositions[i * 3] = x
      pointPositions[i * 3 + 1] = y
      pointPositions[i * 3 + 2] = z

      // Subtle sparkle
      const isLand = Math.sin(phi * 4) * Math.cos(theta * 3) > -0.2
      const c = isLand ? cyanColor : mutedColor
      pointColors[i * 3] = c.r
      pointColors[i * 3 + 1] = c.g
      pointColors[i * 3 + 2] = c.b
    }

    const pointGeo = new THREE.BufferGeometry()
    pointGeo.setAttribute('position', new THREE.BufferAttribute(pointPositions, 3))
    pointGeo.setAttribute('color', new THREE.BufferAttribute(pointColors, 3))
    const pointMat = new THREE.PointsMaterial({
      size: 0.14,
      vertexColors: true,
      transparent: true,
      opacity: 0.75
    })
    const continentPoints = new THREE.Points(pointGeo, pointMat)
    globeGroup.add(continentPoints)

    // 9. Threat Location Pins & Pulsing Sonar Rings
    const ringMeshes = []
    const pinVectors = []

    activeLocations.forEach((loc, index) => {
      const pinPos = latLonToVector3(loc.lat, loc.lon, RADIUS * 1.01)
      pinVectors.push({ pos: pinPos, loc })

      // Glowing Beacon Cylinder / Pin
      const pinGeo = new THREE.CylinderGeometry(0.04, 0.12, 0.8, 8)
      pinGeo.rotateX(Math.PI / 2)
      const pinMat = new THREE.MeshBasicMaterial({
        color: loc.isVictim ? 0x38bdf8 : themeColor
      })
      const pinMesh = new THREE.Mesh(pinGeo, pinMat)
      pinMesh.position.copy(pinPos)
      pinMesh.lookAt(0, 0, 0)
      pinMesh.position.add(pinPos.clone().normalize().multiplyScalar(0.4))
      globeGroup.add(pinMesh)

      // Pulsing Sonar Ring on Surface
      const ringGeo = new THREE.RingGeometry(0.2, 0.35, 24)
      const ringMat = new THREE.MeshBasicMaterial({
        color: loc.isVictim ? 0x38bdf8 : themeColor,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.8
      })
      const ringMesh = new THREE.Mesh(ringGeo, ringMat)
      ringMesh.position.copy(pinPos.clone().multiplyScalar(1.005))
      ringMesh.lookAt(0, 0, 0)
      globeGroup.add(ringMesh)

      ringMeshes.push({ mesh: ringMesh, scale: 1.0, speed: 0.015 + index * 0.005 })
    })

    // 10. 3D Attack Trajectory Arcs (Flight Path between Scammer & Victim)
    if (pinVectors.length >= 2) {
      const start = pinVectors[0].pos
      const end = pinVectors[pinVectors.length - 1].pos

      // Elevated midpoint to create an arched trajectory in 3D
      const mid = start.clone().lerp(end, 0.5)
      const alt = start.distanceTo(end) * 0.45 + RADIUS * 0.25
      mid.normalize().multiplyScalar(RADIUS + alt)

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end)
      const points = curve.getPoints(50)
      const curveGeo = new THREE.BufferGeometry().setFromPoints(points)
      const curveMat = new THREE.LineDashedMaterial({
        color: themeColor,
        dashSize: 0.5,
        gapSize: 0.25,
        linewidth: 2,
        transparent: true,
        opacity: 0.95
      })
      const arcLine = new THREE.Line(curveGeo, curveMat)
      arcLine.computeLineDistances()
      globeGroup.add(arcLine)

      // Orbiting Missile / Data Pulse on the Arc
      const missileGeo = new THREE.SphereGeometry(0.16, 12, 12)
      const missileMat = new THREE.MeshBasicMaterial({ color: 0xffffff })
      const missileMesh = new THREE.Mesh(missileGeo, missileMat)
      globeGroup.add(missileMesh)

      // Store in group for animation
      globeGroup.userData.arcCurve = curve
      globeGroup.userData.missile = missileMesh
      globeGroup.userData.missileProgress = 0
    }

    // 11. Mouse Drag to Rotate Globe
    const onMouseDown = (e) => {
      isDraggingRef.current = true
      mousePosRef.current = { x: e.clientX, y: e.clientY }
    }

    const onMouseMove = (e) => {
      if (!isDraggingRef.current) return
      const deltaX = e.clientX - mousePosRef.current.x
      const deltaY = e.clientY - mousePosRef.current.y
      mousePosRef.current = { x: e.clientX, y: e.clientY }

      globeGroup.rotation.y += deltaX * 0.006
      globeGroup.rotation.x += deltaY * 0.006
      globeGroup.rotation.x = Math.max(-1.1, Math.min(1.1, globeGroup.rotation.x))
    }

    const onMouseUp = () => {
      isDraggingRef.current = false
    }

    // Touch events for mobile/tablet
    const onTouchStart = (e) => {
      if (e.touches.length === 1) {
        isDraggingRef.current = true
        mousePosRef.current = { x: e.touches[0].clientX, y: e.touches[0].clientY }
      }
    }

    const onTouchMove = (e) => {
      if (!isDraggingRef.current || e.touches.length !== 1) return
      const deltaX = e.touches[0].clientX - mousePosRef.current.x
      const deltaY = e.touches[0].clientY - mousePosRef.current.y
      mousePosRef.current = { x: e.touches[0].clientX, y: e.touches[0].clientY }

      globeGroup.rotation.y += deltaX * 0.008
      globeGroup.rotation.x += deltaY * 0.008
    }

    const onTouchEnd = () => {
      isDraggingRef.current = false
    }

    container.addEventListener('mousedown', onMouseDown)
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    container.addEventListener('touchstart', onTouchStart)
    window.addEventListener('touchmove', onTouchMove)
    window.addEventListener('touchend', onTouchEnd)

    // 12. Main 60 FPS Render Loop
    let clock = new THREE.Clock()
    const animate = () => {
      animFrameId.current = requestAnimationFrame(animate)

      // Auto-rotation if enabled and not currently dragging
      if (isRotating && !isDraggingRef.current) {
        globeGroup.rotation.y += 0.0035
      }

      // Animate pulsing sonar rings
      ringMeshes.forEach(r => {
        r.scale += r.speed
        if (r.scale > 2.6) r.scale = 1.0
        r.mesh.scale.set(r.scale, r.scale, 1)
        r.mesh.material.opacity = Math.max(0, 1.0 - (r.scale - 1.0) / 1.6)
      })

      // Animate ballistic attack projectile along arc
      if (globeGroup.userData.arcCurve && globeGroup.userData.missile) {
        globeGroup.userData.missileProgress += 0.008
        if (globeGroup.userData.missileProgress > 1.0) {
          globeGroup.userData.missileProgress = 0
        }
        const pt = globeGroup.userData.arcCurve.getPoint(globeGroup.userData.missileProgress)
        globeGroup.userData.missile.position.copy(pt)
      }

      renderer.render(scene, camera)
    }
    animate()

    // 13. Window resize handling
    const handleResize = () => {
      if (!container || !renderer || !camera) return
      const newWidth = container.clientWidth
      camera.aspect = newWidth / currentHeight
      camera.updateProjectionMatrix()
      camera.lookAt(0, 0.6, 0)
      renderer.setSize(newWidth, currentHeight)
    }
    window.addEventListener('resize', handleResize)

    // Initial Threat Focus (rotate towards first threat)
    if (pinVectors.length > 0) {
      const firstThreat = pinVectors[0].loc
      const targetY = -(firstThreat.lon * (Math.PI / 180)) - Math.PI / 2
      globeGroup.rotation.y = targetY
      globeGroup.rotation.x = (firstThreat.lat * (Math.PI / 180)) * 0.4
    }

    return () => {
      cancelAnimationFrame(animFrameId.current)
      window.removeEventListener('resize', handleResize)
      container.removeEventListener('mousedown', onMouseDown)
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
      container.removeEventListener('touchstart', onTouchStart)
      window.removeEventListener('touchmove', onTouchMove)
      window.removeEventListener('touchend', onTouchEnd)
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
      renderer.dispose()
    }
  }, [locations, riskLevel, riskScore, height])

  // Center on specific threat pin
  const focusLocation = (loc) => {
    setSelectedLoc(loc)
    if (!globeGroupRef.current) return
    const targetY = -(loc.lon * (Math.PI / 180)) - Math.PI / 2
    const targetX = (loc.lat * (Math.PI / 180)) * 0.45
    globeGroupRef.current.rotation.y = targetY
    globeGroupRef.current.rotation.x = targetX
  }

  const primaryLoc = activeLocations[0] || {}

  return (
    <div style={{
      position: 'relative',
      background: 'radial-gradient(circle at 50% 50%, #0c182c 0%, #030712 100%)',
      borderRadius: '14px',
      border: '1px solid rgba(56, 189, 248, 0.2)',
      boxShadow: '0 12px 36px rgba(0, 0, 0, 0.6), inset 0 1px 1px rgba(255, 255, 255, 0.1)',
      overflow: 'hidden'
    }}>
      {/* Top Header Overlay */}
      <div style={{
        position: 'absolute',
        top: '12px',
        left: '14px',
        right: '14px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        zIndex: 10,
        pointerEvents: 'none'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            display: 'inline-block',
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            background: hexColorStr,
            boxShadow: `0 0 10px ${hexColorStr}`
          }} />
          <span style={{
            fontSize: '0.78rem',
            fontWeight: 800,
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
            color: '#f8fafc',
            fontFamily: 'var(--font-mono)'
          }}>
            3D Cyber Threat Telemetry Globe
          </span>
        </div>

        <div style={{
          display: 'flex',
          gap: '6px',
          pointerEvents: 'auto'
        }}>
          <button
            onClick={() => setIsRotating(!isRotating)}
            style={{
              background: isRotating ? 'rgba(56, 189, 248, 0.15)' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${isRotating ? '#38bdf8' : 'rgba(255, 255, 255, 0.15)'}`,
              color: isRotating ? '#38bdf8' : '#94a3b8',
              padding: '3px 8px',
              borderRadius: '6px',
              fontSize: '0.68rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            {isRotating ? '⏸ PAUSE ROTATION' : '▶ SPIN GLOBE'}
          </button>
        </div>
      </div>

      {/* 3D WebGL Canvas Mount */}
      <div 
        ref={mountRef} 
        style={{ 
          width: '100%', 
          height: `${height}px`,
          cursor: 'grab'
        }} 
      />

      {/* Bottom Telemetry HUD Bar */}
      <div style={{
        position: 'absolute',
        bottom: '8px',
        left: '10px',
        right: '10px',
        background: 'rgba(8, 14, 26, 0.72)',
        backdropFilter: 'blur(10px)',
        border: '1px solid rgba(56, 189, 248, 0.22)',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
        borderRadius: '8px',
        padding: '5px 10px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        zIndex: 10
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
          <span style={{ fontSize: '0.95rem' }}>📍</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {primaryLoc.city || 'Origin City'}, {primaryLoc.country || 'Host Country'}
            </div>
            <div style={{ fontSize: '0.64rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              IP: {primaryLoc.ip || 'Unknown'} • Lat: {primaryLoc.lat || '0'} Lon: {primaryLoc.lon || '0'}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '4px' }}>
          {activeLocations.map((loc, i) => (
            <button
              key={i}
              onClick={() => focusLocation(loc)}
              style={{
                background: selectedLoc === loc ? 'rgba(56, 189, 248, 0.25)' : 'rgba(255, 255, 255, 0.04)',
                border: `1px solid ${selectedLoc === loc ? '#38bdf8' : 'rgba(255, 255, 255, 0.1)'}`,
                color: selectedLoc === loc ? '#38bdf8' : '#cbd5e1',
                borderRadius: '4px',
                padding: '2px 5px',
                fontSize: '0.62rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Pin #{i + 1}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
