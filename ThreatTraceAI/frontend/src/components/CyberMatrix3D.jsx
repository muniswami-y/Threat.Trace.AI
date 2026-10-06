import React, { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'

/**
 * CyberMatrix3D: Interactive 3D Cyber Threat Infrastructure Matrix
 * Renders nodes (Victim, Ingress MTA, DNS Host, Payload, C2 Attacker)
 * floating in 3D space with particle flows, glowing links, and interactive rotation.
 */
export default function CyberMatrix3D({ 
  riskLevel = 'HIGH', 
  riskScore = null, 
  height = 240,
  theme = 'white'
}) {
  const mountRef = useRef(null)
  const [currentTheme, setCurrentTheme] = useState(theme)
  const [selectedNode, setSelectedNode] = useState(null)
  const isCritical = riskScore !== null ? Number(riskScore) >= 70 : (riskLevel === 'HIGH' || riskLevel === 'CRITICAL')
  const themeColor = isCritical ? 0xef4444 : 0x10b981
  const hexStr = isCritical ? '#ef4444' : '#10b981'

  const isLight = currentTheme === 'white' || currentTheme === 'light'

  const animFrameId = useRef(null)
  const isDraggingRef = useRef(false)
  const mousePosRef = useRef({ x: 0, y: 0 })

  const nodesData = [
    { id: 'src', name: 'Victim Inbox', type: 'Client', pos: [-4.4, 0.2, 1.0], color: 0x38bdf8, icon: '👤' },
    { id: 'mta', name: 'Relay MTA', type: 'Gateway', pos: [-2.0, 1.8, -0.6], color: 0x818cf8, icon: '⚡' },
    { id: 'domain', name: 'Target Host', type: 'DNS Server', pos: [0.3, 0.0, 1.2], color: 0xfbbf24, icon: '🌐' },
    { id: 'url', name: 'Weaponized Link', type: 'Payload', pos: [2.5, 1.7, -0.4], color: themeColor, icon: '🎯' },
    { id: 'c2', name: 'Attacker C2', type: 'Host Node', pos: [4.6, 0.3, 0.6], color: isCritical ? 0xdc2626 : 0x059669, icon: '🖥️' }
  ]

  const linksData = [
    { from: 0, to: 1 },
    { from: 1, to: 2 },
    { from: 2, to: 3 },
    { from: 3, to: 4 }
  ]

  useEffect(() => {
    const container = mountRef.current
    if (!container) return

    const width = container.clientWidth || 380
    const currentHeight = height

    // 1. Scene setup
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(45, width / currentHeight, 0.1, 100)
    camera.position.set(0, 1.2, 13.5)
    camera.lookAt(0, 0.6, 0)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setSize(width, currentHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    container.innerHTML = ''
    container.appendChild(renderer.domElement)

    // 2. Root Group
    const matrixGroup = new THREE.Group()
    scene.add(matrixGroup)

    // 3. 3D Isometric Cyber Grid Floor
    const gridHelper = new THREE.GridHelper(16, 16, 0x0284c7, isLight ? 0xcbd5e1 : 0x1e293b)
    gridHelper.position.y = -1.8
    gridHelper.material.opacity = isLight ? 0.35 : 0.25
    gridHelper.material.transparent = true
    matrixGroup.add(gridHelper)

    // Helper: Floating 3D Text Badge for each node
    const createTextBadge = (text, hexColor) => {
      const canvas = document.createElement('canvas')
      canvas.width = 256
      canvas.height = 64
      const ctx = canvas.getContext('2d')
      ctx.fillStyle = 'rgba(10, 15, 30, 0.82)'
      if (ctx.roundRect) {
        ctx.roundRect(4, 4, 248, 56, 12)
      } else {
        ctx.rect(4, 4, 248, 56)
      }
      ctx.fill()
      ctx.strokeStyle = `#${hexColor.toString(16).padStart(6, '0')}`
      ctx.lineWidth = 3
      ctx.stroke()
      ctx.font = 'bold 22px system-ui, sans-serif'
      ctx.fillStyle = '#FFFFFF'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(text, 128, 33)
      const texture = new THREE.CanvasTexture(canvas)
      const spriteMat = new THREE.SpriteMaterial({ map: texture, transparent: true })
      const sprite = new THREE.Sprite(spriteMat)
      sprite.scale.set(1.9, 0.48, 1)
      sprite.position.set(0, 0.95, 0)
      return sprite
    }

    // 4. Background Cyber Telemetry Dust (Particles)
    const dustCount = 200
    const dustGeo = new THREE.BufferGeometry()
    const dustPos = new Float32Array(dustCount * 3)
    for (let i = 0; i < dustCount * 3; i += 3) {
      dustPos[i] = (Math.random() - 0.5) * 20
      dustPos[i + 1] = (Math.random() - 0.5) * 10 + 0.5
      dustPos[i + 2] = (Math.random() - 0.5) * 14
    }
    dustGeo.setAttribute('position', new THREE.BufferAttribute(dustPos, 3))
    const dustMat = new THREE.PointsMaterial({
      color: 0x38bdf8,
      size: 0.08,
      transparent: true,
      opacity: 0.4
    })
    const dustPoints = new THREE.Points(dustGeo, dustMat)
    matrixGroup.add(dustPoints)

    // 5. 3D Nodes
    const nodeMeshes = []
    nodesData.forEach((node) => {
      const nodeGroup = new THREE.Group()
      nodeGroup.position.set(...node.pos)

      // Core Glowing Sphere
      const sphereGeo = new THREE.SphereGeometry(0.52, 24, 24)
      const sphereMat = new THREE.MeshBasicMaterial({
        color: node.color,
        wireframe: false
      })
      const sphereMesh = new THREE.Mesh(sphereGeo, sphereMat)
      nodeGroup.add(sphereMesh)

      // Outer Wireframe Orbital Ring
      const ringGeo = new THREE.RingGeometry(0.72, 0.86, 24)
      const ringMat = new THREE.MeshBasicMaterial({
        color: node.color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.6
      })
      const ringMesh = new THREE.Mesh(ringGeo, ringMat)
      ringMesh.rotation.x = Math.PI / 3
      nodeGroup.add(ringMesh)

      // Floating 3D Text Badge
      nodeGroup.add(createTextBadge(node.name, node.color))

      // Vertical Stalk to Grid Floor
      const stalkGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(0, -1.8 - node.pos[1], 0)
      ])
      const stalkMat = new THREE.LineDashedMaterial({
        color: node.color,
        dashSize: 0.3,
        gapSize: 0.2,
        transparent: true,
        opacity: 0.3
      })
      const stalkLine = new THREE.Line(stalkGeo, stalkMat)
      stalkLine.computeLineDistances()
      nodeGroup.add(stalkLine)

      matrixGroup.add(nodeGroup)
      nodeMeshes.push({ group: nodeGroup, ring: ringMesh, data: node })
    })

    // 6. 3D Connection Beams & Traveling Laser Pulses
    const linkCurves = []
    linksData.forEach(({ from, to }) => {
      const p1 = new THREE.Vector3(...nodesData[from].pos)
      const p2 = new THREE.Vector3(...nodesData[to].pos)

      // Curved Bézier path in 3D
      const mid = p1.clone().lerp(p2, 0.5)
      mid.y += 1.0

      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2)
      const curvePoints = curve.getPoints(30)
      const curveGeo = new THREE.BufferGeometry().setFromPoints(curvePoints)
      const curveMat = new THREE.LineBasicMaterial({
        color: 0x0284c7,
        transparent: true,
        opacity: 0.5
      })
      const lineMesh = new THREE.Line(curveGeo, curveMat)
      matrixGroup.add(lineMesh)

      // Traveling Laser Pulse Sphere
      const pulseGeo = new THREE.SphereGeometry(0.18, 12, 12)
      const pulseMat = new THREE.MeshBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.95
      })
      const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat)
      matrixGroup.add(pulseMesh)

      linkCurves.push({ curve, pulse: pulseMesh, progress: Math.random() })
    })

    // 7. Mouse Drag to Orbit in 3D
    const onMouseDown = (e) => {
      isDraggingRef.current = true
      mousePosRef.current = { x: e.clientX, y: e.clientY }
    }

    const onMouseMove = (e) => {
      if (!isDraggingRef.current) return
      const deltaX = e.clientX - mousePosRef.current.x
      const deltaY = e.clientY - mousePosRef.current.y
      mousePosRef.current = { x: e.clientX, y: e.clientY }

      matrixGroup.rotation.y += deltaX * 0.007
      matrixGroup.rotation.x += deltaY * 0.007
      matrixGroup.rotation.x = Math.max(-0.6, Math.min(0.6, matrixGroup.rotation.x))
    }

    const onMouseUp = () => {
      isDraggingRef.current = false
    }

    container.addEventListener('mousedown', onMouseDown)
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)

    // Touch support
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
      matrixGroup.rotation.y += deltaX * 0.008
      matrixGroup.rotation.x += deltaY * 0.008
    }
    const onTouchEnd = () => {
      isDraggingRef.current = false
    }

    container.addEventListener('touchstart', onTouchStart)
    window.addEventListener('touchmove', onTouchMove)
    window.addEventListener('touchend', onTouchEnd)

    // 8. Animation Loop
    const animate = () => {
      animFrameId.current = requestAnimationFrame(animate)

      // Idle smooth rotation
      if (!isDraggingRef.current) {
        matrixGroup.rotation.y += 0.0025
      }

      // Rotate orbital rings on nodes
      nodeMeshes.forEach((nm, idx) => {
        nm.ring.rotation.z += 0.02 * (idx % 2 === 0 ? 1 : -1)
      })

      // Move traveling laser pulses along 3D curves
      linkCurves.forEach(lc => {
        lc.progress += 0.012
        if (lc.progress > 1.0) lc.progress = 0
        const pt = lc.curve.getPoint(lc.progress)
        lc.pulse.position.copy(pt)
      })

      renderer.render(scene, camera)
    }
    animate()

    // Resize
    const handleResize = () => {
      if (!container || !renderer || !camera) return
      const newWidth = container.clientWidth
      camera.aspect = newWidth / currentHeight
      camera.updateProjectionMatrix()
      camera.lookAt(0, 0.6, 0)
      renderer.setSize(newWidth, currentHeight)
    }
    window.addEventListener('resize', handleResize)

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
  }, [riskLevel, riskScore, height, currentTheme])

  return (
    <div style={{
      position: 'relative',
      background: isLight 
        ? 'linear-gradient(180deg, #F8FAFC 0%, #F1F5F9 100%)' 
        : 'radial-gradient(circle at 50% 50%, #0c182c 0%, #030712 100%)',
      borderRadius: '12px',
      border: isLight ? '1px solid #E2E8F0' : '1px solid rgba(56, 189, 248, 0.2)',
      boxShadow: isLight ? '0 2px 8px rgba(0, 0, 0, 0.04)' : '0 8px 32px rgba(0, 0, 0, 0.35)',
      overflow: 'hidden'
    }}>
      {/* 3D WebGL Canvas */}
      <div 
        ref={mountRef} 
        style={{ 
          width: '100%', 
          height: `${height}px`,
          cursor: 'grab' 
        }} 
      />

      {/* Top Header Overlay with Theme Toggle */}
      <div style={{
        position: 'absolute',
        top: '8px',
        left: '10px',
        right: '10px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        zIndex: 10,
        pointerEvents: 'none'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          background: isLight ? 'rgba(255, 255, 255, 0.92)' : 'rgba(15, 23, 42, 0.75)',
          backdropFilter: 'blur(8px)',
          padding: '4px 10px',
          borderRadius: '8px',
          border: isLight ? '1px solid #E2E8F0' : '1px solid rgba(255, 255, 255, 0.08)',
          boxShadow: isLight ? '0 2px 6px rgba(0,0,0,0.05)' : 'none',
          pointerEvents: 'auto'
        }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: hexStr, boxShadow: `0 0 8px ${hexStr}` }} />
          <span style={{
            fontSize: '0.7rem',
            fontWeight: 800,
            color: isLight ? '#0F172A' : '#f8fafc',
            letterSpacing: '0.04em',
            textTransform: 'uppercase'
          }}>
            3D Cyber Topology Matrix
          </span>
          <span style={{ fontSize: '0.64rem', color: '#0284C7', fontFamily: 'monospace', fontWeight: 700 }}>
            5 Nodes • 4 Beams
          </span>
        </div>

        <div style={{ display: 'flex', gap: '4px', pointerEvents: 'auto' }}>
          <button
            type="button"
            onClick={() => setCurrentTheme(isLight ? 'dark' : 'white')}
            style={{
              background: isLight ? '#FFFFFF' : 'rgba(255, 255, 255, 0.08)',
              border: isLight ? '1px solid #E2E8F0' : '1px solid rgba(255, 255, 255, 0.15)',
              color: isLight ? '#475569' : '#cbd5e1',
              padding: '3px 8px',
              borderRadius: '6px',
              fontSize: '0.64rem',
              fontWeight: 700,
              cursor: 'pointer',
              boxShadow: isLight ? '0 1px 3px rgba(0,0,0,0.05)' : 'none'
            }}
          >
            {isLight ? '🌙 Dark' : '☀️ White'}
          </button>
        </div>
      </div>

      {/* Interactive Node Legend Bar */}
      <div style={{
        position: 'absolute',
        bottom: '8px',
        left: '10px',
        right: '10px',
        display: 'flex',
        justifyContent: 'center',
        flexWrap: 'wrap',
        gap: '6px',
        background: isLight ? 'rgba(255, 255, 255, 0.95)' : 'rgba(15, 23, 42, 0.85)',
        backdropFilter: 'blur(8px)',
        padding: '5px 10px',
        borderRadius: '8px',
        border: isLight ? '1px solid #E2E8F0' : '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: isLight ? '0 2px 8px rgba(0,0,0,0.06)' : '0 4px 12px rgba(0,0,0,0.3)',
        zIndex: 10
      }}>
        {nodesData.map((node) => (
          <div 
            key={node.id} 
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '4px', 
              fontSize: '0.66rem',
              color: isLight ? '#334155' : '#cbd5e1',
              fontWeight: 600
            }}
          >
            <span style={{ fontSize: '0.78rem' }}>{node.icon}</span>
            <span>{node.name}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
