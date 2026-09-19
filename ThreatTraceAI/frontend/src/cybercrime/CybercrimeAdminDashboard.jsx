import { useLocation } from 'react-router-dom'

export default function CybercrimeAdminDashboard() {
  const location = useLocation()
  const search = location.search || ''

  return (
    <iframe
      src={`/cybercrime.html${search}`}
      title="Cyber Crime Police Portal"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        border: 'none',
        margin: 0,
        padding: 0,
        zIndex: 9999
      }}
    />
  )
}

