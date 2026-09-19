import { Routes, Route } from 'react-router-dom'
import ThreatTraceCockpit from './pages/ThreatTraceCockpit'
import CybercrimeAdminDashboard from './cybercrime/CybercrimeAdminDashboard'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<ThreatTraceCockpit />} />
      <Route path="/case/:caseId" element={<ThreatTraceCockpit />} />
      <Route path="/cybercrime" element={<CybercrimeAdminDashboard />} />
      <Route path="/cybercrime/admin" element={<CybercrimeAdminDashboard />} />
      <Route path="*" element={<ThreatTraceCockpit />} />
    </Routes>
  )
}

