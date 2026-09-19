const BASE = import.meta.env.VITE_API_URL !== undefined ? import.meta.env.VITE_API_URL : ''

async function request(path, options = {}) {
  const reqHeaders = { 'Content-Type': 'application/json', ...(options.headers || {}) }

  // 1. Try relative path (uses Vite dev server proxy to :8000)
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: reqHeaders,
      ...options
    })
    if (res.ok) {
      return await res.json()
    }
  } catch (e) {
    // Relative fetch failed, fallback
  }

  // 2. Try direct localhost:8000
  try {
    const res = await fetch(`http://localhost:8000${path}`, {
      headers: reqHeaders,
      ...options
    })
    if (res.ok) {
      return await res.json()
    }
  } catch (e) {}

  // 3. Try direct 127.0.0.1:8000
  try {
    const res = await fetch(`http://127.0.0.1:8000${path}`, {
      headers: reqHeaders,
      ...options
    })
    if (res.ok) {
      return await res.json()
    }
  } catch (e) {}

  // 4. Try live Render cloud backend (24/7)
  const res = await fetch(`https://threattrace-backend-a8ll.onrender.com${path}`, {
    headers: reqHeaders,
    ...options
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }
  return res.json()
}

export const api = {
  analyze: (body) => request('/api/analyze', { method: 'POST', body: JSON.stringify(body) }),
  listCases: () => request('/api/cases/'),
  getCase: (id) => request(`/api/cases/${id}`),
  seedCases: () => request('/api/cases/seed', { method: 'POST' }),
  generateReport: (caseId) => request(`/api/reports/${caseId}/generate`, { method: 'POST' }),
  health: () => request('/health'),
  
  // End-to-End Cryptography Suite
  cryptoSeal: (caseData) => request('/api/crypto/seal', { method: 'POST', body: JSON.stringify({ case: caseData }) }),
  cryptoVerify: (caseData, signature, expected_hash, public_key_pem) => request('/api/crypto/verify', { method: 'POST', body: JSON.stringify({ case: caseData, signature, expected_hash, public_key_pem }) }),
  cryptoSimulateTamper: (caseData) => request('/api/crypto/simulate-tamper', { method: 'POST', body: JSON.stringify({ case: caseData }) }),
  cryptoEncrypt: (dossier, passphrase) => request('/api/crypto/encrypt', { method: 'POST', body: JSON.stringify({ dossier, passphrase }) }),
  cryptoDecrypt: (envelope, passphrase) => request('/api/crypto/decrypt', { method: 'POST', body: JSON.stringify({ envelope, passphrase }) }),
  cryptoGetKeys: () => request('/api/crypto/keys'),
  cryptoInspectHeaders: (raw_headers) => request('/api/crypto/inspect-headers', { method: 'POST', body: JSON.stringify({ raw_headers }) }),

  // Cybersecurity Department & SOC Integration
  socDispatch: (caseData, webhookUrl) => request('/api/soc/dispatch', { method: 'POST', body: JSON.stringify({ case: caseData, webhook_url: webhookUrl }) }),
  socGetCef: (caseData) => request('/api/soc/cef', { method: 'POST', body: JSON.stringify({ case: caseData }) }),
  socGetJira: (caseData) => request('/api/soc/jira-ticket', { method: 'POST', body: JSON.stringify({ case: caseData }) }),
  socProbeIp: (ip, ports) => request('/api/soc/probe-ip', { method: 'POST', body: JSON.stringify({ ip, ports }) }),
  socUnmaskUrl: (url, maxHops) => request('/api/soc/unmask-url', { method: 'POST', body: JSON.stringify({ url, max_hops: maxHops }) }),
  socGetSubpoenaPackage: (caseData) => request('/api/soc/subpoena-package', { method: 'POST', body: JSON.stringify({ case: caseData }) }),
  socGetCanaryToken: (caseData) => request('/api/soc/canary-token', { method: 'POST', body: JSON.stringify({ case: caseData }) }),
  cybercrimeReport: (reportData) => request('/api/cybercrime/report', { method: 'POST', body: JSON.stringify(reportData) }),
  cybercrimeGetCases: () => request('/api/cybercrime/cases')
}


