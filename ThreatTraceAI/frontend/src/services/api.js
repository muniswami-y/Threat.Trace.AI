const envBase = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''

let cachedWorkingBase = null

async function fetchWithTimeout(url, options = {}, timeoutMs = 2500) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { ...options, signal: controller.signal })
    clearTimeout(timer)
    return res
  } catch (err) {
    clearTimeout(timer)
    throw err
  }
}

async function request(path, options = {}) {
  const reqHeaders = { 'Content-Type': 'application/json', ...(options.headers || {}) }
  const fetchOpts = { headers: reqHeaders, ...options }

  // 1. If we already found a working active base, try it first
  if (cachedWorkingBase) {
    try {
      const res = await fetchWithTimeout(`${cachedWorkingBase}${path}`, fetchOpts, 3500)
      if (res.ok) return await res.json()
    } catch (e) {
      cachedWorkingBase = null // Invalidate on error
    }
  }

  // 2. Try candidates (prioritizing production environment URL if provided)
  const localCandidates = [
    envBase,
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    ''
  ].filter(Boolean)

  for (const base of localCandidates) {
    try {
      const res = await fetchWithTimeout(`${base}${path}`, fetchOpts, 3000)
      if (res.ok) {
        cachedWorkingBase = base
        return await res.json()
      }
    } catch (e) {
      // Continue to next candidate immediately
    }
  }

  throw new Error('Local ThreatTrace AI backend not reachable on port 8000.')
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
  socQuarantine: (payload) => request('/api/soc/quarantine', { method: 'POST', body: JSON.stringify(payload) }),
  socGetQuarantineFolders: () => request('/api/soc/quarantine/folders'),
  cybercrimeReport: (reportData) => request('/api/cybercrime/report', { method: 'POST', body: JSON.stringify(reportData) }),
  cybercrimeGetCases: () => request('/api/cybercrime/cases')
}



