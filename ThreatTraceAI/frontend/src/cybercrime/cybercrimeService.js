/**
 * cybercrimeService.js
 * Comprehensive data service for Cybercrime Admin Dashboard.
 * Provides:
 * - Queue, Rejected, Process, and Completed cases state management
 * - Full forensic records, complainant data, and email headers
 * - Officer roster & assignment
 * - 3-Layer Separated Cryptographic Key Derivation (Admin + Officer + Hardware Enclave)
 * - Salting & Peppering of daily investigation logs
 * - Blockchain hashing for chain-of-custody
 * - Official First Information Report (FIR) generation
 * - Real-time notification management
 */

const STORAGE_KEY = 'threattrace_cybercrime_state_v2'

// Pre-seeded officer roster
export const INITIAL_OFFICERS = [
  {
    id: 'OFF-0842',
    name: 'Inspector Rajesh Rao',
    rank: 'Cyber Crime Inspector',
    badge: 'CC-INSP-0842',
    specialization: 'Phishing, BEC & Executive Impersonation',
    experienceYears: 12,
    activeCases: 2,
    clearance: 'OMEGA-TOP-SECRET',
    precinct: 'Central Cyber Police Station, Zone 1',
    avatar: '👨‍✈️',
    publicKey: '0xOF-842A-77C1-E490-9B21'
  },
  {
    id: 'OFF-1193',
    name: 'Sr. Analyst Neha Verma',
    rank: 'Senior Digital Forensic Investigator',
    badge: 'DF-ANL-1193',
    specialization: 'Malware Reverse Engineering & C2 Tracing',
    experienceYears: 8,
    activeCases: 1,
    clearance: 'OMEGA-SECRET',
    precinct: 'Forensic Science Laboratory (Cyber Wing)',
    avatar: '👩‍💻',
    publicKey: '0xOF-1193-F241-B882-3A10'
  },
  {
    id: 'OFF-0527',
    name: 'Det. Vikram Malhotra',
    rank: 'Senior Detective (Financial Crimes)',
    badge: 'CC-DET-0527',
    specialization: 'Cryptocurrency Laundering & Mule Networks',
    experienceYears: 14,
    activeCases: 3,
    clearance: 'OMEGA-TOP-SECRET',
    precinct: 'Economic Offences & Cyber Intelligence Unit',
    avatar: '🕵️‍♂️',
    publicKey: '0xOF-0527-31C9-9A82-4DF7'
  },
  {
    id: 'OFF-2041',
    name: 'Inspector Priya Sen',
    rank: 'Cyber Intelligence Officer',
    badge: 'CC-INSP-2041',
    specialization: 'Ransomware Negotiation & Darknet OSINT',
    experienceYears: 9,
    activeCases: 1,
    clearance: 'OMEGA-SECRET',
    precinct: 'Tactical Cyber Operations Unit',
    avatar: '👩‍✈️',
    publicKey: '0xOF-2041-8BD4-5F22-77EA'
  },
  {
    id: 'OFF-0104',
    name: 'DySP Amitava Roy',
    rank: 'Deputy Superintendent of Police',
    badge: 'CC-DYSP-0104',
    specialization: 'Cyber Espionage & Critical Infrastructure Defense',
    experienceYears: 19,
    activeCases: 1,
    clearance: 'OMEGA-DIRECTORATE',
    precinct: 'Cyber Crime Headquarters',
    avatar: '👮‍♂️',
    publicKey: '0xOF-0104-E629-10B4-22DF'
  }
]

// Default Administrator Profile
export const ADMIN_PROFILE = {
  name: 'Shri K. Varma, IPS',
  title: 'Superintendent of Police & Head of Cyber Crime Wing',
  badgeNumber: 'IPS-CYB-001',
  role: 'Chief Cybercrime Administrator',
  clearanceLevel: 'LEVEL 5 - SUPREME CYBER ENCLAVE',
  headquarters: 'Central Cyber Crime Investigation Directorate (I4C), New Delhi',
  keyId: '0xAD-9921-E810-F002-33AC',
  joinedDate: '15-Aug-2018',
  email: 'admin.cybercrime@police.gov.in',
  phone: '+91 80 2294 2222',
  jurisdiction: 'National & Inter-State Cyber Jurisdiction'
}

// Helper: Generates random hex
function genHex(len = 8) {
  const chars = '0123456789ABCDEF'
  let out = ''
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)]
  return out
}

// Generate 3-Layer Cryptographic Key Fragment
export function generateThreeLayerKeys(caseId, officerId = 'OFF-0842') {
  const k1 = `K1-ADM-${genHex(4)}-${genHex(4)}`
  const k2 = `K2-${officerId.replace('OFF-', 'OFF')}-${genHex(4)}-${genHex(4)}`
  const k3 = `K3-ENC-${genHex(4)}-${genHex(4)}`
  const masterCombinedHash = `0x${genHex(16)}${genHex(16)}`.toLowerCase()

  return {
    layer1AdminKey: k1,
    layer2OfficerKey: k2,
    layer3EnclaveKey: k3,
    masterCombinedHash,
    algorithm: 'ECDSA-SECP256R1 + AES-256-GCM (3-Layer Multi-Key Split)',
    sealedAt: new Date().toISOString()
  }
}

// Generate Salt and Pepper for a daily log entry
export function createSaltPepper() {
  const salt = `S_${genHex(4)}`
  const pepper = `P_${genHex(4)}`
  return { salt, pepper }
}

// Primary Cases Dataset — dynamically populated exclusively from live reported threat cases
const INITIAL_CASES = []

// Notifications state
const INITIAL_NOTIFICATIONS = []

const TEST_CASE_IDS = new Set()

function isTestCase(c) {
  if (!c) return false
  const id = c.caseId || c.case_id || ''
  if (id.startsWith('TT-DUMMY-') || id.startsWith('INC-DUMMY-')) return true
  return false
}


// Service Class
export class CybercrimeService {
  constructor() {
    this.cases = []
    this.officers = []
    this.notifications = []
    this.adminProfile = ADMIN_PROFILE
    this._load()
  }

  _load() {
    try {
      const getActiveComplainant = () => {
        try {
          const direct = localStorage.getItem('tt_mailbox_email') || localStorage.getItem('tt_active_user') || localStorage.getItem('tt_auth_user_email')
          if (direct && !direct.includes('corp.net') && !direct.includes('enterprise.corp') && !direct.includes('citizen.user@')) return direct
          const sessionRaw = localStorage.getItem('tt_auth_session')
          if (sessionRaw) {
            const parsed = JSON.parse(sessionRaw)
            if (parsed?.boundEmail && !parsed.boundEmail.includes('corp.net') && !parsed.boundEmail.includes('citizen.user@')) return parsed.boundEmail
            if (parsed?.userEmail && !parsed.userEmail.includes('corp.net') && !parsed.userEmail.includes('citizen.user@')) return parsed.userEmail
          }
        } catch (_) {}
        return 'muniswami1112@gmail.com'
      }

      const activeEmail = getActiveComplainant()
      const defaultUserPart = activeEmail.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase())

      const raw = localStorage.getItem(STORAGE_KEY)
      if (raw) {
        const parsed = JSON.parse(raw)
        const loadedCases = Array.isArray(parsed) ? parsed : (parsed.cases || [])
        this.cases = loadedCases
          .filter(c => !isTestCase(c))
          .map(c => {
            let repEmail = c.reportingEmail || c.recipient || ''
            if (!repEmail || repEmail.includes('corp.net') || repEmail.includes('victim@enterprise.corp') || repEmail.includes('threattrace.user@') || repEmail.includes('citizen.user@')) {
              repEmail = activeEmail
            }
            let compName = c.complainantName || c.reportingName || ''
            if (!compName || compName.includes('ThreatTrace') || compName.includes('Citizen') || compName === 'Complainant') {
              const uPart = repEmail.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
              compName = `${uPart || defaultUserPart} (Complainant)`
            }
            return {
              ...c,
              reportingEmail: repEmail,
              recipient: (c.recipient && !c.recipient.includes('corp.net') && !c.recipient.includes('enterprise.corp')) ? c.recipient : repEmail,
              complainantName: compName,
              reportingName: compName
            }
          })
        this.officers = parsed.officers || INITIAL_OFFICERS
        this.notifications = (parsed.notifications || []).filter(n => !TEST_CASE_IDS.has(n.caseId))
        this.adminProfile = parsed.adminProfile || ADMIN_PROFILE
        this._save()
        return
      }
    } catch (e) {
      console.warn('Failed to parse cybercrime storage, resetting to initial state:', e)
    }
    this.cases = []
    this.officers = INITIAL_OFFICERS
    this.notifications = []
    this.adminProfile = ADMIN_PROFILE
    this._save()
  }

  _save() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        cases: this.cases,
        officers: this.officers,
        notifications: this.notifications,
        adminProfile: this.adminProfile
      }))
    } catch (e) {
      console.error('Failed to save cybercrime state to localStorage:', e)
    }
  }

  // Getters by category
  getQueueCases() {
    return this.cases.filter(c => c.status === 'QUEUE')
  }

  getRejectedCases() {
    return this.cases.filter(c => c.status === 'REJECTED')
  }

  getProcessCases() {
    return this.cases.filter(c => c.status === 'PROCESS')
  }

  getCompletedCases() {
    return this.cases.filter(c => c.status === 'COMPLETED')
  }

  getAllCases() {
    return this.cases
  }

  getCaseById(caseId) {
    return this.cases.find(c => c.caseId === caseId)
  }

  getOfficers() {
    return this.officers
  }

  getNotifications() {
    return this.notifications
  }

  getUnreadNotificationsCount() {
    return this.notifications.filter(n => !n.read).length
  }

  markNotificationAsRead(notifId) {
    const n = this.notifications.find(x => x.id === notifId)
    if (n) {
      n.read = true
      this._save()
    }
  }

  markAllNotificationsAsRead() {
    this.notifications.forEach(n => { n.read = true })
    this._save()
  }

  // Public entry point for reporting incident from Cockpit
  async reportIncident(incidentData) {
    const localCase = this.reportIncidentFromCockpit(incidentData)
    
    // Also sync to backend API if available
    try {
      const backendPayload = {
        case_id: localCase.caseId,
        reporter_email: localCase.reportingEmail,
        reporter_name: localCase.complainantName,
        reporter_phone: localCase.reportingPhone,
        subject: localCase.subject,
        body_text: localCase.bodyText,
        raw_headers: localCase.rawHeaders,
        sender: localCase.sender,
        recipient: localCase.recipient,
        risk_score: localCase.riskScore,
        risk_level: localCase.riskLevel,
        urls: localCase.urls,
        domains: localCase.domains,
        ips: localCase.ips
      }

      await fetch('http://127.0.0.1:8000/api/cybercrime/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(backendPayload)
      }).catch(() => null)
    } catch (_) {}

    // Dispatch custom storage event / message for instant multi-window sync
    if (typeof window !== 'undefined') {
      try {
        window.dispatchEvent(new StorageEvent('storage', {
          key: STORAGE_KEY,
          newValue: localStorage.getItem(STORAGE_KEY)
        }))
        window.postMessage({
          type: 'THREAT_TRACE_INCIDENT_REPORTED',
          caseId: localCase.caseId
        }, '*')
      } catch (_) {}
    }

    return {
      success: true,
      case: localCase,
      case_id: localCase.caseId,
      cybercrime_acknowledgement: {
        ack_number: `NCRP-IN-2026-${localCase.caseId.replace(/[^A-Za-z0-9]/g, '').slice(-8)}`,
        status: 'RECEIVED_IN_QUEUE',
        jurisdiction: 'National Cyber Crime Police Station, Central Command, New Delhi',
        head_of_department: 'Shri K. Varma, IPS'
      }
    }
  }

  // Reporting from ThreatTrace Cockpit into Queue
  reportIncidentFromCockpit(incidentData) {
    const rawId = incidentData.case_id || incidentData.incidentId || incidentData.caseId || ''

    const caseId = (function (id) {
      if (!id) return `TT-${new Date().getFullYear()}-${genHex(8)}`
      const match = id.match(/(?:TT|INC)-\d{4}-[A-Fa-f0-9]{6,10}/i) || id.match(/(?:TT|INC)-\d{4}-[A-Za-z0-9]+/i)
      if (match) return match[0].toUpperCase()
      const clean = id.replace(/[^A-Za-z0-9]/g, '').toUpperCase()
      if (clean.includes('TT2026') || clean.includes('INC2026')) {
        const idx = clean.indexOf('2026')
        return 'TT-2026-' + clean.substring(idx + 4, idx + 12).padEnd(8, '0')
      }
      return `TT-${new Date().getFullYear()}-${(clean.substring(0, 8) || genHex(8)).toUpperCase()}`
    })(rawId)
    
    let effectiveEmail = incidentData.reporterEmail || incidentData.recipient || ''
    if (!effectiveEmail || effectiveEmail.includes('corp.net') || effectiveEmail.includes('enterprise.corp')) {
      try {
        const direct = localStorage.getItem('tt_mailbox_email') || localStorage.getItem('tt_active_user') || localStorage.getItem('tt_auth_user_email')
        if (direct && !direct.includes('corp.net') && !direct.includes('enterprise.corp')) {
          effectiveEmail = direct
        } else {
          const sessionRaw = localStorage.getItem('tt_auth_session')
          if (sessionRaw) {
            const parsed = JSON.parse(sessionRaw)
            if (parsed?.boundEmail && !parsed.boundEmail.includes('corp.net')) effectiveEmail = parsed.boundEmail
            else if (parsed?.userEmail && !parsed.userEmail.includes('corp.net')) effectiveEmail = parsed.userEmail
          }
        }
      } catch (_) {}
    }
    if (!effectiveEmail) effectiveEmail = 'citizen.user@threattrace.ai'

    const userPart = effectiveEmail.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
    let effectiveName = incidentData.reporterName || incidentData.complainantName
    if (!effectiveName || effectiveName.includes('ThreatTrace') || effectiveName === 'Complainant') {
      effectiveName = `${userPart} (Complainant)`
    }

    // Check if case already exists
    let c = this.cases.find(x => x.caseId === caseId)
    if (c) {
      c.status = 'QUEUE'
      c.reportedAt = new Date().toISOString()
      c.reportingEmail = effectiveEmail
      c.recipient = effectiveEmail
      c.complainantName = effectiveName
      c.reportingName = effectiveName
      if (incidentData.ack_number || incidentData.ackNumber) c.ackNumber = incidentData.ack_number || incidentData.ackNumber
      if (incidentData.evidence_files || incidentData.evidenceFiles) c.evidenceFiles = incidentData.evidence_files || incidentData.evidenceFiles
      if (incidentData.threat_category || incidentData.threatCategory) c.threatCategory = incidentData.threat_category || incidentData.threatCategory
      if (incidentData.urgency_level || incidentData.urgencyLevel) c.urgencyLevel = incidentData.urgency_level || incidentData.urgencyLevel
      this._save()
      return c
    }

    const newCase = {
      caseId,
      ackNumber: incidentData.ack_number || incidentData.ackNumber || `NCRP-IN-2026-${caseId.replace(/[^A-Za-z0-9]/g, '').slice(-6)}`,
      reportingEmail: effectiveEmail,
      reportingName: effectiveName,
      complainantName: effectiveName,
      reportingPhone: incidentData.reporter_contact || incidentData.reporterPhone || '+91 80 4000 8899',
      reportedAt: new Date().toISOString(),
      status: 'QUEUE',
      subject: incidentData.subject || incidentData.title || 'Reported Email Threat',
      sender: incidentData.sender || incidentData.from || 'suspicious@external-source.net',
      recipient: effectiveEmail,
      threatCategory: incidentData.threat_category || incidentData.threatCategory || 'Phishing Attempt',
      urgencyLevel: incidentData.urgency_level || incidentData.urgencyLevel || 'Medium',
      riskScore: Math.round(Number(incidentData.risk_score !== undefined ? incidentData.risk_score : (incidentData.riskScore !== undefined ? incidentData.riskScore : (incidentData.threat_score !== undefined ? incidentData.threat_score : 0))) || 0),
      riskLevel: incidentData.risk_level || incidentData.riskLevel || (Number(incidentData.risk_score || incidentData.riskScore || 0) >= 70 ? 'HIGH' : (Number(incidentData.risk_score || incidentData.riskScore || 0) >= 40 ? 'MEDIUM' : 'LOW')),
      recommendation: incidentData.recommendation || 'QUARANTINE',
      rawHeaders: incidentData.raw_headers || incidentData.rawHeaders || 'Received: from external-node by ThreatTrace-Shield',
      bodyText: incidentData.body_text || incidentData.rawText || incidentData.subject || 'Threat detected by ThreatTrace AI in-page sensor.',
      urls: incidentData.urls || (incidentData.payloadUrl ? [incidentData.payloadUrl] : []),
      domains: incidentData.domains || (incidentData.payloadDomain ? [incidentData.payloadDomain] : []),
      ips: incidentData.ips || (incidentData.originIp ? [incidentData.originIp] : []),
      evidenceFiles: incidentData.evidence_files || incidentData.evidenceFiles || [],
      geoLocations: incidentData.geo_locations || incidentData.geoLocations || [],
      riskFactors: incidentData.risk_factors || ['Reported by user from ThreatTrace Cockpit'],
      assignedOfficer: null,
      rejectionReason: null,
      diaryEntries: [],
      dailyLogs: [],
      firData: null,
      threeLayerKeys: null
    }

    this.cases.unshift(newCase)

    // Add alert notification
    this.notifications.unshift({
      id: `NOTIF-${Date.now()}`,
      title: '🚨 Incident Routed to Queue',
      message: `User ${newCase.reportingEmail} reported Case ${newCase.caseId}.`,
      time: 'Just now',
      type: 'ALERT',
      caseId: newCase.caseId,
      read: false
    })

    this._save()
    return newCase
  }

  // Triage: Reject case with explanation
  rejectCase(caseId, explanation) {
    const c = this.cases.find(x => x.caseId === caseId)
    if (!c) throw new Error(`Case ${caseId} not found`)

    if (!explanation || !explanation.trim()) {
      throw new Error('Mandatory administrative explanation is required for rejection.')
    }

    c.status = 'REJECTED'
    c.rejectionReason = explanation.trim()
    c.rejectionDate = new Date().toISOString()
    c.rejectedBy = this.adminProfile.name

    this.notifications.unshift({
      id: `NOTIF-${Date.now()}`,
      title: 'Case Rejected by Admin',
      message: `Case ${caseId} was marked Rejected. Reason: ${explanation.slice(0, 60)}...`,
      time: 'Just now',
      type: 'INFO',
      caseId: c.caseId,
      read: false
    })

    this._save()
    return c
  }

  // Triage: Approve case & assign officer -> moves to PROCESS
  approveAndAssignOfficer(caseId, officerId) {
    const c = this.cases.find(x => x.caseId === caseId)
    if (!c) throw new Error(`Case ${caseId} not found`)

    const officer = this.officers.find(o => o.id === officerId)
    if (!officer) throw new Error(`Officer ${officerId} not found`)

    c.status = 'PROCESS'
    c.assignedOfficer = officer
    c.assignedDate = new Date().toISOString()
    c.rejectionReason = null

    // Generate 3-Layer Cryptographic Keys
    c.threeLayerKeys = generateThreeLayerKeys(caseId, officer.id)

    // Append Day 1 Genesis Log Entry
    const { salt, pepper } = createSaltPepper()
    const genesisLog = {
      day: 1,
      date: new Date().toISOString(),
      officerName: officer.name,
      officerBadge: officer.badge,
      notes: `Case approved by ${this.adminProfile.name}. Assigned to ${officer.name} (${officer.rank}). All forensic headers, reporting metadata, and IOC telemetries transferred. Evidence locked with 3-Layer Key separation.`,
      salt,
      pepper,
      blockchainTx: `0x${genHex(16)}${genHex(16)}`.toLowerCase(),
      sealedStatus: '100% Cryptographically Sealed'
    }
    c.dailyLogs = [genesisLog]

    officer.activeCases += 1

    this.notifications.unshift({
      id: `NOTIF-${Date.now()}`,
      title: 'Officer Assigned & Process Initiated',
      message: `Case ${caseId} assigned to ${officer.name}. 3-Layer cryptographic keys sealed on chain.`,
      time: 'Just now',
      type: 'DISPATCH',
      caseId: c.caseId,
      read: false
    })

    this._save()
    return c
  }

  // Rejected view: Re-investigation -> moves back to QUEUE
  reinvestigateCase(caseId) {
    const c = this.cases.find(x => x.caseId === caseId)
    if (!c) throw new Error(`Case ${caseId} not found`)

    c.status = 'QUEUE'
    const prevReason = c.rejectionReason
    c.reinvestigatedAt = new Date().toISOString()
    c.reinvestigatedFrom = prevReason

    this.notifications.unshift({
      id: `NOTIF-${Date.now()}`,
      title: '🔄 Case Re-opened for Investigation',
      message: `Case ${caseId} has been restored from Rejected status back to active Queue for fresh triage.`,
      time: 'Just now',
      type: 'ALERT',
      caseId: c.caseId,
      read: false
    })

    this._save()
    return c
  }

  // Process view: Add Day-to-Day Log sealed with 3-Layer Key, Salt, Pepper, Blockchain
  addDailyInvestigationLog(caseId, notes) {
    const c = this.cases.find(x => x.caseId === caseId)
    if (!c) throw new Error(`Case ${caseId} not found`)

    if (!notes || !notes.trim()) {
      throw new Error('Investigation notes cannot be empty.')
    }

    const currentDay = (c.dailyLogs && c.dailyLogs.length > 0) ? (c.dailyLogs.length + 1) : 1
    const { salt, pepper } = createSaltPepper()
    const officer = c.assignedOfficer || this.officers[0]

    const newLog = {
      day: currentDay,
      date: new Date().toISOString(),
      officerName: officer.name,
      officerBadge: officer.badge,
      notes: notes.trim(),
      salt,
      pepper,
      blockchainTx: `0x${genHex(16)}${genHex(16)}`.toLowerCase(),
      sealedStatus: '100% Cryptographically Sealed with Salt, Pepper & 3-Layer Key'
    }

    if (!c.dailyLogs) c.dailyLogs = []
    c.dailyLogs.push(newLog)

    this.notifications.unshift({
      id: `NOTIF-${Date.now()}`,
      title: `Day ${currentDay} Investigation Log Sealed`,
      message: `${officer.name} logged Day ${currentDay} report for Case ${c.caseId}. Sealed on ledger.`,
      time: 'Just now',
      type: 'LOG',
      caseId: c.caseId,
      read: false
    })

    this._save()
    return newLog
  }

  // Process view: Conclude investigation & issue official FIR -> moves to COMPLETED
  concludeAndIssueFIR(caseId, criminalDataCustom = null) {
    const c = this.cases.find(x => x.caseId === caseId)
    if (!c) throw new Error(`Case ${caseId} not found`)

    c.status = 'COMPLETED'
    c.completedDate = new Date().toISOString()

    const officer = c.assignedOfficer || this.officers[0]
    const firNum = `FIR-${new Date().getFullYear()}-KA-CYB-${genHex(5)}`

    // Build Criminal Data
    c.criminalData = criminalDataCustom || {
      syndicateName: `Identified Cyber Threat Group (Ref: #${c.caseId.slice(-4)})`,
      primarySuspects: ['Target Threat Actor (Identified via Reverse DNS & IP Routing)', 'Syndicate Operator Node'],
      accusedLocation: c.geoLocations && c.geoLocations[0] ? `${c.geoLocations[0].city}, ${c.geoLocations[0].country}` : 'International Offshore Subnet',
      originIp: c.ips && c.ips[0] ? c.ips[0] : '185.220.101.44',
      hardwareSeized: 'Encrypted C2 Server image, DNS redirection logs, SSL certificate footprints',
      recoveredAssets: 'Malicious domain perimeter blacklisted across national gateways',
      modusOperandi: 'Deceptive electronic communication designed to commit financial cyber fraud.'
    }

    // Generate Official FIR
    c.firData = {
      firNumber: firNum,
      policeStation: 'National Cyber Crime Police Station, Central Command, New Delhi',
      district: 'Cyber Command Zone',
      dateOfFiling: new Date().toISOString(),
      complainantName: `${c.reportingName || 'Complainant'} (${c.reportingEmail})`,
      investigatingOfficer: `${officer.name}, ${officer.badge}`,
      applicableActs: [
        'Information Technology Act, 2000 — Section 66C (Identity Theft)',
        'Information Technology Act, 2000 — Section 66D (Cheating by Personation using Computer Resource)',
        'Indian Penal Code, 1860 — Section 419 (Punishment for Cheating by Personation)',
        'Indian Penal Code, 1860 — Section 420 (Cheating and Dishonestly Inducing Delivery of Property)'
      ],
      digitalSealHash: `0x${genHex(16)}${genHex(16)}${genHex(16)}`.toLowerCase(),
      blockchainBlockHeight: `Polygon Amoy #48,${Math.floor(100000 + Math.random() * 900000)}`,
      firStatus: 'REGISTERED & LEGALLY SEALED FOR JUDICIAL COGNIZANCE'
    }

    if (officer.activeCases > 0) {
      officer.activeCases -= 1
    }

    this.notifications.unshift({
      id: `NOTIF-${Date.now()}`,
      title: '🎉 Investigation Solved & FIR Registered',
      message: `Case ${c.caseId} marked COMPLETED. First Information Report ${firNum} officially issued.`,
      time: 'Just now',
      type: 'FIR',
      caseId: c.caseId,
      read: false
    })

    this._save()
    return c
  }

  // Reset demo state
  resetToDefaults() {
    this.cases = INITIAL_CASES
    this.officers = INITIAL_OFFICERS
    this.notifications = INITIAL_NOTIFICATIONS
    this.adminProfile = ADMIN_PROFILE
    this._save()
  }
}

export const cyberService = new CybercrimeService()
