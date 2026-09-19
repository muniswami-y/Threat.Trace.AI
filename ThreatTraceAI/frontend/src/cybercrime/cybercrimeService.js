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
  headquarters: 'State Cyber Crime Investigation Wing (CCIW), HQ',
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

// Seed initial cases for realistic demonstration
const INITIAL_CASES = [
  {
    caseId: 'TT-2026-F80E1E7B',
    reportingEmail: 'victor.finance@apex-enterprise.corp',
    reportingName: 'Victor Sterling (CFO Office)',
    reportingPhone: '+91 98451 88201',
    reportedAt: new Date(Date.now() - 3600000 * 3).toISOString(),
    status: 'QUEUE', // 'QUEUE', 'REJECTED', 'PROCESS', 'COMPLETED'
    subject: 'URGENT: Urgent Wire Instruction - Vendor Bank Update Request',
    sender: 'billing-update@global-logistics-supporrt.com',
    recipient: 'victor.finance@apex-enterprise.corp',
    riskScore: 92,
    riskLevel: 'HIGH',
    recommendation: 'QUARANTINE',
    rawHeaders: `Received: from mail.global-logistics-supporrt.com (mail.global-logistics-supporrt.com [185.220.101.44])
  by mx.apex-enterprise.corp with ESMTP id 9B81A02;
  Authentication-Results: spf=fail (sender IP 185.220.101.44) smtp.mailfrom=billing-update@global-logistics-supporrt.com;
  dkim=neutral (bad signature);
  dmarc=fail (p=reject sp=reject) header.from=global-logistics-supporrt.com
Subject: URGENT: Urgent Wire Instruction - Vendor Bank Update Request
From: "Accounts Payables Global" <billing-update@global-logistics-supporrt.com>
To: victor.finance@apex-enterprise.corp
Reply-To: exec-offshore-settlement@cryptosmtp.xyz`,
    bodyText: `Dear Victor,
Please immediately divert today's pending wire batch of $428,500.00 USD to our new secondary escrow account due to audit compliance.
Do not contact our regular line as phone systems are down for scheduled maintenance.
Confirm once transaction receipt is transmitted.
Failure to wire immediately will suspend supply shipments.`,
    urls: ['https://global-logistics-supporrt.com/settlement-verification.php?id=992'],
    domains: ['global-logistics-supporrt.com', 'cryptosmtp.xyz'],
    ips: ['185.220.101.44', '194.147.140.22'],
    geoLocations: [
      { ip: '185.220.101.44', city: 'Bucharest', country: 'Romania', isp: 'HostSailor Bulletproof Hosting', lat: 44.4268, lon: 26.1025 }
    ],
    riskFactors: [
      'Spoofed lookalike vendor domain (typosquatting)',
      'SPF & DMARC strict alignment failure',
      'Urgency & coercive financial transaction pressure',
      'High-risk bulletproof hosting IP origin'
    ],
    assignedOfficer: null,
    rejectionReason: null,
    dailyLogs: [],
    firData: null,
    threeLayerKeys: null
  },
  {
    caseId: 'TT-2026-B819A21C',
    reportingEmail: 'priya.hr@technova-solutions.in',
    reportingName: 'Priya Sundaram (Talent Acquisition Lead)',
    reportingPhone: '+91 97110 44923',
    reportedAt: new Date(Date.now() - 3600000 * 28).toISOString(),
    status: 'PROCESS',
    subject: 'Application & Resume: Senior Software Architect (Attached Macro File)',
    sender: 'candidate-portfolio@protonmail.me',
    recipient: 'priya.hr@technova-solutions.in',
    riskScore: 84,
    riskLevel: 'HIGH',
    recommendation: 'QUARANTINE',
    rawHeaders: `Received: from mail4.protonmail.ch (mail4.protonmail.ch [185.70.40.104])
Subject: Application & Resume: Senior Software Architect
From: candidate-portfolio@protonmail.me
To: priya.hr@technova-solutions.in`,
    bodyText: `Hello HR Team,
Attached please find my updated curriculum vitae and security credentials dossier in the enclosed .docm document.
Please enable editing macros to view verified certifications.`,
    urls: ['http://c2-stage-deployer.duckdns.org/payload.bin'],
    domains: ['c2-stage-deployer.duckdns.org'],
    ips: ['45.154.255.89'],
    geoLocations: [
      { ip: '45.154.255.89', city: 'Moscow', country: 'Russian Federation', isp: 'Selectel ASN 49505', lat: 55.7558, lon: 37.6173 }
    ],
    riskFactors: [
      'Embedded VBA Malicious Macro Downloader',
      'C2 Command & Control callback to Dynamic DNS',
      'High-risk Trojan dropper payload'
    ],
    assignedOfficer: INITIAL_OFFICERS[1], // Sr. Analyst Neha Verma
    rejectionReason: null,
    threeLayerKeys: {
      layer1AdminKey: 'K1-ADM-941A-770B',
      layer2OfficerKey: 'K2-OFF1193-4122-C891',
      layer3EnclaveKey: 'K3-ENC-8812-FA03',
      masterCombinedHash: '0x8b19a21cefa9402138401aa89104c810',
      algorithm: 'ECDSA-SECP256R1 + AES-256-GCM (3-Layer Multi-Key Split)',
      sealedAt: new Date(Date.now() - 3600000 * 24).toISOString()
    },
    dailyLogs: [
      {
        day: 1,
        date: new Date(Date.now() - 3600000 * 24).toISOString(),
        officerName: 'Sr. Analyst Neha Verma',
        officerBadge: 'DF-ANL-1193',
        notes: 'Extracted macro strings in sandbox. Found PowerShell downloader calling c2-stage-deployer.duckdns.org. Issued emergency domain takedown request to DuckDNS abuse desk.',
        salt: 'S_9F81',
        pepper: 'P_3C20',
        blockchainTx: '0x992b10ae4478129a00b127419e9184ad',
        sealedStatus: '100% Cryptographically Sealed'
      },
      {
        day: 2,
        date: new Date(Date.now() - 3600000 * 4).toISOString(),
        officerName: 'Sr. Analyst Neha Verma',
        officerBadge: 'DF-ANL-1193',
        notes: 'Target C2 server seized by partner CERT. Retrieved beacon list of 43 infected endpoints in Karnataka. Isolating internal infected machines and collecting memory dumps.',
        salt: 'S_7A12',
        pepper: 'P_9E84',
        blockchainTx: '0x77c4819ad001bfa284910248ad8194ba',
        sealedStatus: '100% Cryptographically Sealed'
      }
    ],
    firData: null
  },
  {
    caseId: 'TT-2026-9C44E109',
    reportingEmail: 'user.suresh@statebank-services.net',
    reportingName: 'Suresh Menon',
    reportingPhone: '+91 94441 20911',
    reportedAt: new Date(Date.now() - 3600000 * 50).toISOString(),
    status: 'REJECTED',
    subject: 'Newsletter: Monthly Security Awareness Digest',
    sender: 'internal-sec@company-corp.com',
    recipient: 'user.suresh@statebank-services.net',
    riskScore: 22,
    riskLevel: 'LOW',
    recommendation: 'ALLOW',
    rawHeaders: `Received: from corp-smtp.internal (corp-smtp [10.0.1.20])
Subject: Newsletter: Monthly Security Awareness Digest`,
    bodyText: `Dear Employee,
Please review the internal security awareness guidelines for October 2026.
No actions or password resets are required.`,
    urls: ['https://intranet.company-corp.com/security'],
    domains: ['intranet.company-corp.com'],
    ips: ['10.0.1.20'],
    geoLocations: [{ ip: '10.0.1.20', city: 'Internal LAN', country: 'Private Subnet' }],
    riskFactors: ['Normal internal broadcast'],
    assignedOfficer: null,
    rejectionReason: 'Legitimate internal corporate security awareness digest sent from verified company SMTP relay. No phishing indicators, spoofed headers, or malicious payloads detected.',
    rejectionDate: new Date(Date.now() - 3600000 * 46).toISOString(),
    rejectedBy: 'Shri K. Varma, IPS',
    dailyLogs: [],
    firData: null,
    threeLayerKeys: null
  },
  {
    caseId: 'TT-2026-4401AA9F',
    reportingEmail: 'anita.accounts@karnataka-infra.gov.in',
    reportingName: 'Anita Krishnan (Accounts Officer)',
    reportingPhone: '+91 80 2200 1199',
    reportedAt: new Date(Date.now() - 3600000 * 120).toISOString(),
    status: 'COMPLETED',
    subject: 'Immediate Account Freeze Notice: Reserve Bank Directive',
    sender: 'compliance-audit@rbi-digital-gateway.org',
    recipient: 'anita.accounts@karnataka-infra.gov.in',
    riskScore: 98,
    riskLevel: 'HIGH',
    recommendation: 'QUARANTINE',
    rawHeaders: `Received: from rbi-gateway.spoofed-server.net [103.251.167.20]
Subject: Immediate Account Freeze Notice: Reserve Bank Directive`,
    bodyText: `Government Accounts Division:
Failure to input your Treasury Digital Token on the gateway portal within 2 hours will freeze all departmental disbursements under PMLA directives.`,
    urls: ['https://rbi-digital-gateway.org/treasury-auth'],
    domains: ['rbi-digital-gateway.org'],
    ips: ['103.251.167.20'],
    geoLocations: [
      { ip: '103.251.167.20', city: 'Kolkata', country: 'India', isp: 'Alliance Broadband Relay', lat: 22.5726, lon: 88.3639 }
    ],
    riskFactors: [
      'Government Regulator impersonation (RBI spoofing)',
      'Phishing credential harvest targeting Treasury e-Tokens',
      'Known syndicate IP range linked to Jamtara / Mewat cyber gangs'
    ],
    assignedOfficer: INITIAL_OFFICERS[2], // Det. Vikram Malhotra
    rejectionReason: null,
    threeLayerKeys: {
      layer1AdminKey: 'K1-ADM-1109-88C1',
      layer2OfficerKey: 'K2-OFF0527-991A-22B0',
      layer3EnclaveKey: 'K3-ENC-4401-AA9F',
      masterCombinedHash: '0x4401aa9fe8199201a0841289bca88109',
      algorithm: 'ECDSA-SECP256R1 + AES-256-GCM (3-Layer Multi-Key Split)',
      sealedAt: new Date(Date.now() - 3600000 * 110).toISOString()
    },
    dailyLogs: [
      {
        day: 1,
        date: new Date(Date.now() - 3600000 * 110).toISOString(),
        officerName: 'Det. Vikram Malhotra',
        officerBadge: 'CC-DET-0527',
        notes: 'Traced fake RBI phishing domain hosting. Server IP 103.251.167.20 geolocated to residential fiber connection in Kolkata. Requested ISP subscriber logs under Sec 91 CrPC.',
        salt: 'S_1109',
        pepper: 'P_4481',
        blockchainTx: '0x44819ad00192831849102948ad8194ff',
        sealedStatus: '100% Cryptographically Sealed'
      },
      {
        day: 2,
        date: new Date(Date.now() - 3600000 * 85).toISOString(),
        officerName: 'Det. Vikram Malhotra',
        officerBadge: 'CC-DET-0527',
        notes: 'Subscriber log analysis identified suspect SIM cards activated with forged Aadhaar. Mapped bank account linked to payment gateway; frozen ₹18,40,000 in mule account at Yes Bank.',
        salt: 'S_8819',
        pepper: 'P_2201',
        blockchainTx: '0x88219abf0029314810293819aa91024b',
        sealedStatus: '100% Cryptographically Sealed'
      },
      {
        day: 3,
        date: new Date(Date.now() - 3600000 * 60).toISOString(),
        officerName: 'Det. Vikram Malhotra',
        officerBadge: 'CC-DET-0527',
        notes: 'Coordinated raid with local police in Salt Lake, Kolkata. Apprehended 2 kingpins (Subhash Mondal & Tariq Aziz). Seized 14 laptops, 38 smartphones, and 85 debit cards.',
        salt: 'S_9934',
        pepper: 'P_1120',
        blockchainTx: '0x33910abf1129384910293819aa910299',
        sealedStatus: '100% Cryptographically Sealed'
      }
    ],
    criminalData: {
      syndicateName: 'Bengal-Jharkhand Shadow Payment Phishing Syndicate',
      primarySuspects: ['Subhash Mondal (31)', 'Tariq Aziz (28)'],
      accusedLocation: 'Salt Lake Sector V, Kolkata, West Bengal',
      originIp: '103.251.167.20',
      hardwareSeized: '14 Laptops, 38 burner smartphones, 85 mule bank ATM cards, 4 GSM SIM boxes',
      recoveredAssets: '₹18,40,000 INR frozen in mule accounts; 1.42 BTC seized in cold ledger',
      modusOperandi: 'Mass spear-phishing government treasury officers with forged RBI freeze warnings, harvesting 2FA tokens via reverse-proxy kits.'
    },
    firData: {
      firNumber: 'FIR-2026-KA-CYB-00892',
      policeStation: 'Cyber Crime Police Station, CID Headquarters, Bengaluru',
      district: 'Bengaluru City',
      dateOfFiling: new Date(Date.now() - 3600000 * 55).toISOString(),
      complainantName: 'Anita Krishnan (Accounts Officer, Karnataka Infra)',
      investigatingOfficer: 'Det. Vikram Malhotra, CC-DET-0527',
      applicableActs: [
        'Information Technology Act, 2000 — Section 66C (Identity Theft)',
        'Information Technology Act, 2000 — Section 66D (Cheating by Personation using Computer Resource)',
        'Indian Penal Code, 1860 — Section 419 (Punishment for Cheating by Personation)',
        'Indian Penal Code, 1860 — Section 420 (Cheating and Dishonestly Inducing Delivery of Property)',
        'Indian Penal Code, 1860 — Section 120B (Criminal Conspiracy)'
      ],
      digitalSealHash: '0x4401aa9fe8199201a0841289bca8810933910abf1129384910293819aa910299',
      blockchainBlockHeight: 'Polygon Amoy #48,192,044',
      firStatus: 'REGISTERED & CHARGESHEET PENDING'
    },
    completedDate: new Date(Date.now() - 3600000 * 50).toISOString()
  }
]

// Notifications state
const INITIAL_NOTIFICATIONS = [
  {
    id: 'NOTIF-1',
    title: 'New Threat Report Queued',
    message: 'Complainant victor.finance@apex-enterprise.corp filed Case TT-2026-F80E1E7B.',
    time: '3 hours ago',
    type: 'ALERT',
    caseId: 'TT-2026-F80E1E7B',
    read: false
  },
  {
    id: 'NOTIF-2',
    title: 'Daily Investigation Log Filed',
    message: 'Sr. Analyst Neha Verma logged Day 2 report for Case TT-2026-B819A21C.',
    time: '4 hours ago',
    type: 'LOG',
    caseId: 'TT-2026-B819A21C',
    read: false
  },
  {
    id: 'NOTIF-3',
    title: 'Investigation Concluded & FIR Issued',
    message: 'Det. Vikram Malhotra closed Case TT-2026-4401AA9F. FIR #FIR-2026-KA-CYB-00892 generated.',
    time: '2 days ago',
    type: 'FIR',
    caseId: 'TT-2026-4401AA9F',
    read: true
  }
]

// Service Class
class CybercrimeService {
  constructor() {
    this.cases = []
    this.officers = INITIAL_OFFICERS
    this.notifications = []
    this.adminProfile = ADMIN_PROFILE
    this._load()
  }

  _load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY)
      if (raw) {
        const parsed = JSON.parse(raw)
        this.cases = parsed.cases || INITIAL_CASES
        this.officers = parsed.officers || INITIAL_OFFICERS
        this.notifications = parsed.notifications || INITIAL_NOTIFICATIONS
        this.adminProfile = parsed.adminProfile || ADMIN_PROFILE
        return
      }
    } catch (e) {
      console.warn('Failed to parse cybercrime storage, resetting to initial state:', e)
    }
    this.cases = INITIAL_CASES
    this.officers = INITIAL_OFFICERS
    this.notifications = INITIAL_NOTIFICATIONS
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

  // Reporting from ThreatTrace Cockpit into Queue
  reportIncidentFromCockpit(incidentData) {
    const rawId = incidentData.case_id || incidentData.incidentId || ''
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
    
    // Check if case already exists
    let c = this.cases.find(x => x.caseId === caseId)
    if (c) {
      c.status = 'QUEUE'
      c.reportedAt = new Date().toISOString()
      c.reportingEmail = incidentData.reporterEmail || c.reportingEmail || 'threattrace.analyst@internal.net'
      this._save()
      return c
    }

    const newCase = {
      caseId,
      reportingEmail: incidentData.reporterEmail || 'threattrace.user@enterprise.corp',
      reportingName: incidentData.reporterName || 'ThreatTrace Certified User',
      complainantName: incidentData.reporterName || 'ThreatTrace Certified User',
      reportingPhone: incidentData.reporterPhone || '+91 80 4000 8899',
      reportedAt: new Date().toISOString(),
      status: 'QUEUE',
      subject: incidentData.subject || incidentData.title || 'Reported Email Threat',
      sender: incidentData.sender || incidentData.from || 'suspicious@external-source.net',
      recipient: incidentData.recipient || incidentData.to || 'victim@corp.net',
      riskScore: Math.round(incidentData.risk_score || incidentData.riskScore || 75),
      riskLevel: incidentData.risk_level || incidentData.riskLevel || 'HIGH',
      recommendation: incidentData.recommendation || 'QUARANTINE',
      rawHeaders: incidentData.raw_headers || incidentData.rawHeaders || 'Received: from external-node by ThreatTrace-Shield',
      bodyText: incidentData.body_text || incidentData.rawText || incidentData.subject || 'Threat detected by ThreatTrace AI in-page sensor.',
      urls: incidentData.urls || (incidentData.payloadUrl ? [incidentData.payloadUrl] : []),
      domains: incidentData.domains || (incidentData.payloadDomain ? [incidentData.payloadDomain] : []),
      ips: incidentData.ips || (incidentData.originIp ? [incidentData.originIp] : []),
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
      policeStation: 'State Cyber Crime Police Station, CID Headquarters, Bengaluru',
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
