import React from 'react';
import { Link } from 'react-router-dom';

export default function PrivacyPolicy() {
  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0b0f19 0%, #0f172a 100%)',
      color: '#e2e8f0',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      padding: '40px 20px',
      lineHeight: 1.7
    }}>
      <div style={{
        maxWidth: '860px',
        margin: '0 auto',
        background: 'rgba(15, 23, 42, 0.75)',
        border: '1px solid rgba(56, 189, 248, 0.2)',
        borderRadius: '16px',
        padding: '36px',
        backdropFilter: 'blur(12px)',
        boxShadow: '0 20px 40px rgba(0,0,0,0.5)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '20px', marginBottom: '24px' }}>
          <div>
            <h1 style={{ fontSize: '2rem', fontWeight: 800, color: '#38bdf8', margin: 0 }}>Privacy Policy</h1>
            <div style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '4px' }}>Threat Trace AI • Last Updated: September 2026</div>
          </div>
          <Link to="/" style={{
            background: 'rgba(56, 189, 248, 0.1)',
            color: '#38bdf8',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            padding: '8px 16px',
            borderRadius: '8px',
            textDecoration: 'none',
            fontSize: '0.85rem',
            fontWeight: 600
          }}>← Back to Cockpit</Link>
        </div>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>1. Introduction</h2>
          <p>
            Threat Trace AI ("we", "our", or "the Extension") is dedicated to protecting user privacy while providing advanced email forensics, phishing heuristic detection, threat attribution, and incident dispatching capabilities. This Privacy Policy outlines how our browser extension and web services handle technical data and forensic signals.
          </p>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>2. Data Collection and Usage</h2>
          <p>
            Threat Trace AI operates under a <strong>Zero-Trust and Minimal-Data paradigm</strong>. We do not sell, rent, or monetize your personal data.
          </p>
          <ul>
            <li><strong>Email Forensics Data:</strong> When an email is actively inspected or reported by you, technical headers (SPF, DKIM, DMARC, Received chain), URLs, sender domains, and extracted forensic IOCs (IP addresses, phone numbers) are processed solely to compute threat risk scores and detect spoofing.</li>
            <li><strong>No Continuous Private Message Storage:</strong> Regular, benign email body content is processed locally and ephemeral in-memory without persistent retention on third-party servers.</li>
            <li><strong>Explicit Cybercrime Incident Reporting:</strong> Only when you explicitly click "Report Incident to Cybercrime", the compiled forensic summary, evidence logs, and case payload are transmitted to secure law enforcement / administrative portals.</li>
          </ul>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>3. Browser Permissions & Justification</h2>
          <ul>
            <li><code>activeTab</code> & <code>scripting</code>: Required to inspect active Gmail tabs and render in-page forensic indicators without reading background browsing history.</li>
            <li><code>storage</code>: Used to store local user preferences, incident draft state, and telemetry cache locally on your device.</li>
            <li><code>host_permissions (mail.google.com, vercel.app, onrender.com)</code>: Necessary to attach the forensic scanner overlay in Gmail and communicate with the ThreatTrace verification API.</li>
          </ul>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>4. Third-Party Services and Cloud Infrastructure</h2>
          <p>
            Our backend infrastructure utilizes secure, encrypted cloud providers:
          </p>
          <ul>
            <li><strong>Neon PostgreSQL:</strong> Encrypted storage for registered cybercrime incident reports and audit trails.</li>
            <li><strong>Render & Vercel:</strong> Cloud-native API hosting and edge content delivery protected by TLS 1.3 encryption.</li>
          </ul>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>5. User Rights & Data Deletion</h2>
          <p>
            Users maintain full control over their local inspection data. You may clear extension storage at any time via Chrome/Edge extension settings or request deletion of filed incident reports by contacting the administrative portal.
          </p>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>6. Contact & Inquiries</h2>
          <p>
            For privacy inquiries, technical compliance verification, or support, please reach out via our GitHub repository or email: <a href="mailto:privacy@threattrace.ai" style={{ color: '#38bdf8' }}>privacy@threattrace.ai</a>.
          </p>
        </section>

        <div style={{ borderTop: '1px solid #1e293b', paddingTop: '16px', display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#64748b' }}>
          <span>© 2026 Threat Trace AI. All rights reserved.</span>
          <Link to="/terms" style={{ color: '#38bdf8', textDecoration: 'none' }}>Terms of Service →</Link>
        </div>
      </div>
    </div>
  );
}
