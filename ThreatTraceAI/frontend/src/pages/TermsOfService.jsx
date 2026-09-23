import React from 'react';
import { Link } from 'react-router-dom';

export default function TermsOfService() {
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
            <h1 style={{ fontSize: '2rem', fontWeight: 800, color: '#38bdf8', margin: 0 }}>Terms and Conditions</h1>
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
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>1. Agreement to Terms</h2>
          <p>
            By installing the Threat Trace AI extension or accessing the Threat Trace Cockpit web application, you agree to be bound by these Terms and Conditions. If you disagree with any part of these terms, please uninstall the extension and discontinue use.
          </p>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>2. Intended Purpose & Forensic Tools</h2>
          <p>
            Threat Trace AI is designed for cybersecurity analysis, email forensics, phishing mitigation, and evidence collection.
          </p>
          <ul>
            <li><strong>Permitted Use:</strong> You may use the software for personal defense, enterprise SOC operations, threat intelligence investigation, and legitimate incident reporting.</li>
            <li><strong>Prohibited Use:</strong> You agree not to weaponize canary tokens, reverse-engineer proprietary algorithms, or submit fraudulent or malicious FIR incident reports to the cybercrime portal.</li>
          </ul>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>3. Forensic Evidence & Subpoena Export</h2>
          <p>
            Threat Trace AI generates technical summaries and automated subpoena packages based on received headers and cryptographic signatures. While our algorithms provide high-fidelity attribution, forensic reports are provided for investigative assistance and should be corroborated with standard legal chain-of-custody protocols.
          </p>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>4. Disclaimer of Warranties</h2>
          <p>
            The software and services are provided "as is" and "as available" without warranty of any kind, express or implied, including but not limited to fitness for a particular security posture. We do not warrant that all phishing or malicious vectors will be intercepted with 100% certainty.
          </p>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>5. Limitation of Liability</h2>
          <p>
            In no event shall Threat Trace AI, its authors, or contributors be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use or inability to use this extension.
          </p>
        </section>

        <section style={{ marginBottom: '24px' }}>
          <h2 style={{ fontSize: '1.25rem', color: '#f8fafc', borderLeft: '3px solid #38bdf8', paddingLeft: '10px' }}>6. Modifications to Terms</h2>
          <p>
            We reserve the right to modify these terms at any time. Continued use of the software after any such modifications constitutes your acceptance of the updated terms.
          </p>
        </section>

        <div style={{ borderTop: '1px solid #1e293b', paddingTop: '16px', display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#64748b' }}>
          <span>© 2026 Threat Trace AI. All rights reserved.</span>
          <Link to="/privacy" style={{ color: '#38bdf8', textDecoration: 'none' }}>Privacy Policy →</Link>
        </div>
      </div>
    </div>
  );
}
