import React, { useState } from 'react';
import { findings as findingsApi } from '../api';

const statusOptions = [
  { value: 'open', label: 'Open' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'wont_fix', label: "Won't Fix" },
  { value: 'needs_review', label: 'Needs Manual Review' },
];

export default function FindingDetail({ finding, onClose, onUpdate }) {
  const [status, setStatus] = useState(finding.status);
  const [notes, setNotes] = useState(finding.triage_notes || '');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const save = async () => {
    setSaving(true);
    await findingsApi.triage(finding.id, { status, notes });
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
    onUpdate();
  };

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="slide-over">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ margin: 0 }}>Finding Detail</h2>
          <button className="secondary" onClick={onClose}>Close</button>
        </div>

        <div className="card">
          <div style={{ marginBottom: '0.5rem' }}>
            <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
            <span style={{ marginLeft: '0.5rem', color: 'var(--muted)' }}>{finding.cwe_id} · {finding.owasp_category}</span>
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: '0.9rem', marginBottom: '0.5rem' }}>{finding.rule_id}</div>
          <div style={{ color: 'var(--muted)' }}>{finding.file_path}:{finding.line_start || '-'}</div>
        </div>

        <h3>Evidence</h3>
        <div className="code">{finding.code_snippet || 'No snippet available'}</div>

        <h3>Description</h3>
        <p>{finding.description}</p>

        <h3>Remediation</h3>
        <p>{finding.remediation || 'Investigate manually.'}</p>

        <h3>Triage</h3>
        <div className="card">
          <div style={{ marginBottom: '1rem' }}>
            <label>Status</label>
            <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: '100%' }}>
              {statusOptions.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom: '1rem' }}>
            <label>Reviewer Notes</label>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={6} style={{ width: '100%' }} />
          </div>
          <button onClick={save} disabled={saving}>
            {saving ? 'Saving...' : 'Save Triage'}
          </button>
          {saved && <span style={{ color: 'var(--low)', marginLeft: '1rem' }}>Saved</span>}
        </div>
      </div>
    </>
  );
}
