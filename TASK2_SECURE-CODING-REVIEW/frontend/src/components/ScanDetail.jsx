import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { scans, findings as findingsApi, reports } from '../api';
import FindingDetail from './FindingDetail';

const statusColor = {
  queued: 'var(--info)',
  cloning: 'var(--info)',
  scanning_sast: 'var(--medium)',
  scanning_sca: 'var(--medium)',
  normalizing: 'var(--medium)',
  complete: 'var(--low)',
  failed: 'var(--critical)',
};

const severityClass = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
};

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const [report, setReport] = useState('');

  const loadScan = async () => {
    const res = await scans.get(id);
    setScan(res.data);
  };

  const loadFindings = async () => {
    const params = {};
    if (filters.severity) params.severity = filters.severity;
    if (filters.status) params.status = filters.status;
    const res = await findingsApi.list(id, params);
    setFindings(res.data);
  };

  useEffect(() => {
    loadScan();
    loadFindings();
    const interval = setInterval(() => {
      loadScan();
      if (scan?.status === 'complete') loadFindings();
    }, 3000);
    return () => clearInterval(interval);
  }, [id, filters, scan?.status]);

  const exportReport = async () => {
    const res = await reports.markdown(id, false);
    setReport(res.data.content);
  };

  if (!scan) return <div className="container">Loading...</div>;

  return (
    <div className="container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Scan Detail</h1>
        <div>
          <span className="badge" style={{ background: statusColor[scan.status], marginRight: '1rem' }}>{scan.status}</span>
          {scan.status === 'complete' && <button onClick={exportReport}>Export Markdown Report</button>}
        </div>
      </div>

      {scan.error_message && (
        <div className="card" style={{ color: 'var(--critical)' }}>Error: {scan.error_message}</div>
      )}

      <div className="card" style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <label>Severity</label>
          <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div>
          <label>Status</label>
          <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False Positive</option>
            <option value="wont_fix">Won't Fix</option>
            <option value="needs_review">Needs Review</option>
          </select>
        </div>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule / CWE</th>
            <th>File</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id} onClick={() => setSelected(f)}>
              <td><span className={`badge ${severityClass[f.severity]}`}>{f.severity}</span></td>
              <td>{f.rule_id}<br /><span style={{ color: 'var(--muted)' }}>{f.cwe_id} · {f.owasp_category}</span></td>
              <td>{f.file_path}:{f.line_start || '-'}</td>
              <td><span className="badge" style={{ background: 'var(--surface-2)' }}>{f.status}</span></td>
            </tr>
          ))}
        </tbody>
      </table>

      {selected && (
        <FindingDetail
          finding={selected}
          onClose={() => setSelected(null)}
          onUpdate={loadFindings}
        />
      )}

      {report && (
        <div className="card" style={{ marginTop: '2rem' }}>
          <h3>Report Preview</h3>
          <pre className="code">{report}</pre>
        </div>
      )}
    </div>
  );
}
