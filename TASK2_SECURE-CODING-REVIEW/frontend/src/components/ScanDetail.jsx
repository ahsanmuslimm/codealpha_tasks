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
  const [filters, setFilters] = useState({ severity: '', triage_status: '' });
  const [report, setReport] = useState('');
  const [loading, setLoading] = useState(false);

  const loadScan = async () => {
    try {
      const res = await scans.get(id);
      setScan(res.data);
    } catch (err) {
      console.error('Failed to load scan:', err);
    }
  };

  const loadFindings = async () => {
    try {
      const params = {};
      if (filters.severity) params.severity = filters.severity;
      if (filters.triage_status) params.triage_status = filters.triage_status;
      const res = await findingsApi.list(id, params);
      setFindings(res.data);
    } catch (err) {
      console.error('Failed to load findings:', err);
    }
  };

  // Initial load + poll for non-complete scans.
  useEffect(() => {
    loadScan();
    loadFindings();
    const interval = setInterval(() => {
      loadScan();
    }, 3000);
    return () => clearInterval(interval);
  }, [id]);

  // Re-fetch findings when filters change.
  useEffect(() => {
    loadFindings();
  }, [filters]);

  // Poll for findings only when scan is in progress.
  useEffect(() => {
    if (!scan || scan.status === 'complete') return;
    const interval = setInterval(() => {
      loadFindings();
    }, 3000);
    return () => clearInterval(interval);
  }, [scan?.status]);

  const exportReport = async () => {
    setLoading(true);
    try {
      const res = await reports.markdown(id, false);
      setReport(res.data.content);
    } catch (err) {
      alert('Failed to generate report: ' + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const downloadPdf = async () => {
    setLoading(true);
    try {
      const res = await reports.pdf(id, false);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `codesentry-report-${id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to generate PDF: ' + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = () => {
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `codesentry-report-${id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!scan) return <div className="container">Loading...</div>;

  return (
    <div className="container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Scan Detail</h1>
        <div>
          <span className="badge" style={{ background: statusColor[scan.status], marginRight: '1rem' }}>{scan.status}</span>
          {scan.status === 'complete' && (
            <>
              <button onClick={exportReport} disabled={loading} style={{ marginRight: '0.5rem' }}>
                {loading ? 'Generating...' : 'Preview Report'}
              </button>
              <button onClick={downloadPdf} disabled={loading} className="secondary">
                Download PDF
              </button>
            </>
          )}
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
          <select value={filters.triage_status} onChange={(e) => setFilters({ ...filters, triage_status: e.target.value })}>
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
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3>Report Preview</h3>
            <button onClick={downloadReport}>Download .md</button>
          </div>
          <pre className="code" style={{ maxHeight: '400px', overflow: 'auto' }}>{report}</pre>
        </div>
      )}
    </div>
  );
}
