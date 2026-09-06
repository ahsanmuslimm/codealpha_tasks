import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { dashboard, projects as projectApi } from '../api';

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const severityColor = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  info: 'var(--info)',
};

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [projects, setProjects] = useState([]);

  useEffect(() => {
    dashboard.summary().then((res) => setSummary(res.data));
    projectApi.list().then((res) => setProjects(res.data));
  }, []);

  return (
    <div className="container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1>Dashboard</h1>
        <Link to="/projects/new"><button>+ New Project</button></Link>
      </div>

      {summary && (
        <div className="card" style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: '2rem', fontWeight: 700 }}>{summary.total_projects}</div>
            <div style={{ color: 'var(--muted)' }}>Projects</div>
          </div>
          <div>
            <div style={{ fontSize: '2rem', fontWeight: 700 }}>{summary.total_findings}</div>
            <div style={{ color: 'var(--muted)' }}>Total Findings</div>
          </div>
          {severityOrder.map((sev) => (
            <div key={sev}>
              <div style={{ fontSize: '2rem', fontWeight: 700, color: severityColor[sev] }}>
                {summary.findings_by_severity[sev] || 0}
              </div>
              <div style={{ color: 'var(--muted)', textTransform: 'capitalize' }}>{sev}</div>
            </div>
          ))}
        </div>
      )}

      <h2>Projects</h2>
      {projects.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', color: 'var(--muted)' }}>
          No projects yet. <Link to="/projects/new">Create one</Link>.
        </div>
      ) : (
        projects.map((p) => (
          <div key={p.id} className="card">
            <Link to={`/projects/${p.id}`}>
              <h3 style={{ margin: '0 0 0.5rem' }}>{p.name}</h3>
            </Link>
            <div style={{ color: 'var(--muted)', fontSize: '0.9rem' }}>
              Source: {p.source_type} · Created {new Date(p.created_at).toLocaleString()}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
