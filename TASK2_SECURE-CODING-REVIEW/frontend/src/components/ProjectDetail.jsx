import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { projects, scans } from '../api';

const statusColor = {
  queued: 'var(--info)',
  cloning: 'var(--info)',
  scanning_sast: 'var(--medium)',
  scanning_sca: 'var(--medium)',
  normalizing: 'var(--medium)',
  complete: 'var(--low)',
  failed: 'var(--critical)',
};

export default function ProjectDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [history, setHistory] = useState([]);
  const [scanning, setScanning] = useState(false);

  const load = async () => {
    const [p, h] = await Promise.all([
      projects.get(id),
      scans.history(id),
    ]);
    setProject(p.data);
    setHistory(h.data);
  };

  useEffect(() => {
    load();
  }, [id]);

  const trigger = async () => {
    setScanning(true);
    const res = await scans.trigger(id);
    navigate(`/scans/${res.data.id}`);
  };

  if (!project) return <div className="container">Loading...</div>;

  return (
    <div className="container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>{project.name}</h1>
        <button onClick={trigger} disabled={scanning}>{scanning ? 'Starting...' : 'Run Scan'}</button>
      </div>
      <div className="card" style={{ color: 'var(--muted)' }}>
        Source: {project.source_type} · {project.source_ref}
      </div>

      <h2>Scan History</h2>
      {history.length === 0 ? (
        <div className="card" style={{ color: 'var(--muted)' }}>No scans yet.</div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Ruleset</th>
              <th>Started</th>
              <th>Completed</th>
            </tr>
          </thead>
          <tbody>
            {history.map((s) => (
              <tr key={s.id} onClick={() => navigate(`/scans/${s.id}`)}>
                <td><span className="badge" style={{ background: statusColor[s.status] }}>{s.status}</span></td>
                <td>{s.ruleset_version}</td>
                <td>{s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
                <td>{s.completed_at ? new Date(s.completed_at).toLocaleString() : '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
