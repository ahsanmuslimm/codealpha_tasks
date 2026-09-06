import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { projects } from '../api';

export default function NewProject() {
  const [mode, setMode] = useState('git');
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      let res;
      if (mode === 'git') {
        res = await projects.createGit({ name, source_type: 'git', source_ref: url });
      } else {
        const formData = new FormData();
        formData.append('name', name);
        formData.append('file', file);
        res = await projects.createUpload(formData);
      }
      navigate(`/projects/${res.data.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>New Project</h1>
      <div className="card" style={{ maxWidth: 600 }}>
        {error && <div style={{ color: 'var(--critical)', marginBottom: '1rem' }}>{error}</div>}
        <div style={{ marginBottom: '1rem' }}>
          <button className={mode === 'git' ? '' : 'secondary'} onClick={() => setMode('git')} style={{ marginRight: '0.5rem' }}>Git URL</button>
          <button className={mode === 'upload' ? '' : 'secondary'} onClick={() => setMode('upload')}>Upload ZIP</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1rem' }}>
            <label>Project Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} required style={{ width: '100%' }} />
          </div>
          {mode === 'git' ? (
            <div style={{ marginBottom: '1rem' }}>
              <label>Git URL</label>
              <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/repo.git" required style={{ width: '100%' }} />
            </div>
          ) : (
            <div style={{ marginBottom: '1rem' }}>
              <label>ZIP Archive</label>
              <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} required style={{ width: '100%' }} />
            </div>
          )}
          <button type="submit" disabled={loading} style={{ width: '100%' }}>
            {loading ? 'Creating...' : 'Create Project'}
          </button>
        </form>
      </div>
    </div>
  );
}
