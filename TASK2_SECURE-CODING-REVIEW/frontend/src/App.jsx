import React, { useEffect, useState } from 'react';
import { Routes, Route, Link, useNavigate, Navigate } from 'react-router-dom';
import { auth } from './api';
import Dashboard from './components/Dashboard';
import Login from './components/Login';
import NewProject from './components/NewProject';
import ProjectDetail from './components/ProjectDetail';
import ScanDetail from './components/ScanDetail';

// Auth guard wrapper — redirects to /login if no token.
function ProtectedRoute({ children }) {
  const [checking, setChecking] = useState(true);
  const [hasToken, setHasToken] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    setHasToken(!!token);
    setChecking(false);
    if (!token) {
      navigate('/login', { replace: true });
    }
  }, [navigate]);

  if (checking) {
    return <div className="container">Checking auth...</div>;
  }

  return hasToken ? children : <Navigate to="/login" replace />;
}

function App() {
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      auth.me()
        .then((res) => setUser(res.data))
        .catch(() => {
          localStorage.removeItem('token');
          navigate('/login');
        });
    }
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setUser(null);
    navigate('/login');
  };

  return (
    <div>
      <nav style={{ background: 'var(--surface)', padding: '1rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Link to="/" style={{ fontSize: '1.25rem', fontWeight: 700 }}>CodeSentry</Link>
        <div>
          {user ? (
            <>
              <span style={{ marginRight: '1rem', color: 'var(--muted)' }}>{user.email}</span>
              <button onClick={handleLogout} className="secondary">Logout</button>
            </>
          ) : (
            <Link to="/login">Login</Link>
          )}
        </div>
      </nav>

      <Routes>
        <Route path="/login" element={<Login onLogin={setUser} />} />
        <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/projects/new" element={<ProtectedRoute><NewProject /></ProtectedRoute>} />
        <Route path="/projects/:id" element={<ProtectedRoute><ProjectDetail /></ProtectedRoute>} />
        <Route path="/scans/:id" element={<ProtectedRoute><ScanDetail /></ProtectedRoute>} />
      </Routes>
    </div>
  );
}

export default App;
