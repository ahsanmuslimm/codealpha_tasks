import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export const auth = {
  signup: (email, password) => api.post('/api/auth/signup', { email, password }),
  login: (email, password) =>
    api.post('/api/auth/login', new URLSearchParams({ username: email, password })),
  me: () => api.get('/api/auth/me'),
};

export const projects = {
  list: () => api.get('/api/projects'),
  get: (id) => api.get(`/api/projects/${id}`),
  createGit: (data) => api.post('/api/projects', data),
  createUpload: (formData) =>
    api.post('/api/projects/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  delete: (id) => api.delete(`/api/projects/${id}`),
};

export const scans = {
  trigger: (projectId) => api.post(`/api/scans/project/${projectId}`),
  get: (id) => api.get(`/api/scans/${id}`),
  history: (projectId) => api.get(`/api/scans/project/${projectId}/history`),
};

export const findings = {
  list: (scanId, params) => api.get(`/api/findings/scan/${scanId}`, { params }),
  triage: (id, data) => api.patch(`/api/findings/${id}`, data),
  history: (id) => api.get(`/api/findings/${id}/history`),
};

export const reports = {
  markdown: (scanId, includeAll = false) =>
    api.post(`/api/reports/scan/${scanId}/markdown`, { include_all: includeAll }),
};

export const dashboard = {
  summary: () => api.get('/api/dashboard'),
};

export default api;
