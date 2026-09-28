const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const API_KEY = import.meta.env.VITE_API_KEY || '';

export async function apiFetch(endpoint, options = {}) {
  const url = `${API_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
    ...options.headers,
  };
  const res = await fetch(url, {
    ...options,
    headers,
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`API ${res.status}: ${detail}`);
  }
  return res.json();
}

export function apiPost(endpoint, body) {
  return apiFetch(endpoint, { method: 'POST', body: JSON.stringify(body) });
}

export async function apiUpload(endpoint, file) {
  const url = `${API_URL}${endpoint}`;
  const form = new FormData();
  form.append('file', file);
  const headers = {
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
  };
  const res = await fetch(url, { method: 'POST', body: form, headers });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Upload ${res.status}: ${detail}`);
  }
  return res.json();
}

export function createWebSocket() {
  const wsUrl = API_URL.replace(/^http/, 'ws') + '/ws/live';
  // Pass API key as query param for WebSocket authentication
  const url = API_KEY ? `${wsUrl}?api_key=${encodeURIComponent(API_KEY)}` : wsUrl;
  return new WebSocket(url);
}

export { API_URL };
