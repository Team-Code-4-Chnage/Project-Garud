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

export function apiUpload(endpoint, file, onProgress, { blob = false } = {}) {
  const url = `${API_URL}${endpoint}`;
  const form = new FormData();
  form.append('file', file);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    if (blob) xhr.responseType = 'blob';
    if (API_KEY) xhr.setRequestHeader('X-API-Key', API_KEY);
    xhr.upload.onprogress = (e) => {
      if (onProgress && e.lengthComputable) onProgress(e.loaded / e.total);
    };
    xhr.onerror = () => reject(new Error('Upload failed: the backend is not reachable'));
    xhr.onload = () => {
      if (blob && xhr.status >= 200 && xhr.status < 300) return resolve(xhr.response);
      if (blob) {
        xhr.response.text().then((t) => {
          let d = t;
          try { d = JSON.parse(t).detail ?? t; } catch { /* plain text */ }
          reject(new Error(typeof d === 'string' ? d : JSON.stringify(d)));
        });
        return;
      }
      let body = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        body = null;
      }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body);
      const detail = body?.detail ?? xhr.responseText;
      reject(new Error(typeof detail === 'string' ? detail : JSON.stringify(detail)));
    };
    xhr.send(form);
  });
}

export function createWebSocket() {
  const wsUrl = API_URL.replace(/^http/, 'ws') + '/ws/live';
  // Pass API key as query param for WebSocket authentication
  const url = API_KEY ? `${wsUrl}?api_key=${encodeURIComponent(API_KEY)}` : wsUrl;
  return new WebSocket(url);
}

export { API_URL };
