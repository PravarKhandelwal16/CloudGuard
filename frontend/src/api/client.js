const API_BASE = '/api';

export async function apiRequest(endpoint, options = {}) {
  const token = localStorage.getItem('cloudguard_token');
  const headers = { ...options.headers };

  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // If body is not FormData, default to application/json
  if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401 && endpoint !== '/auth/login' && endpoint !== '/auth/register') {
      localStorage.removeItem('cloudguard_token');
      localStorage.removeItem('cloudguard_user');
      window.dispatchEvent(new Event('cloudguard:unauthorized'));
    }
    const error = new Error(data.message || `Request failed with status ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

export const api = {
  // Auth
  register: (name, email, password) =>
    apiRequest('/auth/register', { method: 'POST', body: JSON.stringify({ name, email, password }) }),
  login: (email, password) =>
    apiRequest('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  logout: () =>
    apiRequest('/auth/logout', { method: 'POST' }),
  getMe: () =>
    apiRequest('/auth/me', { method: 'GET' }),

  // Dashboard
  getDashboardSummary: () =>
    apiRequest('/dashboard/summary', { method: 'GET' }),

  // Scans
  uploadScan: (formData) =>
    apiRequest('/scans', { method: 'POST', body: formData }),
  listScans: () =>
    apiRequest('/scans', { method: 'GET' }),
  getScan: (scanId) =>
    apiRequest(`/scans/${scanId}`, { method: 'GET' }),

  // Cloud Security Auditor
  connectCloudAccount: (accountData) =>
    apiRequest('/cloud-security/connect', { method: 'POST', body: JSON.stringify(accountData) }),
  testCloudConnection: (testData) =>
    apiRequest('/cloud-security/test-connection', { method: 'POST', body: JSON.stringify(testData) }),
  runCloudScan: (scanParams) =>
    apiRequest('/cloud-security/scan', { method: 'POST', body: JSON.stringify(scanParams) }),
  runCloudDemoScan: (region = 'ap-south-1') =>
    apiRequest('/cloud-security/demo-scan', { method: 'POST', body: JSON.stringify({ region }) }),
  getCloudScan: (scanId) =>
    apiRequest(`/cloud-security/scan/${scanId}`, { method: 'GET' }),
  listCloudHistory: () =>
    apiRequest('/cloud-security/history', { method: 'GET' }),
  getCloudFinding: (findingId) =>
    apiRequest(`/cloud-security/findings/${findingId}`, { method: 'GET' }),
  getCloudSummary: () =>
    apiRequest('/cloud-security/summary', { method: 'GET' }),
};

