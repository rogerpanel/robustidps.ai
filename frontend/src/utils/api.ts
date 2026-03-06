import { authHeaders, clearAuth } from './auth'

const API = import.meta.env.VITE_API_URL || '';

/**
 * Authenticated fetch wrapper.
 * Adds JWT Authorization header and handles 401 responses.
 */
async function authFetch(url: string, opts: RequestInit = {}): Promise<Response> {
  const headers = { ...authHeaders(), ...(opts.headers as Record<string, string> || {}) }
  const res = await fetch(url, { ...opts, headers })
  if (res.status === 401) {
    clearAuth()
    window.location.reload()
  }
  return res
}

// ── Public endpoints (no auth required) ──────────────────────────────────

export async function fetchHealth() {
  const res = await fetch(`${API}/api/health`);
  return res.json();
}

export async function fetchAnalytics() {
  const res = await fetch(`${API}/api/analytics`);
  return res.json();
}

export async function fetchModelInfo() {
  const res = await fetch(`${API}/api/model_info`);
  return res.json();
}

export async function fetchModels() {
  const res = await fetch(`${API}/api/models`);
  return res.json();
}

// ── Authenticated endpoints ──────────────────────────────────────────────

export async function activateModel(modelId: string) {
  const res = await authFetch(`${API}/api/models/${modelId}/activate`, {
    method: 'POST',
  });
  return res.json();
}

export async function enableModel(modelId: string) {
  const res = await authFetch(`${API}/api/models/${modelId}/enable`, {
    method: 'POST',
  });
  return res.json();
}

export async function disableModel(modelId: string) {
  const res = await authFetch(`${API}/api/models/${modelId}/disable`, {
    method: 'POST',
  });
  return res.json();
}

export async function uploadCustomModel(file: File, modelName: string) {
  const form = new FormData();
  form.append('file', file);
  if (modelName) form.append('model_name', modelName);
  const res = await authFetch(`${API}/api/models/custom/upload`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Upload failed (${res.status})`);
  }
  return res.json();
}

export async function deleteCustomModel(modelId: string) {
  const res = await authFetch(`${API}/api/models/custom/${modelId}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function uploadFile(file: File) {
  const form = new FormData();
  form.append('file', file);
  const res = await authFetch(`${API}/api/upload`, { method: 'POST', body: form });
  return res.json();
}

export async function getResults(jobId: string) {
  const res = await authFetch(`${API}/api/results/${jobId}`);
  return res.json();
}

export async function uploadAndPredict(file: File, mcPasses = 20, modelName = '') {
  const form = new FormData();
  form.append('file', file);
  form.append('mc_passes', String(mcPasses));
  if (modelName) form.append('model_name', modelName);
  const res = await authFetch(`${API}/api/predict_uncertain`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = `Server error (${res.status})`;
    try {
      const json = JSON.parse(text);
      msg = json.detail || json.error || msg;
    } catch {
      if (text.length < 200) msg = text;
    }
    throw new Error(msg);
  }
  return res.json();
}

export async function runAblation(file: File, disabledBranches: number[], modelName = '') {
  const form = new FormData();
  form.append('file', file);
  form.append('disabled_branches', JSON.stringify(disabledBranches));
  if (modelName) form.append('model_name', modelName);
  const res = await authFetch(`${API}/api/ablation`, {
    method: 'POST',
    body: form,
  });
  return res.json();
}

function wsBaseUrl(): string {
  if (API) return API.replace(/^http/, 'ws');
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}`;
}

export function connectStream(
  jobId: string,
  rate: number,
  onMessage: (data: Record<string, unknown>) => void,
  onDone?: () => void,
  onError?: (err: Event) => void,
) {
  const wsUrl = `${wsBaseUrl()}/ws/stream`;
  const ws = new WebSocket(wsUrl);
  ws.onopen = () => {
    ws.send(JSON.stringify({ job_id: jobId, rate }));
  };
  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.error) {
      onError?.(new Event(data.error));
    } else if (data.done) {
      onDone?.();
    } else {
      onMessage(data);
    }
  };
  ws.onerror = (e) => { onError?.(e); };
  return ws;
}

export async function exportResults(jobId: string) {
  const res = await authFetch(`${API}/api/export/${jobId}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `robustidps_results_${jobId}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Firewall rule generation ─────────────────────────────────────────────

export async function generateFirewallRules(
  jobId: string,
  ruleType: string = 'iptables',
  minConfidence: number = 0.7,
  minSeverity: string = 'high',
  action: string = 'DROP',
) {
  const res = await authFetch(`${API}/api/firewall/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      job_id: jobId,
      rule_type: ruleType,
      min_confidence: minConfidence,
      min_severity: minSeverity,
      action,
    }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Error ${res.status}`);
  }
  return res.json();
}

// ── Admin: Users ─────────────────────────────────────────────────────────

export async function fetchUsers() {
  const res = await authFetch(`${API}/api/auth/users`);
  if (!res.ok) throw new Error(`Failed to fetch users (${res.status})`);
  return res.json();
}

export async function updateUserRole(userId: number, role: string) {
  const res = await authFetch(`${API}/api/auth/users/${userId}/role?role=${encodeURIComponent(role)}`, {
    method: 'PATCH',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Failed (${res.status})`);
  }
  return res.json();
}

export async function resetUserPassword(userId: number, newPassword: string) {
  const res = await authFetch(`${API}/api/auth/users/${userId}/password?new_password=${encodeURIComponent(newPassword)}`, {
    method: 'PATCH',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Failed (${res.status})`);
  }
  return res.json();
}

export async function deleteUser(userId: number) {
  const res = await authFetch(`${API}/api/auth/users/${userId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Failed (${res.status})`);
  }
  return res.json();
}

export async function toggleUserActive(userId: number, active: boolean) {
  const res = await authFetch(`${API}/api/auth/users/${userId}/deactivate?active=${active}`, {
    method: 'PATCH',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Failed (${res.status})`);
  }
  return res.json();
}

// ── Audit logs (admin) ───────────────────────────────────────────────────

export async function fetchAuditLogs(limit = 100, offset = 0) {
  const res = await authFetch(`${API}/api/audit/logs?limit=${limit}&offset=${offset}`);
  return res.json();
}

// ── Continual Learning ──────────────────────────────────────────────────

export async function fetchContinualStatus() {
  const res = await authFetch(`${API}/api/continual/status`);
  return res.json();
}

export async function triggerContinualUpdate(
  file: File,
  epochs: number = 5,
  lr: number = 0.0001,
  ewcLambda: number = 5000,
) {
  const form = new FormData();
  form.append('file', file);
  form.append('epochs', String(epochs));
  form.append('lr', String(lr));
  form.append('ewc_lambda', String(ewcLambda));
  const res = await authFetch(`${API}/api/continual/update`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Update failed (${res.status})`);
  }
  return res.json();
}

export async function measureDrift(file: File) {
  const form = new FormData();
  form.append('file', file);
  const res = await authFetch(`${API}/api/continual/drift`, {
    method: 'POST',
    body: form,
  });
  return res.json();
}

export async function rollbackModel() {
  const res = await authFetch(`${API}/api/continual/rollback`, {
    method: 'POST',
  });
  return res.json();
}

// Sample/fallback data for offline mode
export const SAMPLE_RESULTS = {
  job_id: 'demo',
  n_flows: 1000,
  n_threats: 347,
  n_benign: 653,
  ece: 0.043,
  predictions: [],
  attack_distribution: {
    Benign: 653,
    'DDoS-TCP_Flood': 80,
    'DDoS-UDP_Flood': 50,
    'DDoS-ICMP_Flood': 30,
    'Recon-PortScan': 40,
    'Recon-OSScan': 30,
    'BruteForce-SSH': 30,
    'BruteForce-FTP': 20,
    'Spoofing-ARP': 20,
    'Spoofing-DNS': 20,
    'WebAttack-SQLi': 30,
    'WebAttack-XSS': 30,
    'Malware-Backdoor': 20,
  },
  confusion_matrix: null,
  per_class_metrics: {},
  class_labels: [],
};
