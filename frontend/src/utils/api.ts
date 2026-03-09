import { authHeaders, clearAuth } from './auth'

const API = import.meta.env.VITE_API_URL || '';

/** Extract a human-readable error message from a response body's `detail` field. */
function errorMsg(detail: unknown, fallback: string): string {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((d: any) => d.msg || JSON.stringify(d)).join('; ');
  if (detail && typeof detail === 'object') return JSON.stringify(detail);
  return fallback;
}

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
    throw new Error(errorMsg(data.detail, `Upload failed (${res.status})`));
  }
  return res.json();
}

export async function deleteCustomModel(modelId: string) {
  const res = await authFetch(`${API}/api/models/custom/${modelId}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function benchmarkModels() {
  const res = await authFetch(`${API}/api/models/benchmark`, {
    method: 'POST',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Benchmark failed (${res.status})`));
  }
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
  modelName?: string,
) {
  const wsUrl = `${wsBaseUrl()}/ws/stream`;
  const ws = new WebSocket(wsUrl);
  ws.onopen = () => {
    ws.send(JSON.stringify({ job_id: jobId, rate, model_name: modelName || '' }));
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

// ── Sample Data ─────────────────────────────────────────────────────────

export async function fetchSampleData(dataset: 'ciciot' | 'pqc' = 'ciciot'): Promise<File> {
  const res = await fetch(`${API}/api/sample-data?dataset=${dataset}`);
  if (!res.ok) throw new Error('Failed to fetch sample data');
  const blob = await res.blob();
  const filename = dataset === 'pqc' ? 'pqc_test_dataset.csv' : 'ciciot_sample.csv';
  return new File([blob], filename, { type: 'text/csv' });
}

// ── Datasets Management ──────────────────────────────────────────────────

export interface DatasetMeta {
  name: string
  filename: string
  size_mb: number
  n_rows: number
  n_columns: number
  columns: string[]
  has_pq_metadata: boolean
  pq_distribution: Record<string, number>
  label_distribution: Record<string, number>
}

export async function fetchDatasets(): Promise<{ datasets: DatasetMeta[] }> {
  const res = await authFetch(`${API}/api/datasets`);
  return res.json();
}

export async function fetchDatasetInfo(name: string): Promise<DatasetMeta> {
  const res = await authFetch(`${API}/api/datasets/${encodeURIComponent(name)}/info`);
  return res.json();
}

export async function uploadDataset(file: File) {
  const form = new FormData();
  form.append('file', file);
  const res = await authFetch(`${API}/api/datasets/upload`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Upload failed (${res.status})`));
  }
  return res.json();
}

export async function deleteDataset(name: string) {
  const res = await authFetch(`${API}/api/datasets/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  });
  return res.json();
}

export async function predictDataset(name: string, mcPasses = 20) {
  const res = await authFetch(`${API}/api/datasets/${encodeURIComponent(name)}/predict?mc_passes=${mcPasses}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Prediction failed (${res.status})`));
  }
  return res.json();
}

export async function compareDatasetBranches(name: string, mcPasses = 10) {
  const res = await authFetch(`${API}/api/datasets/${encodeURIComponent(name)}/compare?mc_passes=${mcPasses}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Comparison failed (${res.status})`));
  }
  return res.json();
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
    throw new Error(errorMsg(data.detail, `Error ${res.status}`));
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
    throw new Error(errorMsg(data.detail, `Failed (${res.status})`));
  }
  return res.json();
}

export async function resetUserPassword(userId: number, newPassword: string) {
  const res = await authFetch(`${API}/api/auth/users/${userId}/password?new_password=${encodeURIComponent(newPassword)}`, {
    method: 'PATCH',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Failed (${res.status})`));
  }
  return res.json();
}

export async function deleteUser(userId: number) {
  const res = await authFetch(`${API}/api/auth/users/${userId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Failed (${res.status})`));
  }
  return res.json();
}

export async function toggleUserActive(userId: number, active: boolean) {
  const res = await authFetch(`${API}/api/auth/users/${userId}/deactivate?active=${active}`, {
    method: 'PATCH',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Failed (${res.status})`));
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
    throw new Error(errorMsg(data.detail, `Update failed (${res.status})`));
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

// ── Adversarial Red Team Arena ───────────────────────────────────────────

export async function fetchRedteamAttacks() {
  const res = await fetch(`${API}/api/redteam/attacks`);
  return res.json();
}

// ── Background job polling helper ────────────────────────────────────────

async function pollJobResult(jobId: string, label: string): Promise<unknown> {
  const POLL_INTERVAL = 3000;
  const MAX_POLLS = 200; // ~10 min
  for (let i = 0; i < MAX_POLLS; i++) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL));
    const poll = await authFetch(`${API}/api/job/status/${jobId}`);
    if (!poll.ok) {
      const data = await poll.json().catch(() => ({}));
      throw new Error(errorMsg(data.detail, `${label} failed (${poll.status})`));
    }
    const body = await poll.json();
    if (body.status === 'done') return body.result;
  }
  throw new Error(`${label} timed out`);
}

async function startJobAndPoll(url: string, form: FormData, label: string) {
  const res = await authFetch(url, { method: 'POST', body: form });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `${label} failed (${res.status})`));
  }
  const { job_id } = await res.json();
  return pollJobResult(job_id, label);
}

// ── Red Team Arena ──────────────────────────────────────────────────────

export async function runRedteam(
  file: File,
  attacks: string[] = [],
  epsilon: number = 0.1,
  nSamples: number = 500,
  modelName: string = '',
) {
  const form = new FormData();
  form.append('file', file);
  form.append('attacks', JSON.stringify(attacks));
  form.append('epsilon', String(epsilon));
  form.append('n_samples', String(nSamples));
  if (modelName) form.append('model_name', modelName);
  return startJobAndPoll(`${API}/api/redteam/run`, form, 'Red team');
}

// ── Explainability Studio (XAI) ─────────────────────────────────────────

export async function runXai(
  file: File,
  method: string = 'all',
  nSamples: number = 200,
  modelName: string = '',
) {
  const form = new FormData();
  form.append('file', file);
  form.append('method', method);
  form.append('n_samples', String(nSamples));
  if (modelName) form.append('model_name', modelName);
  return startJobAndPoll(`${API}/api/xai/run`, form, 'XAI analysis');
}

// ── Federated Learning Simulator ────────────────────────────────────────

export async function runFederated(
  file: File,
  opts: {
    nNodes?: number
    rounds?: number
    localEpochs?: number
    lr?: number
    strategy?: string
    dpEnabled?: boolean
    dpSigma?: number
    iid?: boolean
    modelName?: string
  } = {},
) {
  const form = new FormData();
  form.append('file', file);
  if (opts.nNodes !== undefined) form.append('n_nodes', String(opts.nNodes));
  if (opts.rounds !== undefined) form.append('rounds', String(opts.rounds));
  if (opts.localEpochs !== undefined) form.append('local_epochs', String(opts.localEpochs));
  if (opts.lr !== undefined) form.append('lr', String(opts.lr));
  if (opts.strategy) form.append('strategy', opts.strategy);
  if (opts.dpEnabled !== undefined) form.append('dp_enabled', String(opts.dpEnabled));
  if (opts.dpSigma !== undefined) form.append('dp_sigma', String(opts.dpSigma));
  if (opts.iid !== undefined) form.append('iid', String(opts.iid));
  if (opts.modelName) form.append('model_name', opts.modelName);

  return startJobAndPoll(`${API}/api/federated/run`, form, 'Federated simulation');
}

// ── PQ Cryptography ──────────────────────────────────────────────────────

export async function fetchPqAlgorithms() {
  const res = await authFetch(`${API}/api/pq/algorithms`);
  return res.json();
}

export async function benchmarkPqAlgorithm(algorithm: string, iterations = 100) {
  const res = await authFetch(`${API}/api/pq/benchmark`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, iterations }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Benchmark failed (${res.status})`));
  }
  return res.json();
}

export async function fetchPqRiskAssessment() {
  const res = await authFetch(`${API}/api/pq/risk-assessment`);
  return res.json();
}

export async function simulatePqHandshake(algorithm: string) {
  const res = await authFetch(`${API}/api/pq/simulate-handshake`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, iterations: 1 }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Simulation failed (${res.status})`));
  }
  return res.json();
}

export async function fetchPqComparisonMatrix() {
  const res = await authFetch(`${API}/api/pq/comparison-matrix`);
  return res.json();
}

export async function fetchPqMigrationAssessment(targetLevel = 3, includeHybrid = true) {
  const res = await authFetch(`${API}/api/pq/migration-assessment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_nist_level: targetLevel, include_hybrid: includeHybrid }),
  });
  return res.json();
}

// ── PQ Enhanced Simulation ───────────────────────────────────────────────

export async function pqTrafficAnalysis(algorithm: string, scenario = 'normal', nFlows = 100) {
  const res = await authFetch(`${API}/api/pq/traffic-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, scenario, n_flows: nFlows }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Traffic analysis failed (${res.status})`));
  }
  return res.json();
}

export async function pqHandshakeIdsEval(algorithm: string) {
  const res = await authFetch(`${API}/api/pq/handshake-ids-eval`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `IDS evaluation failed (${res.status})`));
  }
  return res.json();
}

export async function pqAttackSimulation(algorithm: string, attackType = 'downgrade_attack') {
  const res = await authFetch(`${API}/api/pq/attack-simulation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm, attack_type: attackType }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Attack simulation failed (${res.status})`));
  }
  return res.json();
}

export async function pqModelComparison(algorithm: string) {
  const res = await authFetch(`${API}/api/pq/model-comparison`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ algorithm }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Model comparison failed (${res.status})`));
  }
  return res.json();
}

// ── Zero-Trust AI Governance ─────────────────────────────────────────────

export async function fetchTrustScore() {
  const res = await authFetch(`${API}/api/zerotrust/trust-score`);
  return res.json();
}

export async function fetchSystemTrustScore() {
  const res = await authFetch(`${API}/api/zerotrust/trust-score/system`);
  return res.json();
}

export async function fetchGovernancePolicies() {
  const res = await authFetch(`${API}/api/zerotrust/policies`);
  return res.json();
}

export async function updateGovernancePolicy(policyId: string, newValue: number | boolean) {
  const res = await authFetch(`${API}/api/zerotrust/policies/${policyId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policy_id: policyId, new_value: newValue }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Update failed (${res.status})`));
  }
  return res.json();
}

export async function fetchComplianceDashboard() {
  const res = await authFetch(`${API}/api/zerotrust/compliance`);
  return res.json();
}

export async function fetchModelProvenance() {
  const res = await authFetch(`${API}/api/zerotrust/model-provenance`);
  return res.json();
}

export async function fetchAccessAnalytics() {
  const res = await authFetch(`${API}/api/zerotrust/access-analytics`);
  return res.json();
}

export async function fetchVerificationStatus() {
  const res = await authFetch(`${API}/api/zerotrust/verification-status`);
  return res.json();
}

// ── Autonomous Threat Response ───────────────────────────────────────────

export async function fetchPlaybooks() {
  const res = await authFetch(`${API}/api/threat-response/playbooks`);
  return res.json();
}

export async function fetchPlaybook(playbookId: string) {
  const res = await authFetch(`${API}/api/threat-response/playbooks/${playbookId}`);
  return res.json();
}

export async function togglePlaybookAutoExecute(playbookId: string, autoExecute: boolean) {
  const res = await authFetch(`${API}/api/threat-response/playbooks/${playbookId}/toggle`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ auto_execute: autoExecute }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Toggle failed (${res.status})`));
  }
  return res.json();
}

export async function simulateThreatResponse(
  playbookId: string,
  sourceIp = '192.168.1.100',
  targetIp = '10.0.0.1',
  confidence = 0.95,
) {
  const res = await authFetch(`${API}/api/threat-response/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      playbook_id: playbookId,
      source_ip: sourceIp,
      target_ip: targetIp,
      confidence,
    }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Simulation failed (${res.status})`));
  }
  return res.json();
}

export async function fetchIncidents(limit = 50, severity?: string) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (severity) params.set('severity', severity);
  const res = await authFetch(`${API}/api/threat-response/incidents?${params}`);
  return res.json();
}

export async function fetchIncident(incidentId: string) {
  const res = await authFetch(`${API}/api/threat-response/incidents/${incidentId}`);
  return res.json();
}

export async function addIncidentNote(incidentId: string, note: string) {
  const res = await authFetch(`${API}/api/threat-response/incidents/${incidentId}/note`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ note }),
  });
  return res.json();
}

export async function fetchSecurityIntegrations() {
  const res = await authFetch(`${API}/api/threat-response/integrations`);
  return res.json();
}

export async function fetchResponseMetrics() {
  const res = await authFetch(`${API}/api/threat-response/response-metrics`);
  return res.json();
}

export async function createPlaybook(data: {
  name: string;
  description: string;
  trigger_classes: string[];
  severity: string;
  requires_approval: boolean;
  response_chain: { step: number; action: string; description: string; delay_ms: number }[];
}) {
  const res = await authFetch(`${API}/api/threat-response/playbooks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(errorMsg(d.detail, `Create playbook failed (${res.status})`));
  }
  return res.json();
}

export async function updatePlaybook(playbookId: string, data: Record<string, unknown>) {
  const res = await authFetch(`${API}/api/threat-response/playbooks/${playbookId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(errorMsg(d.detail, `Update playbook failed (${res.status})`));
  }
  return res.json();
}

export async function deletePlaybook(playbookId: string) {
  const res = await authFetch(`${API}/api/threat-response/playbooks/${playbookId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(errorMsg(d.detail, `Delete playbook failed (${res.status})`));
  }
  return res.json();
}

// ── Model Supply Chain Security ──────────────────────────────────────────

export async function fetchSupplyChainOverview() {
  const res = await authFetch(`${API}/api/supply-chain/overview`);
  return res.json();
}

export async function fetchSupplyChainModels() {
  const res = await authFetch(`${API}/api/supply-chain/models`);
  return res.json();
}

export async function fetchPipelineChecks() {
  const res = await authFetch(`${API}/api/supply-chain/pipeline-checks`);
  return res.json();
}

export async function fetchVulnerabilities() {
  const res = await authFetch(`${API}/api/supply-chain/vulnerabilities`);
  return res.json();
}

export async function fetchRiskMatrix() {
  const res = await authFetch(`${API}/api/supply-chain/risk-matrix`);
  return res.json();
}

export async function runSupplyChainScan(modelId = 'all', scanType = 'full') {
  const res = await authFetch(`${API}/api/supply-chain/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model_id: modelId, scan_type: scanType }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `Scan failed (${res.status})`));
  }
  return res.json();
}

export async function fetchModelSbom(modelId: string, format = 'cyclonedx') {
  const res = await authFetch(`${API}/api/supply-chain/models/${modelId}/sbom?format=${encodeURIComponent(format)}`);
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(errorMsg(data.detail, `SBOM generation failed (${res.status})`));
  }
  return res.json();
}

export async function fetchScanHistory(limit = 20) {
  const res = await authFetch(`${API}/api/supply-chain/scan-history?limit=${limit}`);
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
