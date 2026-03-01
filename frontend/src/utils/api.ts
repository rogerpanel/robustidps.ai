const API = import.meta.env.VITE_API_URL || '';

export async function fetchHealth() {
  const res = await fetch(`${API}/api/health`);
  return res.json();
}

export async function fetchModelInfo() {
  const res = await fetch(`${API}/api/model_info`);
  return res.json();
}

export async function uploadFile(file: File) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}/api/upload`, { method: 'POST', body: form });
  return res.json();
}

export async function getResults(jobId: string) {
  const res = await fetch(`${API}/api/results/${jobId}`);
  return res.json();
}

export async function uploadAndPredict(file: File, mcPasses = 50) {
  const form = new FormData();
  form.append('file', file);
  form.append('mc_passes', String(mcPasses));
  const res = await fetch(`${API}/api/predict_uncertain`, {
    method: 'POST',
    body: form,
  });
  return res.json();
}

export async function runAblation(file: File, disabledBranches: number[]) {
  const form = new FormData();
  form.append('file', file);
  form.append('disabled_branches', JSON.stringify(disabledBranches));
  const res = await fetch(`${API}/api/ablation`, {
    method: 'POST',
    body: form,
  });
  return res.json();
}

export function connectStream(
  jobId: string,
  rate: number,
  onMessage: (data: Record<string, unknown>) => void,
  onDone?: () => void,
) {
  const wsUrl = `${API.replace(/^http/, 'ws')}/ws/stream`;
  const ws = new WebSocket(wsUrl);
  ws.onopen = () => {
    ws.send(JSON.stringify({ job_id: jobId, rate }));
  };
  ws.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.done) {
      onDone?.();
    } else {
      onMessage(data);
    }
  };
  return ws;
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
