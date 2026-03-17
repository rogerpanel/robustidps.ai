import { useState } from 'react'
import { Code, Copy, Check, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'

/* ── Endpoint definitions ──────────────────────────────────────────────── */

interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  path: string
  summary: string
  description: string
  auth: boolean
  params?: { name: string; type: string; required: boolean; desc: string }[]
  response?: string
}

interface EndpointGroup {
  name: string
  endpoints: Endpoint[]
}

const ENDPOINT_GROUPS: EndpointGroup[] = [
  {
    name: 'Health & Status',
    endpoints: [
      {
        method: 'GET', path: '/api/health', summary: 'System health check', auth: false,
        description: 'Returns backend status, model availability, and system metrics.',
        response: '{ "status": "healthy", "models_loaded": 7, "uptime_seconds": 86400 }',
      },
    ],
  },
  {
    name: 'Analysis',
    endpoints: [
      {
        method: 'POST', path: '/api/analyse', summary: 'Analyse network flows', auth: true,
        description: 'Upload a CSV or PCAP file for IDS analysis. Returns per-flow predictions with confidence, severity, and uncertainty estimates.',
        params: [
          { name: 'file', type: 'File (CSV/PCAP)', required: true, desc: 'Network traffic capture file' },
          { name: 'model', type: 'string', required: false, desc: 'Model to use (default: surrogate ensemble)' },
        ],
        response: `{
  "job_id": "abc123",
  "n_flows": 1000,
  "n_threats": 347,
  "n_benign": 653,
  "ece": 0.043,
  "predictions": [
    {
      "flow_id": 1, "src_ip": "192.168.1.5",
      "dst_ip": "10.0.0.1", "label_predicted": "DDoS-SYN_Flood",
      "confidence": 0.97, "severity": "critical"
    }
  ]
}`,
      },
    ],
  },
  {
    name: 'Analytics & Models',
    endpoints: [
      {
        method: 'GET', path: '/api/analytics', summary: 'Full performance analytics', auth: false,
        description: 'Returns comprehensive model performance data: accuracy, F1, convergence curves, robustness metrics, and calibration data.',
        response: '{ "models": [...], "convergence": [...], "robustness": [...] }',
      },
      {
        method: 'GET', path: '/api/models', summary: 'List available models', auth: false,
        description: 'Returns all IDS models with their architecture details, parameter counts, and current status.',
        response: '{ "models": [{ "id": "surrogate", "name": "SurrogateIDS", "params": "2.1M", ... }] }',
      },
      {
        method: 'POST', path: '/api/models/{model_id}/activate', summary: 'Activate model', auth: true,
        description: 'Set a model as the active inference model for the platform.',
      },
    ],
  },
  {
    name: 'Ablation Studies',
    endpoints: [
      {
        method: 'POST', path: '/api/ablation', summary: 'Run ablation study', auth: true,
        description: 'Toggle any combination of the 7 methods and compute the ensemble accuracy impact on a selected dataset.',
        params: [
          { name: 'enabled_methods', type: 'string[]', required: true, desc: 'List of method IDs to enable' },
          { name: 'dataset', type: 'string', required: false, desc: 'Dataset to evaluate on (default: CIC-IoT-2023)' },
        ],
      },
    ],
  },
  {
    name: 'Explainability',
    endpoints: [
      {
        method: 'GET', path: '/api/explainability/{flow_id}', summary: 'Get explanations', auth: true,
        description: 'Returns SHAP values, feature importance, attention weights, and counterfactual analysis for a specific prediction.',
      },
    ],
  },
  {
    name: 'Adversarial & Red Team',
    endpoints: [
      {
        method: 'POST', path: '/api/redteam/attack', summary: 'Simulate adversarial attack', auth: true,
        description: 'Generate adversarial examples using FGSM, PGD, C&W, or custom perturbation methods.',
        params: [
          { name: 'attack_type', type: 'string', required: true, desc: 'fgsm | pgd | cw | custom' },
          { name: 'epsilon', type: 'float', required: false, desc: 'Perturbation budget (default: 0.1)' },
        ],
      },
    ],
  },
  {
    name: 'Federated Learning',
    endpoints: [
      {
        method: 'GET', path: '/api/federated/status', summary: 'FL node status', auth: true,
        description: 'Returns federated learning node status, round progress, and aggregation metrics.',
      },
      {
        method: 'POST', path: '/api/federated/simulate', summary: 'Simulate FL round', auth: true,
        description: 'Run a simulated federated learning round with configurable number of clients and privacy parameters.',
      },
    ],
  },
  {
    name: 'Continual Learning & Drift',
    endpoints: [
      {
        method: 'POST', path: '/api/continual/train', summary: 'Trigger CL update', auth: true,
        description: 'Trigger a continual learning training step using the latest data buffer.',
      },
      {
        method: 'GET', path: '/api/drift/status', summary: 'Drift detection', auth: false,
        description: 'Returns concept drift detection metrics and alerts for model staleness.',
      },
    ],
  },
]

/* ── Component ─────────────────────────────────────────────────────────── */

export default function ApiDocs() {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(ENDPOINT_GROUPS.map(g => g.name)))
  const [copiedPath, setCopiedPath] = useState<string | null>(null)

  const toggleGroup = (name: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const copyToClipboard = (text: string, path: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedPath(path)
      setTimeout(() => setCopiedPath(null), 2000)
    })
  }

  const methodColor = (method: string) => {
    switch (method) {
      case 'GET': return 'bg-accent-green/15 text-accent-green'
      case 'POST': return 'bg-accent-blue/15 text-accent-blue'
      case 'PUT': return 'bg-accent-amber/15 text-accent-amber'
      case 'DELETE': return 'bg-accent-red/15 text-accent-red'
      default: return 'bg-bg-card text-text-secondary'
    }
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-display font-bold">API Documentation</h1>
        <p className="text-sm text-text-secondary mt-2 max-w-3xl">
          RESTful API with JSON responses. All endpoints are available at <code className="px-1.5 py-0.5 bg-bg-card rounded text-xs font-mono">https://robustidps.ai/api</code>.
          Authenticated endpoints require a Bearer token from <code className="px-1.5 py-0.5 bg-bg-card rounded text-xs font-mono">/api/auth/login</code>.
        </p>
      </div>

      {/* Quick start */}
      <div className="bg-bg-secondary rounded-xl border border-bg-card p-5">
        <h2 className="text-sm font-display font-semibold mb-3 flex items-center gap-2">
          <Code className="w-4 h-4 text-accent-blue" />
          Quick Start
        </h2>
        <pre className="bg-bg-primary rounded-lg p-4 text-xs font-mono text-text-secondary overflow-x-auto">
          <code>{`# 1. Authenticate
TOKEN=$(curl -s -X POST https://robustidps.ai/api/auth/login \\
  -d "username=demo@robustidps.ai&password=demo" | jq -r .access_token)

# 2. Upload and analyse traffic
curl -X POST https://robustidps.ai/api/analyse \\
  -H "Authorization: Bearer $TOKEN" \\
  -F "file=@traffic.csv"

# 3. Get analytics (public, no auth needed)
curl https://robustidps.ai/api/analytics`}</code>
        </pre>
      </div>

      {/* Endpoint groups */}
      {ENDPOINT_GROUPS.map(group => (
        <div key={group.name} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
          <button
            onClick={() => toggleGroup(group.name)}
            className="w-full flex items-center justify-between px-5 py-3 hover:bg-bg-card/30 transition-colors"
          >
            <span className="font-display font-semibold text-sm text-text-primary">{group.name}</span>
            <div className="flex items-center gap-2">
              <span className="text-xs text-text-secondary">{group.endpoints.length} endpoint{group.endpoints.length > 1 ? 's' : ''}</span>
              {expandedGroups.has(group.name) ? (
                <ChevronDown className="w-4 h-4 text-text-secondary" />
              ) : (
                <ChevronRight className="w-4 h-4 text-text-secondary" />
              )}
            </div>
          </button>

          {expandedGroups.has(group.name) && (
            <div className="border-t border-bg-card">
              {group.endpoints.map((ep, i) => (
                <div key={ep.path + ep.method} className={`p-5 ${i > 0 ? 'border-t border-bg-card/50' : ''}`}>
                  {/* Method + path */}
                  <div className="flex items-center gap-3 mb-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${methodColor(ep.method)}`}>
                      {ep.method}
                    </span>
                    <code className="font-mono text-sm text-text-primary">{ep.path}</code>
                    {!ep.auth && (
                      <span className="px-1.5 py-0.5 bg-accent-green/10 text-accent-green text-[10px] rounded font-medium">
                        PUBLIC
                      </span>
                    )}
                    {ep.auth && (
                      <span className="px-1.5 py-0.5 bg-accent-amber/10 text-accent-amber text-[10px] rounded font-medium">
                        AUTH
                      </span>
                    )}
                    <button
                      onClick={() => copyToClipboard(`curl ${ep.method === 'GET' ? '' : `-X ${ep.method} `}https://robustidps.ai${ep.path}`, ep.path)}
                      className="ml-auto text-text-secondary hover:text-text-primary transition-colors"
                      title="Copy cURL"
                    >
                      {copiedPath === ep.path ? (
                        <Check className="w-3.5 h-3.5 text-accent-green" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>

                  <p className="text-xs text-text-secondary mb-3">{ep.description}</p>

                  {/* Parameters */}
                  {ep.params && ep.params.length > 0 && (
                    <div className="mb-3">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-text-secondary/60 mb-1.5">Parameters</div>
                      <div className="space-y-1">
                        {ep.params.map(p => (
                          <div key={p.name} className="flex items-center gap-2 text-xs">
                            <code className="px-1.5 py-0.5 bg-bg-primary rounded font-mono text-accent-blue">{p.name}</code>
                            <span className="text-text-secondary/50">{p.type}</span>
                            {p.required && <span className="text-accent-red text-[10px]">required</span>}
                            <span className="text-text-secondary">{p.desc}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Response example */}
                  {ep.response && (
                    <div>
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-text-secondary/60 mb-1.5">Response</div>
                      <pre className="bg-bg-primary rounded-lg p-3 text-[11px] font-mono text-text-secondary overflow-x-auto">
                        <code>{ep.response}</code>
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {/* SDK section */}
      <div className="bg-bg-secondary rounded-xl border border-bg-card p-5">
        <h2 className="text-sm font-display font-semibold mb-3">Python SDK</h2>
        <pre className="bg-bg-primary rounded-lg p-4 text-xs font-mono text-text-secondary overflow-x-auto">
          <code>{`pip install robustidps  # Coming soon

from robustidps import Client

client = Client("https://robustidps.ai", api_key="...")
results = client.analyse("traffic.csv")
print(results.summary())
`}</code>
        </pre>
      </div>
    </div>
  )
}
