import { useState } from 'react'
import {
  Plus, Trash2, Save, X, ChevronDown, ChevronUp, GripVertical, AlertTriangle,
} from 'lucide-react'

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'] as const
const SEV_COLORS: Record<string, string> = {
  critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6',
}

const ACTION_PRESETS = [
  'detect', 'verify', 'alert', 'rate_limit', 'firewall', 'block_temp', 'block_perm',
  'throttle', 'captcha', 'isolate', 'block_c2', 'snapshot', 'ioc_extract',
  'threat_intel', 'edr_scan', 'waf_rule', 'session_kill', 'honeypot', 'tarpit',
  'intel_collect', 'validate', 'arp_guard', 'dns_sinkhole', 'credential_reset',
  'upstream_notify', 'input_sanitise', 'geo_check', 'log',
]

// All known threat classes for the dropdown
const ALL_THREAT_CLASSES = [
  'DDoS-TCP_Flood', 'DDoS-UDP_Flood', 'DDoS-ICMP_Flood', 'DDoS-HTTP_Flood',
  'DDoS-SYN_Flood', 'DDoS-SlowLoris', 'DDoS-PSHACK_Flood', 'DDoS-RSTFINFlood',
  'DDoS-SynonymousIP_Flood', 'DDoS-ACK_Fragmentation', 'DDoS-UDP_Fragmentation',
  'DDoS-ICMP_Fragmentation', 'DoS-TCP_Flood', 'DoS-UDP_Flood', 'DoS-SYN_Flood',
  'DoS-HTTP_Flood', 'Recon-PortScan', 'Recon-OSScan', 'Recon-HostDiscovery',
  'Recon-PingSweep', 'BruteForce-SSH', 'BruteForce-FTP', 'BruteForce-HTTP',
  'BruteForce-RDP', 'Spoofing-ARP', 'Spoofing-DNS', 'Spoofing-IP',
  'WebAttack-SQLi', 'WebAttack-XSS', 'WebAttack-CommandInjection',
  'WebAttack-BrowserHijacking', 'Malware-Backdoor', 'Malware-Ransomware',
  'Malware-C2', 'Mirai-greip_flood', 'Mirai-greeth_flood', 'Mirai-udpplain',
]

interface Step {
  action: string
  description: string
  delay_ms: number
}

interface PlaybookEditorProps {
  uncoveredClasses?: string[]
  onSave: (data: {
    name: string
    description: string
    trigger_classes: string[]
    severity: string
    requires_approval: boolean
    response_chain: { step: number; action: string; description: string; delay_ms: number }[]
  }) => Promise<void>
  onCancel: () => void
  saving?: boolean
}

export default function PlaybookEditor({ uncoveredClasses = [], onSave, onCancel, saving }: PlaybookEditorProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<string>('medium')
  const [requiresApproval, setRequiresApproval] = useState(true)
  const [triggerClasses, setTriggerClasses] = useState<string[]>([])
  const [steps, setSteps] = useState<Step[]>([
    { action: 'detect', description: 'ML model classifies threat traffic', delay_ms: 0 },
    { action: 'log', description: 'Record incident with evidence chain', delay_ms: 100 },
  ])
  const [showClassPicker, setShowClassPicker] = useState(false)
  const [error, setError] = useState('')

  const toggleClass = (cls: string) => {
    setTriggerClasses(prev =>
      prev.includes(cls) ? prev.filter(c => c !== cls) : [...prev, cls]
    )
  }

  const addStep = () => {
    setSteps(prev => [...prev, { action: 'alert', description: '', delay_ms: 100 }])
  }

  const removeStep = (idx: number) => {
    setSteps(prev => prev.filter((_, i) => i !== idx))
  }

  const updateStep = (idx: number, field: keyof Step, value: string | number) => {
    setSteps(prev => prev.map((s, i) => i === idx ? { ...s, [field]: value } : s))
  }

  const moveStep = (idx: number, dir: -1 | 1) => {
    const target = idx + dir
    if (target < 0 || target >= steps.length) return
    setSteps(prev => {
      const next = [...prev]
      ;[next[idx], next[target]] = [next[target], next[idx]]
      return next
    })
  }

  const handleSubmit = async () => {
    setError('')
    if (!name.trim()) { setError('Name is required'); return }
    if (triggerClasses.length === 0) { setError('Select at least one trigger class'); return }
    if (steps.length < 2) { setError('Add at least two response steps'); return }
    if (steps.some(s => !s.action || !s.description)) { setError('All steps need an action and description'); return }

    try {
      await onSave({
        name: name.trim(),
        description: description.trim(),
        trigger_classes: triggerClasses,
        severity,
        requires_approval: requiresApproval,
        response_chain: steps.map((s, i) => ({ step: i + 1, ...s })),
      })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed')
    }
  }

  const estimatedMs = steps.reduce((sum, s) => sum + s.delay_ms, 0)

  return (
    <div className="bg-bg-secondary rounded-xl border border-accent-orange/30 p-5 space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-accent-orange flex items-center gap-2">
          <Plus className="w-4 h-4" /> Create New Playbook
        </h3>
        <button onClick={onCancel} className="p-1 text-text-secondary hover:text-text-primary">
          <X className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-xs flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> {error}
        </div>
      )}

      {/* Basic info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-text-secondary block mb-1">Playbook Name *</label>
          <input
            type="text" value={name} onChange={e => setName(e.target.value)}
            placeholder="e.g. DoS Flood Mitigation"
            className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-text-secondary block mb-1">Severity</label>
            <select
              value={severity} onChange={e => setSeverity(e.target.value)}
              className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary"
            >
              {SEVERITY_OPTIONS.map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-text-secondary block mb-1">Approval Required</label>
            <button
              onClick={() => setRequiresApproval(!requiresApproval)}
              className={`w-full px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                requiresApproval
                  ? 'bg-accent-amber/10 border-accent-amber/30 text-accent-amber'
                  : 'bg-bg-primary border-bg-card text-text-secondary'
              }`}
            >
              {requiresApproval ? 'Yes' : 'No'}
            </button>
          </div>
        </div>
      </div>

      <div>
        <label className="text-xs text-text-secondary block mb-1">Description</label>
        <textarea
          value={description} onChange={e => setDescription(e.target.value)}
          placeholder="Describe the playbook's purpose and response strategy..."
          rows={2}
          className="w-full px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-sm text-text-primary resize-none"
        />
      </div>

      {/* Trigger classes */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs text-text-secondary">Trigger Classes * ({triggerClasses.length} selected)</label>
          <button
            onClick={() => setShowClassPicker(!showClassPicker)}
            className="text-[10px] text-accent-blue hover:underline flex items-center gap-1"
          >
            {showClassPicker ? 'Hide' : 'Show all classes'}
            {showClassPicker ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>

        {/* Quick-add uncovered classes */}
        {uncoveredClasses.length > 0 && (
          <div className="mb-2">
            <div className="text-[10px] text-accent-amber mb-1">Uncovered classes (click to add):</div>
            <div className="flex flex-wrap gap-1">
              {uncoveredClasses.map(c => (
                <button
                  key={c}
                  onClick={() => toggleClass(c)}
                  className={`px-1.5 py-0.5 text-[9px] rounded font-mono transition-colors ${
                    triggerClasses.includes(c)
                      ? 'bg-accent-green/15 text-accent-green'
                      : 'bg-accent-amber/10 text-accent-amber hover:bg-accent-amber/20'
                  }`}
                >
                  {triggerClasses.includes(c) ? '✓ ' : '+ '}{c}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Full class picker */}
        {showClassPicker && (
          <div className="flex flex-wrap gap-1 p-3 bg-bg-primary rounded-lg border border-bg-card max-h-40 overflow-y-auto">
            {ALL_THREAT_CLASSES.map(c => (
              <button
                key={c}
                onClick={() => toggleClass(c)}
                className={`px-1.5 py-0.5 text-[9px] rounded font-mono transition-colors ${
                  triggerClasses.includes(c)
                    ? 'bg-accent-green/15 text-accent-green'
                    : 'bg-bg-secondary text-text-secondary hover:text-text-primary'
                }`}
              >
                {triggerClasses.includes(c) ? '✓ ' : ''}{c}
              </button>
            ))}
          </div>
        )}

        {/* Selected classes display */}
        {triggerClasses.length > 0 && !showClassPicker && (
          <div className="flex flex-wrap gap-1">
            {triggerClasses.map(c => (
              <span key={c} className="px-1.5 py-0.5 bg-accent-green/10 text-accent-green text-[9px] rounded font-mono flex items-center gap-1">
                {c}
                <button onClick={() => toggleClass(c)} className="hover:text-accent-red">
                  <X className="w-2.5 h-2.5" />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Response chain builder */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs text-text-secondary">
            Response Chain ({steps.length} steps, ~{estimatedMs}ms total)
          </label>
          <button
            onClick={addStep}
            className="text-[10px] text-accent-blue hover:underline flex items-center gap-1"
          >
            <Plus className="w-3 h-3" /> Add Step
          </button>
        </div>
        <div className="space-y-2">
          {steps.map((step, idx) => (
            <div key={idx} className="flex items-center gap-2 bg-bg-primary rounded-lg px-3 py-2 group">
              <div className="flex flex-col gap-0.5">
                <button
                  onClick={() => moveStep(idx, -1)} disabled={idx === 0}
                  className="text-text-secondary hover:text-text-primary disabled:opacity-20"
                >
                  <ChevronUp className="w-3 h-3" />
                </button>
                <button
                  onClick={() => moveStep(idx, 1)} disabled={idx === steps.length - 1}
                  className="text-text-secondary hover:text-text-primary disabled:opacity-20"
                >
                  <ChevronDown className="w-3 h-3" />
                </button>
              </div>
              <span className="text-[10px] font-mono text-text-secondary w-4 text-center">{idx + 1}</span>
              <select
                value={step.action}
                onChange={e => updateStep(idx, 'action', e.target.value)}
                className="px-2 py-1 bg-bg-secondary border border-bg-card rounded text-[11px] text-text-primary font-mono"
              >
                {ACTION_PRESETS.map(a => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </select>
              <input
                type="text"
                value={step.description}
                onChange={e => updateStep(idx, 'description', e.target.value)}
                placeholder="Step description..."
                className="flex-1 px-2 py-1 bg-bg-secondary border border-bg-card rounded text-[11px] text-text-primary"
              />
              <div className="flex items-center gap-1">
                <input
                  type="number" min={0} max={30000} step={50}
                  value={step.delay_ms}
                  onChange={e => updateStep(idx, 'delay_ms', parseInt(e.target.value) || 0)}
                  className="w-16 px-2 py-1 bg-bg-secondary border border-bg-card rounded text-[11px] text-text-primary font-mono text-right"
                />
                <span className="text-[9px] text-text-secondary">ms</span>
              </div>
              <button
                onClick={() => removeStep(idx)}
                disabled={steps.length <= 1}
                className="p-1 text-text-secondary hover:text-accent-red disabled:opacity-20"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Preview summary */}
      <div className="flex items-center justify-between bg-bg-primary rounded-lg px-4 py-3 border border-bg-card">
        <div className="flex items-center gap-3 text-xs">
          <span className="px-2 py-0.5 rounded font-medium" style={{
            background: `${SEV_COLORS[severity]}20`,
            color: SEV_COLORS[severity],
          }}>
            {severity}
          </span>
          <span className="text-text-secondary">{triggerClasses.length} triggers</span>
          <span className="text-text-secondary">{steps.length} steps</span>
          <span className="font-mono text-accent-green">~{estimatedMs}ms</span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-xs text-text-secondary hover:text-text-primary transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="px-4 py-2 bg-accent-orange text-white rounded-lg text-xs font-medium hover:bg-accent-orange/80 transition-colors disabled:opacity-40 flex items-center gap-1.5"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'Saving...' : 'Create Playbook'}
          </button>
        </div>
      </div>
    </div>
  )
}
