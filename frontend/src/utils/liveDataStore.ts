/* ── Live Data Store ─────────────────────────────────────────────────
 * Shared in-memory store for passing captured data from the Live Monitor
 * to other analysis pages. Data is stored globally and persists until
 * explicitly cleared or the page is refreshed.
 * ──────────────────────────────────────────────────────────────────── */

export interface LiveCapturedData {
  predictions: {
    flow_id: string
    src_ip: string
    dst_ip: string
    label_predicted: string
    confidence: number
    severity: string
    epistemic_uncertainty: number
  }[]
  source: string  // 'Live Capture' | 'File Replay' | filename
  threatCount: number
  benignCount: number
  totalFlows: number
  timestamp: number
}

let _liveData: LiveCapturedData | null = null

export function setLiveData(data: LiveCapturedData): void {
  _liveData = { ...data }
}

export function getLiveData(): LiveCapturedData | null {
  return _liveData
}

export function hasLiveData(): boolean {
  return _liveData !== null && _liveData.predictions.length > 0
}

export function clearLiveData(): void {
  _liveData = null
}
