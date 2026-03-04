import { useCallback, useEffect, useRef, useState } from 'react'
import { Play, Pause, Upload } from 'lucide-react'
import FileUpload from '../components/FileUpload'
import PageGuide from '../components/PageGuide'
import { uploadFile, connectStream } from '../utils/api'

interface FlowEvent {
  flow_id: number
  src_ip: string
  dst_ip: string
  label_predicted: string
  confidence: number
  severity: string
}

const SEV_COLOR: Record<string, string> = {
  benign: 'text-accent-blue',
  low: 'text-accent-green',
  medium: 'text-accent-amber',
  high: 'text-accent-orange',
  critical: 'text-accent-red',
}

export default function LiveMonitor() {
  const [jobId, setJobId] = useState<string | null>(null)
  const [rate, setRate] = useState(100)
  const [events, setEvents] = useState<FlowEvent[]>([])
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(false)
  const [threatCount, setThreatCount] = useState(0)
  const [benignCount, setBenignCount] = useState(0)
  const wsRef = useRef<WebSocket | null>(null)

  const handleUpload = async (file: File) => {
    try {
      const res = await uploadFile(file)
      setJobId(res.job_id)
      setEvents([])
      setThreatCount(0)
      setBenignCount(0)
      setDone(false)
    } catch {
      // ignore
    }
  }

  const startStream = useCallback(() => {
    if (!jobId) return
    setRunning(true)
    setDone(false)
    const ws = connectStream(
      jobId,
      rate,
      (data) => {
        const ev = data as unknown as FlowEvent
        setEvents((prev) => [ev, ...prev].slice(0, 500))
        if (ev.severity === 'benign') {
          setBenignCount((c) => c + 1)
        } else {
          setThreatCount((c) => c + 1)
        }
      },
      () => {
        setRunning(false)
        setDone(true)
      },
    )
    wsRef.current = ws
  }, [jobId, rate])

  const stopStream = useCallback(() => {
    wsRef.current?.close()
    setRunning(false)
  }, [])

  useEffect(() => {
    return () => {
      wsRef.current?.close()
    }
  }, [])

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-display font-bold">Live Monitor</h1>

      <PageGuide
        title="How to use Live Monitor"
        steps={[
          { title: 'Upload a dataset', desc: 'Drop a CSV file (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15) or PCAP capture. The file is uploaded and features are extracted server-side.' },
          { title: 'Press Start', desc: 'Flows stream via WebSocket in real time. Each row is classified by the IDS model as it arrives.' },
          { title: 'Adjust speed', desc: 'Use the speed slider (10-1000 flows/sec) to control playback rate. Slower speeds let you observe individual detections.' },
          { title: 'Monitor threats', desc: 'Watch the threat/benign counters update live. Severity is color-coded: red = critical, orange = high, amber = medium, green = low, blue = benign.' },
        ]}
        tip="Tip: For PCAP files, flows are automatically extracted using NFStream before streaming. Use a small CSV (<5K rows) for smooth real-time visualization."
      />

      {!jobId ? (
        <div className="max-w-lg">
          <p className="text-sm text-text-secondary mb-4">
            Upload a CSV or PCAP file to start. Flows will be streamed and classified in real time.
          </p>
          <FileUpload onFileSelect={handleUpload} />
        </div>
      ) : (
        <>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3">
              {!running ? (
                <button
                  onClick={startStream}
                  disabled={done}
                  className="flex items-center gap-2 px-4 py-2 bg-accent-green text-white rounded-lg text-sm font-medium hover:bg-accent-green/80 disabled:opacity-50"
                >
                  <Play className="w-4 h-4" /> Start
                </button>
              ) : (
                <button
                  onClick={stopStream}
                  className="flex items-center gap-2 px-4 py-2 bg-accent-red text-white rounded-lg text-sm font-medium hover:bg-accent-red/80"
                >
                  <Pause className="w-4 h-4" /> Stop
                </button>
              )}
              <button
                onClick={() => {
                  stopStream()
                  setJobId(null)
                  setEvents([])
                }}
                className="flex items-center gap-2 px-4 py-2 border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary"
              >
                <Upload className="w-4 h-4" /> New File
              </button>
            </div>

            <div className="flex items-center gap-2">
              <label className="text-xs text-text-secondary">Speed: {rate} flows/sec</label>
              <input
                type="range"
                min={10}
                max={1000}
                step={10}
                value={rate}
                onChange={(e) => setRate(+e.target.value)}
                className="w-32 accent-accent-blue"
                disabled={running}
              />
            </div>

            <div className="flex gap-6 ml-auto text-sm">
              <span className="text-accent-red font-mono">
                Threats: {threatCount}
              </span>
              <span className="text-accent-blue font-mono">
                Benign: {benignCount}
              </span>
              <span className="text-text-secondary font-mono">
                Total: {threatCount + benignCount}
              </span>
            </div>
          </div>

          {done && (
            <div className="px-4 py-2 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-sm">
              Stream complete — all flows processed.
            </div>
          )}

          <div className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
            <div className="max-h-[600px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-bg-secondary z-10">
                  <tr className="text-text-secondary text-xs">
                    <th className="px-3 py-2 text-left">#</th>
                    <th className="px-3 py-2 text-left">Src IP</th>
                    <th className="px-3 py-2 text-left">Dst IP</th>
                    <th className="px-3 py-2 text-left">Label</th>
                    <th className="px-3 py-2 text-left">Confidence</th>
                    <th className="px-3 py-2 text-left">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev, i) => (
                    <tr
                      key={`${ev.flow_id}-${i}`}
                      className={`border-t border-bg-card/50 ${i === 0 ? 'animate-pulse' : ''}`}
                    >
                      <td className="px-3 py-1.5 font-mono text-text-secondary text-xs">
                        {ev.flow_id}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs">{ev.src_ip}</td>
                      <td className="px-3 py-1.5 font-mono text-xs">{ev.dst_ip}</td>
                      <td className="px-3 py-1.5 text-xs">{ev.label_predicted}</td>
                      <td className="px-3 py-1.5 font-mono text-xs">
                        {(ev.confidence * 100).toFixed(1)}%
                      </td>
                      <td className="px-3 py-1.5">
                        <span className={`text-xs font-medium ${SEV_COLOR[ev.severity] || ''}`}>
                          {ev.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {events.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-3 py-8 text-center text-text-secondary text-sm">
                        Press Start to begin streaming
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
