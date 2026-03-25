import { useCallback, useState, useEffect, useRef } from 'react'
import { Upload, FileText, FileArchive, CheckCircle2 } from 'lucide-react'

interface Props {
  /** Called when a file is selected (primary name) */
  onFileSelect?: (file: File) => void
  /** Alias for onFileSelect — pages can use either */
  onFile?: (file: File) => void
  loading?: boolean
  acceptPcap?: boolean
  /** Custom accept string (e.g. ".csv,.parquet"). Overrides acceptPcap. */
  accept?: string
  /** Optional label override */
  label?: string
  /** Persisted file name to show after navigation (from usePageState) */
  fileName?: string | null
  /** If true, show a loading/parsing progress bar after file select */
  fileLoading?: boolean
}

export default function FileUpload({
  onFileSelect,
  onFile,
  loading,
  acceptPcap = true,
  accept,
  label,
  fileName: persistedName,
  fileLoading,
}: Props) {
  const handler = onFileSelect || onFile
  const [drag, setDrag] = useState(false)
  const [localName, setLocalName] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)
  const progressRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // The displayed name: local selection takes priority, then persisted name
  const displayName = localName || persistedName || null
  const isPcap = displayName?.match(/\.(pcap|pcapng)$/i)

  const acceptStr = accept || (acceptPcap ? '.csv,.pcap,.pcapng' : '.csv')
  const labelText = label || `Drop a ${acceptPcap ? 'CSV or PCAP' : 'CSV'} file here or click to browse`

  // Animate progress bar when fileLoading changes
  useEffect(() => {
    if (fileLoading) {
      setProgress(0)
      let p = 0
      progressRef.current = setInterval(() => {
        p += Math.random() * 15 + 5
        if (p > 90) p = 90
        setProgress(p)
      }, 200)
    } else {
      if (progressRef.current) {
        clearInterval(progressRef.current)
        progressRef.current = null
      }
      if (progress > 0) {
        setProgress(100)
        const t = setTimeout(() => setProgress(0), 600)
        return () => clearTimeout(t)
      }
    }
    return () => {
      if (progressRef.current) clearInterval(progressRef.current)
    }
  }, [fileLoading]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDrag(false)
      const file = e.dataTransfer.files[0]
      if (file) {
        setLocalName(file.name)
        handler?.(file)
      }
    },
    [handler],
  )

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) {
        setLocalName(file.name)
        handler?.(file)
      }
    },
    [handler],
  )

  return (
    <div className="space-y-0">
      <label
        onDragOver={(e) => {
          e.preventDefault()
          setDrag(true)
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={handleDrop}
        className={`flex flex-col items-center justify-center gap-3 p-10 rounded-xl border-2 border-dashed cursor-pointer transition-colors ${
          drag
            ? 'border-accent-blue bg-accent-blue/10'
            : displayName
            ? 'border-accent-green/40 bg-accent-green/5'
            : 'border-bg-card hover:border-text-secondary'
        } ${loading ? 'opacity-50 pointer-events-none' : ''}`}
      >
        {displayName ? (
          <>
            {isPcap ? (
              <FileArchive className="w-10 h-10 text-accent-purple" />
            ) : (
              <FileText className="w-10 h-10 text-accent-green" />
            )}
            <span className="text-text-primary font-mono text-sm">{displayName}</span>
            {isPcap && (
              <span className="text-xs text-accent-purple">PCAP file — will be converted to flow features</span>
            )}
          </>
        ) : (
          <>
            <Upload className="w-10 h-10 text-text-secondary" />
            <span className="text-text-secondary text-sm">{labelText}</span>
            {!accept && acceptPcap && (
              <span className="text-xs text-text-secondary/60">
                Supports: .csv (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15) &middot; .pcap / .pcapng
              </span>
            )}
          </>
        )}
        <input type="file" accept={acceptStr} className="hidden" onChange={handleChange} />
      </label>

      {/* Dataset loading progress bar */}
      {(fileLoading || progress === 100) && (
        <div className="mt-2">
          <div className="flex items-center justify-between text-[10px] text-text-secondary mb-1">
            <span>{progress < 100 ? 'Loading dataset…' : 'Dataset ready'}</span>
            <span className="font-mono">
              {progress < 100 ? `${Math.round(progress)}%` : (
                <span className="text-accent-green flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Ready
                </span>
              )}
            </span>
          </div>
          <div className="w-full h-1.5 bg-bg-card rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                progress < 100 ? 'bg-accent-blue' : 'bg-accent-green'
              }`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}
    </div>
  )
}
