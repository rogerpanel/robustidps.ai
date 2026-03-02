import { useCallback, useState } from 'react'
import { Upload, FileText, FileArchive } from 'lucide-react'

interface Props {
  onFileSelect: (file: File) => void
  loading?: boolean
  acceptPcap?: boolean
}

export default function FileUpload({ onFileSelect, loading, acceptPcap = true }: Props) {
  const [drag, setDrag] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)

  const acceptStr = acceptPcap ? '.csv,.pcap,.pcapng' : '.csv'
  const isPcap = fileName?.match(/\.(pcap|pcapng)$/i)

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDrag(false)
      const file = e.dataTransfer.files[0]
      if (file) {
        setFileName(file.name)
        onFileSelect(file)
      }
    },
    [onFileSelect],
  )

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) {
        setFileName(file.name)
        onFileSelect(file)
      }
    },
    [onFileSelect],
  )

  return (
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
          : 'border-bg-card hover:border-text-secondary'
      } ${loading ? 'opacity-50 pointer-events-none' : ''}`}
    >
      {fileName ? (
        <>
          {isPcap ? (
            <FileArchive className="w-10 h-10 text-accent-purple" />
          ) : (
            <FileText className="w-10 h-10 text-accent-green" />
          )}
          <span className="text-text-primary font-mono text-sm">{fileName}</span>
          {isPcap && (
            <span className="text-xs text-accent-purple">PCAP file — will be converted to flow features</span>
          )}
        </>
      ) : (
        <>
          <Upload className="w-10 h-10 text-text-secondary" />
          <span className="text-text-secondary text-sm">
            Drop a {acceptPcap ? 'CSV or PCAP' : 'CSV'} file here or click to browse
          </span>
          {acceptPcap && (
            <span className="text-xs text-text-secondary/60">
              Supports: .csv (CIC-IoT-2023, CSE-CIC-IDS2018) &middot; .pcap / .pcapng
            </span>
          )}
        </>
      )}
      <input type="file" accept={acceptStr} className="hidden" onChange={handleChange} />
    </label>
  )
}
