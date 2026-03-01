import { useCallback, useState } from 'react'
import { Upload, FileText } from 'lucide-react'

interface Props {
  onFileSelect: (file: File) => void
  loading?: boolean
}

export default function FileUpload({ onFileSelect, loading }: Props) {
  const [drag, setDrag] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)

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
          <FileText className="w-10 h-10 text-accent-green" />
          <span className="text-text-primary font-mono text-sm">{fileName}</span>
        </>
      ) : (
        <>
          <Upload className="w-10 h-10 text-text-secondary" />
          <span className="text-text-secondary text-sm">
            Drop a CSV file here or click to browse
          </span>
        </>
      )}
      <input type="file" accept=".csv" className="hidden" onChange={handleChange} />
    </label>
  )
}
