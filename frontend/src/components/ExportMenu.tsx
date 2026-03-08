/**
 * ExportMenu — reusable export dropdown for all reporting pages.
 *
 * Supports: PNG screenshot, PDF report, PDF landscape slides.
 * Uses html2canvas + jsPDF (already in package.json).
 */

import { useState, useRef, useEffect } from 'react'
import { Download, Image, FileText, Presentation, Loader2 } from 'lucide-react'
import html2canvas from 'html2canvas'
import jsPDF from 'jspdf'

interface ExportMenuProps {
  /** CSS selector or ref to the container element to capture */
  targetSelector?: string
  /** Filename prefix (without extension) */
  filename?: string
}

export default function ExportMenu({ targetSelector = '.space-y-6', filename = 'report' }: ExportMenuProps) {
  const [open, setOpen] = useState(false)
  const [exporting, setExporting] = useState<string | null>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const getTarget = (): HTMLElement | null => {
    return document.querySelector(targetSelector)
  }

  const captureCanvas = async (): Promise<HTMLCanvasElement | null> => {
    const el = getTarget()
    if (!el) return null
    return html2canvas(el, {
      backgroundColor: '#0F172A',
      scale: 2,
      useCORS: true,
      logging: false,
    })
  }

  const exportPng = async () => {
    setExporting('png')
    try {
      const canvas = await captureCanvas()
      if (!canvas) return
      const link = document.createElement('a')
      link.download = `${filename}.png`
      link.href = canvas.toDataURL('image/png')
      link.click()
    } finally {
      setExporting(null)
      setOpen(false)
    }
  }

  const exportPdf = async (landscape = false) => {
    setExporting(landscape ? 'slides' : 'pdf')
    try {
      const canvas = await captureCanvas()
      if (!canvas) return

      const imgData = canvas.toDataURL('image/png')
      const orientation = landscape ? 'l' : 'p'
      const pdf = new jsPDF(orientation, 'mm', 'a4')
      const pageW = pdf.internal.pageSize.getWidth()
      const pageH = pdf.internal.pageSize.getHeight()

      const margin = 10
      const usableW = pageW - margin * 2
      const imgAspect = canvas.width / canvas.height

      if (landscape) {
        // Slide mode: split into pages
        const slideH = pageH - margin * 2
        const slideW = usableW
        const pxPerPage = (slideH / slideW) * canvas.width
        const totalPages = Math.ceil(canvas.height / pxPerPage)

        for (let i = 0; i < totalPages; i++) {
          if (i > 0) pdf.addPage()
          const srcY = i * pxPerPage
          const srcH = Math.min(pxPerPage, canvas.height - srcY)

          // Create a slice canvas
          const slice = document.createElement('canvas')
          slice.width = canvas.width
          slice.height = srcH
          const ctx = slice.getContext('2d')!
          ctx.drawImage(canvas, 0, srcY, canvas.width, srcH, 0, 0, canvas.width, srcH)

          const sliceData = slice.toDataURL('image/png')
          const drawH = (srcH / canvas.width) * slideW
          pdf.addImage(sliceData, 'PNG', margin, margin, slideW, drawH)
        }
      } else {
        // Portrait mode: fit width, paginate
        const imgW = usableW
        const imgH = imgW / imgAspect
        const pxPerPage = ((pageH - margin * 2) / imgH) * canvas.height
        const totalPages = Math.ceil(canvas.height / pxPerPage)

        for (let i = 0; i < totalPages; i++) {
          if (i > 0) pdf.addPage()
          const srcY = i * pxPerPage
          const srcH = Math.min(pxPerPage, canvas.height - srcY)

          const slice = document.createElement('canvas')
          slice.width = canvas.width
          slice.height = srcH
          const ctx = slice.getContext('2d')!
          ctx.drawImage(canvas, 0, srcY, canvas.width, srcH, 0, 0, canvas.width, srcH)

          const sliceData = slice.toDataURL('image/png')
          const drawH = (srcH / canvas.width) * imgW
          pdf.addImage(sliceData, 'PNG', margin, margin, imgW, drawH)
        }
      }

      pdf.save(`${filename}${landscape ? '_slides' : ''}.pdf`)
    } finally {
      setExporting(null)
      setOpen(false)
    }
  }

  return (
    <div ref={menuRef} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-secondary border border-bg-card rounded-lg text-xs text-text-secondary hover:text-text-primary hover:border-accent-blue/40 transition-colors"
      >
        <Download className="w-3.5 h-3.5" />
        Export
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-48 bg-bg-secondary border border-bg-card rounded-lg shadow-xl z-50 overflow-hidden">
          <button
            onClick={exportPng}
            disabled={!!exporting}
            className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-bg-card/50 transition-colors disabled:opacity-40"
          >
            {exporting === 'png' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Image className="w-3.5 h-3.5 text-accent-blue" />}
            Export as PNG
          </button>
          <button
            onClick={() => exportPdf(false)}
            disabled={!!exporting}
            className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-bg-card/50 transition-colors disabled:opacity-40"
          >
            {exporting === 'pdf' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileText className="w-3.5 h-3.5 text-accent-green" />}
            Export as PDF
          </button>
          <button
            onClick={() => exportPdf(true)}
            disabled={!!exporting}
            className="w-full px-3 py-2 flex items-center gap-2 text-xs hover:bg-bg-card/50 transition-colors disabled:opacity-40"
          >
            {exporting === 'slides' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Presentation className="w-3.5 h-3.5 text-accent-purple" />}
            Export as PDF Slides
          </button>
        </div>
      )}
    </div>
  )
}
