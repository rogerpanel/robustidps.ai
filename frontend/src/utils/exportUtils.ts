/**
 * Export utilities for capturing charts as PNG / PDF / PDF Slides.
 * Uses html2canvas + jsPDF (added as dependencies).
 */

import html2canvas from 'html2canvas'
import jsPDF from 'jspdf'

/** Capture a DOM element as a PNG and trigger download. */
export async function exportAsPNG(
  element: HTMLElement,
  filename: string = 'robustidps_export.png',
) {
  const canvas = await html2canvas(element, {
    backgroundColor: '#0F172A', // bg-primary dark
    scale: 2, // retina quality
    useCORS: true,
    logging: false,
  })
  const url = canvas.toDataURL('image/png')
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
}

/** Capture a DOM element as a single-page PDF and trigger download. */
export async function exportAsPDF(
  element: HTMLElement,
  filename: string = 'robustidps_export.pdf',
) {
  const canvas = await html2canvas(element, {
    backgroundColor: '#0F172A',
    scale: 2,
    useCORS: true,
    logging: false,
  })

  const imgData = canvas.toDataURL('image/png')
  const imgW = canvas.width
  const imgH = canvas.height

  // A4 landscape (wider) or portrait depending on aspect ratio
  const isWide = imgW > imgH * 1.2
  const orientation = isWide ? 'landscape' : 'portrait'
  const pdf = new jsPDF({ orientation, unit: 'mm', format: 'a4' })

  const pageW = pdf.internal.pageSize.getWidth()
  const pageH = pdf.internal.pageSize.getHeight()
  const margin = 10

  const usableW = pageW - margin * 2
  const usableH = pageH - margin * 2
  const ratio = Math.min(usableW / imgW, usableH / imgH)
  const drawW = imgW * ratio
  const drawH = imgH * ratio
  const offsetX = (pageW - drawW) / 2
  const offsetY = (pageH - drawH) / 2

  pdf.addImage(imgData, 'PNG', offsetX, offsetY, drawW, drawH)
  pdf.save(filename)
}

/**
 * Capture multiple DOM elements as a multi-page PDF (slides presentation).
 * Each element becomes one slide (landscape A4 page).
 */
export async function exportAsSlides(
  elements: HTMLElement[],
  filename: string = 'robustidps_slides.pdf',
  title: string = 'RobustIDPS.AI — Analytics Report',
) {
  const pdf = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' })
  const pageW = pdf.internal.pageSize.getWidth()
  const pageH = pdf.internal.pageSize.getHeight()

  // Title slide
  pdf.setFillColor(15, 23, 42) // bg-primary
  pdf.rect(0, 0, pageW, pageH, 'F')
  pdf.setTextColor(248, 250, 252)
  pdf.setFontSize(28)
  pdf.text(title, pageW / 2, pageH / 2 - 10, { align: 'center' })
  pdf.setFontSize(12)
  pdf.setTextColor(148, 163, 184)
  pdf.text(`Generated ${new Date().toLocaleDateString()} — robustidps.ai`, pageW / 2, pageH / 2 + 8, { align: 'center' })

  for (let i = 0; i < elements.length; i++) {
    const el = elements[i]
    if (!el) continue

    pdf.addPage('a4', 'landscape')

    const canvas = await html2canvas(el, {
      backgroundColor: '#0F172A',
      scale: 2,
      useCORS: true,
      logging: false,
    })

    const imgData = canvas.toDataURL('image/png')
    const imgW = canvas.width
    const imgH = canvas.height

    const margin = 8
    const usableW = pageW - margin * 2
    const usableH = pageH - margin * 2
    const ratio = Math.min(usableW / imgW, usableH / imgH)
    const drawW = imgW * ratio
    const drawH = imgH * ratio
    const offsetX = (pageW - drawW) / 2
    const offsetY = (pageH - drawH) / 2

    pdf.addImage(imgData, 'PNG', offsetX, offsetY, drawW, drawH)

    // Page number
    pdf.setFontSize(8)
    pdf.setTextColor(100, 116, 139)
    pdf.text(`${i + 1} / ${elements.length}`, pageW - 12, pageH - 5, { align: 'right' })
  }

  pdf.save(filename)
}
