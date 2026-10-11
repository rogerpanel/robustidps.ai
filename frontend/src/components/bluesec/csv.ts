// Minimal CSV export for result tables (RFC 4180 quoting).
// Cells starting with = + - @ are prefixed with ' so spreadsheet apps do not
// evaluate them as formulas (task ids and labels come from uploaded files).

export type Cell = string | number | null | undefined

function quote(v: Cell): string {
  if (v === null || v === undefined) return ''
  let s = typeof v === 'number' ? String(v) : v
  if (typeof v === 'string' && /^[=+\-@]/.test(s)) s = `'${s}`
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

export function toCsv(rows: Cell[][]): string {
  return rows.map(r => r.map(quote).join(',')).join('\r\n') + '\r\n'
}

export function downloadCsv(filename: string, rows: Cell[][]): void {
  const blob = new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename.endsWith('.csv') ? filename : `${filename}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
