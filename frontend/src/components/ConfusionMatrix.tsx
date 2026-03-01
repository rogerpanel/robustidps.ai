interface Props {
  matrix: number[][] | null
  labels?: string[]
}

export default function ConfusionMatrix({ matrix, labels }: Props) {
  if (!matrix || matrix.length === 0) {
    return (
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Confusion Matrix</h3>
        <p className="text-text-secondary text-sm">No ground-truth labels available</p>
      </div>
    )
  }

  const maxVal = Math.max(...matrix.flat())

  return (
    <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card overflow-x-auto">
      <h3 className="text-sm font-medium text-text-secondary mb-4">Confusion Matrix</h3>
      <div className="inline-block">
        <table className="border-collapse text-xs font-mono">
          <thead>
            <tr>
              <th className="p-1"></th>
              {(labels || matrix[0].map((_, i) => `C${i}`)).map((l, i) => (
                <th
                  key={i}
                  className="p-1 text-text-secondary truncate max-w-[60px]"
                  title={l}
                >
                  {l.length > 6 ? l.slice(0, 5) + '..' : l}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row, ri) => (
              <tr key={ri}>
                <td className="p-1 text-text-secondary truncate max-w-[60px]" title={labels?.[ri]}>
                  {labels?.[ri]
                    ? labels[ri].length > 6
                      ? labels[ri].slice(0, 5) + '..'
                      : labels[ri]
                    : `C${ri}`}
                </td>
                {row.map((v, ci) => {
                  const intensity = maxVal > 0 ? v / maxVal : 0
                  const bg =
                    ri === ci
                      ? `rgba(59, 130, 246, ${0.1 + intensity * 0.7})`
                      : v > 0
                        ? `rgba(239, 68, 68, ${0.1 + intensity * 0.5})`
                        : 'transparent'
                  return (
                    <td
                      key={ci}
                      className="p-1 text-center min-w-[32px]"
                      style={{ backgroundColor: bg }}
                    >
                      {v > 0 ? v : ''}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
