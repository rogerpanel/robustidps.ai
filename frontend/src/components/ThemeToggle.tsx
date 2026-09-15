import { useEffect, useState } from 'react'
import { Moon, Printer } from 'lucide-react'

type Theme = 'dark' | 'print'

const STORAGE_KEY = 'robustidps.theme'

function readInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark'
  const stored = window.localStorage.getItem(STORAGE_KEY)
  return stored === 'print' ? 'print' : 'dark'
}

function applyTheme(t: Theme): void {
  const root = document.documentElement
  if (t === 'print') {
    root.setAttribute('data-theme', 'print')
  } else {
    root.removeAttribute('data-theme')
  }
}

// Apply the persisted theme as soon as this module is imported so the
// initial paint matches the user's last choice (no dark-flash before
// the React tree mounts).
if (typeof window !== 'undefined') {
  applyTheme(readInitialTheme())
}

interface ThemeToggleProps {
  /** Compact icon-only variant for tight headers. */
  compact?: boolean
}

export default function ThemeToggle({ compact = false }: ThemeToggleProps) {
  const [theme, setTheme] = useState<Theme>(readInitialTheme)

  useEffect(() => {
    applyTheme(theme)
    window.localStorage.setItem(STORAGE_KEY, theme)
  }, [theme])

  const setPrint = () => setTheme('print')
  const setDark = () => setTheme('dark')

  if (compact) {
    return (
      <button
        onClick={() => setTheme(theme === 'dark' ? 'print' : 'dark')}
        className="p-1.5 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50 focus-ring-blue"
        title={theme === 'dark' ? 'Switch to Print theme (for screenshots)' : 'Switch to Dark theme'}
        aria-label="Toggle theme"
      >
        {theme === 'dark'
          ? <Printer className="w-4 h-4" />
          : <Moon className="w-4 h-4" />}
      </button>
    )
  }

  return (
    <div
      role="group"
      aria-label="Display theme"
      className="inline-flex items-center rounded-full border border-bg-card/60 p-0.5 text-[10px] font-medium"
    >
      <button
        onClick={setDark}
        aria-pressed={theme === 'dark'}
        className={`flex items-center gap-1 px-2 py-1 rounded-full transition-colors focus-ring-blue ${
          theme === 'dark'
            ? 'bg-accent-blue/15 text-accent-blue'
            : 'text-text-secondary hover:text-text-primary'
        }`}
        title="Dark — analyst working theme"
      >
        <Moon className="w-3 h-3" />
        Dark
      </button>
      <button
        onClick={setPrint}
        aria-pressed={theme === 'print'}
        className={`flex items-center gap-1 px-2 py-1 rounded-full transition-colors focus-ring-orange ${
          theme === 'print'
            ? 'bg-accent-orange/15 text-accent-orange'
            : 'text-text-secondary hover:text-text-primary'
        }`}
        title="Print — high-contrast theme for screenshots & dissertation pages"
      >
        <Printer className="w-3 h-3" />
        Print
      </button>
    </div>
  )
}
