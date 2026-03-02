import { Routes, Route, NavLink } from 'react-router-dom'
import { useEffect, useState } from 'react'
import {
  LayoutDashboard,
  Upload,
  FlaskConical,
  Radio,
  Info,
  ShieldCheck,
  Wifi,
  WifiOff,
  Brain,
  Loader2,
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import UploadPage from './pages/Upload'
import AblationStudio from './pages/AblationStudio'
import LiveMonitor from './pages/LiveMonitor'
import Models from './pages/Models'
import About from './pages/About'
import { fetchHealth } from './utils/api'
import { useAnalysis } from './hooks/useAnalysis'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/upload', label: 'Upload & Analyse', icon: Upload },
  { to: '/models', label: 'Models', icon: Brain },
  { to: '/ablation', label: 'Ablation Studio', icon: FlaskConical },
  { to: '/live', label: 'Live Monitor', icon: Radio },
  { to: '/about', label: 'About', icon: Info },
]

export default function App() {
  const [online, setOnline] = useState<boolean | null>(null)
  const { loading: analysisRunning } = useAnalysis()

  useEffect(() => {
    fetchHealth()
      .then(() => setOnline(true))
      .catch(() => setOnline(false))
    const id = setInterval(() => {
      fetchHealth()
        .then(() => setOnline(true))
        .catch(() => setOnline(false))
    }, 15000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 bg-bg-secondary flex flex-col border-r border-bg-card">
        <div className="p-4 flex items-center gap-2">
          <ShieldCheck className="w-7 h-7 text-accent-blue" />
          <span className="font-display font-bold text-lg">RobustIDPS</span>
        </div>

        <nav className="flex-1 px-2 space-y-1">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-accent-blue/15 text-accent-blue'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
                }`
              }
            >
              <n.icon className="w-4 h-4" />
              {n.label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-bg-card space-y-2">
          {analysisRunning && (
            <div className="flex items-center gap-2 text-xs text-accent-blue">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Analysing...</span>
            </div>
          )}
          <div className="flex items-center gap-2 text-xs">
            {online === true ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-accent-green" />
                <span className="text-accent-green">Backend online</span>
              </>
            ) : online === false ? (
              <>
                <WifiOff className="w-3.5 h-3.5 text-accent-red" />
                <span className="text-accent-red">Backend offline</span>
              </>
            ) : (
              <>
                <Wifi className="w-3.5 h-3.5 text-text-secondary animate-pulse" />
                <span className="text-text-secondary">Connecting...</span>
              </>
            )}
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto p-6">
        {online === false && (
          <div className="mb-4 px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
            Backend offline — showing cached / sample data
          </div>
        )}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/models" element={<Models />} />
          <Route path="/ablation" element={<AblationStudio />} />
          <Route path="/live" element={<LiveMonitor />} />
          <Route path="/about" element={<About />} />
        </Routes>
      </main>
    </div>
  )
}
