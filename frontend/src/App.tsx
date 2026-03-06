import { Routes, Route, NavLink, useLocation } from 'react-router-dom'
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
  BarChart3,
  Database,
  Menu,
  X,
  LogOut,
  Sparkles,
  User,
  RefreshCw,
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import UploadPage from './pages/Upload'
import Analytics from './pages/Analytics'
import Datasets from './pages/Datasets'
import AblationStudio from './pages/AblationStudio'
import LiveMonitor from './pages/LiveMonitor'
import Models from './pages/Models'
import About from './pages/About'
import Copilot from './pages/Copilot'
import ContinualLearning from './pages/ContinualLearning'
import AdminDashboard from './pages/AdminDashboard'
import Login from './pages/Login'
import { fetchHealth } from './utils/api'
import { useAnalysis } from './hooks/useAnalysis'
import { isAuthenticated, getUser, clearAuth, type AuthUser } from './utils/auth'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/upload', label: 'Upload & Analyse', icon: Upload },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/datasets', label: 'Datasets', icon: Database },
  { to: '/models', label: 'Models', icon: Brain },
  { to: '/ablation', label: 'Ablation Studio', icon: FlaskConical },
  { to: '/live', label: 'Live Monitor', icon: Radio },
  { to: '/continual', label: 'Continual Learning', icon: RefreshCw },
  { to: '/copilot', label: 'SOC Copilot', icon: Sparkles },
  { to: '/admin', label: 'Admin', icon: ShieldCheck, adminOnly: true },
  { to: '/about', label: 'About', icon: Info },
]

export default function App() {
  const [online, setOnline] = useState<boolean | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [authed, setAuthed] = useState(isAuthenticated())
  const [user, setUser] = useState<AuthUser | null>(getUser())
  const { loading: analysisRunning } = useAnalysis()
  const location = useLocation()

  const handleLogin = () => {
    setAuthed(true)
    setUser(getUser())
  }

  const handleLogout = () => {
    clearAuth()
    setAuthed(false)
    setUser(null)
  }

  // Close mobile sidebar on navigation
  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])

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

  // Show login page if not authenticated
  if (!authed) {
    return <Login onLogin={handleLogin} />
  }

  const sidebarContent = (
    <>
      <div className="p-4 flex items-center gap-2">
        <ShieldCheck className="w-7 h-7 text-accent-blue" />
        <span className="font-display font-bold text-lg">RobustIDPS<span className="text-accent-blue">.AI</span></span>
      </div>

      <nav className="flex-1 px-2 space-y-1 overflow-y-auto">
        {NAV.filter(n => !('adminOnly' in n && n.adminOnly) || user?.role === 'admin').map((n) => (
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
        {/* User info */}
        {user && (
          <div className="flex items-center gap-2 text-xs text-text-secondary mb-2">
            <User className="w-3.5 h-3.5" />
            <span className="truncate flex-1">{user.email}</span>
            <span className="px-1.5 py-0.5 bg-accent-blue/15 text-accent-blue rounded text-[10px] font-medium uppercase">
              {user.role}
            </span>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 text-xs text-text-secondary hover:text-accent-red transition-colors w-full"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign Out
        </button>

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
    </>
  )

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Desktop sidebar */}
      <aside className="hidden lg:flex w-56 shrink-0 bg-bg-secondary flex-col border-r border-bg-card">
        {sidebarContent}
      </aside>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Mobile sidebar drawer */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-bg-secondary flex flex-col border-r border-bg-card transform transition-transform duration-200 ease-in-out lg:hidden ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="absolute top-3 right-3">
          <button
            onClick={() => setSidebarOpen(false)}
            className="p-1 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        {sidebarContent}
      </aside>

      {/* Main content area */}
      <main className="flex-1 overflow-y-auto">
        {/* Mobile top bar */}
        <div className="sticky top-0 z-30 lg:hidden flex items-center gap-3 px-4 py-3 bg-bg-secondary/95 backdrop-blur border-b border-bg-card">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-1.5 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50"
          >
            <Menu className="w-5 h-5" />
          </button>
          <ShieldCheck className="w-5 h-5 text-accent-blue" />
          <span className="font-display font-bold text-sm">RobustIDPS<span className="text-accent-blue">.AI</span></span>
          <div className="ml-auto flex items-center gap-2">
            {analysisRunning && <Loader2 className="w-3.5 h-3.5 animate-spin text-accent-blue" />}
            {online === true ? (
              <Wifi className="w-3.5 h-3.5 text-accent-green" />
            ) : online === false ? (
              <WifiOff className="w-3.5 h-3.5 text-accent-red" />
            ) : (
              <Wifi className="w-3.5 h-3.5 text-text-secondary animate-pulse" />
            )}
          </div>
        </div>

        <div className="p-3 md:p-6 3xl:px-10 3xl:py-8 max-w-[2200px] 3xl:mx-auto">
          {online === false && (
            <div className="mb-4 px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              Backend offline — showing cached / sample data
            </div>
          )}
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/datasets" element={<Datasets />} />
            <Route path="/models" element={<Models />} />
            <Route path="/ablation" element={<AblationStudio />} />
            <Route path="/live" element={<LiveMonitor />} />
            <Route path="/continual" element={<ContinualLearning />} />
            <Route path="/copilot" element={<Copilot />} />
            <Route path="/admin" element={<AdminDashboard />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
