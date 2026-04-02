import { Routes, Route, NavLink, useLocation } from 'react-router-dom'
import { useEffect, useState, useCallback, useMemo, lazy, Suspense } from 'react'
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
  Swords,
  Eye,
  Network,
  KeySquare,
  Fingerprint,
  Crosshair,
  Package,
  Scale,
  BookOpen,
  Target,
  Filter,
  ChevronRight,
  ChevronDown,
  Diamond,
  Building2,
  GraduationCap,
  ClipboardCheck,
  Trophy,
  Syringe,
  BookOpenCheck,
  DatabaseBackup,
  GitMerge,
  TrendingUp,
  GitBranch,
  Layers,
  FileText,
  Globe,
  Zap,
  Search,
  Shield,
  AlertTriangle,
} from 'lucide-react'
import NoticeBoard from './components/NoticeBoard'
// ── Lazy-loaded page components (route-based code splitting) ─────────────
const LandingPage = lazy(() => import('./pages/LandingPage'))
const EthicalUseAgreement = lazy(() => import('./components/EthicalUseAgreement'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const UploadPage = lazy(() => import('./pages/Upload'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Datasets = lazy(() => import('./pages/Datasets'))
const AblationStudio = lazy(() => import('./pages/AblationStudio'))
const LiveMonitor = lazy(() => import('./pages/LiveMonitor'))
const Models = lazy(() => import('./pages/Models'))
const About = lazy(() => import('./pages/About'))
const Copilot = lazy(() => import('./pages/Copilot'))
const ContinualLearning = lazy(() => import('./pages/ContinualLearning'))
const RedTeamArena = lazy(() => import('./pages/RedTeamArena'))
const ExplainabilityStudio = lazy(() => import('./pages/ExplainabilityStudio'))
const FederatedSimulator = lazy(() => import('./pages/FederatedSimulator'))
const PQCryptography = lazy(() => import('./pages/PQCryptography'))
const ZeroTrustGovernance = lazy(() => import('./pages/ZeroTrustGovernance'))
const ThreatResponse = lazy(() => import('./pages/ThreatResponse'))
const ModelSupplyChain = lazy(() => import('./pages/ModelSupplyChain'))
const ResearchHub = lazy(() => import('./pages/ResearchHub'))
const RLResponseAgent = lazy(() => import('./pages/RLResponseAgent'))
const AdversarialRobustness = lazy(() => import('./pages/AdversarialRobustness'))
const LabPartnerships = lazy(() => import('./pages/LabPartnerships'))
const PostdocPortal = lazy(() => import('./pages/PostdocPortal'))
const InterviewPrep = lazy(() => import('./pages/InterviewPrep'))
const Benchmarks = lazy(() => import('./pages/Benchmarks'))
const AdminDashboard = lazy(() => import('./pages/AdminDashboard'))
const ApiDocs = lazy(() => import('./pages/ApiDocs'))
const Architecture = lazy(() => import('./pages/Architecture'))
const Login = lazy(() => import('./pages/Login'))
const PromptInjectionPlayground = lazy(() => import('./pages/PromptInjectionPlayground'))
const JailbreakTaxonomy = lazy(() => import('./pages/JailbreakTaxonomy'))
const RAGPoisoning = lazy(() => import('./pages/RAGPoisoning'))
const MultiAgentChain = lazy(() => import('./pages/MultiAgentChain'))
const MitreAttackMapper = lazy(() => import('./pages/MitreAttackMapper'))
const AlertTriage = lazy(() => import('./pages/AlertTriage'))
const ComplianceHub = lazy(() => import('./pages/ComplianceHub'))
const AttackChainPredictor = lazy(() => import('./pages/AttackChainPredictor'))
const DataPoisoningSim = lazy(() => import('./pages/DataPoisoningSim'))
const AlertCausalityGraph = lazy(() => import('./pages/AlertCausalityGraph'))
const AutoencoderDetector = lazy(() => import('./pages/AutoencoderDetector'))
const IncidentReports = lazy(() => import('./pages/IncidentReports'))
const ThreatIntel = lazy(() => import('./pages/ThreatIntel'))
const AutoInvestigation = lazy(() => import('./pages/AutoInvestigation'))
const ThreatHunt = lazy(() => import('./pages/ThreatHunt'))
const RuleGenerator = lazy(() => import('./pages/RuleGenerator'))
const CVEMapper = lazy(() => import('./pages/CVEMapper'))
import { fetchHealth } from './utils/api'
import { trackPageView } from './utils/analytics'
import { useAnalysis } from './hooks/useAnalysis'
import { isAuthenticated, getUser, clearAuth, type AuthUser } from './utils/auth'
import { resetAllSessions } from './utils/sessionReset'
import {
  startSession,
  stopSession,
  serverLogout,
  broadcastLogout,
  clearSessionId,
} from './utils/sessionManager'

type NavItem = { to: string; label: string; icon: typeof LayoutDashboard; adminOnly?: boolean }
type NavGroup = { heading: string; items: NavItem[] }

const NAV_GROUPS: NavGroup[] = [
  {
    heading: 'AI Command Center',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/upload', label: 'Upload & Analyse', icon: Upload },
      { to: '/analytics', label: 'Analytics', icon: BarChart3 },
      { to: '/live', label: 'Live Monitor', icon: Radio },
      { to: '/causality-graph', label: 'Alert Causality', icon: GitBranch },
    ],
  },
  {
    heading: 'AI Data & Models',
    items: [
      { to: '/datasets', label: 'Datasets', icon: Database },
      { to: '/models', label: 'Models', icon: Brain },
      { to: '/ablation', label: 'Ablation Studio', icon: FlaskConical },
    ],
  },
  {
    heading: 'AI Novel Methods',
    items: [
      { to: '/continual', label: 'Continual Learning', icon: RefreshCw },
      { to: '/rl-agent', label: 'RL Response Agent', icon: Crosshair },
      { to: '/adversarial', label: 'Adversarial Eval', icon: Fingerprint },
      { to: '/xai', label: 'Explainability', icon: Eye },
      { to: '/autoencoder', label: 'Autoencoder Detector', icon: Layers },
    ],
  },
  {
    heading: 'AI Active Defence',
    items: [
      { to: '/redteam', label: 'Red Team Arena', icon: Swords },
      { to: '/threat-response', label: 'Threat Response', icon: Crosshair },
      { to: '/copilot', label: 'SOC Copilot', icon: Sparkles },
      { to: '/federated', label: 'Federated Learning', icon: Network },
      { to: '/attack-chain', label: 'Attack Chain Predictor', icon: TrendingUp },
    ],
  },
  {
    heading: 'SOC Intelligence',
    items: [
      { to: '/auto-investigate', label: 'Auto-Investigation', icon: Zap },
      { to: '/threat-hunt', label: 'Threat Hunt', icon: Search },
      { to: '/incident-reports', label: 'Incident Reports', icon: FileText },
      { to: '/threat-intel', label: 'Threat Intel', icon: Globe },
      { to: '/rule-generator', label: 'Rule Generator', icon: Shield },
      { to: '/cve-mapper', label: 'CVE Mapper', icon: AlertTriangle },
    ],
  },
  {
    heading: 'LLM Attack Surfaces',
    items: [
      { to: '/prompt-injection', label: 'Prompt Injection', icon: Syringe },
      { to: '/jailbreak-taxonomy', label: 'Jailbreak Taxonomy', icon: BookOpenCheck },
      { to: '/rag-poisoning', label: 'RAG Poisoning', icon: DatabaseBackup },
      { to: '/multi-agent', label: 'Multi-Agent Chain', icon: GitMerge },
      { to: '/data-poisoning', label: 'Data Poisoning Sim', icon: FlaskConical },
    ],
  },
  {
    heading: 'MLSecOps Standards',
    items: [
      { to: '/mitre-attack', label: 'MITRE ATT&CK', icon: Target },
      { to: '/alert-triage', label: 'Alert Triage', icon: Filter },
      { to: '/compliance', label: 'Compliance Hub', icon: ClipboardCheck },
    ],
  },
  {
    heading: 'AI Security & Gov',
    items: [
      { to: '/pq-crypto', label: 'PQ Cryptography', icon: KeySquare },
      { to: '/zero-trust', label: 'Zero-Trust Gov', icon: Fingerprint },
      { to: '/supply-chain', label: 'Supply Chain', icon: Package },
      { to: '/research', label: 'Research Hub', icon: BookOpen },
    ],
  },
  {
    heading: 'Industry & Research',
    items: [
      { to: '/lab-partnerships', label: 'Lab Partnerships', icon: Building2 },
      { to: '/postdoc-portal', label: 'Postdoc Portal', icon: GraduationCap },
      { to: '/interview-prep', label: 'Interview Prep', icon: ClipboardCheck },
      { to: '/benchmarks', label: 'Benchmarks', icon: Trophy },
    ],
  },
  {
    heading: 'System',
    items: [
      { to: '/admin', label: 'Admin', icon: ShieldCheck, adminOnly: true },
      { to: '/architecture', label: 'Architecture', icon: Database },
      { to: '/api-docs', label: 'API Docs', icon: BookOpen },
      { to: '/about', label: 'About', icon: Info },
    ],
  },
]

// Identify which groups are "operations" (left sidebar) vs "research" (right sidebar on mobile)
const LEFT_GROUPS = ['AI Command Center', 'AI Data & Models', 'AI Active Defence', 'SOC Intelligence', 'System']
const RIGHT_GROUPS = ['AI Novel Methods', 'LLM Attack Surfaces', 'MLSecOps Standards', 'AI Security & Gov', 'Industry & Research']

export default function App() {
  const [online, setOnline] = useState<boolean | null>(null)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [rightSidebarOpen, setRightSidebarOpen] = useState(false)
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set())
  const [authed, setAuthed] = useState(isAuthenticated())
  const [user, setUser] = useState<AuthUser | null>(getUser())
  const [ethicalAccepted, setEthicalAccepted] = useState(false)
  const [showPolicyViewer, setShowPolicyViewer] = useState(false)
  const [demoMode, setDemoMode] = useState(false)
  const [showLogin, setShowLogin] = useState(false)
  const { loading: analysisRunning, clearResults } = useAnalysis()
  const location = useLocation()

  // Toggle group collapse
  const toggleGroup = useCallback((heading: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev)
      if (next.has(heading)) next.delete(heading)
      else next.add(heading)
      return next
    })
  }, [])

  // Find current breadcrumb: Group > Page
  const breadcrumb = useMemo(() => {
    for (const group of NAV_GROUPS) {
      const item = group.items.find((n) =>
        n.to === '/' ? location.pathname === '/' : location.pathname.startsWith(n.to),
      )
      if (item) return { group: group.heading, page: item.label }
    }
    return null
  }, [location.pathname])

  // Auto-expand group containing the active page
  useEffect(() => {
    if (breadcrumb) {
      setCollapsedGroups((prev) => {
        if (prev.has(breadcrumb.group)) {
          const next = new Set(prev)
          next.delete(breadcrumb.group)
          return next
        }
        return prev
      })
    }
  }, [breadcrumb])

  // Keyboard shortcuts: [ opens left sidebar, ] opens right sidebar
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger when typing in inputs
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if ((e.target as HTMLElement)?.isContentEditable) return

      if (e.key === '[') {
        setSidebarOpen((prev) => !prev)
      } else if (e.key === ']') {
        setRightSidebarOpen((prev) => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  const handleLogin = useCallback(() => {
    setAuthed(true)
    setUser(getUser())
    setEthicalAccepted(false) // require acceptance on every login
  }, [])

  const handleEnterDemo = () => {
    setDemoMode(true)
    setEthicalAccepted(true) // skip ethical agreement in demo mode
  }

  const handleLogout = useCallback(() => {
    // Invalidate server-side session + notify other tabs
    serverLogout(false)
    broadcastLogout()
    stopSession()

    resetAllSessions()   // wipe all module-level stores + user-scoped localStorage
    clearResults()        // flush AnalysisProvider context
    clearAuth()           // remove token + user from localStorage
    clearSessionId()      // remove session_id from localStorage
    setAuthed(false)
    setUser(null)
    setDemoMode(false)
    setShowLogin(false)
    setEthicalAccepted(false)
  }, [clearResults])

  // ── Session lifecycle: heartbeat, cross-tab sync, auto-logout ─────────
  useEffect(() => {
    if (!authed) return
    startSession(() => {
      // Called when session expires or another tab logs out
      resetAllSessions()
      clearResults()
      clearAuth()
      clearSessionId()
      setAuthed(false)
      setUser(null)
      setDemoMode(false)
      setShowLogin(false)
      setEthicalAccepted(false)
    })
    return () => stopSession()
  }, [authed])

  // Close mobile sidebars on navigation
  useEffect(() => {
    setSidebarOpen(false)
    setRightSidebarOpen(false)
  }, [location.pathname])

  // Track page views on route changes
  useEffect(() => {
    trackPageView(location.pathname)
  }, [location.pathname])

  useEffect(() => {
    let cancelled = false
    const check = () => {
      fetchHealth()
        .then(() => { if (!cancelled) setOnline(true) })
        .catch(() => { if (!cancelled) setOnline(false) })
    }
    // Defer first health check so it doesn't compete with initial page resources
    const startDelay = setTimeout(check, 2000)
    const id = setInterval(check, 15000)
    return () => { cancelled = true; clearTimeout(startDelay); clearInterval(id) }
  }, [])

  // Show public landing page if not authenticated and not in demo mode
  if (!authed && !demoMode) {
    // If user clicked "Sign In" from landing, show login form
    if (showLogin) {
      return (
        <Suspense fallback={
          <div className="flex items-center justify-center h-screen bg-bg-primary">
            <Loader2 className="w-6 h-6 animate-spin text-accent-blue" />
          </div>
        }>
          <Login onLogin={handleLogin} />
        </Suspense>
      )
    }

    // Otherwise show the public landing page
    return (
      <Suspense fallback={
        <div className="flex items-center justify-center h-screen bg-bg-primary">
          <Loader2 className="w-6 h-6 animate-spin text-accent-blue" />
        </div>
      }>
        <LandingPage
          onEnterDemo={handleEnterDemo}
          onSignIn={() => setShowLogin(true)}
        />
      </Suspense>
    )
  }

  // Show ethical use agreement overlay before granting access (skip in demo mode)
  if (!ethicalAccepted) {
    return (
      <Suspense fallback={
        <div className="flex items-center justify-center h-screen bg-bg-primary">
          <Loader2 className="w-6 h-6 animate-spin text-accent-blue" />
        </div>
      }>
        <EthicalUseAgreement onAccept={() => setEthicalAccepted(true)} />
      </Suspense>
    )
  }

  // Render nav groups with collapsible headers
  const renderNavGroups = (groups: NavGroup[]) => (
    <>
      {groups.map((group) => {
        const visibleItems = group.items.filter(
          (n) => !n.adminOnly || user?.role === 'admin',
        )
        if (visibleItems.length === 0) return null
        const isCollapsed = collapsedGroups.has(group.heading)
        const isActiveGroup = breadcrumb?.group === group.heading
        return (
          <div key={group.heading} className="mb-1">
            <button
              onClick={() => toggleGroup(group.heading)}
              className={`w-full flex items-center gap-1.5 px-3 pt-4 pb-1.5 text-[10px] font-semibold uppercase tracking-wider transition-colors ${
                isActiveGroup
                  ? group.heading === 'LLM Attack Surfaces' ? 'text-accent-orange/70' : 'text-accent-blue/70'
                  : 'text-text-secondary/50 hover:text-text-secondary/80'
              }`}
            >
              {isCollapsed ? (
                <ChevronRight className="w-3 h-3 shrink-0" />
              ) : (
                <ChevronDown className="w-3 h-3 shrink-0" />
              )}
              {group.heading}
            </button>
            {!isCollapsed && (
              <div className="space-y-0.5">
                {visibleItems.map((n) => (
                  <NavLink
                    key={n.to}
                    to={n.to}
                    end={n.to === '/'}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        isActive
                          ? group.heading === 'LLM Attack Surfaces'
                            ? 'bg-accent-orange/15 text-accent-orange'
                            : 'bg-accent-blue/15 text-accent-blue'
                          : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
                      }`
                    }
                  >
                    <n.icon className="w-4 h-4" />
                    {n.label}
                  </NavLink>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </>
  )

  const sidebarFooter = (
    <div className="p-4 border-t border-accent-blue/10 space-y-2">
      {demoMode && !authed && (
        <div className="flex items-center gap-2 text-xs mb-2">
          <span className="px-2 py-0.5 bg-accent-amber/15 text-accent-amber rounded text-[10px] font-medium uppercase">
            Demo Mode
          </span>
          <span className="text-text-secondary text-[10px]">Read-only</span>
        </div>
      )}
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
        {demoMode && !authed ? 'Exit Demo' : 'Sign Out'}
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
  )

  const sidebarContent = (
    <>
      <div className="p-4 flex items-center gap-2">
        <ShieldCheck className="w-7 h-7 text-accent-blue" />
        <span className="font-display font-bold text-lg">RobustIDPS<span className="text-accent-blue">.AI</span></span>
      </div>
      <nav className="flex-1 px-2 overflow-y-auto">
        {renderNavGroups(NAV_GROUPS)}
      </nav>
      {sidebarFooter}
    </>
  )

  // Mobile-only: split nav into left (operations) and right (research) panels
  const leftNavGroups = NAV_GROUPS.filter((g) => LEFT_GROUPS.includes(g.heading))
  const rightNavGroups = NAV_GROUPS.filter((g) => RIGHT_GROUPS.includes(g.heading))

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Policy viewer overlay — accessible from the persistent footer link */}
      {showPolicyViewer && (
        <Suspense fallback={null}>
          <EthicalUseAgreement onAccept={() => setShowPolicyViewer(false)} />
        </Suspense>
      )}

      {/* Desktop LEFT sidebar — Operations */}
      <aside className="hidden lg:flex w-52 shrink-0 bg-bg-secondary flex-col border-r border-bg-card">
        <div className="p-4 flex items-center gap-2">
          <ShieldCheck className="w-7 h-7 text-accent-blue" />
          <span className="font-display font-bold text-lg">RobustIDPS<span className="text-accent-blue">.AI</span></span>
        </div>
        <nav className="flex-1 px-2 overflow-y-auto">
          {renderNavGroups(leftNavGroups)}
        </nav>
        {sidebarFooter}
      </aside>

      {/* Overlays for mobile drawers */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      {rightSidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setRightSidebarOpen(false)}
        />
      )}

      {/* Mobile LEFT sidebar drawer — Operations */}
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
        <div className="p-4 flex items-center gap-2">
          <ShieldCheck className="w-7 h-7 text-accent-blue" />
          <span className="font-display font-bold text-lg">RobustIDPS<span className="text-accent-blue">.AI</span></span>
        </div>
        <div className="px-3 pb-1 text-[9px] font-bold uppercase tracking-widest text-accent-blue/50">Operations</div>
        <nav className="flex-1 px-2 overflow-y-auto">
          {renderNavGroups(leftNavGroups)}
        </nav>
        {sidebarFooter}
      </aside>

      {/* Mobile RIGHT sidebar drawer — Research */}
      <aside
        className={`fixed inset-y-0 right-0 z-50 w-64 bg-bg-secondary flex flex-col border-l border-bg-card transform transition-transform duration-200 ease-in-out lg:hidden ${
          rightSidebarOpen ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        <div className="absolute top-3 left-3">
          <button
            onClick={() => setRightSidebarOpen(false)}
            className="p-1 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 flex items-center gap-2 justify-end">
          <ShieldCheck className="w-7 h-7 text-accent-blue" />
          <span className="font-display font-bold text-lg">RobustIDPS<span className="text-accent-blue">.AI</span></span>
        </div>
        <nav className="flex-1 px-2 overflow-y-auto">
          {renderNavGroups(rightNavGroups)}
        </nav>
        <NoticeBoard />
      </aside>

      {/* Main content area */}
      <main className="flex-1 overflow-y-auto">
        {/* Mobile top bar — dual hamburger buttons */}
        <div className="sticky top-0 z-30 lg:hidden flex items-center gap-3 px-4 py-3 bg-bg-secondary/95 backdrop-blur border-b border-bg-card">
          {/* Left hamburger — Operations */}
          <button
            onClick={() => { setSidebarOpen(true); setRightSidebarOpen(false) }}
            className="p-1.5 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50"
            title="Operations (shortcut: [)"
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
            {/* Right hamburger — Research */}
            <button
              onClick={() => { setRightSidebarOpen(true); setSidebarOpen(false) }}
              className="p-1.5 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-card/50"
              title="Research & Methods (shortcut: ])"
            >
              <Diamond className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-3 md:p-6 3xl:px-10 3xl:py-8 max-w-[2200px] 3xl:mx-auto">
          {/* Breadcrumb bar */}
          {breadcrumb && (
            <div className="mb-3 flex items-center gap-2 text-xs text-text-secondary/60">
              <span className={`font-semibold uppercase tracking-wider ${breadcrumb.group === 'LLM Attack Surfaces' ? 'text-accent-orange/50' : ''}`}>{breadcrumb.group}</span>
              <ChevronRight className="w-3 h-3" />
              <span className="text-text-primary font-medium">{breadcrumb.page}</span>
            </div>
          )}

          {online === false && (
            <div className="mb-4 px-4 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              Backend offline — showing cached / sample data
            </div>
          )}
          <Suspense fallback={
            <div className="flex items-center justify-center py-24">
              <Loader2 className="w-6 h-6 animate-spin text-accent-blue" />
              <span className="ml-2 text-text-secondary text-sm">Loading...</span>
            </div>
          }>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/upload" element={<UploadPage />} />
              <Route path="/analytics" element={<Analytics />} />
              <Route path="/datasets" element={<Datasets />} />
              <Route path="/models" element={<Models />} />
              <Route path="/ablation" element={<AblationStudio />} />
              <Route path="/live" element={<LiveMonitor />} />
              <Route path="/continual" element={<ContinualLearning />} />
              <Route path="/rl-agent" element={<RLResponseAgent />} />
              <Route path="/adversarial" element={<AdversarialRobustness />} />
              <Route path="/redteam" element={<RedTeamArena />} />
              <Route path="/xai" element={<ExplainabilityStudio />} />
              <Route path="/federated" element={<FederatedSimulator />} />
              <Route path="/pq-crypto" element={<PQCryptography />} />
              <Route path="/zero-trust" element={<ZeroTrustGovernance />} />
              <Route path="/threat-response" element={<ThreatResponse />} />
              <Route path="/supply-chain" element={<ModelSupplyChain />} />
              <Route path="/research" element={<ResearchHub />} />
              <Route path="/copilot" element={<Copilot />} />
              <Route path="/lab-partnerships" element={<LabPartnerships />} />
              <Route path="/postdoc-portal" element={<PostdocPortal />} />
              <Route path="/interview-prep" element={<InterviewPrep />} />
              <Route path="/benchmarks" element={<Benchmarks />} />
              <Route path="/admin" element={<AdminDashboard />} />
              <Route path="/architecture" element={<Architecture />} />
              <Route path="/api-docs" element={<ApiDocs />} />
              <Route path="/prompt-injection" element={<PromptInjectionPlayground />} />
              <Route path="/jailbreak-taxonomy" element={<JailbreakTaxonomy />} />
              <Route path="/rag-poisoning" element={<RAGPoisoning />} />
              <Route path="/multi-agent" element={<MultiAgentChain />} />
              <Route path="/mitre-attack" element={<MitreAttackMapper />} />
              <Route path="/alert-triage" element={<AlertTriage />} />
              <Route path="/compliance" element={<ComplianceHub />} />
              <Route path="/attack-chain" element={<AttackChainPredictor />} />
              <Route path="/data-poisoning" element={<DataPoisoningSim />} />
              <Route path="/causality-graph" element={<AlertCausalityGraph />} />
              <Route path="/autoencoder" element={<AutoencoderDetector />} />
              <Route path="/incident-reports" element={<IncidentReports />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/auto-investigate" element={<AutoInvestigation />} />
              <Route path="/threat-hunt" element={<ThreatHunt />} />
              <Route path="/rule-generator" element={<RuleGenerator />} />
              <Route path="/cve-mapper" element={<CVEMapper />} />
              <Route path="/about" element={<About />} />
            </Routes>
          </Suspense>

          {/* Persistent policy footer link — unobtrusive, always accessible */}
          <div className="mt-12 pb-4 text-center">
            <button
              onClick={() => setShowPolicyViewer(true)}
              className="inline-flex items-center gap-1.5 text-[11px] text-text-secondary/40 hover:text-text-secondary/70 transition-colors"
            >
              <Scale className="w-3 h-3" />
              Ethical Use Policy &amp; Guidance
            </button>
          </div>
        </div>
      </main>

      {/* Desktop RIGHT sidebar — Research & Methods */}
      <aside className="hidden lg:flex w-52 shrink-0 bg-bg-secondary flex-col border-l border-bg-card">
        <div className="p-4 flex items-center gap-2 justify-end">
          <ShieldCheck className="w-7 h-7 text-accent-blue" />
          <span className="font-display font-bold text-lg">RobustIDPS<span className="text-accent-blue">.AI</span></span>
        </div>
        <nav className="flex-1 px-2 overflow-y-auto">
          {renderNavGroups(rightNavGroups)}
        </nav>
        <NoticeBoard />
      </aside>
    </div>
  )
}
