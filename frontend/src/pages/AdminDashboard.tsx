import { useState, useEffect, useCallback } from 'react'
import {
  Users, Shield, Activity, Search, ChevronDown, ChevronUp,
  Trash2, UserX, UserCheck, KeyRound, Clock, Globe, Monitor,
  AlertTriangle, LogIn, Upload, Cpu, Download, Flame, RefreshCw,
} from 'lucide-react'
import { getUser } from '../utils/auth'
import PageGuide from '../components/PageGuide'
import {
  fetchUsers, fetchAuditLogs, exportAuditLogs, updateUserRole,
  resetUserPassword, deleteUser, toggleUserActive,
  fetchActiveSessions, fetchSystemHealth,
} from '../utils/api'

/* ── Types ─────────────────────────────────────────────────────────────── */

interface UserRecord {
  id: number
  email: string
  full_name: string
  role: string
  organization: string
  use_case: string
  is_active: boolean
  created_at: string
  last_login?: string
}

interface AuditRecord {
  id: number
  user_id: number | null
  action: string
  resource: string
  details: string
  ip_address: string
  user_agent: string
  timestamp: string
}

/* ── Helpers ───────────────────────────────────────────────────────────── */

function formatDate(iso: string) {
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

const ROLE_COLORS: Record<string, string> = {
  admin: 'bg-accent-red/15 text-accent-red',
  analyst: 'bg-accent-blue/15 text-accent-blue',
  viewer: 'bg-accent-green/15 text-accent-green',
}

const ACTION_ICONS: Record<string, typeof LogIn> = {
  LOGIN: LogIn,
  REGISTER: Users,
  UPLOAD: Upload,
  PREDICT: Cpu,
  PREDICT_UNCERTAIN: Cpu,
  ABLATION: Flame,
  EXPORT: Download,
  MODEL_SWITCH: RefreshCw,
  FIREWALL_GENERATE: Shield,
}

const ACTION_COLORS: Record<string, string> = {
  LOGIN: 'text-accent-blue',
  REGISTER: 'text-accent-green',
  UPLOAD: 'text-accent-purple',
  PREDICT: 'text-accent-orange',
  PREDICT_UNCERTAIN: 'text-accent-orange',
  ABLATION: 'text-accent-red',
  EXPORT: 'text-accent-blue',
  MODEL_SWITCH: 'text-accent-yellow',
  FIREWALL_GENERATE: 'text-accent-green',
}

/* ── Sessions Tab ──────────────────────────────────────────────────────── */

function SessionsTab() {
  const [sessions, setSessions] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [online, setOnline] = useState(0)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await fetchActiveSessions()
      setSessions(data.sessions || [])
      setOnline(data.online || 0)
    } catch {}
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm font-semibold text-text-primary">Active Sessions</span>
          <span className="text-xs px-2 py-0.5 rounded bg-accent-green/15 text-accent-green">{online} online</span>
          <span className="text-xs text-text-secondary">{sessions.length} total</span>
        </div>
        <button onClick={load} className="p-1.5 rounded-lg text-text-secondary hover:text-text-primary">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {loading && sessions.length === 0 ? (
        <div className="text-center py-8 text-text-secondary text-sm">Loading sessions...</div>
      ) : sessions.length === 0 ? (
        <div className="text-center py-8 text-text-secondary text-sm">No active sessions</div>
      ) : (
        <div className="space-y-2">
          {sessions.sort((a: any, b: any) => a.idle_seconds - b.idle_seconds).map((s: any, i: number) => (
            <div key={i} className="flex items-center gap-3 px-4 py-3 bg-bg-card border border-bg-card rounded-lg">
              <div className={`w-2.5 h-2.5 rounded-full ${s.is_online ? 'bg-accent-green animate-pulse' : 'bg-text-secondary/30'}`} />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-text-primary truncate">{s.email}</div>
                <div className="text-[10px] text-text-secondary">
                  Page: <span className="text-accent-blue">{s.current_page || '/'}</span>
                  {' \u00b7 '}
                  {s.is_online ? <span className="text-accent-green">active</span> : `idle ${Math.floor(s.idle_seconds / 60)}m`}
                </div>
              </div>
              <div className="text-xs text-text-secondary">{s.last_heartbeat ? timeAgo(s.last_heartbeat) : '\u2014'}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/* ── Health Tab ─────────────────────────────────────────────────────────── */

function HealthTab() {
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await fetchSystemHealth()
      setHealth(data)
    } catch {}
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [load])

  if (loading && !health) return <div className="text-center py-8 text-text-secondary text-sm">Loading system health...</div>
  if (!health) return <div className="text-center py-8 text-text-secondary text-sm">Failed to load health data</div>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold text-text-primary">System Health</span>
        <button onClick={load} className="p-1.5 rounded-lg text-text-secondary hover:text-text-primary">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-bg-card rounded-lg p-4 border border-bg-card">
          <div className="text-[10px] text-text-secondary uppercase">CPU</div>
          <div className={`text-2xl font-display font-bold ${health.cpu_percent > 80 ? 'text-accent-red' : health.cpu_percent > 50 ? 'text-accent-amber' : 'text-accent-green'}`}>
            {health.cpu_percent}%
          </div>
        </div>
        <div className="bg-bg-card rounded-lg p-4 border border-bg-card">
          <div className="text-[10px] text-text-secondary uppercase">Memory</div>
          <div className={`text-2xl font-display font-bold ${health.memory?.percent > 85 ? 'text-accent-red' : health.memory?.percent > 60 ? 'text-accent-amber' : 'text-accent-green'}`}>
            {health.memory?.percent}%
          </div>
          <div className="text-[10px] text-text-secondary">{health.memory?.used_gb} / {health.memory?.total_gb} GB</div>
        </div>
        <div className="bg-bg-card rounded-lg p-4 border border-bg-card">
          <div className="text-[10px] text-text-secondary uppercase">Disk</div>
          <div className={`text-2xl font-display font-bold ${health.disk?.percent > 90 ? 'text-accent-red' : health.disk?.percent > 70 ? 'text-accent-amber' : 'text-accent-green'}`}>
            {health.disk?.percent}%
          </div>
          <div className="text-[10px] text-text-secondary">{health.disk?.used_gb} / {health.disk?.total_gb} GB</div>
        </div>
        <div className="bg-bg-card rounded-lg p-4 border border-bg-card">
          <div className="text-[10px] text-text-secondary uppercase">Active Jobs</div>
          <div className="text-2xl font-display font-bold text-accent-blue">{health.application?.active_jobs}</div>
          <div className="text-[10px] text-text-secondary">{health.application?.total_jobs} total &middot; {health.application?.cached_results} cached</div>
        </div>
      </div>

      {/* Model Status */}
      <div className="bg-bg-card rounded-lg p-4 border border-bg-card">
        <h3 className="text-xs font-semibold text-text-primary mb-2">Model Status</h3>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${health.model?.loaded ? 'bg-accent-green' : 'bg-accent-red'}`} />
            {health.model?.loaded ? 'Loaded' : 'Not loaded'}
          </div>
          <span className="text-text-secondary">Active: <span className="text-accent-blue">{health.model?.active_model || 'none'}</span></span>
          <span className="text-text-secondary">Device: <span className="text-text-primary">{health.model?.device}</span></span>
          <span className="text-text-secondary">PID: <span className="font-mono">{health.application?.pid}</span></span>
        </div>
      </div>
    </div>
  )
}

/* ── Component ─────────────────────────────────────────────────────────── */

export default function AdminDashboard() {
  const currentUser = getUser()
  const [tab, setTab] = useState<'users' | 'audit' | 'sessions' | 'health'>('users')

  // Users state
  const [users, setUsers] = useState<UserRecord[]>([])
  const [usersLoading, setUsersLoading] = useState(true)
  const [usersError, setUsersError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [sortField, setSortField] = useState<'created_at' | 'email' | 'role'>('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  // Action modals
  const [actionUser, setActionUser] = useState<UserRecord | null>(null)
  const [actionType, setActionType] = useState<'role' | 'password' | 'delete' | 'toggle' | null>(null)
  const [newRole, setNewRole] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [actionLoading, setActionLoading] = useState(false)
  const [actionMsg, setActionMsg] = useState('')

  // Audit state
  const [logs, setLogs] = useState<AuditRecord[]>([])
  const [logsLoading, setLogsLoading] = useState(false)
  const [logsTotal, setLogsTotal] = useState(0)
  const [logsOffset, setLogsOffset] = useState(0)
  const [logsFilter, setLogsFilter] = useState('')
  const LOGS_LIMIT = 50

  // Email map for audit display
  const userEmailMap = users.reduce<Record<number, string>>((acc, u) => {
    acc[u.id] = u.email
    return acc
  }, {})

  const loadUsers = useCallback(async () => {
    setUsersLoading(true)
    setUsersError('')
    try {
      const data = await fetchUsers()
      setUsers(data)
    } catch (e: any) {
      setUsersError(e.message || 'Failed to load users')
    } finally {
      setUsersLoading(false)
    }
  }, [])

  const loadLogs = useCallback(async (offset = 0) => {
    setLogsLoading(true)
    try {
      const data = await fetchAuditLogs(LOGS_LIMIT, offset)
      setLogs(data.logs || [])
      setLogsTotal(data.total || 0)
      setLogsOffset(offset)
    } catch {
      // silently fail
    } finally {
      setLogsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadUsers()
  }, [loadUsers])

  useEffect(() => {
    if (tab === 'audit') loadLogs(0)
  }, [tab, loadLogs])

  // Check admin access
  if (!currentUser || currentUser.role !== 'admin') {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-accent-red mx-auto mb-3" />
          <h2 className="text-xl font-bold text-text-primary mb-2">Access Denied</h2>
          <p className="text-text-secondary">Admin privileges required to access this page.</p>
        </div>
      </div>
    )
  }

  // Filter and sort users
  const filteredUsers = users
    .filter(u => {
      if (!searchQuery) return true
      const q = searchQuery.toLowerCase()
      return u.email.toLowerCase().includes(q)
        || u.full_name.toLowerCase().includes(q)
        || u.organization.toLowerCase().includes(q)
        || u.role.toLowerCase().includes(q)
    })
    .sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1
      if (sortField === 'email') return a.email.localeCompare(b.email) * dir
      if (sortField === 'role') return a.role.localeCompare(b.role) * dir
      return (new Date(a.created_at).getTime() - new Date(b.created_at).getTime()) * dir
    })

  // Filter audit logs
  const filteredLogs = logs.filter(l => {
    if (!logsFilter) return true
    const q = logsFilter.toLowerCase()
    const email = l.user_id ? (userEmailMap[l.user_id] || '') : ''
    return l.action.toLowerCase().includes(q)
      || email.toLowerCase().includes(q)
      || l.resource.toLowerCase().includes(q)
      || l.ip_address.toLowerCase().includes(q)
  })

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  const SortIcon = ({ field }: { field: typeof sortField }) => {
    if (sortField !== field) return null
    return sortDir === 'asc'
      ? <ChevronUp className="w-3 h-3 inline ml-0.5" />
      : <ChevronDown className="w-3 h-3 inline ml-0.5" />
  }

  const openAction = (user: UserRecord, type: typeof actionType) => {
    setActionUser(user)
    setActionType(type)
    setNewRole(user.role)
    setNewPassword('')
    setActionMsg('')
  }

  const closeAction = () => {
    setActionUser(null)
    setActionType(null)
    setActionMsg('')
  }

  const executeAction = async () => {
    if (!actionUser || !actionType) return
    setActionLoading(true)
    setActionMsg('')
    try {
      if (actionType === 'role') {
        await updateUserRole(actionUser.id, newRole)
        setActionMsg(`Role updated to ${newRole}`)
      } else if (actionType === 'password') {
        await resetUserPassword(actionUser.id, newPassword)
        setActionMsg('Password reset successfully')
      } else if (actionType === 'delete') {
        await deleteUser(actionUser.id)
        setActionMsg('User deleted')
      } else if (actionType === 'toggle') {
        await toggleUserActive(actionUser.id, !actionUser.is_active)
        setActionMsg(actionUser.is_active ? 'User deactivated' : 'User activated')
      }
      await loadUsers()
      setTimeout(closeAction, 1200)
    } catch (e: any) {
      setActionMsg(`Error: ${e.message || 'Action failed'}`)
    } finally {
      setActionLoading(false)
    }
  }

  // Stats
  const totalUsers = users.length
  const activeUsers = users.filter(u => u.is_active).length
  const adminCount = users.filter(u => u.role === 'admin').length
  const recentLogins = users.filter(u => {
    if (!u.last_login) return false
    return Date.now() - new Date(u.last_login).getTime() < 7 * 86400000
  }).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent-blue" />
            Admin Dashboard
          </h1>
          <p className="text-sm text-text-secondary mt-1">
            Manage users, monitor activity, and control access
          </p>
        </div>
      </div>

      <PageGuide
        title="How to use Admin Dashboard"
        steps={[
          { title: 'Manage users', desc: 'View all user accounts, change roles (admin/analyst/viewer), reset passwords, activate/deactivate accounts, or delete users.' },
          { title: 'Review audit logs', desc: 'Browse all user activities (logins, uploads, predictions, exports) with filtering by action type. Export logs as CSV for compliance.' },
          { title: 'Monitor active sessions', desc: 'See who is currently online, which page they are viewing, and their idle time. Auto-refreshes every 10 seconds.' },
          { title: 'Check system health', desc: 'Monitor CPU, memory, disk usage, active jobs, model status, and device info. Auto-refreshes every 15 seconds.' },
        ]}
        tip="Tip: The Active Sessions tab shows real-time user activity — useful for monitoring during live demonstrations and security audits."
      />

      {/* Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-bg-card border border-bg-card rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Users className="w-4 h-4 text-accent-blue" />
            <span className="text-xs text-text-secondary">Total Users</span>
          </div>
          <p className="text-2xl font-bold text-text-primary">{totalUsers}</p>
        </div>
        <div className="bg-bg-card border border-bg-card rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <UserCheck className="w-4 h-4 text-accent-green" />
            <span className="text-xs text-text-secondary">Active</span>
          </div>
          <p className="text-2xl font-bold text-text-primary">{activeUsers}</p>
        </div>
        <div className="bg-bg-card border border-bg-card rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-accent-red" />
            <span className="text-xs text-text-secondary">Admins</span>
          </div>
          <p className="text-2xl font-bold text-text-primary">{adminCount}</p>
        </div>
        <div className="bg-bg-card border border-bg-card rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-4 h-4 text-accent-purple" />
            <span className="text-xs text-text-secondary">Active (7d)</span>
          </div>
          <p className="text-2xl font-bold text-text-primary">{recentLogins}</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 w-fit">
        <button
          onClick={() => setTab('users')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === 'users'
              ? 'bg-accent-blue/15 text-accent-blue'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          <Users className="w-4 h-4 inline mr-1.5 -mt-0.5" />
          Users ({totalUsers})
        </button>
        <button
          onClick={() => setTab('audit')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === 'audit'
              ? 'bg-accent-blue/15 text-accent-blue'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          <Activity className="w-4 h-4 inline mr-1.5 -mt-0.5" />
          Audit Logs ({logsTotal})
        </button>
        <button
          onClick={() => setTab('sessions')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === 'sessions'
              ? 'bg-accent-green/15 text-accent-green'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          <Globe className="w-4 h-4" /> Active Sessions
        </button>
        <button
          onClick={() => setTab('health')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            tab === 'health'
              ? 'bg-accent-purple/15 text-accent-purple'
              : 'text-text-secondary hover:text-text-primary'
          }`}
        >
          <Monitor className="w-4 h-4" /> System Health
        </button>
      </div>

      {/* Users Tab */}
      {tab === 'users' && (
        <div className="bg-bg-card border border-bg-card rounded-xl overflow-hidden">
          {/* Search */}
          <div className="p-4 border-b border-bg-secondary">
            <div className="relative max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search users by email, name, org..."
                className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-sm text-text-primary placeholder:text-text-secondary focus:outline-none focus:ring-1 focus:ring-accent-blue"
              />
            </div>
          </div>

          {usersLoading ? (
            <div className="p-8 text-center text-text-secondary text-sm">Loading users...</div>
          ) : usersError ? (
            <div className="p-8 text-center text-accent-red text-sm">{usersError}</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-bg-secondary text-left">
                    <th
                      className="px-4 py-3 text-text-secondary font-medium cursor-pointer hover:text-text-primary"
                      onClick={() => handleSort('email')}
                    >
                      User <SortIcon field="email" />
                    </th>
                    <th
                      className="px-4 py-3 text-text-secondary font-medium cursor-pointer hover:text-text-primary"
                      onClick={() => handleSort('role')}
                    >
                      Role <SortIcon field="role" />
                    </th>
                    <th className="px-4 py-3 text-text-secondary font-medium">Organization</th>
                    <th className="px-4 py-3 text-text-secondary font-medium">Use Case</th>
                    <th className="px-4 py-3 text-text-secondary font-medium">Status</th>
                    <th
                      className="px-4 py-3 text-text-secondary font-medium cursor-pointer hover:text-text-primary"
                      onClick={() => handleSort('created_at')}
                    >
                      Joined <SortIcon field="created_at" />
                    </th>
                    <th className="px-4 py-3 text-text-secondary font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map(u => (
                    <tr key={u.id} className="border-b border-bg-secondary/50 hover:bg-bg-secondary/30">
                      <td className="px-4 py-3">
                        <div>
                          <p className="text-text-primary font-medium">{u.full_name || '—'}</p>
                          <p className="text-text-secondary text-xs">{u.email}</p>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${ROLE_COLORS[u.role] || 'bg-bg-secondary text-text-secondary'}`}>
                          {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-text-secondary">{u.organization || '—'}</td>
                      <td className="px-4 py-3 text-text-secondary text-xs">{u.use_case || '—'}</td>
                      <td className="px-4 py-3">
                        {u.is_active ? (
                          <span className="text-accent-green text-xs font-medium flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-accent-green" /> Active
                          </span>
                        ) : (
                          <span className="text-accent-red text-xs font-medium flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-accent-red" /> Disabled
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-text-secondary text-xs">{formatDate(u.created_at)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => openAction(u, 'role')}
                            title="Change role"
                            className="p-1.5 rounded hover:bg-bg-secondary text-text-secondary hover:text-accent-blue transition-colors"
                          >
                            <Shield className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => openAction(u, 'password')}
                            title="Reset password"
                            className="p-1.5 rounded hover:bg-bg-secondary text-text-secondary hover:text-accent-orange transition-colors"
                          >
                            <KeyRound className="w-3.5 h-3.5" />
                          </button>
                          {u.id !== currentUser.id && (
                            <>
                              <button
                                onClick={() => openAction(u, 'toggle')}
                                title={u.is_active ? 'Deactivate' : 'Activate'}
                                className={`p-1.5 rounded hover:bg-bg-secondary transition-colors ${
                                  u.is_active
                                    ? 'text-text-secondary hover:text-accent-yellow'
                                    : 'text-text-secondary hover:text-accent-green'
                                }`}
                              >
                                {u.is_active ? <UserX className="w-3.5 h-3.5" /> : <UserCheck className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                onClick={() => openAction(u, 'delete')}
                                title="Delete user"
                                className="p-1.5 rounded hover:bg-bg-secondary text-text-secondary hover:text-accent-red transition-colors"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredUsers.length === 0 && (
                <div className="p-8 text-center text-text-secondary text-sm">No users found</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Audit Log Tab */}
      {tab === 'audit' && (
        <div className="bg-bg-card border border-bg-card rounded-xl overflow-hidden">
          {/* Filter + Refresh */}
          <div className="p-4 border-b border-bg-secondary flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
            <div className="relative max-w-sm flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
              <input
                type="text"
                value={logsFilter}
                onChange={e => setLogsFilter(e.target.value)}
                placeholder="Filter by action, user, IP..."
                className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-sm text-text-primary placeholder:text-text-secondary focus:outline-none focus:ring-1 focus:ring-accent-blue"
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={async () => {
                  try {
                    const blob = await exportAuditLogs(logsFilter || undefined)
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url; a.download = 'audit_logs.csv'; a.click()
                    URL.revokeObjectURL(url)
                  } catch {}
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-accent-green/15 text-accent-green rounded-lg text-xs font-medium hover:bg-accent-green/25 transition-colors"
              >
                <Download className="w-3 h-3" /> Export CSV
              </button>
              <button
                onClick={() => loadLogs(logsOffset)}
                className="px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-sm text-text-secondary hover:text-text-primary transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 inline mr-1.5 -mt-0.5 ${logsLoading ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>

          {logsLoading && logs.length === 0 ? (
            <div className="p-8 text-center text-text-secondary text-sm">Loading audit logs...</div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-bg-secondary text-left">
                      <th className="px-4 py-3 text-text-secondary font-medium">Time</th>
                      <th className="px-4 py-3 text-text-secondary font-medium">Action</th>
                      <th className="px-4 py-3 text-text-secondary font-medium">User</th>
                      <th className="px-4 py-3 text-text-secondary font-medium">Resource</th>
                      <th className="px-4 py-3 text-text-secondary font-medium">IP Address</th>
                      <th className="px-4 py-3 text-text-secondary font-medium">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map(l => {
                      const Icon = ACTION_ICONS[l.action] || Activity
                      const color = ACTION_COLORS[l.action] || 'text-text-secondary'
                      return (
                        <tr key={l.id} className="border-b border-bg-secondary/50 hover:bg-bg-secondary/30">
                          <td className="px-4 py-3 text-text-secondary text-xs whitespace-nowrap">
                            <Clock className="w-3 h-3 inline mr-1 -mt-0.5" />
                            <span title={formatDate(l.timestamp)}>{timeAgo(l.timestamp)}</span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${color}`}>
                              <Icon className="w-3.5 h-3.5" />
                              {l.action}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-text-primary text-xs">
                            {l.user_id ? (userEmailMap[l.user_id] || `User #${l.user_id}`) : '—'}
                          </td>
                          <td className="px-4 py-3 text-text-secondary text-xs font-mono max-w-[200px] truncate">
                            {l.resource || '—'}
                          </td>
                          <td className="px-4 py-3 text-text-secondary text-xs">
                            <Globe className="w-3 h-3 inline mr-1 -mt-0.5" />
                            {l.ip_address || '—'}
                          </td>
                          <td className="px-4 py-3 text-text-secondary text-xs max-w-[150px] truncate">
                            {l.details || '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                {filteredLogs.length === 0 && (
                  <div className="p-8 text-center text-text-secondary text-sm">No audit logs found</div>
                )}
              </div>

              {/* Pagination */}
              {logsTotal > LOGS_LIMIT && (
                <div className="p-4 border-t border-bg-secondary flex items-center justify-between">
                  <span className="text-xs text-text-secondary">
                    Showing {logsOffset + 1}–{Math.min(logsOffset + LOGS_LIMIT, logsTotal)} of {logsTotal}
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => loadLogs(Math.max(0, logsOffset - LOGS_LIMIT))}
                      disabled={logsOffset === 0}
                      className="px-3 py-1.5 bg-bg-secondary border border-bg-card rounded text-xs text-text-secondary hover:text-text-primary disabled:opacity-40 transition-colors"
                    >
                      Previous
                    </button>
                    <button
                      onClick={() => loadLogs(logsOffset + LOGS_LIMIT)}
                      disabled={logsOffset + LOGS_LIMIT >= logsTotal}
                      className="px-3 py-1.5 bg-bg-secondary border border-bg-card rounded text-xs text-text-secondary hover:text-text-primary disabled:opacity-40 transition-colors"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Sessions Tab */}
      {tab === 'sessions' && (
        <SessionsTab />
      )}

      {/* Health Tab */}
      {tab === 'health' && (
        <HealthTab />
      )}

      {/* Action Modal */}
      {actionUser && actionType && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={closeAction}>
          <div
            className="bg-bg-card border border-bg-secondary rounded-xl p-6 max-w-md w-full shadow-xl"
            onClick={e => e.stopPropagation()}
          >
            <h3 className="text-lg font-bold text-text-primary mb-1">
              {actionType === 'role' && 'Change User Role'}
              {actionType === 'password' && 'Reset Password'}
              {actionType === 'delete' && 'Delete User'}
              {actionType === 'toggle' && (actionUser.is_active ? 'Deactivate User' : 'Activate User')}
            </h3>
            <p className="text-sm text-text-secondary mb-4">
              {actionUser.email}
            </p>

            {actionType === 'role' && (
              <div className="space-y-2 mb-4">
                <label className="text-xs text-text-secondary">Select role:</label>
                <div className="flex gap-2">
                  {['admin', 'analyst', 'viewer'].map(r => (
                    <button
                      key={r}
                      onClick={() => setNewRole(r)}
                      className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                        newRole === r
                          ? 'bg-accent-blue text-white'
                          : 'bg-bg-secondary text-text-secondary hover:text-text-primary'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {actionType === 'password' && (
              <div className="space-y-2 mb-4">
                <label className="text-xs text-text-secondary">New password (min 8 chars):</label>
                <input
                  type="text"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  className="w-full px-3 py-2 bg-bg-secondary border border-bg-card rounded-lg text-sm text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-blue"
                />
              </div>
            )}

            {actionType === 'delete' && (
              <div className="p-3 bg-accent-red/10 border border-accent-red/30 rounded-lg mb-4">
                <p className="text-sm text-accent-red">
                  <AlertTriangle className="w-4 h-4 inline mr-1 -mt-0.5" />
                  This action is permanent and cannot be undone.
                </p>
              </div>
            )}

            {actionType === 'toggle' && (
              <p className="text-sm text-text-secondary mb-4">
                {actionUser.is_active
                  ? 'This will prevent the user from logging in until reactivated.'
                  : 'This will allow the user to log in again.'}
              </p>
            )}

            {actionMsg && (
              <p className={`text-sm mb-3 ${actionMsg.startsWith('Error') ? 'text-accent-red' : 'text-accent-green'}`}>
                {actionMsg}
              </p>
            )}

            <div className="flex gap-2 justify-end">
              <button
                onClick={closeAction}
                className="px-4 py-2 bg-bg-secondary rounded-lg text-sm text-text-secondary hover:text-text-primary transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={executeAction}
                disabled={actionLoading || (actionType === 'password' && newPassword.length < 8)}
                className={`px-4 py-2 rounded-lg text-sm font-medium text-white transition-colors disabled:opacity-40 ${
                  actionType === 'delete' ? 'bg-accent-red hover:bg-accent-red/80' : 'bg-accent-blue hover:bg-accent-blue/80'
                }`}
              >
                {actionLoading ? 'Processing...' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
