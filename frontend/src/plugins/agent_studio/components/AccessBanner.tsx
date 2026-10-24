import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, KeyRound, Eye, Sparkles, AlertCircle,
} from 'lucide-react'
import { fetchAccessInfo, getStoredApiKey } from '../api'
import type { AccessInfo } from '../api'
import { useAgentStudioState } from '../../../hooks/useAgentStudioState'
import { getUser } from '../../../utils/auth'

type Mode =
  | { kind: 'admin'; via: 'platform' | 'env' }
  | { kind: 'user'; tier: string; email: string }
  | { kind: 'api_key' }
  | { kind: 'demo' }
  | { kind: 'locked' }

/**
 * Single-line banner shown on every Agent Studio page so assessors /
 * demonstrators can see at a glance what identity the platform is
 * treating them as. Resolves the priority order:
 *
 *   platform_jwt(admin) > platform_jwt(user) > api_key > demo > locked
 *
 * Designed to be a non-intrusive strip — collapses on click.
 */
export default function AccessBanner() {
  const [info, setInfo] = useAgentStudioState<AccessInfo | null>('access', 'info', null)
  const [collapsed, setCollapsed] = useAgentStudioState<boolean>('access', 'collapsed', false)
  const [, force] = useState(0)

  useEffect(() => {
    fetchAccessInfo().then(setInfo).catch(() => {})
    const t = window.setInterval(() => force((n) => n + 1), 4000) // refresh chip if user logs in/out
    return () => window.clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const mode: Mode = (() => {
    const user = getUser()
    if (user?.role === 'admin') return { kind: 'admin', via: 'platform' }
    if (info?.auth_disabled) return { kind: 'admin', via: 'env' }
    if (user) return { kind: 'user', tier: 'community', email: user.email }
    if (getStoredApiKey()) return { kind: 'api_key' }
    if (info?.demo_mode) return { kind: 'demo' }
    return { kind: 'locked' }
  })()

  const tone = {
    admin:   'bg-accent-green/10 text-accent-green border-accent-green/30',
    user:    'bg-accent-blue/10 text-accent-blue border-accent-blue/30',
    api_key: 'bg-accent-blue/10 text-accent-blue border-accent-blue/30',
    demo:    'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
    locked:  'bg-accent-red/10 text-accent-red border-accent-red/30',
  }[mode.kind]

  const Icon = mode.kind === 'admin' ? ShieldCheck
             : mode.kind === 'user' ? Sparkles
             : mode.kind === 'api_key' ? KeyRound
             : mode.kind === 'demo' ? Eye
             : AlertCircle

  const label = mode.kind === 'admin'
    ? (mode.via === 'platform' ? 'Admin · full unrestricted access (platform login)'
                                : 'Admin · full unrestricted access (server env bypass)')
    : mode.kind === 'user'
      ? `${mode.email} · ${mode.tier} tier — features gated by subscription`
      : mode.kind === 'api_key'
        ? 'API key · tier-scoped access per the issued key'
        : mode.kind === 'demo'
          ? 'Demo mode · anonymous community-tier; rate-limited; no write persistence to your customer'
          : 'Locked · no identity — sign in, paste an API key, or ask the admin to enable demo mode'

  return (
    <div className={`flex items-center gap-2 text-[11px] font-mono border rounded px-2 py-1 ${tone}`}>
      <Icon className="w-3.5 h-3.5 shrink-0" />
      <span className="truncate flex-1">{label}</span>
      {!collapsed && info && (
        <span className="text-[10px] opacity-70 hidden md:inline">
          server accepts: {info.sources_accepted.join(' · ')}
        </span>
      )}
      {mode.kind === 'locked' && (
        <>
          <Link to="/login" className="underline hover:text-accent-blue">Sign in</Link>
          <span className="opacity-50">·</span>
          <Link to="/agent-studio/account" className="underline hover:text-accent-blue">
            Get API key
          </Link>
        </>
      )}
      <button onClick={() => setCollapsed(!collapsed)}
              className="opacity-50 hover:opacity-100 text-[10px]"
              title={collapsed ? 'Show detail' : 'Hide detail'}>
        {collapsed ? '…' : '×'}
      </button>
    </div>
  )
}
