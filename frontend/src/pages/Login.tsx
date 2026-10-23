import { useEffect, useState } from 'react'
import { ShieldCheck, LogIn, UserPlus, Eye, EyeOff, AlertCircle, CheckCircle2, MailCheck } from 'lucide-react'
import ThemeToggle from '../components/ThemeToggle'
import { setAuth, type AuthUser } from '../utils/auth'
import { setSessionId, broadcastLogin } from '../utils/sessionManager'

const API = import.meta.env.VITE_API_URL || ''

const USE_CASE_OPTIONS = [
  'Industry Work',
  'Academic Research',
  'Evaluation & Assessment',
  'Government / Defense',
  'Personal / Self-Study',
]

interface Props {
  onLogin: () => void
}

export default function Login({ onLogin }: Props) {
  const [isRegister, setIsRegister] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [organization, setOrganization] = useState('')
  const [useCase, setUseCase] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)
  const [registrationOpen, setRegistrationOpen] = useState(false)
  const [canResend, setCanResend] = useState(false)

  // Is self-registration open? And are we arriving from a confirmation link (/?verified=...)?
  useEffect(() => {
    fetch(`${API}/api/auth/registration`)
      .then((r) => (r.ok ? r.json() : { mode: 'closed' }))
      .then((d) => setRegistrationOpen(d.mode === 'verify'))
      .catch(() => setRegistrationOpen(false))
    const verified = new URLSearchParams(window.location.search).get('verified')
    if (verified) {
      if (verified === '1') setNotice('Your e-mail address is confirmed. You can sign in now.')
      else if (verified === 'expired') { setError('This confirmation link has expired. Sign in to request a new one.'); setCanResend(true) }
      else setError('This confirmation link is not valid. Sign in to request a new one.')
      window.history.replaceState(null, '', window.location.pathname)
    }
  }, [])

  const resend = async () => {
    setError('')
    setLoading(true)
    try {
      const res = await fetch(`${API}/api/auth/resend-verification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.detail || `Error ${res.status}`)
      setNotice(data.detail || 'If the account is waiting for confirmation, a new link is on its way.')
      setCanResend(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send the e-mail')
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setNotice('')
    setCanResend(false)
    setLoading(true)

    try {
      if (isRegister) {
        // Registration
        const res = await fetch(`${API}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            password,
            full_name: fullName,
            organization,
            use_case: useCase,
          }),
        })

        const data = await res.json().catch(() => ({}))
        if (!res.ok) throw new Error(data.detail || `Error ${res.status}`)

        // Account created but not yet confirmed: the user signs in after opening the mailed link.
        setNotice(data.detail || 'Check your e-mail for a confirmation link, then sign in.')
        setPassword('')
        setIsRegister(false)
      } else {
        // Login
        const form = new URLSearchParams()
        form.append('username', email)
        form.append('password', password)
        const res = await fetch(`${API}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form,
        })

        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          const detail = String(data.detail || `Error ${res.status}`)
          if (res.status === 403 && detail.startsWith('Email not confirmed')) setCanResend(true)
          throw new Error(detail)
        }

        const data = await res.json()
        setAuth(data.access_token, data.user as AuthUser)
        if (data.session_id) {
          setSessionId(data.session_id)
          broadcastLogin(data.access_token, data.user as AuthUser, data.session_id)
        }
        onLogin()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  const toggleMode = () => {
    setIsRegister(!isRegister)
    setError('')
    setNotice('')
    setCanResend(false)
  }

  return (
    <div className="min-h-screen bg-bg-primary flex items-center justify-center p-4 relative">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <ShieldCheck className="w-10 h-10 text-accent-blue" />
            <h1 className="font-display font-bold text-2xl text-text-primary">
              RobustIDPS.ai
            </h1>
          </div>
          <p className="text-text-secondary text-sm">
            Advanced AI-Powered Intrusion Detection & Prevention System
          </p>
        </div>

        {/* Form Card */}
        <div className="bg-bg-card border border-bg-card rounded-xl p-6 shadow-xl">
          <h2 className="text-lg font-semibold text-text-primary mb-6">
            {isRegister ? 'Create Account' : 'Sign In'}
          </h2>

          {notice && (
            <div className="mb-4 flex items-center gap-2 px-3 py-2 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-sm">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              {notice}
            </div>
          )}

          {error && (
            <div className="mb-4 px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
              {canResend && registrationOpen && email && (
                <button
                  type="button"
                  onClick={resend}
                  disabled={loading}
                  className="mt-2 inline-flex items-center gap-1.5 text-accent-blue hover:underline font-medium disabled:opacity-50"
                >
                  <MailCheck className="w-4 h-4" /> Send a new confirmation link to {email}
                </button>
              )}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {isRegister && (
              <>
                <div>
                  <label className="block text-sm text-text-secondary mb-1">
                    Full Name
                  </label>
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full px-3 py-2.5 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
                    placeholder="Your full name"
                  />
                </div>
                <div>
                  <label className="block text-sm text-text-secondary mb-1">
                    Organization
                  </label>
                  <input
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full px-3 py-2.5 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
                    placeholder="University or company (optional)"
                  />
                </div>
                <div>
                  <label className="block text-sm text-text-secondary mb-1">
                    Use Case
                  </label>
                  <select
                    value={useCase}
                    onChange={(e) => setUseCase(e.target.value)}
                    className="w-full px-3 py-2.5 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
                  >
                    <option value="">Select a use case (optional)</option>
                    {USE_CASE_OPTIONS.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                </div>
              </>
            )}

            <div>
              <label className="block text-sm text-text-secondary mb-1">
                Email
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2.5 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label className="block text-sm text-text-secondary mb-1">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2.5 pr-10 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
                  placeholder={isRegister ? 'Create a strong password' : 'Enter your password'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-secondary hover:text-text-primary"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {isRegister && (
                <p className="mt-1 text-[11px] text-text-secondary">
                  Min 8 chars, uppercase, lowercase, digit, and special character required.
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-accent-blue hover:bg-accent-blue/90 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : isRegister ? (
                <UserPlus className="w-4 h-4" />
              ) : (
                <LogIn className="w-4 h-4" />
              )}
              {isRegister ? 'Register' : 'Sign In'}
            </button>
          </form>

          <p className="mt-4 text-center text-sm text-text-secondary">
            {!registrationOpen && !isRegister ? (
              <>Accounts are created by the administrator. Contact support@robustidps.ai for access.</>
            ) : isRegister ? (
              <>
                Already have an account?{' '}
                <button onClick={toggleMode} className="text-accent-blue hover:underline font-medium">
                  Sign In
                </button>
              </>
            ) : (
              <>
                Don&apos;t have an account?{' '}
                <button onClick={toggleMode} className="text-accent-blue hover:underline font-medium">
                  Register
                </button>
              </>
            )}
          </p>
        </div>

        {/* Footer */}
        <div className="mt-6 text-center text-xs text-text-secondary">
          <p>MEPhI University | PhD Dissertation Implementation</p>
          <p className="mt-1">Roger Nick Anaedevha</p>
        </div>
      </div>
    </div>
  )
}
