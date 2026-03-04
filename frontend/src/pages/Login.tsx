import { useState } from 'react'
import { ShieldCheck, LogIn, UserPlus, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { setAuth, type AuthUser } from '../utils/auth'

const API = import.meta.env.VITE_API_URL || ''

interface Props {
  onLogin: () => void
}

export default function Login({ onLogin }: Props) {
  const [isRegister, setIsRegister] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      let res: Response

      if (isRegister) {
        res = await fetch(`${API}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, full_name: fullName }),
        })
      } else {
        const form = new URLSearchParams()
        form.append('username', email)
        form.append('password', password)
        res = await fetch(`${API}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form,
        })
      }

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || `Error ${res.status}`)
      }

      const data = await res.json()
      setAuth(data.access_token, data.user as AuthUser)
      onLogin()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg-primary flex items-center justify-center p-4">
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
            Advanced AI-Powered Intrusion Detection System
          </p>
        </div>

        {/* Form Card */}
        <div className="bg-bg-card border border-bg-card rounded-xl p-6 shadow-xl">
          <h2 className="text-lg font-semibold text-text-primary mb-6">
            {isRegister ? 'Create Account' : 'Sign In'}
          </h2>

          {error && (
            <div className="mb-4 flex items-center gap-2 px-3 py-2 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {isRegister && (
              <div>
                <label className="block text-sm text-text-secondary mb-1">
                  Full Name
                </label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full px-3 py-2.5 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
                  placeholder="Roger Anaedevha"
                />
              </div>
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
                placeholder="admin@robustidps.ai"
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
                  placeholder="Min. 8 characters"
                  minLength={isRegister ? 8 : 1}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-secondary hover:text-text-primary"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
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
              {isRegister ? 'Create Account' : 'Sign In'}
            </button>
          </form>

          <div className="mt-4 text-center">
            <button
              onClick={() => {
                setIsRegister(!isRegister)
                setError('')
              }}
              className="text-sm text-accent-blue hover:underline"
            >
              {isRegister
                ? 'Already have an account? Sign in'
                : "Don't have an account? Register"}
            </button>
          </div>
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
