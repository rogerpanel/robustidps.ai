import { useState, useEffect, useCallback } from 'react'
import {
  User, Shield, Edit3, Save, X, CheckCircle2, Loader2,
  BarChart3, Clock, Building2, BookOpen, Palette,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'
import { getUser, getToken } from '../utils/auth'

const API = import.meta.env.VITE_API_URL || ''

const AVATAR_COLORS = [
  '#3B82F6', '#EF4444', '#22C55E', '#F59E0B', '#A855F7', '#F97316',
  '#EC4899', '#06B6D4', '#8B5CF6', '#14B8A6',
]

const SPECIALIZATIONS = [
  'SOC Analyst', 'Threat Hunter', 'ML Researcher', 'Security Engineer',
  'Penetration Tester', 'DevSecOps', 'Incident Responder', 'CISO/Manager',
  'Student/Academic', 'Lab Researcher', 'Other',
]

const USE_CASES = [
  'Industry Work', 'Academic Research', 'Lab Testing', 'Training/Education', 'Evaluation',
]

interface ProfileData {
  id: number
  email: string
  full_name: string
  role: string
  organization: string
  specialization: string
  bio: string
  use_case: string
  avatar_color: string
  robust_id: string
  created_at: string
  analyses_run: number
  actions_logged: number
  preferred_model: string
  timezone: string
  orcid: string
}

async function fetchProfile(): Promise<ProfileData> {
  const resp = await fetch(`${API}/api/auth/profile`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  })
  if (!resp.ok) throw new Error('Failed to load profile')
  return resp.json()
}

async function updateProfile(data: Record<string, string>): Promise<ProfileData> {
  const resp = await fetch(`${API}/api/auth/profile`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
    body: JSON.stringify(data),
  })
  if (!resp.ok) throw new Error('Failed to update profile')
  return resp.json()
}

function Avatar({ name, color, size = 'lg' }: { name: string; color: string; size?: 'sm' | 'md' | 'lg' }) {
  const initials = (name || 'U').split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
  const sizes = { sm: 'w-8 h-8 text-xs', md: 'w-12 h-12 text-lg', lg: 'w-20 h-20 text-2xl' }
  return (
    <div
      className={`${sizes[size]} rounded-full flex items-center justify-center font-bold text-white`}
      style={{ backgroundColor: color }}
    >
      {initials}
    </div>
  )
}

const GUIDE_STEPS = [
  { title: 'View your profile', desc: 'See your RobustID badge, role, organization, activity stats, preferred model, timezone, and ORCID. Your RobustID is a unique identifier for attribution and collaboration.' },
  { title: 'Edit your details', desc: 'Click the Edit button to update your name, organization, specialization, bio, use case, preferred detection model, timezone, ORCID, and avatar color.' },
  { title: 'Share your RobustID', desc: 'Copy your RobustID (e.g., ROB-A7X2) to share with teammates, embed in reports, or reference in SOC Copilot conversations for collaboration.' },
]

export default function Profile() {
  const localUser = getUser()
  const [profile, setProfile] = useState<ProfileData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [copied, setCopied] = useState(false)

  // Editable fields
  const [fullName, setFullName] = useState('')
  const [organization, setOrganization] = useState('')
  const [specialization, setSpecialization] = useState('')
  const [bio, setBio] = useState('')
  const [useCase, setUseCase] = useState('')
  const [avatarColor, setAvatarColor] = useState(AVATAR_COLORS[0])
  const [preferredModel, setPreferredModel] = useState('surrogate')
  const [timezone, setTimezone] = useState('UTC')
  const [orcid, setOrcid] = useState('')

  const loadProfile = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await fetchProfile()
      setProfile(data)
      setFullName(data.full_name || '')
      setOrganization(data.organization || '')
      setSpecialization(data.specialization || '')
      setBio(data.bio || '')
      setUseCase(data.use_case || '')
      setAvatarColor(data.avatar_color || AVATAR_COLORS[0])
      setPreferredModel(data.preferred_model || 'surrogate')
      setTimezone(data.timezone || 'UTC')
      setOrcid(data.orcid || '')
    } catch (err) {
      // Fall back to local user data
      if (localUser) {
        const fallback: ProfileData = {
          id: localUser.id,
          email: localUser.email,
          full_name: localUser.full_name,
          role: localUser.role,
          organization: localUser.organization || '',
          specialization: '',
          bio: '',
          use_case: localUser.use_case || '',
          avatar_color: AVATAR_COLORS[0],
          robust_id: `ROB-${String(localUser.id || 0).padStart(4, '0')}`,
          created_at: localUser.created_at || '',
          analyses_run: 0,
          actions_logged: 0,
          preferred_model: 'surrogate',
          timezone: 'UTC',
          orcid: '',
        }
        setProfile(fallback)
        setFullName(fallback.full_name)
        setOrganization(fallback.organization)
        setUseCase(fallback.use_case)
        setAvatarColor(fallback.avatar_color)
      } else {
        setError('Failed to load profile')
      }
    } finally {
      setLoading(false)
    }
  }, [localUser])

  useEffect(() => {
    loadProfile()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSave = async () => {
    try {
      setSaving(true)
      const data = await updateProfile({
        full_name: fullName,
        organization,
        specialization,
        bio,
        use_case: useCase,
        avatar_color: avatarColor,
        preferred_model: preferredModel,
        timezone,
        orcid,
      })
      setProfile(data)
      setEditing(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch {
      setError('Failed to save profile')
    } finally {
      setSaving(false)
    }
  }

  const handleCancel = () => {
    if (profile) {
      setFullName(profile.full_name || '')
      setOrganization(profile.organization || '')
      setSpecialization(profile.specialization || '')
      setBio(profile.bio || '')
      setUseCase(profile.use_case || '')
      setAvatarColor(profile.avatar_color || AVATAR_COLORS[0])
      setPreferredModel(profile.preferred_model || 'surrogate')
      setTimezone(profile.timezone || 'UTC')
      setOrcid(profile.orcid || '')
    }
    setEditing(false)
  }

  const handleCopyId = () => {
    const id = profile?.robust_id || `ROB-${String(profile?.id || 0).padStart(4, '0')}`
    navigator.clipboard.writeText(id)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const robustId = profile?.robust_id || `ROB-${String(profile?.id || 0).padStart(4, '0')}`
  const memberSince = profile?.created_at
    ? new Date(profile.created_at).toLocaleDateString('en-US', { month: 'long', year: 'numeric' })
    : 'N/A'

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <Loader2 className="w-6 h-6 animate-spin text-accent-blue" />
        <span className="ml-2 text-text-secondary text-sm">Loading profile...</span>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <PageGuide
        title="My Profile"
        steps={GUIDE_STEPS}
        tip="Your RobustID is a unique identifier used across the platform for attribution and collaboration."
      />

      {/* Success toast */}
      {saved && (
        <div className="flex items-center gap-2 px-4 py-2.5 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green text-sm">
          <CheckCircle2 className="w-4 h-4" />
          Profile updated successfully
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 px-4 py-2.5 bg-accent-red/10 border border-accent-red/30 rounded-lg text-accent-red text-sm">
          {error}
        </div>
      )}

      {/* Profile Header Card */}
      <div className="bg-bg-card border border-border-primary rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
          <Avatar
            name={editing ? fullName : (profile?.full_name || '')}
            color={editing ? avatarColor : (profile?.avatar_color || AVATAR_COLORS[0])}
            size="lg"
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-xl font-bold text-text-primary">
                {profile?.full_name || profile?.email || 'User'}
              </h1>
              <span className="px-2.5 py-0.5 bg-accent-blue/15 text-accent-blue rounded text-[11px] font-semibold uppercase tracking-wide">
                {profile?.role || 'analyst'}
              </span>
            </div>
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-bg-secondary rounded-full border border-border-primary">
                <Shield className="w-3.5 h-3.5 text-accent-blue" />
                <span className="text-xs font-mono font-semibold text-text-primary tracking-wide">{robustId}</span>
              </span>
              <button
                onClick={handleCopyId}
                className="text-xs text-accent-blue hover:text-accent-blue/80 transition-colors font-medium"
              >
                {copied ? 'Copied!' : 'Copy RobustID'}
              </button>
            </div>
            {profile?.organization && (
              <div className="flex items-center gap-1.5 mt-2 text-sm text-text-secondary">
                <Building2 className="w-3.5 h-3.5" />
                {profile.organization}
              </div>
            )}
            <div className="flex items-center gap-1.5 mt-1 text-xs text-text-secondary/70">
              <Clock className="w-3 h-3" />
              Member since {memberSince}
            </div>
          </div>
          <div>
            {!editing ? (
              <button
                onClick={() => setEditing(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-secondary hover:text-text-primary hover:border-accent-blue/30 transition-colors"
              >
                <Edit3 className="w-4 h-4" />
                Edit
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCancel}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-secondary hover:text-text-primary transition-colors"
                >
                  <X className="w-4 h-4" />
                  Cancel
                </button>
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-accent-blue text-white text-sm font-medium hover:bg-accent-blue/90 transition-colors disabled:opacity-50"
                >
                  {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                  Save
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Editable Details */}
        <div className="lg:col-span-2 bg-bg-card border border-border-primary rounded-xl p-6">
          <h2 className="text-sm font-semibold text-text-primary mb-4 flex items-center gap-2">
            <User className="w-4 h-4 text-accent-blue" />
            Profile Details
          </h2>
          <div className="space-y-4">
            {/* Full Name */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Full Name</label>
              {editing ? (
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors"
                  placeholder="Enter your full name"
                />
              ) : (
                <p className="text-sm text-text-primary">{profile?.full_name || '-'}</p>
              )}
            </div>

            {/* Organization */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Organization</label>
              {editing ? (
                <input
                  type="text"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors"
                  placeholder="Your organization or company"
                />
              ) : (
                <p className="text-sm text-text-primary">{profile?.organization || '-'}</p>
              )}
            </div>

            {/* Specialization */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Specialization</label>
              {editing ? (
                <select
                  value={specialization}
                  onChange={(e) => setSpecialization(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors"
                >
                  <option value="">Select specialization</option>
                  {SPECIALIZATIONS.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              ) : (
                <p className="text-sm text-text-primary">{profile?.specialization || '-'}</p>
              )}
            </div>

            {/* Bio */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">
                Bio {editing && <span className="text-text-secondary/50 font-normal">({bio.length}/500)</span>}
              </label>
              {editing ? (
                <textarea
                  value={bio}
                  onChange={(e) => { if (e.target.value.length <= 500) setBio(e.target.value) }}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors resize-none"
                  placeholder="Tell us about yourself and your work..."
                />
              ) : (
                <p className="text-sm text-text-primary whitespace-pre-wrap">{profile?.bio || '-'}</p>
              )}
            </div>

            {/* Use Case */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Use Case</label>
              {editing ? (
                <select
                  value={useCase}
                  onChange={(e) => setUseCase(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors"
                >
                  <option value="">Select use case</option>
                  {USE_CASES.map((u) => (
                    <option key={u} value={u}>{u}</option>
                  ))}
                </select>
              ) : (
                <p className="text-sm text-text-primary">{profile?.use_case || '-'}</p>
              )}
            </div>

            {/* Preferred Detection Model */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Preferred Detection Model</label>
              {editing ? (
                <select
                  value={preferredModel}
                  onChange={(e) => setPreferredModel(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors"
                >
                  <option value="surrogate">SurrogateIDS (7-Branch Ensemble)</option>
                  <option value="neural_ode">Neural ODE (TA-BN-ODE)</option>
                  <option value="optimal_transport">Optimal Transport (PPFOT-IDS)</option>
                  <option value="fedgtd">FedGTD (Byzantine-Resilient)</option>
                  <option value="sde_tgnn">SDE-TGNN (Stochastic)</option>
                  <option value="cybersec_llm">CyberSecLLM (Mamba-MoE)</option>
                  <option value="clrl_unified">CL-RL Unified</option>
                  <option value="multi_agent_pqc">Multi-Agent PQC-IDS</option>
                </select>
              ) : (
                <p className="text-sm text-text-primary">{profile?.preferred_model || 'surrogate'}</p>
              )}
            </div>

            {/* Timezone */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">Timezone</label>
              {editing ? (
                <select
                  value={timezone}
                  onChange={(e) => setTimezone(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary focus:outline-none focus:border-accent-blue/50 transition-colors"
                >
                  {['UTC', 'Europe/Moscow', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'US/Eastern', 'US/Central', 'US/Pacific', 'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Dubai', 'Asia/Kolkata', 'Africa/Lagos', 'Australia/Sydney'].map(tz => (
                    <option key={tz} value={tz}>{tz}</option>
                  ))}
                </select>
              ) : (
                <p className="text-sm text-text-primary">{profile?.timezone || 'UTC'}</p>
              )}
            </div>

            {/* ORCID */}
            <div>
              <label className="block text-xs font-medium text-text-secondary mb-1">
                ORCID
                {orcid && (
                  <a href={`https://orcid.org/${orcid}`} target="_blank" rel="noopener noreferrer" className="ml-2 text-accent-green hover:underline text-[9px]">
                    View on orcid.org
                  </a>
                )}
              </label>
              {editing ? (
                <input
                  type="text"
                  value={orcid}
                  onChange={(e) => setOrcid(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-bg-secondary border border-border-primary text-sm text-text-primary font-mono focus:outline-none focus:border-accent-blue/50 transition-colors placeholder:text-text-secondary/40"
                  placeholder="0000-0002-1825-0097"
                />
              ) : (
                <p className="text-sm text-text-primary font-mono">
                  {profile?.orcid ? (
                    <a href={`https://orcid.org/${profile.orcid}`} target="_blank" rel="noopener noreferrer" className="text-accent-green hover:underline">{profile.orcid}</a>
                  ) : '-'}
                </p>
              )}
            </div>

            {/* Avatar Color */}
            {editing && (
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-2 flex items-center gap-1.5">
                  <Palette className="w-3.5 h-3.5" />
                  Avatar Color
                </label>
                <div className="flex items-center gap-2 flex-wrap">
                  {AVATAR_COLORS.map((c) => (
                    <button
                      key={c}
                      onClick={() => setAvatarColor(c)}
                      className={`w-8 h-8 rounded-full border-2 transition-all ${
                        avatarColor === c ? 'border-white scale-110 ring-2 ring-accent-blue/50' : 'border-transparent hover:scale-105'
                      }`}
                      style={{ backgroundColor: c }}
                      title={c}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Activity Stats Panel */}
        <div className="bg-bg-card border border-border-primary rounded-xl p-6 h-fit">
          <h2 className="text-sm font-semibold text-text-primary mb-4 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-accent-blue" />
            Activity
          </h2>
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-accent-blue/10 flex items-center justify-center">
                <BarChart3 className="w-4 h-4 text-accent-blue" />
              </div>
              <div>
                <div className="text-lg font-bold text-text-primary">{profile?.analyses_run ?? 0}</div>
                <div className="text-[11px] text-text-secondary">Analyses Run</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-accent-green/10 flex items-center justify-center">
                <BookOpen className="w-4 h-4 text-accent-green" />
              </div>
              <div>
                <div className="text-lg font-bold text-text-primary">{profile?.actions_logged ?? 0}</div>
                <div className="text-[11px] text-text-secondary">Actions Logged</div>
              </div>
            </div>
            <div className="border-t border-border-primary pt-3 space-y-2.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Role</span>
                <span className="font-medium text-text-primary capitalize">{profile?.role || 'analyst'}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Member Since</span>
                <span className="font-medium text-text-primary">{memberSince}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">Email</span>
                <span className="font-medium text-text-primary truncate ml-2">{profile?.email || '-'}</span>
              </div>
              {profile?.specialization && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-secondary">Specialization</span>
                  <span className="font-medium text-text-primary">{profile.specialization}</span>
                </div>
              )}
              {profile?.use_case && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-secondary">Use Case</span>
                  <span className="font-medium text-text-primary">{profile.use_case}</span>
                </div>
              )}
              {profile?.preferred_model && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-secondary">Default Model</span>
                  <span className="font-medium text-text-primary">{profile.preferred_model}</span>
                </div>
              )}
              {profile?.timezone && profile.timezone !== 'UTC' && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-secondary">Timezone</span>
                  <span className="font-medium text-text-primary">{profile.timezone}</span>
                </div>
              )}
              {profile?.orcid && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-secondary">ORCID</span>
                  <a href={`https://orcid.org/${profile.orcid}`} target="_blank" rel="noopener noreferrer" className="font-medium text-accent-green hover:underline font-mono">{profile.orcid}</a>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
