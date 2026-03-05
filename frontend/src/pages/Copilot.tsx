import { useState, useRef, useEffect } from 'react'
import { Send, Bot, User, Key, Loader2, Sparkles, X, Settings } from 'lucide-react'
import { authHeaders } from '../utils/auth'

interface Message {
  role: 'user' | 'assistant'
  content: string
  provider?: string
}

const API = import.meta.env.VITE_API_URL || ''

const SUGGESTIONS = [
  'Show me the threat summary',
  'What are the recent scan jobs?',
  'Show audit logs',
  'What can you do?',
]

export default function Copilot() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('robustidps_anthropic_key') || '')
  const [showSettings, setShowSettings] = useState(false)
  const [serverHasKey, setServerHasKey] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetch(`${API}/api/copilot/status`, { headers: authHeaders() })
      .then((r) => r.json())
      .then((d) => setServerHasKey(d.claude_configured))
      .catch(() => {})
  }, [])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const saveKey = (key: string) => {
    setApiKey(key)
    if (key) localStorage.setItem('robustidps_anthropic_key', key)
    else localStorage.removeItem('robustidps_anthropic_key')
  }

  const sendMessage = async (text?: string) => {
    const msg = text || input.trim()
    if (!msg || loading) return
    setInput('')

    const userMsg: Message = { role: 'user', content: msg }
    const newMessages = [...messages, userMsg]
    setMessages(newMessages)
    setLoading(true)

    try {
      const payload = {
        messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
        api_key: apiKey,
      }

      const res = await fetch(`${API}/api/copilot/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify(payload),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || `Error ${res.status}`)
      }

      const contentType = res.headers.get('content-type') || ''

      if (contentType.includes('text/event-stream')) {
        const reader = res.body?.getReader()
        const decoder = new TextDecoder()
        let fullContent = ''

        setMessages((prev) => [...prev, { role: 'assistant', content: '', provider: 'claude' }])

        if (reader) {
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            const text = decoder.decode(value, { stream: true })
            const lines = text.split('\n')
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.slice(6))
                  if (data.error) {
                    fullContent += `\n\n**Error:** ${data.error}`
                  } else if (data.content) {
                    fullContent += data.content
                  }
                  setMessages((prev) => {
                    const updated = [...prev]
                    updated[updated.length - 1] = { role: 'assistant', content: fullContent, provider: 'claude' }
                    return updated
                  })
                } catch {}
              }
            }
          }
        }
      } else {
        const data = await res.json()
        setMessages((prev) => [...prev, { role: 'assistant', content: data.content, provider: data.provider }])
      }
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'assistant', content: `**Error:** ${err instanceof Error ? err.message : 'Request failed'}`, provider: 'error' }])
    } finally {
      setLoading(false)
    }
  }

  const usingClaude = !!(apiKey || serverHasKey)

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] md:h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <h1 className="text-xl md:text-2xl font-display font-bold">SOC Copilot</h1>
          <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${usingClaude ? 'bg-accent-blue/15 text-accent-blue' : 'bg-bg-card text-text-secondary'}`}>
            {usingClaude ? 'Claude AI' : 'Local Mode'}
          </span>
        </div>
        <button onClick={() => setShowSettings(!showSettings)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-text-secondary hover:text-text-primary hover:bg-bg-card/50 transition-colors">
          <Settings className="w-3.5 h-3.5" /> API Key
        </button>
      </div>

      {/* API Key Settings */}
      {showSettings && (
        <div className="mb-4 p-4 bg-bg-secondary rounded-xl border border-bg-card">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-accent-amber" />
              <span className="text-sm font-medium text-text-primary">Anthropic API Key</span>
            </div>
            <button onClick={() => setShowSettings(false)} className="text-text-secondary hover:text-text-primary"><X className="w-4 h-4" /></button>
          </div>
          <p className="text-xs text-text-secondary mb-3">
            Add your Anthropic API key for full Claude-powered analysis with tool-use. Without a key, the copilot runs in local mode with structured data lookups.
            {serverHasKey && <span className="text-accent-green"> Server-side key is configured.</span>}
          </p>
          <div className="flex gap-2">
            <input
              type="password"
              value={apiKey}
              onChange={(e) => saveKey(e.target.value)}
              placeholder="sk-ant-..."
              className="flex-1 px-3 py-2 bg-bg-primary border border-bg-card rounded-lg text-text-primary text-sm focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
            />
            {apiKey && (
              <button onClick={() => saveKey('')} className="px-3 py-2 text-xs text-accent-red hover:bg-accent-red/10 rounded-lg">Clear</button>
            )}
          </div>
        </div>
      )}

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto space-y-4 pb-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <Bot className="w-12 h-12 text-accent-blue/30 mb-4" />
            <h2 className="text-lg font-semibold text-text-primary mb-2">RobustIDPS.ai SOC Copilot</h2>
            <p className="text-sm text-text-secondary mb-6 max-w-md">
              Your AI security analyst. Ask about threats, investigate scan results, generate reports, or get remediation advice.
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button key={s} onClick={() => sendMessage(s)} className="px-3 py-1.5 bg-bg-card/50 border border-bg-card rounded-lg text-xs text-text-secondary hover:text-accent-blue hover:border-accent-blue/30 transition-colors">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
            {msg.role === 'assistant' && (
              <div className="shrink-0 w-7 h-7 rounded-full bg-accent-blue/15 flex items-center justify-center">
                {msg.provider === 'claude' ? <Sparkles className="w-3.5 h-3.5 text-accent-blue" /> : <Bot className="w-3.5 h-3.5 text-accent-blue" />}
              </div>
            )}
            <div className={`max-w-[80%] px-4 py-3 rounded-xl text-sm leading-relaxed ${
              msg.role === 'user'
                ? 'bg-accent-blue text-white rounded-br-sm'
                : 'bg-bg-secondary border border-bg-card text-text-primary rounded-bl-sm'
            }`}>
              {msg.role === 'assistant' ? (
                <div className="prose prose-sm prose-invert max-w-none [&_strong]:text-text-primary [&_code]:text-accent-blue [&_code]:bg-bg-card/50 [&_code]:px-1 [&_code]:rounded" dangerouslySetInnerHTML={{ __html: msg.content.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br/>').replace(/- (.*?)(<br\/>|$)/g, '<li>$1</li>').replace(/(<li>.*<\/li>)/g, '<ul class="list-disc list-inside space-y-0.5 my-1">$1</ul>') }} />
              ) : (
                msg.content
              )}
              {msg.provider && msg.role === 'assistant' && (
                <div className="mt-2 text-[10px] text-text-secondary opacity-60">
                  via {msg.provider === 'claude' ? 'Claude AI' : 'local engine'}
                </div>
              )}
            </div>
            {msg.role === 'user' && (
              <div className="shrink-0 w-7 h-7 rounded-full bg-accent-blue/30 flex items-center justify-center">
                <User className="w-3.5 h-3.5 text-accent-blue" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="shrink-0 w-7 h-7 rounded-full bg-accent-blue/15 flex items-center justify-center">
              <Loader2 className="w-3.5 h-3.5 text-accent-blue animate-spin" />
            </div>
            <div className="px-4 py-3 bg-bg-secondary border border-bg-card rounded-xl rounded-bl-sm">
              <div className="flex gap-1">
                <div className="w-2 h-2 bg-accent-blue/40 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-2 h-2 bg-accent-blue/40 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-2 h-2 bg-accent-blue/40 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="pt-3 border-t border-bg-card">
        <form onSubmit={(e) => { e.preventDefault(); sendMessage() }} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about threats, scan results, or security advice..."
            className="flex-1 px-4 py-3 bg-bg-secondary border border-bg-card rounded-xl text-sm text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-blue/50"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-3 bg-accent-blue text-white rounded-xl hover:bg-accent-blue/90 disabled:opacity-50 transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  )
}
