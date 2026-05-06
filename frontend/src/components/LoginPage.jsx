import { useState } from 'react'
import { Shield, Lock, User, AlertCircle } from 'lucide-react'
import { login } from '../auth'

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      onLogin()
    } catch (err) {
      setError(err.message || 'Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center p-4">
      {/* Ambient glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan-400/10 border border-cyan-400/20 mb-4">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-widest">SYNDICATE4</h1>
          <p className="text-slate-500 text-xs mt-1 tracking-wider uppercase">
            AI Cyber Threat Detection
          </p>
        </div>

        {/* Card */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-6 shadow-2xl">
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-widest mb-5">
            SOC Access
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                  autoFocus
                  autoComplete="username"
                  className="w-full bg-soc-bg border border-soc-border rounded-lg pl-9 pr-3 py-2.5
                             text-sm text-slate-200 placeholder-slate-600
                             focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                             transition-colors"
                  placeholder="username"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                  className="w-full bg-soc-bg border border-soc-border rounded-lg pl-9 pr-3 py-2.5
                             text-sm text-slate-200 placeholder-slate-600
                             focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20
                             transition-colors"
                  placeholder="••••••••"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 bg-rose-500/10 border border-rose-500/30
                              rounded-lg px-3 py-2 text-rose-400 text-xs">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-cyan-400/10 hover:bg-cyan-400/20 border border-cyan-400/30
                         hover:border-cyan-400/60 text-cyan-400 font-bold text-sm
                         rounded-lg py-2.5 transition-all duration-200
                         disabled:opacity-50 disabled:cursor-not-allowed
                         focus:outline-none focus:ring-2 focus:ring-cyan-400/30"
            >
              {loading ? 'AUTHENTICATING...' : 'ACCESS SYSTEM'}
            </button>
          </form>
        </div>

        <p className="text-center text-slate-700 text-[10px] mt-4 tracking-wider uppercase">
          Restricted access · Authorized personnel only
        </p>
      </div>
    </div>
  )
}
