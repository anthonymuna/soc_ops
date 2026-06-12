import { useState } from 'react'
import { Shield, Lock, User, AlertCircle, Settings, ArrowLeft, Cpu } from 'lucide-react'
import { login } from '../auth'

export default function LoginPage({ onLogin }) {
  const [role, setRole] = useState('user')

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (role === 'admin') {
      // Redirect to Django admin, ignoring JWT auth since Django admin uses session auth
      window.location.href = `http://${window.location.hostname}:8088/admin/`
      return
    }

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
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2
                        w-96 h-96 bg-sky-500/5 dark:bg-cyan-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 mb-4 bg-white/5 rounded-xl">
            <img src="/logo.jpeg" alt="Logo" className="w-full h-full object-contain rounded-xl shadow-md" />
          </div>
          <h1 className="text-2xl font-bold text-slate-800 dark:text-slate-100 tracking-widest">
            NGAO SOC
          </h1>
          <p className="text-slate-400 text-xs mt-1 tracking-wider uppercase">
            AI Cyber Threat Detection
          </p>
        </div>

        {/* Card */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-6 shadow-lg">
            
            <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-widest mb-6 flex items-center gap-2">
              <Cpu className="w-4 h-4" /> System Authentication
            </h2>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-xs text-cyan-400/70 uppercase tracking-wider mb-2 font-semibold">
                  Access Level
                </label>
                <div className="relative group">
                  <Shield className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-500/50 group-focus-within:text-cyan-400 transition-colors pointer-events-none" />
                  <select
                    value={role}
                    onChange={e => setRole(e.target.value)}
                    className="w-full bg-black/40 border border-cyan-500/20 rounded-lg pl-10 pr-3 py-3
                              text-sm text-cyan-100 placeholder-slate-600 appearance-none cursor-pointer
                              focus:outline-none focus:border-cyan-400
                              focus:ring-1 focus:ring-cyan-400/30
                              transition-all"
                  >
                    <option value="user" className="bg-[#0a0f18] text-cyan-100">SOC Analyst (User)</option>
                    <option value="admin" className="bg-[#0a0f18] text-cyan-100">System Admin</option>
                  </select>
                  <div className="absolute inset-y-0 right-3 flex items-center pointer-events-none">
                    <svg className="w-4 h-4 text-cyan-500/50 group-focus-within:text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path></svg>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-xs text-cyan-400/70 uppercase tracking-wider mb-2 font-semibold">
                  Username
                </label>
                <div className="relative group">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-500/50 group-focus-within:text-cyan-400 transition-colors pointer-events-none" />
                  <input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    required={role === 'user'}
                    autoFocus
                    autoComplete="username"
                    className="w-full bg-black/40 border border-cyan-500/20 rounded-lg pl-10 pr-3 py-3
                              text-sm text-cyan-100 placeholder-slate-600
                              focus:outline-none focus:border-cyan-400
                              focus:ring-1 focus:ring-cyan-400/30
                              transition-all"
                    placeholder="Enter your username"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-cyan-400/70 uppercase tracking-wider mb-2 font-semibold">
                  Password
                </label>
                <div className="relative group">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-500/50 group-focus-within:text-cyan-400 transition-colors pointer-events-none" />
                  <input
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required={role === 'user'}
                    autoComplete="current-password"
                    className="w-full bg-black/40 border border-cyan-500/20 rounded-lg pl-10 pr-3 py-3
                              text-sm text-cyan-100 placeholder-slate-600
                              focus:outline-none focus:border-cyan-400
                              focus:ring-1 focus:ring-cyan-400/30
                              transition-all"
                    placeholder="••••••••"
                  />
                </div>
              </div>

              {error && (
                <div className="flex items-center gap-2 rounded-lg px-4 py-3 text-xs
                              bg-rose-500/10 border border-rose-500/30 text-rose-400">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full font-bold text-sm rounded-lg py-3.5 transition-all duration-300
                          bg-cyan-500/10 hover:bg-cyan-400/20
                          border border-cyan-400/30 hover:border-cyan-400/60
                          text-cyan-400 hover:text-cyan-300 hover:shadow-[0_0_20px_rgba(0,255,255,0.2)]
                          disabled:opacity-50 disabled:cursor-not-allowed
                          focus:outline-none focus:ring-2 focus:ring-cyan-400/40 tracking-wider uppercase mt-2"
              >
                {loading ? 'Authenticating...' : (role === 'admin' ? 'Go to Admin Portal' : 'Initialize Session')}
              </button>
            </form>
        </div>

        <p className="text-center text-slate-400 text-[10px] mt-4 tracking-wider uppercase">
          Restricted access · Authorized personnel only
        </p>
      </div>
    </div>
  )
}
