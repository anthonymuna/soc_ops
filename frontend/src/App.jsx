import { useState, useCallback, useEffect } from 'react'
import { Shield, AlertTriangle, Database, Cpu, RefreshCw, Wifi, WifiOff, LogOut, Sun, Moon, FlaskConical, LayoutDashboard } from 'lucide-react'
import { useSOC } from './hooks/useSOC'
import { isLoggedIn, logout } from './auth'
import LoginPage from './components/LoginPage'
import StatCard from './components/StatCard'
import AlertFeed from './components/AlertFeed'
import MitreHeatmap from './components/MitreHeatmap'
import TimelineChart from './components/TimelineChart'
import ModelStatus from './components/ModelStatus'
import ModelTestPage from './components/ModelTestPage'
import ReportGenerator from './components/ReportGenerator'
import AlertMap from './components/AlertMap'

export default function App() {
  const [authed, setAuthed] = useState(isLoggedIn)
  const [dark, setDark] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
  }, [dark])

  const handleLogout = useCallback(async () => {
    await logout()
    setAuthed(false)
  }, [])

  const handleUnauth = useCallback(() => setAuthed(false), [])

  if (!authed) {
    return <LoginPage onLogin={() => setAuthed(true)} />
  }

  return <Dashboard onLogout={handleLogout} onUnauth={handleUnauth} dark={dark} onToggleTheme={() => setDark(d => !d)} />
}

function Dashboard({ onLogout, onUnauth, dark, onToggleTheme }) {
  const [tab, setTab] = useState('dashboard')
  const [selectedMitreId, setSelectedMitreId] = useState(null)
  const { health, stats, alerts, history, error, lastTick, refresh } = useSOC(10000, onUnauth)

  const isOnline = !error && health !== null
  const anomalyRate = stats
    ? ((stats.anomalies_detected / Math.max(stats.logs_scanned, 1)) * 100).toFixed(1)
    : null

  const criticalCount = alerts.filter(a => a.ml_severity === 'critical').length
  const highCount = alerts.filter(a => a.ml_severity === 'high').length

  return (
    <div className="min-h-screen grid-bg">
      {/* Header */}
      <header className="border-b border-soc-border bg-soc-panel/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-screen-xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/logo.jpeg" alt="Logo" className="w-8 h-8 object-contain rounded bg-white/5" />
            <span className="font-bold text-cyan-400 tracking-widest text-sm">NGAO SOC</span>
            <span className="text-slate-600 text-xs hidden sm:inline">AI-BASED CYBER THREAT DETECTION</span>
            <div className="hidden sm:flex items-center gap-1 ml-2">
              {[
                { id: 'dashboard', icon: <LayoutDashboard className="w-3 h-3" />, label: 'Dashboard' },
                { id: 'test', icon: <FlaskConical className="w-3 h-3" />, label: 'Model Tests' },
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs transition-colors ${tab === t.id
                    ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-500 hover:text-slate-300'
                    }`}
                >
                  {t.icon}{t.label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-4">
            <ReportGenerator stats={stats} alerts={alerts} history={history} health={health} />
            {criticalCount > 0 && (
              <span className="flex items-center gap-1 text-rose-400 text-xs font-bold animate-pulse">
                <AlertTriangle className="w-3 h-3" />
                {criticalCount} CRITICAL
              </span>
            )}
            <div className="flex items-center gap-1.5">
              {isOnline
                ? <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                : <WifiOff className="w-3.5 h-3.5 text-rose-400" />
              }
              <span className={`text-xs ${isOnline ? 'text-emerald-400' : 'text-rose-400'}`}>
                {isOnline ? 'LIVE' : 'OFFLINE'}
              </span>
            </div>
            <button
              onClick={onToggleTheme}
              className="text-slate-500 hover:text-cyan-400 transition-colors"
              title={dark ? 'Light mode' : 'Dark mode'}
            >
              {dark ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            </button>
            <button
              onClick={refresh}
              className="text-slate-500 hover:text-cyan-400 transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={onLogout}
              className="text-slate-500 hover:text-rose-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
            {lastTick && (
              <span className="text-slate-600 text-[10px] hidden sm:inline">
                {lastTick.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>
      </header>

      {error && (
        <div className="max-w-screen-xl mx-auto px-4 py-2">
          <div className="bg-rose-900/20 border border-rose-500/30 rounded text-rose-400 text-xs px-3 py-2">
            Connection error: {error} — ensure SSH tunnel is running: <code>./deploy.sh --tunnel</code>
          </div>
        </div>
      )}

      {tab === 'test' && <ModelTestPage onUnauth={onUnauth} />}

      <main className={`max-w-screen-xl mx-auto px-4 py-4 space-y-4 ${tab !== 'dashboard' ? 'hidden' : ''}`}>

        {/* Stat row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard
            label="Logs Scanned"
            value={(stats?.logs_scanned ?? 0).toLocaleString()}
            color="soc-accent"
            icon={<Database className="w-4 h-4" />}
          />
          <StatCard
            label="ML Alerts (60m)"
            value={alerts.length}
            sub={`${anomalyRate ?? 0}% anomaly rate`}
            color="soc-red"
            icon={<AlertTriangle className="w-4 h-4" />}
          />
          <StatCard
            label="Critical"
            value={criticalCount}
            color="soc-red"
          />
          <StatCard
            label="High"
            value={highCount}
            color="soc-yellow"
          />
          <StatCard
            label="Session Alerts"
            value={history.length}
            color="soc-purple"
          />
          <StatCard
            label="Model"
            value={health?.model_trained ? 'ACTIVE' : 'TRAINING'}
            sub={
              health?.zs_classifier_ready ? 'RF + GB + ZeroShot + IF' :
                health?.live_supervised ? 'RF + GB + IF' :
                  health?.nsl_kdd_trained ? 'RF + IF' :
                    'IsolationForest'
            }
            color={health?.model_trained ? 'soc-green' : 'soc-yellow'}
            icon={<Cpu className="w-4 h-4" />}
          />
        </div>

        {/* Timeline */}
        <TimelineChart history={history} dark={dark} />

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          
          {/* Left panel: MITRE Heatmap */}
          <div className="lg:col-span-1 space-y-4">
            <MitreHeatmap history={history} selectedMitreId={selectedMitreId} onSelectMitreId={setSelectedMitreId} />
          </div>

          {/* Alert feed — takes 2 cols (Middle) */}
          <div className="lg:col-span-2 h-96">
            <AlertFeed alerts={alerts} history={history} selectedMitreId={selectedMitreId} />
          </div>

          {/* Right panel */}
          <div className="lg:col-span-1 space-y-4">
            <AlertMap history={history} />
            <ModelStatus health={health} />

            {/* Scan errors / quick stats */}
            <div className="bg-soc-panel border border-soc-border rounded-lg p-4 space-y-2">
              <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest">System</div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {[
                  ['Scan errors', stats?.scan_errors ?? 0, stats?.scan_errors > 0 ? 'text-rose-400' : 'text-slate-500'],
                  ['Last scan', stats?.last_scan?.slice(11, 19) ?? '—', 'text-slate-400'],
                  ['Last train', health?.trained_at?.slice(11, 19) ?? '—', 'text-slate-400'],
                  ['ES online', health?.es_connected ? 'YES' : 'NO', health?.es_connected ? 'text-emerald-400' : 'text-rose-400'],
                ].map(([k, v, cls]) => (
                  <div key={k}>
                    <div className="text-slate-600">{k}</div>
                    <div className={cls}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* RF class breakdown */}
        {history.length > 0 && <AttackClassBreakdown history={history} />}

      </main>

      <footer className="border-t border-soc-border mt-8 py-3 text-center text-[10px] text-slate-700">
        NGAO SOC · AI-Based Cyber Threat Detection · Defensive SOC System
      </footer>
    </div>
  )
}

function AttackClassBreakdown({ history }) {
  const counts = {}
  for (const a of history) {
    const cls = a.ml_rf_class || 'unclassified'
    counts[cls] = (counts[cls] || 0) + 1
  }
  const total = Object.values(counts).reduce((s, v) => s + v, 0)
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1])

  const clsColor = {
    dos: 'bg-rose-500', probe: 'bg-amber-500', r2l: 'bg-orange-500',
    u2r: 'bg-red-600', normal: 'bg-emerald-500', unclassified: 'bg-slate-600',
  }

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4">
      <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest mb-3">
        RF Attack Classification (session)
      </div>
      <div className="space-y-2">
        {sorted.map(([cls, count]) => (
          <div key={cls} className="flex items-center gap-3">
            <span className="text-xs text-slate-400 w-20 capitalize">{cls}</span>
            <div className="flex-1 bg-soc-border rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full rounded-full ${clsColor[cls] || 'bg-slate-500'}`}
                style={{ width: `${(count / total) * 100}%` }}
              />
            </div>
            <span className="text-xs text-slate-500 w-12 text-right">
              {count} ({((count / total) * 100).toFixed(0)}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
