import { useState, useCallback, useEffect } from 'react'
import { Shield, AlertTriangle, Database, Cpu, RefreshCw, Wifi, WifiOff, LogOut, Sun, Moon, FlaskConical, LayoutDashboard, Settings, X, Menu, ChevronDown } from 'lucide-react'
import { useSOC } from './hooks/useSOC'
import { isLoggedIn, logout, getToken, updateUserCards } from './auth'
import LoginPage from './components/LoginPage'
import StatCard from './components/StatCard'
import AlertFeed from './components/AlertFeed'
import MitreHeatmap from './components/MitreHeatmap'
import TimelineChart from './components/TimelineChart'
import ModelStatus from './components/ModelStatus'
import ModelTestPage from './components/ModelTestPage'
import ReportGenerator from './components/ReportGenerator'
import AlertMap from './components/AlertMap'
import PredictiveAnalysis from './components/PredictiveAnalysis'
import ThreatIntelligence from './components/ThreatIntelligence'
const ALL_CARDS = [
  { id: 'stat_logs', label: 'Logs Scanned (Stat)' },
  { id: 'stat_alerts', label: 'ML Alerts (Stat)' },
  { id: 'stat_critical', label: 'Critical Alerts (Stat)' },
  { id: 'stat_high', label: 'High Alerts (Stat)' },
  { id: 'stat_session', label: 'Session Alerts (Stat)' },
  { id: 'stat_model', label: 'Model Status (Stat)' },
  { id: 'timeline', label: 'Timeline Chart' },
  { id: 'heatmap', label: 'MITRE Heatmap' },
  { id: 'alert_feed', label: 'Alert Feed' },
  { id: 'alert_map', label: 'Geo Map' },
  { id: 'model_status', label: 'Detailed Model Status' },
  { id: 'class_breakdown', label: 'Attack Class Breakdown' }
]

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
  const [selectedConnector, setSelectedConnector] = useState('wazuh')
  const [showConnectorMenu, setShowConnectorMenu] = useState(false)
  const { health, stats, alerts, history, error, lastTick, refresh } = useSOC(10000, onUnauth, selectedConnector)
  
  const [user, setUser] = useState(null)
  const [showSettings, setShowSettings] = useState(false)
  const [visibleCards, setVisibleCards] = useState([])
  const [alertFilter, setAlertFilter] = useState('all')

  useEffect(() => {
    const fetchUser = async () => {
      const token = getToken()
      if (!token) return
      try {
        const r = await fetch('/api/auth/me/', { headers: { Authorization: `Bearer ${token}` } })
        if (r.ok) {
          const d = await r.json()
          setUser(d)
          setVisibleCards(d.visible_cards || [])
        }
      } catch(e) {}
    }
    fetchUser()
  }, [])

  const toggleCard = (cardId) => {
    setVisibleCards(prev => {
      let next = []
      if (prev.length === 0) {
        next = ALL_CARDS.map(c => c.id).filter(id => id !== cardId)
      } else if (prev.includes(cardId)) {
        next = prev.filter(id => id !== cardId)
      } else {
        next = [...prev, cardId]
      }
      updateUserCards(next)
      return next
    })
  }

  const isVisible = (id) => visibleCards.length === 0 || visibleCards.includes(id)

  const isOnline = !error && health !== null
  const anomalyRate = stats
    ? ((stats.anomalies_detected / Math.max(stats.logs_scanned, 1)) * 100).toFixed(1)
    : null

  const criticalCount = alerts.filter(a => a.ml_severity === 'critical').length
  const highCount = alerts.filter(a => a.ml_severity === 'high').length

  return (
    <div className="min-h-screen grid-bg relative">
      {/* Header */}
      <header className="border-b border-soc-border bg-soc-panel/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-screen-xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <button 
                onClick={() => setShowConnectorMenu(!showConnectorMenu)}
                className="flex items-center gap-2 text-slate-300 hover:text-cyan-400 transition-colors bg-soc-panel/50 px-2 py-1.5 rounded border border-soc-border hover:border-cyan-500/50"
              >
                <Menu className="w-5 h-5" />
                <span className="text-xs font-bold uppercase tracking-wider hidden sm:inline">
                  {selectedConnector === 'umbrella' ? 'Cisco Umbrella' : 
                   selectedConnector === 'predictive_analysis' ? 'Predictive Analysis' :
                   selectedConnector === 'threat_intelligence' ? 'Threat Intelligence' : 
                   selectedConnector}
                </span>
                <ChevronDown className="w-3 h-3" />
              </button>
              {showConnectorMenu && (
                <div className="absolute top-full left-0 mt-2 w-48 bg-soc-bg border border-soc-border rounded shadow-xl overflow-hidden z-50">
                  {['wazuh', 'fortisiem', 'umbrella', 'predictive_analysis', 'threat_intelligence'].map(c => (
                    <button
                      key={c}
                      onClick={() => { setSelectedConnector(c); setShowConnectorMenu(false); }}
                      className={`w-full text-left px-4 py-2 text-xs uppercase tracking-wider transition-colors ${selectedConnector === c ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:bg-soc-panel hover:text-slate-200'}`}
                    >
                      {c === 'umbrella' ? 'Cisco Umbrella' : 
                       c === 'predictive_analysis' ? 'Predictive Analysis' :
                       c === 'threat_intelligence' ? 'Threat Intelligence' : 
                       c}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <img src="/logo.jpeg" alt="Logo" className="w-8 h-8 object-contain rounded bg-white/5" />
            <span className="font-bold text-cyan-400 tracking-widest text-sm hidden sm:inline">NGAO SOC</span>
            <span className="text-slate-600 text-xs hidden lg:inline">AI-BASED CYBER THREAT DETECTION</span>
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
              onClick={() => setShowSettings(true)}
              className="text-slate-500 hover:text-cyan-400 transition-colors"
              title="Dashboard Settings"
            >
              <Settings className="w-3.5 h-3.5" />
            </button>
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
          {isVisible('stat_logs') && (
            <StatCard
              label="Logs Scanned"
              value={(stats?.logs_scanned ?? 0).toLocaleString()}
              color="soc-accent"
              icon={<Database className="w-4 h-4" />}
            />
          )}
          {isVisible('stat_alerts') && (
            <StatCard
              label="ML Alerts (60m)"
              value={alerts.length}
              sub={`${anomalyRate ?? 0}% anomaly rate`}
              color="soc-red"
              icon={<AlertTriangle className="w-4 h-4" />}
              onClick={() => { setAlertFilter('all'); setSelectedMitreId(null); document.getElementById('alert-feed')?.scrollIntoView({ behavior: 'smooth' }); }}
            />
          )}
          {isVisible('stat_critical') && (
            <StatCard
              label="Critical"
              value={criticalCount}
              color="soc-red"
              onClick={() => { setAlertFilter('critical'); setSelectedMitreId(null); document.getElementById('alert-feed')?.scrollIntoView({ behavior: 'smooth' }); }}
            />
          )}
          {isVisible('stat_high') && (
            <StatCard
              label="High"
              value={highCount}
              color="soc-yellow"
              onClick={() => { setAlertFilter('high'); setSelectedMitreId(null); document.getElementById('alert-feed')?.scrollIntoView({ behavior: 'smooth' }); }}
            />
          )}
          {isVisible('stat_session') && (
            <StatCard
              label="Session Alerts"
              value={history.length}
              color="soc-purple"
            />
          )}
          {isVisible('stat_model') && (
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
          )}
        </div>

        {/* Timeline */}
        {isVisible('timeline') && <TimelineChart history={history} dark={dark} />}

        {/* Main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          
          {/* Left panel: MITRE Heatmap & System Status */}
          <div className="lg:col-span-1 space-y-4 flex flex-col">
            {isVisible('heatmap') && <MitreHeatmap history={history} selectedMitreId={selectedMitreId} onSelectMitreId={setSelectedMitreId} />}

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

          {/* Alert feed — takes 2 cols (Middle) */}
          <div id="alert-feed" className="lg:col-span-2 relative min-h-[24rem]">
            <div className="absolute inset-0 flex flex-col">
              {selectedConnector === 'predictive_analysis' ? (
                <PredictiveAnalysis onUnauth={onUnauth} />
              ) : selectedConnector === 'threat_intelligence' ? (
                <ThreatIntelligence onUnauth={onUnauth} />
              ) : (
                isVisible('alert_feed') && <AlertFeed alerts={alerts} history={history} selectedMitreId={selectedMitreId} filter={alertFilter} onFilterChange={setAlertFilter} />
              )}
            </div>
          </div>

          {/* Right panel */}
          <div className="lg:col-span-1 space-y-4">
            {isVisible('alert_map') && <AlertMap history={history} />}
            {isVisible('model_status') && <ModelStatus health={health} />}
          </div>
        </div>

        {/* RF class breakdown */}
        {isVisible('class_breakdown') && history.length > 0 && <AttackClassBreakdown history={history} />}

      </main>

      <footer className="border-t border-soc-border mt-8 py-3 text-center text-[10px] text-slate-700">
        NGAO SOC · AI-Based Cyber Threat Detection · Defensive SOC System
      </footer>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
          <div className="bg-soc-bg border border-soc-border rounded-lg shadow-2xl w-full max-w-md overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-soc-border bg-soc-panel">
              <h3 className="text-sm font-bold text-cyan-400 tracking-wider">DASHBOARD SETTINGS</h3>
              <button onClick={() => setShowSettings(false)} className="text-slate-500 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <p className="text-xs text-slate-400 mb-4">
                Select which cards you want to display on your dashboard. Your preferences are saved automatically.
              </p>
              <div className="space-y-2 max-h-96 overflow-y-auto pr-2">
                {ALL_CARDS.map(card => (
                  <label key={card.id} className="flex items-center gap-3 p-2 rounded bg-soc-panel/50 hover:bg-soc-panel border border-transparent hover:border-soc-border cursor-pointer transition-colors">
                    <input
                      type="checkbox"
                      className="rounded bg-black border-soc-border text-cyan-500 focus:ring-cyan-500/30 w-4 h-4"
                      checked={isVisible(card.id)}
                      onChange={() => toggleCard(card.id)}
                    />
                    <span className="text-sm text-slate-300">{card.label}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="p-4 border-t border-soc-border bg-soc-panel flex justify-end">
              <button onClick={() => setShowSettings(false)} className="px-4 py-1.5 bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 rounded text-xs font-bold tracking-wider transition-colors">
                DONE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function AttackClassBreakdown({ history }) {
  const counts = {}
  for (const a of history) {
    let cls = a.ml_rf_class || 'unclassified'
    if (cls === 'unknown_anomaly') cls = 'unclassified'
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
            <span className="text-xs text-slate-400 w-24 truncate capitalize">{cls}</span>
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
