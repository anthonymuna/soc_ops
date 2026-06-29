import { useState, useCallback, useEffect } from 'react'
import { 
  Shield, AlertTriangle, Database, Cpu, Search, Bell, LogOut, 
  Settings, Layers, Map, Activity, Clock, FileText, Crosshair, ChevronDown, User as UserIcon, Brain
} from 'lucide-react'
import { useSOC } from './hooks/useSOC'
import { isLoggedIn, logout, getToken, updateUserCards } from './auth'
import LoginPage from './components/LoginPage'
import AlertFeed from './components/AlertFeed'
import MitreHeatmap from './components/MitreHeatmap'
import TimelineChart from './components/TimelineChart'
import SystemHealth from './components/SystemHealth'
import TriageQueue from './components/TriageQueue'
import ChatPanel from './components/ChatPanel'
import ThreatIntelligence from './components/ThreatIntelligence'
import ThreatHunting from './components/ThreatHunting'
import PredictiveAnalysis from './components/PredictiveAnalysis'
import ReportGenerator from './components/ReportGenerator'
import SettingsView from './components/Settings'
import ThreatMap from './components/ThreatMap'

const CONNECTORS = [
  { id: 'wazuh', label: 'Wazuh' },
  // { id: 'fortisiem', label: 'FortiSIEM' },
  // { id: 'umbrella', label: 'Cisco Umbrella' },
  // { id: 'predictive_analysis', label: 'Predictive Analysis' },
  // { id: 'threat_intelligence', label: 'Threat Intel' }
];

export default function App() {
  const [authed, setAuthed] = useState(isLoggedIn)
  const [dark, setDark] = useState(true)

  useEffect(() => {
    const theme = localStorage.getItem('theme');
    if (theme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  }, [])

  const handleLogout = useCallback(async () => {
    await logout()
    setAuthed(false)
  }, [])
  
  const handleUnauth = useCallback(() => setAuthed(false), [])

  // Auto-logout due to inactivity (15 minutes)
  useEffect(() => {
    if (!authed) return;

    let timeoutId;
    const INACTIVITY_LIMIT = 15 * 60 * 1000; // 15 minutes

    const resetTimer = () => {
      if (timeoutId) clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        handleLogout();
        alert("You have been automatically signed out due to inactivity for security purposes.");
      }, INACTIVITY_LIMIT);
    };

    // Initialize timer
    resetTimer();

    // Listeners for user interaction
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    
    // Use throttling to prevent excessive reset calls if needed, but a simple clear/set is fine.
    const handleActivity = () => resetTimer();

    events.forEach(event => document.addEventListener(event, handleActivity));

    return () => {
      if (timeoutId) clearTimeout(timeoutId);
      events.forEach(event => document.removeEventListener(event, handleActivity));
    };
  }, [authed, handleLogout]);

  if (!authed) {
    return <LoginPage onLogin={() => setAuthed(true)} />
  }

  return <Dashboard onLogout={handleLogout} onUnauth={handleUnauth} />
}

function Dashboard({ onLogout, onUnauth }) {
  const [tab, setTab] = useState('dashboard')
  const [selectedMitreId, setSelectedMitreId] = useState(null)
  const [selectedConnector, setSelectedConnector] = useState('wazuh')
  const [timeframe, setTimeframe] = useState('live')
  const { health, stats, alerts, history, error, lastTick } = useSOC(10000, onUnauth, selectedConnector, timeframe)
  const [alertFilter, setAlertFilter] = useState('all')
  const [savedAlerts, setSavedAlerts] = useState(new Set())

  const handleInvestigate = useCallback((alert) => {
    const mitreId = alert.mitre_id || 'T1059'
    const srcIp = alert.src_ip || 'unknown'
    const agent = alert.agent_name || (alert.agent && alert.agent.name) || alert.hostname || alert.computer_name || 'N/A'
    const eventType = alert.event_type || 'Anomaly'
    
    const msg = `Investigate alert: MITRE ID ${mitreId} (${eventType}) detected from agent "${agent}" (Source IP: ${srcIp}). Please analyze this incident.`
    
    const event = new CustomEvent('ai-investigate', {
      detail: { message: msg }
    })
    window.dispatchEvent(event)
  }, [])

  const handleSaveIncident = useCallback(async (alert) => {
    const alertId = alert.id || alert._id || `${alert.ml_detected_at}${alert.src_ip}${alert.event_type}`;
    const token = getToken();
    if (!token) return;
    
    try {
      const resp = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/feedback/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          label: 'threat',
          comment: `Investigation: ${alert.explanation || alert.message || 'Identified as ML anomaly.'}`
        })
      });
      if (resp.ok) {
        setSavedAlerts(prev => {
          const next = new Set(prev)
          next.add(alertId)
          return next
        })
      }
    } catch (e) {
      console.error("Failed to save alert:", e);
    }
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100 font-sans">
      {/* Top Header */}
      <header className="h-16 bg-[#0e1522] border-b border-slate-800 flex items-center justify-between px-6 shrink-0 z-50">
        
        {/* Left: Brand */}
        <div className="flex items-center gap-3">
          <div className="relative alert-teal-glow rounded-full p-1.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <Shield className="w-5 h-5" />
          </div>
          <span className="font-bold text-slate-100 tracking-wider text-sm uppercase">NGAO SOC</span>
        </div>

        {/* Center: Tabs */}
        <div className="hidden md:flex items-center gap-6">
          {[
            { id: 'dashboard', icon: <Layers className="w-4 h-4" />, label: 'Dashboard' },
            { id: 'incidents', icon: <AlertTriangle className="w-4 h-4" />, label: 'Incidents' },
            { id: 'predictive_analysis', icon: <Brain className="w-4 h-4" />, label: 'Predictive Analysis' },
            { id: 'threat_intel', icon: <Activity className="w-4 h-4" />, label: 'Threat Intel' },
            { id: 'hunt', icon: <Crosshair className="w-4 h-4" />, label: 'Hunt' },
            { id: 'reports', icon: <FileText className="w-4 h-4" />, label: 'Reports' }
          ].map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 pb-1 border-b-2 text-[11px] font-semibold uppercase tracking-widest transition-all ${
                tab === t.id
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {t.icon}
              <span>{t.label}</span>
            </button>
          ))}
        </div>

        {/* Right: Controls & Profile */}
        <div className="flex items-center gap-5">
          {/* Connector Selector */}
          <div className="flex items-center gap-2 bg-[#151c2b] border border-slate-800 rounded-md px-3 py-1.5 cursor-pointer relative group">
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-widest">
              Connector: <span className="text-cyan-400">{CONNECTORS.find(c => c.id === selectedConnector)?.label}</span>
            </span>
            <ChevronDown className="w-3 h-3 text-slate-500" />
            
            {/* Dropdown Menu */}
            <div className="absolute top-full right-0 mt-1 w-48 bg-[#0e1522] border border-slate-700/80 rounded shadow-xl hidden group-hover:block z-50">
              {CONNECTORS.map(c => (
                <div 
                  key={c.id} 
                  onClick={() => setSelectedConnector(c.id)}
                  className={`px-3 py-2 text-xs font-bold uppercase tracking-wider cursor-pointer transition-colors ${
                    selectedConnector === c.id ? 'bg-cyan-500/10 text-cyan-400' : 'text-slate-400 hover:bg-[#151c2b] hover:text-slate-200'
                  }`}
                >
                  {c.label}
                </div>
              ))}
            </div>
          </div>
          
          <div className="flex items-center gap-3 pl-4 border-l border-slate-700/50">
            <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-slate-300">
              <UserIcon className="w-4 h-4" />
            </div>
            <div className="hidden sm:flex flex-col">
              <span className="text-xs font-semibold text-slate-200">SOC Analyst</span>
              <span className="text-[9px] text-slate-500 font-mono">Tier-1 • {new Date().toLocaleTimeString('en-US', { hour12: false })}</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* Thin Sidebar */}
        <aside className="w-16 bg-[#0e1522] border-r border-slate-800 flex flex-col items-center py-6 shrink-0 z-40 justify-between">
          <div className="space-y-6">
            {[
              { id: 'dashboard', icon: <Layers className="w-5 h-5" /> },
              { id: 'map', icon: <Map className="w-5 h-5" /> },
              { id: 'settings', icon: <Settings className="w-5 h-5" /> },
            ].map(item => (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`w-10 h-10 flex items-center justify-center rounded-xl transition-all ${
                  tab === item.id ? 'bg-cyan-500/20 text-cyan-400 shadow-[0_0_12px_rgba(0,173,181,0.3)]' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50'
                }`}
              >
                {item.icon}
              </button>
            ))}
          </div>
          <button onClick={onLogout} className="w-10 h-10 flex items-center justify-center rounded-xl text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-all">
            <LogOut className="w-5 h-5" />
          </button>
        </aside>

        {/* Content Area */}
        <main className="flex-1 p-6 overflow-y-auto bg-[#090d16]">
          {error && (
            <div className="mb-4 bg-rose-950/20 border border-rose-500/20 rounded-lg text-rose-400 text-xs px-4 py-2.5">
              Connection error: {error}
            </div>
          )}

          {tab === 'dashboard' && (
            <div className="grid grid-cols-12 gap-6 h-full auto-rows-max">
              
              {/* TOP ROW */}
              
              {/* Stats Summary (3 cols) */}
              <div className="col-span-12 lg:col-span-3 glass-panel p-5 rounded-xl border-slate-800 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-[0.2em] mb-4">Pipeline Stats</h3>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center border-b border-slate-800/60 pb-2">
                      <span className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Logs Scanned</span>
                      <span className="text-sm text-cyan-400 font-mono font-bold">{(stats?.logs_scanned ?? 0).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-slate-800/60 pb-2">
                      <span className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">ML Alerts</span>
                      <span className="text-sm text-amber-400 font-mono font-bold">{alerts.length}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-slate-800/60 pb-2">
                      <span className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">Critical</span>
                      <span className="text-sm text-rose-500 font-mono font-bold">{alerts.filter(a => a.ml_severity === 'critical').length}</span>
                    </div>
                  </div>
                </div>
                <div className="mt-4 pt-4 border-t border-slate-800/60 flex items-center justify-between text-[9px] font-mono">
                  <span className="text-slate-500 uppercase tracking-wider">Status: <span className={health?.es_connected ? 'text-teal-400' : 'text-rose-400'}>{health?.es_connected ? 'Online' : 'Offline'}</span></span>
                  <span className="text-slate-500">{lastTick?.toLocaleTimeString()}</span>
                </div>
              </div>

              {/* Threat Landscape Graph (6 cols) */}
              <div className="col-span-12 lg:col-span-6 glass-panel p-5 rounded-xl border-slate-800 flex flex-col">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-[0.2em]">Threat Landscape & Anomalies</h3>
                  <div className="flex items-center gap-2 bg-[#151c2b] border border-slate-800 rounded px-2 py-1 cursor-pointer">
                    <span className="text-[9px] text-slate-400">Period: <span className="text-slate-200">Last 24 Hours</span></span>
                    <ChevronDown className="w-3 h-3 text-slate-500" />
                  </div>
                </div>
                <div className="flex-1 min-h-[250px]">
                  <TimelineChart history={history} />
                </div>
              </div>

              {/* Live Incident Feed (3 cols) */}
              <div className="col-span-12 lg:col-span-3 glass-panel p-0 rounded-xl border-slate-800 overflow-hidden flex flex-col h-[330px]">
                <AlertFeed alerts={alerts} filter={alertFilter} onFilterChange={setAlertFilter} />
              </div>

              {/* BOTTOM ROW */}
              
              {/* Detailed Mitre Heatmap (6 cols) */}
              <div className="col-span-12 lg:col-span-6 h-[400px]">
                <MitreHeatmap history={alerts} selectedMitreId={selectedMitreId} onSelectMitreId={setSelectedMitreId} />
              </div>

              {/* Triage Queue (3 cols) */}
              <div className="col-span-12 lg:col-span-3 h-[400px] overflow-hidden">
                <TriageQueue onUnauth={onUnauth} />
              </div>

              {/* System Health (3 cols) */}
              <div className="col-span-12 lg:col-span-3 h-[400px]">
                <SystemHealth status={health || {}} logsScanned={stats?.logs_scanned || 0} />
              </div>

            </div>
          )}

          {(tab === 'incidents' || tab === 'alerts') && (
            <div className="space-y-6 h-full flex flex-col">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-slate-100 uppercase tracking-wider">Discovered Threats & Anomalies</h2>
                  <p className="text-xs text-slate-500 mt-1">Real-time alerts generated by Machine Learning detectors and SIEM integrations.</p>
                </div>
                <div className="flex items-center gap-2 bg-[#151c2b] border border-slate-800 rounded px-3 py-1.5 cursor-pointer">
                  <span className="text-[10px] text-slate-400 font-bold uppercase tracking-widest">Filter Severity:</span>
                  <select 
                    value={alertFilter} 
                    onChange={(e) => setAlertFilter(e.target.value)}
                    className="bg-transparent text-cyan-400 font-bold text-xs uppercase outline-none cursor-pointer border-none"
                  >
                    <option value="all">ALL SEVERITIES</option>
                    <option value="critical">CRITICAL</option>
                    <option value="high">HIGH</option>
                    <option value="medium">MEDIUM</option>
                    <option value="low">LOW</option>
                  </select>
                </div>
              </div>
              
              <div className="flex-1 glass-panel p-6 rounded-xl border-slate-800 overflow-y-auto">
                <div className="grid grid-cols-12 gap-6 h-full">
                  <div className="col-span-12 lg:col-span-8 flex flex-col h-full">
                    {/* Active Threats List */}
                    <div className="overflow-y-auto flex-1 space-y-4 pr-2 max-h-[70vh]">
                      {alerts.filter(a => alertFilter === 'all' || a.ml_severity === alertFilter).length === 0 ? (
                        <div className="py-20 text-center text-slate-500 font-mono text-sm uppercase tracking-widest">
                          No matching threats found.
                        </div>
                      ) : (
                        alerts.filter(a => alertFilter === 'all' || a.ml_severity === alertFilter).map((a, i) => {
                          const rawTs = a.ml_detected_at || a['@timestamp'] || ''
                          const ts = new Date(rawTs).toLocaleString()
                          const sev = a.ml_severity || 'info'
                          
                          return (
                            <div key={i} className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-5 hover:border-cyan-500/20 hover:shadow-lg transition-all flex flex-col md:flex-row md:items-center justify-between gap-4">
                              <div className="flex items-start gap-4">
                                <div className={`p-2 rounded-lg border shrink-0 ${
                                  sev === 'critical' ? 'bg-[#ff2e63]/10 border-[#ff2e63]/30 text-[#ff2e63]' :
                                  sev === 'high' ? 'bg-[#f9d342]/10 border-[#f9d342]/30 text-[#f9d342]' :
                                  sev === 'medium' ? 'bg-violet-500/10 border-violet-500/30 text-violet-400' :
                                  'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                                }`}>
                                  <AlertTriangle className="w-5 h-5" />
                                </div>
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2">
                                    <span className="text-xs font-mono font-bold text-slate-400">{a.mitre_id || 'T1059'}</span>
                                    <span className="text-sm font-semibold text-slate-100">{a.event_type || 'Anomaly Detection'}</span>
                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider font-mono ${
                                      sev === 'critical' ? 'bg-[#ff2e63]/10 border-[#ff2e63]/25 text-[#ff2e63]' :
                                      sev === 'high' ? 'bg-[#f9d342]/10 border-[#f9d342]/25 text-[#f9d342]' :
                                      sev === 'medium' ? 'bg-violet-500/10 border-violet-500/25 text-violet-400' :
                                      'bg-cyan-500/10 border-cyan-500/25 text-cyan-400'
                                    }`}>{sev}</span>
                                  </div>
                                  <p className="text-xs text-slate-400 leading-relaxed font-mono">{a.explanation || a.message || 'Anomaly detected in system logstream.'}</p>
                                  <div className="flex items-center gap-4 text-[10px] text-slate-500 pt-1">
                                    <span>Source IP: <span className="text-slate-300 font-mono">{a.src_ip || 'N/A'}</span></span>
                                    {a.dst_ip && <span>Dest IP: <span className="text-slate-300 font-mono">{a.dst_ip}</span></span>}
                                    <span>Agent: <span className="text-slate-300 font-mono">{a.agent_name || (a.agent && a.agent.name) || a.hostname || a.computer_name || 'N/A'}</span></span>
                                    <span>Time: <span className="text-slate-300 font-mono">{ts}</span></span>
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-center gap-2 shrink-0 md:self-center">
                                <button 
                                  onClick={() => handleInvestigate(a)}
                                  className="bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 hover:border-cyan-400 text-cyan-400 text-[10px] font-bold tracking-wider uppercase px-3 py-1.5 rounded transition-all"
                                >
                                  Investigate
                                </button>
                                {savedAlerts.has(a.id || a._id || `${a.ml_detected_at}${a.src_ip}${a.event_type}`) ? (
                                  <span className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold tracking-wider uppercase px-3 py-1.5 rounded flex items-center gap-1">
                                    ✓ Saved
                                  </span>
                                ) : (
                                  <button 
                                    onClick={() => handleSaveIncident(a)}
                                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 text-[10px] font-bold tracking-wider uppercase px-3 py-1.5 rounded transition-all"
                                  >
                                    Save to DB
                                  </button>
                                )}
                              </div>
                            </div>
                          )
                        })
                      )}
                    </div>
                  </div>
                  
                  {/* Sidebar stats/insights (4 cols) */}
                  <div className="col-span-12 lg:col-span-4 space-y-6">
                    <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 space-y-4">
                      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest">Severity Distribution</h3>
                      <div className="space-y-3 pt-2">
                        {[
                          { label: 'Critical', count: alerts.filter(a => a.ml_severity === 'critical').length, color: 'bg-rose-500', text: 'text-rose-400' },
                          { label: 'High', count: alerts.filter(a => a.ml_severity === 'high').length, color: 'bg-orange-500', text: 'text-orange-400' },
                          { label: 'Medium', count: alerts.filter(a => a.ml_severity === 'medium').length, color: 'bg-violet-500', text: 'text-violet-400' },
                          { label: 'Low', count: alerts.filter(a => a.ml_severity === 'low').length, color: 'bg-emerald-500', text: 'text-emerald-400' },
                        ].map((sev, idx) => (
                          <div key={idx} className="flex items-center justify-between text-xs">
                            <span className="text-slate-400">{sev.label}</span>
                            <div className="flex items-center gap-2">
                              <span className={`font-mono font-semibold ${sev.text}`}>{sev.count}</span>
                              <div className="w-24 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                                <div 
                                  className={`${sev.color} h-full`}
                                  style={{ width: `${alerts.length > 0 ? (sev.count / alerts.length) * 100 : 0}%` }}
                                />
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 space-y-3">
                      <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest">TTP Techniques</h3>
                      <div className="flex flex-wrap gap-2 pt-2">
                        {Array.from(new Set(alerts.flatMap(a => Array.isArray(a.mitre_id) ? a.mitre_id : [a.mitre_id]).filter(Boolean))).slice(0, 10).map((tech, idx) => (
                          <span key={idx} className="bg-slate-800/80 border border-slate-700/60 text-slate-300 px-2 py-1 rounded text-[10px] font-mono">
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {tab === 'threat_intel' && (
            <ThreatIntelligence onUnauth={onUnauth} />
          )}

          {tab === 'predictive_analysis' && (
            <PredictiveAnalysis onUnauth={onUnauth} />
          )}

          {tab === 'hunt' && (
            <ThreatHunting onUnauth={onUnauth} />
          )}

          {tab === 'reports' && (
            <ReportGenerator onUnauth={onUnauth} />
          )}

          {tab === 'map' && (
            <ThreatMap />
          )}

          {tab === 'settings' && (
            <SettingsView onUnauth={onUnauth} />
          )}

          {tab !== 'dashboard' && tab !== 'incidents' && tab !== 'map' && tab !== 'alerts' && tab !== 'threat_intel' && tab !== 'hunt' && tab !== 'predictive_analysis' && tab !== 'reports' && tab !== 'settings' && (
            <div className="flex items-center justify-center h-full text-slate-500 text-sm uppercase tracking-widest font-bold">
              {tab} view under construction
            </div>
          )}
        </main>
      </div>

      {/* Floating ChatPanel (Langchain AI) */}
      <ChatPanel onUnauth={onUnauth} />
    </div>
  )
}
