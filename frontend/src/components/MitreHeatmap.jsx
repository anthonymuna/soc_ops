import { useState } from 'react'
import { ShieldCheck, Info } from 'lucide-react'

const TECHNIQUES = [
  { id: 'T1046',     name: 'Net Scan',      tactic: 'Discovery',  defense: 'Network Traffic Filtering' },
  { id: 'T1018',     name: 'Remote Sys',    tactic: 'Discovery',  defense: 'System Network Configuration' },
  { id: 'T1049',     name: 'Net Conns',     tactic: 'Discovery',  defense: 'Host-based Traffic Analysis' },
  { id: 'T1057',     name: 'Proc Disc',     tactic: 'Discovery',  defense: 'Process Monitoring' },
  { id: 'T1082',     name: 'Sys Info',      tactic: 'Discovery',  defense: 'Operating System Monitoring' },
  { id: 'T1083',     name: 'File Disc',     tactic: 'Discovery',  defense: 'File Analysis' },
  { id: 'T1110',     name: 'Brute Force',   tactic: 'Credential', defense: 'Credential Rotation' },
  { id: 'T1110.001', name: 'Pwd Guess',     tactic: 'Credential', defense: 'Multi-factor Authentication' },
  { id: 'T1021',     name: 'Remote Svc',    tactic: 'Lateral',    defense: 'Privileged Account Management' },
  { id: 'T1041',     name: 'Exfil C2',      tactic: 'Exfil',      defense: 'Data Loss Prevention' },
  { id: 'T1071',     name: 'C2 Beacon',     tactic: 'C2',         defense: 'Application-Aware Filtering' },
  { id: 'T1105',     name: 'Tool Transfer', tactic: 'C2',         defense: 'File Execution Prevention' },
  { id: 'T1059',     name: 'Cmd Exec',      tactic: 'Execution',  defense: 'User Account Control' },
  { id: 'T1068',     name: 'Priv Esc',      tactic: 'PrivEsc',    defense: 'Execution Prevention' },
  { id: 'T1498',     name: 'Net DoS',       tactic: 'Impact',     defense: 'Endpoint Traffic Eviction' },
]

const TACTIC_COLOR = {
  Discovery:  'from-blue-100 to-blue-50 border-blue-200 dark:from-blue-600/40 dark:to-blue-900/60 dark:border-blue-500/50',
  Credential: 'from-orange-100 to-orange-50 border-orange-200 dark:from-orange-600/40 dark:to-orange-900/60 dark:border-orange-500/50',
  Lateral:    'from-purple-100 to-purple-50 border-purple-200 dark:from-purple-600/40 dark:to-purple-900/60 dark:border-purple-500/50',
  Exfil:      'from-red-100 to-red-50 border-red-200 dark:from-red-600/40 dark:to-red-900/60 dark:border-red-500/50',
  C2:         'from-rose-100 to-rose-50 border-rose-200 dark:from-rose-600/40 dark:to-rose-900/60 dark:border-rose-500/50',
  Execution:  'from-yellow-100 to-yellow-50 border-yellow-200 dark:from-yellow-600/40 dark:to-yellow-900/60 dark:border-yellow-500/50',
  PrivEsc:    'from-violet-100 to-violet-50 border-violet-200 dark:from-violet-600/40 dark:to-violet-900/60 dark:border-violet-500/50',
  Impact:     'from-gray-100 to-gray-50 border-gray-300 dark:from-gray-600/40 dark:to-gray-900/60 dark:border-gray-500/50',
}

export default function MitreHeatmap({ history, activeFilter, onSelectTechnique }) {
  const [activeTactic, setActiveTactic] = useState(null)

  const counts = {}
  for (const alert of history) {
    const t = alert.mitre_technique
    if (t) counts[t] = (counts[t] || 0) + 1
    const evtMap = {
      port_scan: 'T1046', brute_force: 'T1110', lateral_movement: 'T1021.002',
      data_exfil: 'T1041', c2_beacon: 'T1071', recon: 'T1018',
    }
    const mapped = evtMap[alert.event_type]
    if (mapped && !t) counts[mapped] = (counts[mapped] || 0) + 1
  }

  const visibleTechniques = activeTactic
    ? TECHNIQUES.filter(t => t.tactic === activeTactic)
    : TECHNIQUES

  const maxCount = Math.max(...Object.values(counts), 1)

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4 transition-all duration-500">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest">
            MITRE ATT&CK Framework
          </div>
          <span className="text-[10px] text-slate-500 px-1.5 py-0.5 rounded-full border border-soc-border bg-black/20">
            D3FEND Mapped
          </span>
        </div>
        
        <div className="flex items-center gap-3">
          {(activeTactic || activeFilter) && (
            <button
              onClick={() => { setActiveTactic(null); onSelectTechnique(null); }}
              className="text-[10px] text-cyan-500 hover:text-cyan-400 transition-colors uppercase font-bold"
            >
              Reset Filters ×
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
        {visibleTechniques.map(t => {
          const count = counts[t.id] || 0
          const heat = count / maxCount
          const colors = TACTIC_COLOR[t.tactic] || TACTIC_COLOR.Discovery
          const isFiltered = activeFilter === t.id

          return (
            <div
              key={t.id}
              onClick={() => onSelectTechnique(isFiltered ? null : t.id)}
              className={`bg-gradient-to-br ${colors} border rounded-md p-2 text-center cursor-pointer
                transition-all duration-300 group relative
                ${count > 0 ? 'ring-1 ring-white/10' : 'opacity-30 grayscale'}
                ${isFiltered ? 'ring-2 ring-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.4)] scale-105 z-10' : 'hover:scale-102'}
              `}
              style={{ opacity: count > 0 ? 0.6 + heat * 0.4 : 0.3 }}
            >
              {/* Tooltip for Defense */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-48 bg-slate-900 border border-soc-border p-2 rounded shadow-2xl opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-50">
                 <div className="flex items-center gap-1.5 text-emerald-400 text-[10px] font-bold uppercase mb-1">
                   <ShieldCheck className="w-3 h-3" />
                   Defensive Counter
                 </div>
                 <div className="text-[10px] text-slate-200 leading-tight font-medium">
                   {t.defense}
                 </div>
              </div>

              <div className={`text-[10px] font-black ${count > 0 ? 'text-white' : 'text-slate-500'}`}>{t.id}</div>
              <div className={`text-[9px] font-bold leading-tight mt-0.5 ${count > 0 ? 'text-slate-200' : 'text-slate-600'}`}>{t.name}</div>
              
              {count > 0 && (
                <div className="flex items-center justify-center gap-1 mt-1">
                   <span className="text-[11px] font-black text-white">{count}</span>
                   <span className="text-[8px] text-white/50 uppercase">Hits</span>
                </div>
              )}
            </div>
          )
        })}
      </div>

      <div className="flex gap-2 mt-4 flex-wrap border-t border-soc-border/50 pt-3">
        <div className="text-[9px] text-slate-600 uppercase font-bold w-full mb-1">Tactics Filter</div>
        {Object.entries(TACTIC_COLOR).map(([tactic, cls]) => {
          const isActive = activeTactic === tactic
          return (
            <button
              key={tactic}
              onClick={() => setActiveTactic(isActive ? null : tactic)}
              className={`text-[9px] px-2 py-1 rounded-sm bg-gradient-to-r ${cls} border
                transition-all duration-150 cursor-pointer font-bold
                ${isActive
                  ? 'ring-2 ring-white/50 brightness-125 scale-105 z-10'
                  : 'opacity-50 hover:opacity-100'}`}
            >
              {tactic}
            </button>
          )
        })}
      </div>
    </div>
  )
}
