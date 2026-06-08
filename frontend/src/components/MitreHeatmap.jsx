const TECHNIQUES = [
  { id: 'T1046',     name: 'Net Scan',      tactic: 'Discovery' },
  { id: 'T1018',     name: 'Remote Sys',    tactic: 'Discovery' },
  { id: 'T1049',     name: 'Net Conns',     tactic: 'Discovery' },
  { id: 'T1057',     name: 'Proc Disc',     tactic: 'Discovery' },
  { id: 'T1082',     name: 'Sys Info',      tactic: 'Discovery' },
  { id: 'T1083',     name: 'File Disc',     tactic: 'Discovery' },
  { id: 'T1078',     name: 'Valid Accts',   tactic: 'Credential' },
  { id: 'T1110',     name: 'Brute Force',   tactic: 'Credential' },
  { id: 'T1110.001', name: 'Pwd Guess',     tactic: 'Credential' },
  { id: 'T1021',     name: 'Remote Svc',    tactic: 'Lateral' },
  { id: 'T1041',     name: 'Exfil C2',      tactic: 'Exfil' },
  { id: 'T1071',     name: 'C2 Beacon',     tactic: 'C2' },
  { id: 'T1105',     name: 'Tool Transfer', tactic: 'C2' },
  { id: 'T1059',     name: 'Cmd Exec',      tactic: 'Execution' },
  { id: 'T1068',     name: 'Priv Esc',      tactic: 'PrivEsc' },
  { id: 'T1498',     name: 'Net DoS',       tactic: 'Impact' },
]

const TACTIC_COLOR = {
  Discovery:  'from-blue-100 to-blue-50 border-blue-200 dark:from-blue-900/60 dark:to-blue-800/40 dark:border-blue-700/30',
  Credential: 'from-orange-100 to-orange-50 border-orange-200 dark:from-orange-900/60 dark:to-orange-800/40 dark:border-orange-700/30',
  Lateral:    'from-purple-100 to-purple-50 border-purple-200 dark:from-purple-900/60 dark:to-purple-800/40 dark:border-purple-700/30',
  Exfil:      'from-red-100 to-red-50 border-red-200 dark:from-red-900/60 dark:to-red-800/40 dark:border-red-700/30',
  C2:         'from-rose-100 to-rose-50 border-rose-200 dark:from-rose-900/60 dark:to-rose-800/40 dark:border-rose-700/30',
  Execution:  'from-yellow-100 to-yellow-50 border-yellow-200 dark:from-yellow-900/60 dark:to-yellow-800/40 dark:border-yellow-700/30',
  PrivEsc:    'from-violet-100 to-violet-50 border-violet-200 dark:from-violet-900/60 dark:to-violet-800/40 dark:border-violet-700/30',
  Impact:     'from-gray-100 to-gray-50 border-gray-300 dark:from-gray-900/60 dark:to-gray-800/40 dark:border-gray-600/30',
}

import { useState } from 'react'

export default function MitreHeatmap({ history, selectedMitreId, onSelectMitreId }) {
  const [activeTactic, setActiveTactic] = useState(null)

  const counts = {}
  const evtMap = {
    port_scan: 'T1046', brute_force: 'T1110', lateral_movement: 'T1021.002',
    data_exfil: 'T1041', c2_beacon: 'T1071', recon: 'T1018',
  }
  
  for (const alert of history) {
    let ids = [];
    if (Array.isArray(alert.mitre_id)) ids.push(...alert.mitre_id);
    else if (typeof alert.mitre_id === 'string') ids.push(alert.mitre_id);
    
    if (ids.length === 0) {
      const tech = alert.mitre_technique;
      if (Array.isArray(tech)) {
        ids.push(...tech.filter(x => typeof x === 'string' && x.startsWith('T')));
      } else if (typeof tech === 'string' && tech.startsWith('T')) {
        ids.push(tech);
      }
    }
    
    if (ids.length === 0) {
      const mapped = evtMap[alert.event_type];
      if (mapped) ids.push(mapped);
    }
    
    for (const id of ids) {
      counts[id] = (counts[id] || 0) + 1;
    }
  }

  const visibleTechniques = activeTactic
    ? TECHNIQUES.filter(t => t.tactic === activeTactic)
    : TECHNIQUES

  const maxCount = Math.max(...Object.values(counts), 1)

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest flex items-center gap-2">
          MITRE ATT&CK Coverage
          {selectedMitreId && (
            <span className="text-[9px] bg-cyan-500/20 text-cyan-300 px-1.5 py-0.5 rounded border border-cyan-500/30">
              Filter: {selectedMitreId}
            </span>
          )}
        </div>
        {(activeTactic || selectedMitreId) && (
          <button
            onClick={() => {
              setActiveTactic(null)
              if (onSelectMitreId) onSelectMitreId(null)
            }}
            className="text-[10px] text-slate-500 hover:text-cyan-400 transition-colors"
          >
            clear all ×
          </button>
        )}
      </div>

      <div className="grid grid-cols-4 sm:grid-cols-7 lg:grid-cols-3 xl:grid-cols-4 gap-1.5">
        {visibleTechniques.map(t => {
          const count = counts[t.id] || 0
          const heat = count / maxCount
          const colors = TACTIC_COLOR[t.tactic] || TACTIC_COLOR.Discovery
          const isSelected = selectedMitreId === t.id
          
          return (
            <div
              key={t.id}
              title={`${t.id}: ${t.name} — ${count} hits`}
              onClick={() => {
                if (count > 0 && onSelectMitreId) {
                  onSelectMitreId(isSelected ? null : t.id)
                }
              }}
              className={`bg-gradient-to-br ${colors} border rounded p-1.5 text-center transition-all duration-300
                ${count > 0 ? 'ring-1 ring-white/10 cursor-pointer hover:brightness-125' : 'opacity-40 cursor-default'}
                ${isSelected ? 'ring-2 ring-cyan-400 scale-105 brightness-150 shadow-lg z-10 relative' : ''}`}
              style={{ opacity: isSelected ? 1 : (count > 0 ? 0.4 + heat * 0.6 : 0.2) }}
            >
              <div className="text-[9px] font-bold text-slate-600 dark:text-slate-400">{t.id}</div>
              <div className="text-[8px] leading-tight mt-0.5 text-slate-500 dark:text-slate-500">{t.name}</div>
              {count > 0 && (
                <div className="text-[10px] font-bold mt-1 text-slate-800 dark:text-white">{count}</div>
              )}
            </div>
          )
        })}
      </div>

      <div className="flex gap-2 mt-3 flex-wrap">
        {Object.entries(TACTIC_COLOR).map(([tactic, cls]) => {
          const isActive = activeTactic === tactic
          return (
            <button
              key={tactic}
              onClick={() => setActiveTactic(isActive ? null : tactic)}
              className={`text-[9px] px-1.5 py-0.5 rounded-sm bg-gradient-to-r ${cls} border
                transition-all duration-150 cursor-pointer
                ${isActive
                  ? 'ring-1 ring-white/50 brightness-125 scale-105'
                  : 'opacity-70 hover:opacity-100'}`}
            >
              {tactic}
            </button>
          )
        })}
      </div>
    </div>
  )
}
