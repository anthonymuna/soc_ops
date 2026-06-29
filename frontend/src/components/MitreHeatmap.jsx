import { useState } from 'react'
import { Layers } from 'lucide-react'

const TACTICS_MAP = [
  { id: 'TA0001', name: 'Reconnaissance',     techniques: [{id:'T1595', name:'Active Scanning'}], theme: 'red' },
  { id: 'TA0002', name: 'Resource Development', techniques: [{id:'T1583', name:'Acquire Infra'}, {id:'T1584', name:'Compromise Infra'}], theme: 'yellow' },
  { id: 'TA0003', name: 'Initial Access',     techniques: [{id:'T1190', name:'Exploit Public'}], theme: 'red' },
  { id: 'TA0004', name: 'Execution',          techniques: [{id:'T1059', name:'Command and Script'}], theme: 'blue' },
  { id: 'TA0005', name: 'Persistence',        techniques: [{id:'T1098', name:'Account Manipulation'}], theme: 'blue' },
  { id: 'TA0006', name: 'Lateral Movement',   techniques: [{id:'T1021', name:'Remote Services'}, {id:'T1080', name:'Taint Shared Content'}], theme: 'blue' },
  { id: 'TA0007', name: 'Defense Evasion',    techniques: [{id:'T1140', name:'Deobfuscate'}], theme: 'blue' },
  { id: 'TA0078', name: 'Exfiltration',       techniques: [{id:'T1041', name:'Exfil over C2'}], theme: 'muted' },
]

// To match existing techniques to the mockup structure, we adapt our techniques:
const OUR_TECHNIQUES = [
  { id: 'T1046', name: 'Net Scan',       tacticId: 'TA0001' },
  { id: 'T1018', name: 'Remote Sys',     tacticId: 'TA0001' },
  { id: 'T1049', name: 'Net Conns',      tacticId: 'TA0001' },
  { id: 'T1057', name: 'Proc Disc',      tacticId: 'TA0002' },
  { id: 'T1082', name: 'Sys Info',       tacticId: 'TA0002' },
  { id: 'T1083', name: 'File Disc',      tacticId: 'TA0002' },
  { id: 'T1078', name: 'Valid Accts',    tacticId: 'TA0003' },
  { id: 'T1110', name: 'Brute Force',    tacticId: 'TA0003' },
  { id: 'T1110.001', name: 'Pwd Guess',  tacticId: 'TA0003' },
  { id: 'T1021', name: 'Remote Svc',     tacticId: 'TA0006' },
  { id: 'T1041', name: 'Exfil C2',       tacticId: 'TA0078' },
  { id: 'T1071', name: 'C2 Beacon',      tacticId: 'TA0004' },
  { id: 'T1105', name: 'Tool Transfer',  tacticId: 'TA0004' },
  { id: 'T1059', name: 'Cmd Exec',       tacticId: 'TA0005' },
  { id: 'T1068', name: 'Priv Esc',       tacticId: 'TA0005' },
  { id: 'T1498', name: 'Net DoS',        tacticId: 'TA0007' },
]

const THEME_STYLES = {
  red: 'bg-[#e11d48]/20 border-[#e11d48]/50 text-rose-100 hover:shadow-[0_0_15px_rgba(225,29,72,0.3)]',
  yellow: 'bg-[#d97706]/20 border-[#d97706]/50 text-amber-100 hover:shadow-[0_0_15px_rgba(217,119,6,0.3)]',
  blue: 'bg-[#0284c7]/20 border-[#0284c7]/50 text-sky-100 hover:shadow-[0_0_15px_rgba(2,132,199,0.3)]',
  muted: 'bg-slate-700/20 border-slate-600/50 text-slate-300 hover:shadow-[0_0_15px_rgba(100,116,139,0.3)]'
}

export default function MitreHeatmap({ history, selectedMitreId, onSelectMitreId }) {
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

  // Populate dynamic techniques based on hits or defaults
  const columns = TACTICS_MAP.map(tactic => {
    const activeTechs = OUR_TECHNIQUES.filter(t => t.tacticId === tactic.id);
    return {
      ...tactic,
      techniques: activeTechs.length > 0 ? activeTechs : tactic.techniques
    }
  });

  return (
    <div className="glass-panel p-5 flex flex-col h-full border-slate-800 rounded-xl relative overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-teal-500/0 via-teal-400 to-teal-500/0 opacity-50"></div>
      
      <div className="flex items-center justify-between mb-6 border-b border-slate-800/40 pb-4">
        <div className="text-xs font-semibold text-slate-300 uppercase tracking-[0.2em] flex items-center gap-2">
          <span>MITRE ATT&CK FRAMEWORK COVERAGE</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="w-48 h-1 bg-slate-800 rounded-full overflow-hidden relative">
            <div className="absolute top-0 left-0 h-full bg-gradient-to-r from-cyan-600 to-teal-400 w-[70%] drop-shadow-[0_0_8px_rgba(45,212,191,0.8)]"></div>
          </div>
          <span className="text-[10px] text-slate-400 font-mono">70% Covered</span>
        </div>
      </div>

      <div className="grid grid-cols-8 gap-2 h-full">
        {columns.map(tactic => (
          <div key={tactic.id} className="flex flex-col h-full border border-slate-800/50 rounded-lg overflow-hidden bg-[#0c1322]">
            <div className="text-center py-2 border-b border-slate-800/60 bg-slate-800/30">
              <span className="text-[10px] font-mono text-slate-300">{tactic.id}</span>
            </div>
            
            <div className="p-2 space-y-2 flex-grow">
              {tactic.techniques.map(t => {
                const count = counts[t.id] || 0
                const isSelected = selectedMitreId === t.id
                const themeClass = THEME_STYLES[tactic.theme] || THEME_STYLES.muted;
                const opacityClass = count > 0 || isSelected ? 'opacity-100' : 'opacity-40';
                
                return (
                  <div
                    key={t.id}
                    onClick={() => {
                      if (onSelectMitreId) onSelectMitreId(isSelected ? null : t.id)
                    }}
                    className={`flex flex-col p-2 rounded cursor-pointer border transition-all duration-300 ${themeClass} ${opacityClass} ${isSelected ? 'ring-2 ring-white shadow-lg opacity-100' : ''}`}
                  >
                    <span className="text-[10px] font-medium leading-tight mb-2 truncate">{t.name}</span>
                    <div className="flex items-center justify-between mt-auto">
                      <span className="text-[10px] font-mono opacity-80">{t.id}</span>
                      {count > 0 && (
                        <span className="text-[9px] font-bold bg-white/20 px-1 rounded animate-pulse">
                          {count}
                        </span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
