import { useState } from 'react'

const MITRE = {
  T1046: 'Network Scan', T1110: 'Brute Force', 'T1110.001': 'Brute Force',
  T1021: 'Lateral Move', 'T1021.002': 'Lateral Move (SMB)',
  T1041: 'Data Exfil', T1071: 'C2 Beacon', T1018: 'Recon',
  T1049: 'Net Discovery', T1057: 'Proc Discovery', T1082: 'Sys Info',
  T1083: 'File Discovery', T1105: 'Tool Transfer', T1059: 'Execution',
  T1498: 'DoS', 'T1498.001': 'SYN Flood', T1190: 'Initial Access',
  T1048: 'Exfiltration', T1068: 'Privilege Escalation', T1571: 'Non-Std Port',
}

const SEV = {
  critical: { bg: 'bg-[#ff2e63]/20', border: 'border-[#ff2e63]/50', text: 'text-[#ff2e63]' },
  high:     { bg: 'bg-[#f9d342]/20', border: 'border-[#f9d342]/50', text: 'text-[#f9d342]' },
  medium:   { bg: 'bg-violet-500/20', border: 'border-violet-500/50', text: 'text-violet-400' },
  low:      { bg: 'bg-cyan-500/20', border: 'border-cyan-500/50', text: 'text-cyan-400' },
  info:     { bg: 'bg-slate-700/20', border: 'border-slate-700/50', text: 'text-slate-400' },
}

export default function AlertFeed({ alerts, filter }) {
  const filtered = alerts.filter(a => filter === 'all' || a.ml_severity === filter)
  
  // Group duplicate consecutive events for cleanliness
  const dedupedFiltered = []
  for (const item of filtered) {
    const last = dedupedFiltered[dedupedFiltered.length - 1]
    const currentSig = `${item.event_type}-${item.src_ip}-${item.ml_severity}`
    const lastSig = last ? `${last.event_type}-${last.src_ip}-${last.ml_severity}` : null
    
    if (lastSig === currentSig) {
      last._count = (last._count || 1) + 1
    } else {
      dedupedFiltered.push({ ...item, _count: 1 })
    }
  }

  return (
    <div className="flex flex-col h-full bg-[#0c1322] rounded-xl border border-slate-800">
      <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800/40 shrink-0">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-[0.2em]">Live Incident Feed</h3>
      </div>
      
      <div className="px-5 py-2 border-b border-slate-800/40 text-[10px] text-slate-500 font-bold uppercase tracking-[0.2em] shrink-0">
        List
      </div>

      <div className="overflow-y-auto flex-1 p-5 space-y-4">
        {dedupedFiltered.length === 0 && (
          <div className="p-12 text-center text-slate-500 text-xs font-mono tracking-widest">
            NO MATCHING ALERTS
          </div>
        )}

        {dedupedFiltered.slice(0, 50).map((a, i) => {
          const rawTs = a.ml_detected_at || a['@timestamp'] || ''
          let ts = rawTs.slice(11, 16)
          
          let ids = [];
          if (Array.isArray(a.mitre_id)) ids.push(...a.mitre_id);
          else if (typeof a.mitre_id === 'string') ids.push(a.mitre_id);
          if (ids.length === 0 && a.mitre_technique) {
            if (Array.isArray(a.mitre_technique)) ids.push(...a.mitre_technique.filter(x => typeof x === 'string' && x.startsWith('T')));
            else if (typeof a.mitre_technique === 'string' && a.mitre_technique.startsWith('T')) ids.push(a.mitre_technique);
          }
          const mitreId = ids[0] || 'T1059'
          const mitreName = MITRE[mitreId] || a.event_type || 'Command & Scripting'
          const sevStyle = SEV[a.ml_severity] || SEV.info

          return (
            <div key={i} className="flex gap-4 items-start">
              <div className="text-[10px] text-slate-400 font-mono mt-0.5">{ts}</div>
              <div className="flex flex-col min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border tracking-wider font-mono uppercase ${sevStyle.bg} ${sevStyle.border} ${sevStyle.text}`}>
                    {a.ml_severity === 'critical' ? 'Critical' : a.ml_severity === 'high' ? 'High' : a.ml_severity === 'medium' ? 'Medium' : 'Low'}
                  </span>
                </div>
                <div className="text-[10px] text-slate-200 font-mono">
                  {mitreId} {mitreName} {['critical', 'high'].includes(a.ml_severity) && <span className="text-[#ff2e63] font-sans ml-1">(Active)</span>}
                  {a._count > 1 && <span className="ml-2 text-slate-500">[{a._count}x]</span>}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
