import { useState } from 'react'

const SEV = {
  critical: 'bg-rose-100 text-rose-700 border-rose-200 dark:bg-rose-500/20 dark:text-rose-300 dark:border-rose-500/40',
  high:     'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-500/20 dark:text-orange-300 dark:border-orange-500/40',
  medium:   'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-500/20 dark:text-amber-300 dark:border-amber-500/40',
  low:      'bg-emerald-100 text-emerald-700 border-emerald-200 dark:bg-emerald-500/20 dark:text-emerald-300 dark:border-emerald-500/40',
  info:     'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-500/20 dark:text-slate-300 dark:border-slate-500/40',
}

const MITRE = {
  T1046: 'Network Scan', T1110: 'Brute Force', 'T1110.001': 'Brute Force',
  T1021: 'Lateral Move', 'T1021.002': 'Lateral Move (SMB)',
  T1041: 'Data Exfil', T1071: 'C2 Beacon', T1018: 'Recon',
  T1049: 'Net Discovery', T1057: 'Proc Discovery', T1082: 'Sys Info',
  T1083: 'File Discovery', T1105: 'Tool Transfer',
}

function Badge({ sev }) {
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${SEV[sev] || SEV.info}`}>
      {sev?.toUpperCase() ?? 'UNK'}
    </span>
  )
}

export default function AlertFeed({ alerts }) {
  const [filter, setFilter] = useState('all')

  const filtered = filter === 'all'
    ? alerts
    : alerts.filter(a => a.ml_severity === filter)

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border">
        <span className="text-xs font-bold text-cyan-400 uppercase tracking-widest">
          Live Alert Feed
        </span>
        <div className="flex gap-1">
          {['all','critical','high','medium','low'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`text-[10px] px-2 py-0.5 rounded capitalize transition-colors
                ${filter === f
                  ? 'bg-cyan-400/20 text-cyan-400 border border-cyan-400/40'
                  : 'text-slate-500 hover:text-slate-300'}`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-y-auto flex-1 divide-y divide-soc-border/50">
        {filtered.length === 0 && (
          <div className="p-6 text-center text-slate-600 text-sm">
            No alerts matching filter
          </div>
        )}
        {filtered.map((a, i) => {
          const ts = (a.ml_detected_at || a['@timestamp'] || '').slice(11, 19)
          const mitreName = MITRE[a.mitre_technique] || a.mitre_technique || ''
          const rfClass = a.ml_rf_class && a.ml_rf_class !== 'normal' ? a.ml_rf_class : null
          return (
            <div
              key={i}
              className={`px-4 py-2.5 text-xs hover:bg-white/[0.02] transition-colors
                ${a.ml_severity === 'critical' ? 'border-l-2 border-rose-500' : ''}`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Badge sev={a.ml_severity} />
                  <span className="text-slate-300 font-semibold truncate">{a.event_type}</span>
                  {rfClass && (
                    <span className="text-purple-400 text-[10px]">[{rfClass.toUpperCase()}]</span>
                  )}
                  {mitreName && (
                    <span className="text-slate-600 hidden sm:inline">· {mitreName}</span>
                  )}
                </div>
                <span className="text-slate-600 shrink-0">{ts}</span>
              </div>
              <div className="mt-1 text-slate-500 truncate">
                <span className="text-cyan-700">{a.src_ip}</span>
                {a.dst_ip && <span> → <span className="text-cyan-700">{a.dst_ip}</span></span>}
                {a.bytes && <span className="ml-2">{(a.bytes/1024).toFixed(0)}KB</span>}
              </div>
              {a.ml_explanation && (
                <div className="mt-1 text-slate-600 text-[10px] truncate">{a.ml_explanation}</div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
