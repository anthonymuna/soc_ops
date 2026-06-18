import { useState } from 'react'
import { ChevronDown, ChevronRight, X, ExternalLink, ThumbsUp, ThumbsDown, CheckCircle, Info, FileText } from 'lucide-react'
import { getToken } from '../auth'

const SEV = {
  critical: 'bg-rose-100 text-rose-700 border-rose-200 dark:bg-rose-500/20 dark:text-rose-300 dark:border-rose-500/40',
  high:     'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-500/20 dark:text-orange-300 dark:border-orange-500/40',
  medium:   'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-500/20 dark:text-amber-300 dark:border-amber-500/40',
  low:      'bg-emerald-100 text-emerald-700 border-emerald-200 dark:bg-emerald-500/20 dark:text-emerald-300 dark:border-emerald-500/40',
  info:     'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-500/20 dark:text-slate-300 dark:border-slate-500/40',
}

const SEV_BORDER = {
  critical: 'border-l-2 border-rose-500',
  high:     'border-l-2 border-orange-500',
  medium:   'border-l-2 border-amber-400',
  low:      '',
  info:     '',
}

const MITRE = {
  T1046: 'Network Scan', T1110: 'Brute Force', 'T1110.001': 'Brute Force',
  T1021: 'Lateral Move', 'T1021.002': 'Lateral Move (SMB)',
  T1041: 'Data Exfil', T1071: 'C2 Beacon', T1018: 'Recon',
  T1049: 'Net Discovery', T1057: 'Proc Discovery', T1082: 'Sys Info',
  T1083: 'File Discovery', T1105: 'Tool Transfer', T1059: 'Execution',
  T1498: 'DoS', 'T1498.001': 'SYN Flood', T1190: 'Initial Access',
  T1048: 'Exfiltration', T1068: 'Privilege Escalation', T1571: 'Non-Std Port',
}

function Badge({ sev }) {
  return (
    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${SEV[sev] || SEV.info}`}>
      {sev?.toUpperCase() ?? 'UNK'}
    </span>
  )
}

// ── Raw field grid shown when alert is expanded ──────────────────────────────
function AlertDetail({ alert }) {
  const skip = new Set(['ml_explanation', 'ml_detected_at', 'ml_anomaly'])
  const mlFields = Object.entries(alert).filter(([k]) => k.startsWith('ml_') && !skip.has(k))
  const rawFields = Object.entries(alert).filter(([k]) =>
    !k.startsWith('ml_') && !k.startsWith('sigma_') && !skip.has(k) &&
    !['mitre_technique','mitre_tactic','detection_method'].includes(k)
  )

  return (
    <div className="mt-2 space-y-2 text-[10px]">
      {/* AI Analysis */}
      {alert.ml_explanation && (
        <div className="mt-2 mb-3 border-l-2 border-cyan-500 pl-3 bg-cyan-500/5 rounded-r py-2">
          <div className="text-cyan-500 font-semibold text-[10px] uppercase tracking-wider mb-1">
            AI Analysis
          </div>
          <p className="text-slate-300 text-xs italic leading-relaxed">
            {alert.ml_explanation}
          </p>
        </div>
      )}

      {/* ML scores */}
      <div>
        <div className="text-cyan-500 font-semibold mb-1 uppercase tracking-wider">ML Scores</div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
          {mlFields.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-2">
              <span className="text-slate-500">{k.replace('ml_', '')}</span>
              <span className="text-slate-300 font-mono truncate max-w-[120px]">
                {typeof v === 'object' ? JSON.stringify(v) : String(v)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Raw log fields */}
      <div>
        <div className="text-cyan-500 font-semibold mb-1 uppercase tracking-wider">Raw Log</div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
          {rawFields.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-2">
              <span className="text-slate-500">{k}</span>
              <span className="text-slate-300 font-mono truncate max-w-[120px]" title={String(v)}>
                {String(v)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Geographical Info */}
      {(alert.ml_src_geo || alert.ml_dst_geo) && (
        <div className="flex items-center gap-4 text-slate-500 py-1">
          {alert.ml_src_geo && (
            <div className="flex items-center gap-1">
              <span className="text-slate-600">Origin:</span>
              <span className="text-cyan-400/80">{alert.ml_src_geo}</span>
            </div>
          )}
          {alert.ml_dst_geo && (
            <div className="flex items-center gap-1">
              <span className="text-slate-600">Destination:</span>
              <span className="text-cyan-400/80">{alert.ml_dst_geo}</span>
            </div>
          )}
        </div>
      )}

    </div>
  )
}

// ── IP Correlation Drawer ─────────────────────────────────────────────────────
function IPCorrelationDrawer({ ip, history, onClose }) {
  const events = history.filter(a => a.src_ip === ip || a.dst_ip === ip)
  const asSource = events.filter(a => a.src_ip === ip)
  const asDest   = events.filter(a => a.dst_ip === ip)

  const techniques = {}
  for (const e of asSource) {
    const k = e.event_type || e.ml_rf_class || 'unknown'
    techniques[k] = (techniques[k] || 0) + 1
  }
  const sorted = Object.entries(techniques).sort((a, b) => b[1] - a[1])

  const severities = asSource.map(a => a.ml_severity)
  const worstSev = ['critical','high','medium','low'].find(s => severities.includes(s)) || 'info'

  const firstSeen = [...asSource].sort((a,b) =>
    (a.ml_detected_at||'') < (b.ml_detected_at||'') ? -1 : 1
  )[0]?.ml_detected_at?.slice(11,19) || '—'
  const lastSeen = [...asSource].sort((a,b) =>
    (a.ml_detected_at||'') > (b.ml_detected_at||'') ? -1 : 1
  )[0]?.ml_detected_at?.slice(11,19) || '—'

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* panel */}
      <div className="relative w-full max-w-sm bg-soc-panel border-l border-soc-border flex flex-col h-full shadow-2xl">
        {/* header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border">
          <div>
            <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest">IP Analysis</div>
            <div className="font-mono text-sm text-slate-200 mt-0.5">{ip}</div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* summary */}
        <div className="px-4 py-3 border-b border-soc-border grid grid-cols-3 gap-2 text-center">
          {[
            ['Events (src)', asSource.length],
            ['Events (dst)', asDest.length],
            ['Techniques', sorted.length],
          ].map(([label, val]) => (
            <div key={label}>
              <div className="text-lg font-bold text-slate-200">{val}</div>
              <div className="text-[9px] text-slate-500 uppercase">{label}</div>
            </div>
          ))}
        </div>

        <div className="px-4 py-2 border-b border-soc-border flex justify-between text-[10px] text-slate-500">
          <span>Worst severity: <span className={`font-bold ${
            worstSev === 'critical' ? 'text-rose-400' :
            worstSev === 'high'     ? 'text-orange-400' :
            worstSev === 'medium'   ? 'text-amber-400' : 'text-emerald-400'
          }`}>{worstSev.toUpperCase()}</span></span>
          <span>{firstSeen} → {lastSeen}</span>
        </div>

        {/* technique breakdown */}
        <div className="px-4 py-3 border-b border-soc-border">
          <div className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest mb-2">
            Technique Breakdown
          </div>
          <div className="space-y-1.5">
            {sorted.map(([tech, count]) => (
              <div key={tech} className="flex items-center gap-2 text-[10px]">
                <span className="text-slate-400 w-28 truncate capitalize">{tech.replace('_',' ')}</span>
                <div className="flex-1 bg-soc-border rounded-full h-1 overflow-hidden">
                  <div
                    className="h-full bg-cyan-500 rounded-full"
                    style={{ width: `${(count / asSource.length) * 100}%` }}
                  />
                </div>
                <span className="text-slate-500 w-6 text-right">{count}</span>
              </div>
            ))}
            {sorted.length === 0 && (
              <div className="text-slate-600 text-[10px]">IP seen as destination only</div>
            )}
          </div>
        </div>

        {/* recent events timeline */}
        <div className="flex-1 overflow-y-auto px-4 py-3">
          <div className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest mb-2">
            Event Timeline
          </div>
          <div className="space-y-1.5">
            {events.slice(0, 50).map((e, i) => (
              <div key={i} className="flex items-start gap-2 text-[10px]">
                <span className="text-slate-600 shrink-0 font-mono">
                  {(e.ml_detected_at || e['@timestamp'] || '').slice(11,19)}
                </span>
                <Badge sev={e.ml_severity} />
                <span className="text-slate-400 truncate">{e.event_type}</span>
                {e.src_ip === ip
                  ? <span className="text-slate-600 shrink-0">→ {e.dst_ip}</span>
                  : <span className="text-slate-600 shrink-0">← {e.src_ip}</span>
                }
              </div>
            ))}
            {events.length === 0 && (
              <div className="text-slate-600">No events found for this IP</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main AlertFeed ────────────────────────────────────────────────────────────
export default function AlertFeed({ alerts, history = [], selectedMitreId, filter = 'all', onFilterChange }) {
  const [expanded,  setExpanded]  = useState(null)
  const [ipDrawer,  setIpDrawer]  = useState(null)
  const [feedbackSent, setFeedbackSent] = useState({})

  // Use history if a mitre filter is active, since the heatmap counts are based on history
  const baseArray = selectedMitreId ? history : alerts
  let filtered = filter === 'all' ? baseArray : baseArray.filter(a => a.ml_severity === filter)

  if (selectedMitreId) {
    const evtMap = {
      port_scan: 'T1046', brute_force: 'T1110', lateral_movement: 'T1021.002',
      data_exfil: 'T1041', c2_beacon: 'T1071', recon: 'T1018',
    }
    filtered = filtered.filter(a => {
      let ids = [];
      if (Array.isArray(a.mitre_id)) ids.push(...a.mitre_id);
      else if (typeof a.mitre_id === 'string') ids.push(a.mitre_id);
      
      if (ids.length === 0) {
        const tech = a.mitre_technique;
        if (Array.isArray(tech)) ids.push(...tech.filter(x => typeof x === 'string' && x.startsWith('T')));
        else if (typeof tech === 'string' && tech.startsWith('T')) ids.push(tech);
      }
      
      if (ids.length === 0 && evtMap[a.event_type]) {
        ids.push(evtMap[a.event_type]);
      }
      
      if (ids.length === 0) return false;
      return ids.some(id => id === selectedMitreId || id.startsWith(selectedMitreId + '.'));
    })
  }

  // Deduplicate alerts with same agent, source IP, destination IP, and event type/description
  const dedupMap = new Map();
  const dedupedFiltered = [];
  for (const a of filtered) {
    const key = [a.agent_name || 'unknown', a.src_ip, a.dst_ip, a.event_type, a.wazuh_description || a.mitre_technique || ''].join('|');
    if (dedupMap.has(key)) {
      dedupMap.get(key)._count += 1;
    } else {
      const copy = { ...a, _count: 1 };
      dedupMap.set(key, copy);
      dedupedFiltered.push(copy);
    }
  }

  const toggleExpand = (i) => setExpanded(prev => prev === i ? null : i)

  const getAlertId = (a) => a.id || a._id || `${a.ml_detected_at}${a.src_ip}${a.event_type}`

  const onFeedback = async (alert, label) => {
    const alertId = getAlertId(alert)
    try {
      const resp = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/feedback/`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getToken()}`
        },
        body: JSON.stringify({ label, comment: `User manually labeled as ${label}` })
      })
      if (resp.ok) {
        setFeedbackSent(prev => ({ ...prev, [alertId]: label }))
      }
    } catch (e) {
      console.error("Feedback failed", e)
    }
  }

  return (
    <>
      <div className="bg-soc-panel border border-soc-border rounded-lg flex flex-col h-full">
        {/* toolbar */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border">
          <span className="text-xs font-bold text-cyan-400 uppercase tracking-widest flex gap-2 items-center">
            Live Alert Feed
            <span className="bg-cyan-500/10 text-cyan-500 px-2 py-0.5 rounded-full text-[10px] border border-cyan-500/20">
              {filtered.length} Alerts ({dedupedFiltered.length} groups)
            </span>
          </span>
          <div className="flex gap-1">
            {['all','critical','high','medium','low'].map(f => (
              <button
                key={f}
                onClick={() => onFilterChange ? onFilterChange(f) : null}
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

        {/* list */}
        <div className="overflow-y-auto flex-1 divide-y divide-soc-border/50">
          {dedupedFiltered.length === 0 && (
            <div className="p-6 text-center text-slate-600 text-sm">No alerts matching filter</div>
          )}

          {dedupedFiltered.map((a, i) => {
            const rawTs = a.ml_detected_at || a['@timestamp'] || ''
            let ts = rawTs.slice(11, 19)
            let dateStr = ''
            if (rawTs) {
              const d = new Date(rawTs)
              if (!isNaN(d.getTime())) {
                ts = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                dateStr = d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
              }
            }
            let ids = [];
            if (Array.isArray(a.mitre_id)) ids.push(...a.mitre_id);
            else if (typeof a.mitre_id === 'string') ids.push(a.mitre_id);
            
            if (ids.length === 0) {
              const tech = a.mitre_technique;
              if (Array.isArray(tech)) ids.push(...tech.filter(x => typeof x === 'string' && x.startsWith('T')));
              else if (typeof tech === 'string' && tech.startsWith('T')) ids.push(tech);
            }
            
            let mitreName = '';
            if (ids.length > 0) {
              mitreName = ids.map(id => MITRE[id] || id).join(', ');
            } else if (a.mitre_technique) {
              mitreName = Array.isArray(a.mitre_technique) ? a.mitre_technique.join(', ') : a.mitre_technique;
            }
            const rfClass   = a.ml_rf_class && a.ml_rf_class !== 'normal' ? a.ml_rf_class : null
            const isOpen    = expanded === i
            const alertId   = getAlertId(a)

            return (
              <div
                key={i}
                className={`px-4 py-2.5 text-xs transition-colors
                  ${SEV_BORDER[a.ml_severity] || ''}
                  ${isOpen ? 'bg-white/[0.03] dark:bg-white/[0.03]' : 'hover:bg-white/[0.02]'}`}
              >
                {/* row header — click to expand */}
                <div
                  className="flex items-center justify-between gap-2 cursor-pointer"
                  onClick={() => toggleExpand(i)}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {isOpen
                      ? <ChevronDown className="w-3 h-3 text-slate-500 shrink-0" />
                      : <ChevronRight className="w-3 h-3 text-slate-500 shrink-0" />
                    }
                    <Badge sev={a.ml_severity} />
                    <span className="text-slate-300 font-semibold truncate">{a.event_type}</span>
                    {a._count > 1 && (
                      <span className="bg-slate-700/50 text-slate-300 text-[10px] px-1.5 py-0.5 rounded-full ml-1 border border-slate-600/50 font-bold">
                        {a._count}x
                      </span>
                    )}
                    {rfClass && (
                      <span className="text-purple-400 text-[10px]">
                        [{rfClass === 'unknown_anomaly' ? 'ANOMALY' : rfClass.toUpperCase()}]
                      </span>
                    )}
                    {mitreName && (
                      <span className="text-slate-600 hidden sm:inline">· {mitreName}</span>
                    )}
                  </div>
                  <div className="flex flex-col items-end shrink-0">
                    <span className="text-slate-500 font-mono text-xs">{ts}</span>
                    {dateStr && <span className="text-slate-600 font-mono text-[9px]">{dateStr}</span>}
                  </div>
                </div>

                {/* IPs row */}
                <div className="mt-1 text-slate-500 flex flex-wrap items-center gap-2 pl-5">
                  {a.agent_name && (
                    <span className="text-emerald-400/80 font-mono text-[9px] bg-emerald-400/10 px-1.5 py-0.5 rounded border border-emerald-400/20">
                      Host: {a.agent_name}
                    </span>
                  )}
                  {a.src_ip && (
                    <button
                      className="text-cyan-700 hover:text-cyan-400 transition-colors flex items-center gap-0.5"
                      onClick={(e) => { e.stopPropagation(); setIpDrawer(a.src_ip) }}
                      title="Investigate IP"
                    >
                      {a.src_ip}
                      <ExternalLink className="w-2.5 h-2.5" />
                    </button>
                  )}
                  {a.dst_ip && (
                    <>
                      <span>→</span>
                      <button
                        className="text-cyan-700 hover:text-cyan-400 transition-colors flex items-center gap-0.5"
                        onClick={(e) => { e.stopPropagation(); setIpDrawer(a.dst_ip) }}
                        title="Investigate IP"
                      >
                        {a.dst_ip}
                        <ExternalLink className="w-2.5 h-2.5" />
                      </button>
                    </>
                  )}
                  {a.dst_port && <span className="text-slate-600">:{a.dst_port}</span>}
                  {a.bytes > 0 && (
                    <span className="ml-2 text-slate-600">{(a.bytes/1024).toFixed(0)}KB</span>
                  )}
                </div>

                {/* collapsed explanation */}
                {!isOpen && a.ml_explanation && (
                  <div className="mt-1 text-slate-600 text-[10px] truncate pl-5">
                    {a.ml_explanation}
                  </div>
                )}

                {/* expanded detail */}
                {isOpen && (
                  <div className="pl-5 pb-2">
                    <AlertDetail alert={a} />
                    
                    {/* Feedback Buttons */}
                    <div className="mt-4 flex items-center gap-2">
                      {(a.human_labeled || feedbackSent[alertId]) ? (
                        <div className="flex items-center gap-3">
                          <span className="flex items-center gap-1.5 text-cyan-400 text-[10px] font-bold uppercase tracking-widest bg-cyan-400/10 px-2 py-1 rounded border border-cyan-400/30">
                            <CheckCircle className="w-3 h-3" />
                            {(a.human_labeled || feedbackSent[alertId]) === 'normal' ? 'Labled Normal' : 'Confirmed Threat'}
                          </span>
                          
                          {(a.human_labeled || feedbackSent[alertId]) !== 'normal' && (
                            <button
                              onClick={(e) => { e.stopPropagation(); window.open(`/api/alerts/${encodeURIComponent(alertId)}/report`, '_blank') }}
                              className="flex items-center gap-1.5 px-3 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 transition-all text-[10px] font-bold uppercase"
                            >
                              <FileText className="w-3 h-3" />
                              Download Intel Report
                            </button>
                          )}
                        </div>
                      ) : (
                        <>
                          <button
                            onClick={(e) => { e.stopPropagation(); onFeedback(a, a.ml_rf_class || 'attack') }}
                            className="flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-all text-[10px]"
                            title="Confirm this is a real threat"
                          >
                            <ThumbsUp className="w-3 h-3" />
                            CONFIRM THREAT
                          </button>
                          <button
                            onClick={(e) => { e.stopPropagation(); onFeedback(a, 'normal') }}
                            className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-500/10 hover:bg-slate-500/20 text-slate-400 border border-slate-500/30 transition-all text-[10px]"
                            title="Mark as false positive / normal traffic"
                          >
                            <ThumbsDown className="w-3 h-3" />
                            DISMISS (FALSE POSITIVE)
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* IP correlation drawer */}
      {ipDrawer && (
        <IPCorrelationDrawer
          ip={ipDrawer}
          history={history}
          onClose={() => setIpDrawer(null)}
        />
      )}
    </>
  )
}
