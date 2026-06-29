import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, Check, X, RefreshCw, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react'
import { getToken } from '../auth'

const SEV_CLASS = {
  critical: 'bg-rose-500/10 text-rose-400 border-rose-500/25',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/25',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/25',
  low: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
}

export default function TriageQueue({ onUnauth }) {
  const [actions, setActions] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [processingId, setProcessingId] = useState(null)

  const fetchQueue = useCallback(async () => {
    setLoading(true)
    setError(null)
    const token = getToken()
    if (!token) {
      if (onUnauth) onUnauth()
      return
    }

    try {
      const resp = await fetch('/api/brain/triage/', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json'
        }
      })
      if (resp.status === 401) {
        if (onUnauth) onUnauth()
        return
      }
      if (!resp.ok) {
        throw new Error(`Failed to fetch triage queue: ${resp.statusText}`)
      }
      const data = await resp.json()
      // Sort: show awaiting_approval first, then newest first
      const sorted = data.sort((a, b) => {
        if (a.status === 'awaiting_approval' && b.status !== 'awaiting_approval') return -1
        if (a.status !== 'awaiting_approval' && b.status === 'awaiting_approval') return 1
        return new Date(b.created_at) - new Date(a.created_at)
      })
      setActions(sorted)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [onUnauth])

  useEffect(() => {
    fetchQueue()
  }, [fetchQueue])

  const handleAction = async (triageId, type) => {
    setProcessingId(triageId)
    setError(null)
    const token = getToken()
    if (!token) {
      if (onUnauth) onUnauth()
      return
    }

    try {
      const endpoint = `/api/brain/triage/${triageId}/${type}/`
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      })

      if (resp.status === 401) {
        if (onUnauth) onUnauth()
        return
      }

      const resData = await resp.json()
      if (!resp.ok || resData.success === false) {
        throw new Error(resData.message || `Action failed with status ${resp.status}`)
      }

      // Update local state status
      setActions(prev => prev.map(act => {
        if (act.triage_id === triageId) {
          return {
            ...act,
            status: type === 'approve' ? 'executed' : 'dismissed'
          }
        }
        return act
      }))
    } catch (err) {
      setError(err.message)
    } finally {
      setProcessingId(null)
    }
  }

  const pendingCount = actions.filter(a => a.status === 'awaiting_approval').length

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4 space-y-4 flex flex-col h-full">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-cyan-400 animate-pulse" />
          <h2 className="text-sm font-bold text-cyan-400 uppercase tracking-widest">
            Threat Review Desk
          </h2>
          {pendingCount > 0 && (
            <span className="bg-rose-500/20 text-rose-400 text-[10px] font-bold px-2 py-0.5 rounded-full border border-rose-500/30">
              {pendingCount} PENDING
            </span>
          )}
        </div>
        <button
          onClick={fetchQueue}
          disabled={loading}
          className="text-slate-500 hover:text-cyan-400 disabled:opacity-50 transition-colors p-1"
          title="Refresh Queue"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {error && (
        <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 text-xs p-3 rounded leading-relaxed">
          {error}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-3 pr-1 max-h-[30rem]">
        {actions.length === 0 && !loading ? (
          <div className="text-center py-8 text-slate-500 text-xs">
            No active proposals in the queue.
          </div>
        ) : (
          actions.map(action => {
            const isPending = action.status === 'awaiting_approval'
            const isExecuted = action.status === 'executed'
            const isDismissed = action.status === 'dismissed'

            let statusBadge = null
            if (isExecuted) {
              statusBadge = (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                  <ShieldCheck className="w-3 h-3" /> BLOCKED
                </span>
              )
            } else if (isDismissed) {
              statusBadge = (
                <span className="flex items-center gap-1 text-[10px] font-semibold text-slate-500 bg-slate-500/10 border border-slate-500/20 px-2 py-0.5 rounded">
                  <X className="w-3 h-3" /> DISMISSED
                </span>
              )
            }

            return (
              <div
                key={action.triage_id}
                className={`border rounded-lg p-3 transition-all relative ${
                  isPending
                    ? 'bg-soc-bg/40 border-soc-border hover:border-cyan-500/30 hover:shadow-lg hover:shadow-cyan-500/5'
                    : 'bg-soc-panel/30 border-soc-border/40 opacity-70'
                }`}
              >
                {/* Header */}
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${SEV_CLASS[action.severity] || SEV_CLASS.medium}`}>
                      {action.severity?.toUpperCase()}
                    </span>
                    <span className="font-mono text-sm text-cyan-300 font-bold tracking-wide">
                      {action.ip_address}
                    </span>
                  </div>
                  {statusBadge}
                </div>

                {/* Body Details */}
                <p className="text-xs text-slate-300 leading-relaxed mb-3 italic">
                  {action.incident_summary || action.reason}
                </p>

                {/* Meta details */}
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[10px] text-slate-500 border-t border-soc-border/30 pt-2.5">
                  <div>
                    <span className="text-slate-600 block">AI Confidence</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <div className="flex-1 bg-soc-border h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-cyan-400 h-full rounded-full"
                          style={{ width: `${action.confidence}%` }}
                        />
                      </div>
                      <span className="text-cyan-400 font-semibold">{action.confidence}%</span>
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-600 block">AbuseIPDB Threat Score</span>
                    <span className={`font-semibold ${action.abuseipdb_score > 50 ? 'text-rose-400' : 'text-slate-400'}`}>
                      {action.abuseipdb_score}%
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-600 block">MITRE Techniques</span>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {Array.isArray(action.mitre_techniques) && action.mitre_techniques.length > 0 ? (
                        action.mitre_techniques.map(tech => (
                          <span key={tech} className="bg-soc-border/60 text-slate-300 px-1 py-0.5 rounded text-[8px] font-mono">
                            {tech}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-600 font-mono">—</span>
                      )}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-600 block">Source Agent</span>
                    <span className="text-slate-400 mt-0.5 block truncate">
                      {action.agent_name || 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Actions row */}
                {isPending && (
                  <div className="flex items-center justify-end gap-2 mt-3 pt-2.5 border-t border-soc-border/20">
                    <button
                      onClick={() => handleAction(action.triage_id, 'dismiss')}
                      disabled={processingId !== null}
                      className="flex items-center gap-1 px-2.5 py-1 text-slate-400 hover:text-slate-200 bg-soc-border/30 hover:bg-soc-border/60 disabled:opacity-50 rounded text-[10px] font-bold uppercase tracking-wider transition-colors"
                    >
                      <X className="w-3.5 h-3.5" /> Dismiss
                    </button>
                    <button
                      onClick={() => handleAction(action.triage_id, 'approve')}
                      disabled={processingId !== null}
                      className="flex items-center gap-1 px-3 py-1 text-cyan-400 hover:text-white bg-cyan-500/10 hover:bg-cyan-500/30 disabled:opacity-50 rounded text-[10px] font-bold uppercase tracking-wider border border-cyan-500/30 hover:border-cyan-400 transition-colors"
                    >
                      <Check className="w-3.5 h-3.5" /> Approve Block
                    </button>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
