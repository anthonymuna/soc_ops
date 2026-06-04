import { useState, useEffect, useRef, useCallback } from 'react'
import { FlaskConical, Play, Clock, CheckCircle, XCircle, RefreshCw } from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { getToken, clearToken } from '../auth'

const ML_API = import.meta.env.VITE_ML_API || '/api'

const INTERVALS = [
  { label: 'Off',   value: 0 },
  { label: '5 min', value: 5 * 60 * 1000 },
  { label: '15 min', value: 15 * 60 * 1000 },
  { label: '30 min', value: 30 * 60 * 1000 },
  { label: '1 hr',  value: 60 * 60 * 1000 },
]

const CLASS_COLORS = {
  normal: '#10b981',
  dos:    '#f43f5e',
  probe:  '#f59e0b',
  r2l:    '#f97316',
  u2r:    '#dc2626',
}

async function fetchTest(onUnauth) {
  const token = getToken()
  const r = await fetch(`${ML_API}/test`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (r.status === 401) { clearToken(); onUnauth?.(); throw new Error('Session expired') }
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`)
  return r.json()
}

export default function ModelTestPage({ onUnauth }) {
  const [runs, setRuns] = useState([])          // { ...result, id }
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [intervalMs, setIntervalMs] = useState(0)
  const timerRef = useRef(null)

  const runTest = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fetchTest(onUnauth)
      setRuns(prev => [{ ...result, id: Date.now() }, ...prev].slice(0, 50))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [onUnauth])

  // Auto-run on interval change
  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current)
    if (intervalMs > 0) {
      timerRef.current = setInterval(runTest, intervalMs)
    }
    return () => clearInterval(timerRef.current)
  }, [intervalMs, runTest])

  const latest = runs[0] || null
  const chartData = [...runs].reverse().map((r, i) => ({
    idx: i + 1,
    accuracy: +(r.accuracy * 100).toFixed(2),
    time: r.evaluated_at?.slice(11, 19) ?? '',
  }))

  return (
    <div className="max-w-screen-xl mx-auto px-4 py-6 space-y-6">

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 text-cyan-400">
          <FlaskConical className="w-4 h-4" />
          <span className="font-bold text-sm tracking-widest uppercase">Model Test Bench</span>
        </div>

        <button
          onClick={runTest}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
        >
          {loading
            ? <RefreshCw className="w-3 h-3 animate-spin" />
            : <Play className="w-3 h-3" />}
          {loading ? 'Running…' : 'Run Test Now'}
        </button>

        <div className="flex items-center gap-1.5 ml-auto">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-xs text-slate-500">Auto-run:</span>
          {INTERVALS.map(iv => (
            <button
              key={iv.value}
              onClick={() => setIntervalMs(iv.value)}
              className={`text-xs px-2 py-1 rounded border transition-colors ${
                intervalMs === iv.value
                  ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400'
                  : 'border-soc-border text-slate-500 hover:text-slate-300'
              }`}
            >
              {iv.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-rose-900/20 border border-rose-500/30 rounded text-rose-400 text-xs px-3 py-2">
          {error}
        </div>
      )}

      {/* Latest result */}
      {latest ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Accuracy + summary */}
          <div className="bg-soc-panel border border-soc-border rounded-lg p-5 space-y-4">
            <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest">Latest Result</div>
            <div className="flex items-end gap-3">
              <span className="text-5xl font-bold text-emerald-400">
                {(latest.accuracy * 100).toFixed(2)}%
              </span>
              <span className="text-slate-500 text-xs mb-1">RF accuracy on KDDTest+</span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              {[
                ['Test samples', latest.test_samples?.toLocaleString() ?? '—'],
                ['Skipped',      latest.skipped_samples?.toLocaleString() ?? '0'],
                ['Evaluated at', latest.evaluated_at?.slice(11, 19) + ' UTC'],
                ['Total runs',   runs.length],
              ].map(([k, v]) => (
                <div key={k}>
                  <div className="text-slate-600">{k}</div>
                  <div className="text-slate-300">{v}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Per-class metrics */}
          <div className="bg-soc-panel border border-soc-border rounded-lg p-5 space-y-3">
            <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest">Per-Class Metrics</div>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-600 border-b border-soc-border">
                  <th className="text-left pb-1.5">Class</th>
                  <th className="text-right pb-1.5">Precision</th>
                  <th className="text-right pb-1.5">Recall</th>
                  <th className="text-right pb-1.5">F1</th>
                  <th className="text-right pb-1.5">Support</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/50">
                {Object.entries(latest.per_class || {}).map(([cls, m]) => (
                  <tr key={cls}>
                    <td className="py-1.5 flex items-center gap-1.5">
                      <span
                        className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{ background: CLASS_COLORS[cls] || '#64748b' }}
                      />
                      <span className="capitalize text-slate-300">{cls}</span>
                    </td>
                    <td className="text-right text-slate-400">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="text-right text-slate-400">{(m.recall * 100).toFixed(1)}%</td>
                    <td className={`text-right font-semibold ${m.f1 > 0.9 ? 'text-emerald-400' : m.f1 > 0.7 ? 'text-amber-400' : 'text-rose-400'}`}>
                      {(m.f1 * 100).toFixed(1)}%
                    </td>
                    <td className="text-right text-slate-600">{m.support.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        !loading && (
          <div className="bg-soc-panel border border-soc-border rounded-lg p-8 text-center text-slate-600 text-sm">
            No tests run yet. Hit "Run Test Now" or enable auto-run.
          </div>
        )
      )}

      {/* Accuracy trend chart */}
      {chartData.length > 1 && (
        <div className="bg-soc-panel border border-soc-border rounded-lg p-5">
          <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest mb-4">Accuracy Over Runs</div>
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#64748b' }} />
              <YAxis domain={[80, 100]} tick={{ fontSize: 10, fill: '#64748b' }} unit="%" />
              <Tooltip
                contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', fontSize: 11 }}
                formatter={v => [`${v}%`, 'Accuracy']}
              />
              <Line
                type="monotone"
                dataKey="accuracy"
                stroke="#10b981"
                strokeWidth={2}
                dot={{ r: 3, fill: '#10b981' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Run history */}
      {runs.length > 0 && (
        <div className="bg-soc-panel border border-soc-border rounded-lg p-5">
          <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest mb-3">Run History</div>
          <div className="overflow-auto max-h-48">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-600 border-b border-soc-border">
                  <th className="text-left pb-1.5">#</th>
                  <th className="text-left pb-1.5">Time (UTC)</th>
                  <th className="text-right pb-1.5">Accuracy</th>
                  <th className="text-right pb-1.5">Samples</th>
                  <th className="text-right pb-1.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/50">
                {runs.map((r, i) => (
                  <tr key={r.id}>
                    <td className="py-1 text-slate-600">{runs.length - i}</td>
                    <td className="py-1 text-slate-400">{r.evaluated_at?.slice(0, 19).replace('T', ' ')}</td>
                    <td className={`py-1 text-right font-semibold ${r.accuracy > 0.95 ? 'text-emerald-400' : r.accuracy > 0.85 ? 'text-amber-400' : 'text-rose-400'}`}>
                      {(r.accuracy * 100).toFixed(2)}%
                    </td>
                    <td className="py-1 text-right text-slate-500">{r.test_samples?.toLocaleString()}</td>
                    <td className="py-1 text-right">
                      <CheckCircle className="w-3 h-3 text-emerald-400 inline" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
