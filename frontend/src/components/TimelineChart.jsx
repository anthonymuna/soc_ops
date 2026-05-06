import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts'
import { useMemo } from 'react'

function bucketAlerts(alerts, bucketMinutes = 5) {
  const buckets = {}
  for (const a of alerts) {
    const ts = a.ml_detected_at || a['@timestamp']
    if (!ts) continue
    const d = new Date(ts)
    const bucket = new Date(Math.floor(d.getTime() / (bucketMinutes * 60000)) * bucketMinutes * 60000)
    const key = bucket.toISOString()
    if (!buckets[key]) buckets[key] = { time: key, critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    const sev = a.ml_severity || 'low'
    buckets[key][sev] = (buckets[key][sev] || 0) + 1
    buckets[key].total++
  }
  return Object.values(buckets)
    .sort((a, b) => a.time.localeCompare(b.time))
    .slice(-24)
    .map(b => ({ ...b, time: b.time.slice(11, 16) }))
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-soc-bg border border-soc-border rounded p-2 text-xs">
      <div className="text-cyan-400 mb-1">{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  )
}

const CHART_COLORS = {
  dark:  { grid: '#1e2d4a', axis: '#334155', tick: '#475569' },
  light: { grid: '#e2e8f0', axis: '#94a3b8', tick: '#6b7280' },
}

const SERIES_COLORS = [
  { key: 'critical', dark: '#ff3366', light: '#e11d48' },
  { key: 'high',     dark: '#f97316', light: '#ea580c' },
  { key: 'medium',   dark: '#ffaa00', light: '#d97706' },
  { key: 'low',      dark: '#00ff88', light: '#059669' },
]

export default function TimelineChart({ history, dark = false }) {
  const data = useMemo(() => bucketAlerts(history), [history])
  const c = dark ? CHART_COLORS.dark : CHART_COLORS.light

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4">
      <div className="text-xs font-semibold text-cyan-400 uppercase tracking-widest mb-3">
        Alert Timeline (5-min buckets)
      </div>
      {data.length === 0 ? (
        <div className="h-32 flex items-center justify-center text-slate-600 text-sm">
          Collecting data...
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={160}>
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <defs>
              {SERIES_COLORS.map(({ key, dark: dc, light: lc }) => {
                const color = dark ? dc : lc
                return (
                  <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={color} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={color} stopOpacity={0} />
                  </linearGradient>
                )
              })}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={c.grid} />
            <XAxis dataKey="time" stroke={c.axis} tick={{ fill: c.tick, fontSize: 9 }} />
            <YAxis stroke={c.axis} tick={{ fill: c.tick, fontSize: 9 }} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} />
            {SERIES_COLORS.map(({ key, dark: dc, light: lc }) => {
              const stroke = dark ? dc : lc
              return (
                <Area key={key} type="monotone" dataKey={key} stackId="1"
                  stroke={stroke} fill={`url(#grad-${key})`} strokeWidth={1.5} />
              )
            })}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
