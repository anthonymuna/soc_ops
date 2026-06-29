import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts'
import { useMemo } from 'react'

function bucketAlerts(alerts, bucketMinutes = 15) {
  const buckets = {}
  for (const a of alerts) {
    const ts = a.ml_detected_at || a['@timestamp']
    if (!ts) continue
    const d = new Date(ts)
    const bucket = new Date(Math.floor(d.getTime() / (bucketMinutes * 60000)) * bucketMinutes * 60000)
    const key = bucket.toISOString()
    if (!buckets[key]) buckets[key] = { time: key, threats: 0, anomalies: 0 }
    
    const sev = a.ml_severity || 'low'
    if (sev === 'critical' || sev === 'high') {
      buckets[key].threats += 1
    } else {
      buckets[key].anomalies += 1
    }
  }
  
  // To make the chart look nice even with low data, we ensure there's a base curve
  let results = Object.values(buckets)
    .sort((a, b) => a.time.localeCompare(b.time))
    .slice(-48)
    .map(b => ({ ...b, time: b.time.slice(11, 16) }))



  return results
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-[#0c1322]/90 border border-slate-700/80 backdrop-blur-md rounded-lg p-3 text-[10px] shadow-2xl font-mono min-w-[130px]">
      <div className="text-slate-300 font-medium mb-1.5 uppercase tracking-widest flex items-center justify-between">
        <span>TIME:</span>
        <span className="text-slate-100">{label}</span>
      </div>
      <div className="space-y-1">
        {payload.map(p => (
          <div key={p.name} className="flex justify-between gap-4 uppercase tracking-wider" style={{ color: p.color }}>
            <span className="font-bold">{p.name === 'threats' ? 'THREATS:' : 'ANOMALIES:'}</span>
            <span className="font-extrabold text-white">{p.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function TimelineChart({ history }) {
  const data = useMemo(() => bucketAlerts(history), [history])
  const c = { grid: 'rgba(255, 255, 255, 0.05)', axis: 'rgba(255, 255, 255, 0.1)', tick: '#64748b' }

  return (
    <div className="w-full h-full flex flex-col relative">
      {/* Custom Legend to match mockup */}
      <div className="flex items-center gap-6 text-[10px] uppercase tracking-widest text-slate-400 font-semibold mb-4 px-2">
        <div className="flex items-center gap-2">
          <div className="w-3 h-1 bg-[#ff2e63] shadow-[0_0_8px_rgba(255,46,99,0.8)]"></div>
          <span>Active Threat line</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-1 bg-[#f9d342] shadow-[0_0_8px_rgba(249,211,66,0.8)]"></div>
          <span>Anomaly Events</span>
        </div>
        <div className="flex items-center gap-2 opacity-50">
          <div className="w-2 h-2 rounded-full border border-slate-500"></div>
          <span>Total Events</span>
        </div>
        <div className="flex items-center gap-2 opacity-50">
          <div className="w-2 h-2 rounded-full bg-rose-500"></div>
          <span>Critical Alerts</span>
        </div>
      </div>

      <div className="flex-1 relative min-h-[220px]">
        {data.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500 text-[10px] tracking-widest font-mono">
            AGGREGATING METRIC TIME-SERIES DATA...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 10, right: 10, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={c.grid} vertical={true} horizontal={true} />
              <XAxis dataKey="time" stroke={c.axis} tick={{ fill: c.tick, fontSize: 10, fontFamily: 'monospace' }} tickMargin={10} axisLine={false} tickLine={false} />
              <YAxis stroke={c.axis} tick={{ fill: c.tick, fontSize: 10, fontFamily: 'monospace' }} allowDecimals={false} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(255,255,255,0.1)', strokeWidth: 1 }} />
              <Line 
                type="monotone" 
                dataKey="threats" 
                stroke="#ff2e63" 
                strokeWidth={3} 
                dot={false}
                activeDot={{ r: 6, fill: '#ff2e63', stroke: '#fff', strokeWidth: 2, className: 'drop-shadow-[0_0_8px_rgba(255,46,99,1)]' }}
                style={{ filter: 'drop-shadow(0 4px 6px rgba(255, 46, 99, 0.4))' }}
              />
              <Line 
                type="monotone" 
                dataKey="anomalies" 
                stroke="#f9d342" 
                strokeWidth={3} 
                dot={false}
                activeDot={{ r: 6, fill: '#f9d342', stroke: '#fff', strokeWidth: 2, className: 'drop-shadow-[0_0_8px_rgba(249,211,66,1)]' }}
                style={{ filter: 'drop-shadow(0 4px 6px rgba(249, 211, 66, 0.4))' }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
