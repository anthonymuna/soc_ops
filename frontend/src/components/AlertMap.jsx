import { Globe, MapPin } from 'lucide-react'

export default function AlertMap({ history }) {
  const geoCounts = {}
  history.forEach(a => {
    if (a.ml_src_geo && a.ml_src_geo !== 'Local Network') {
      geoCounts[a.ml_src_geo] = (geoCounts[a.ml_src_geo] || 0) + 1
    }
  })

  const sorted = Object.entries(geoCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest flex items-center gap-2">
          <Globe className="w-3.5 h-3.5" />
          Threat Origins
        </div>
        <span className="text-[10px] text-slate-500 uppercase">Geo Correlation</span>
      </div>

      <div className="space-y-3">
        {sorted.map(([geo, count]) => (
          <div key={geo} className="flex items-center justify-between group">
            <div className="flex items-center gap-3">
              <div className="w-1.5 h-1.5 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]" />
              <span className="text-xs text-slate-300 group-hover:text-cyan-400 transition-colors">{geo}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-1 w-12 bg-soc-border rounded-full overflow-hidden">
                <div 
                  className="h-full bg-rose-500/50 rounded-full" 
                  style={{ width: `${Math.min(count * 10, 100)}%` }} 
                />
              </div>
              <span className="text-[10px] font-mono text-slate-500">{count}</span>
            </div>
          </div>
        ))}

        {sorted.length === 0 && (
          <div className="py-4 text-center">
            <MapPin className="w-6 h-6 text-slate-700 mx-auto mb-2 opacity-20" />
            <div className="text-xs text-slate-600">No external threats detected</div>
            <div className="text-[9px] text-slate-700 mt-1 uppercase tracking-tight">System monitoring local traffic</div>
          </div>
        )}
      </div>

      {sorted.length > 0 && (
        <div className="mt-4 pt-3 border-t border-soc-border/50 text-center">
            <span className="text-[9px] text-slate-600 uppercase tracking-widest">
                AI Correlation: {sorted[0][0]} cluster active
            </span>
        </div>
      )}
    </div>
  )
}
