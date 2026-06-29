export default function StatCard({ label, value, sub, color = 'soc-accent', icon, onClick }) {
  const colorMap = {
    'soc-accent':  'text-cyan-400/90 border-cyan-500/10 hover:border-cyan-500/20',
    'soc-green':   'text-cyan-400/90 border-cyan-500/10 hover:border-cyan-500/20',
    'soc-red':     'text-rose-400/90 border-rose-500/10 hover:border-rose-500/25 alert-critical-glow',
    'soc-yellow':  'text-amber-400/90 border-amber-500/10 hover:border-amber-500/25 alert-high-glow',
    'soc-purple':  'text-purple-400/90 border-purple-500/10 hover:border-purple-500/20',
  }
  const cls = colorMap[color] || colorMap['soc-accent']

  return (
    <div 
      onClick={onClick}
      className={`glass-panel border ${cls} rounded-lg p-5 flex flex-col gap-1.5 ${
        onClick ? 'cursor-pointer hover:scale-[1.02] transition-all hover:bg-slate-800/40' : ''
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">{label}</span>
        {icon && <span className="text-slate-600 hover:text-cyan-400/50 transition-colors">{icon}</span>}
      </div>
      <div className={`text-2xl font-bold font-mono tracking-tight`}>
        {value ?? '—'}
      </div>
      {sub && <div className="text-[10px] text-slate-400 font-medium truncate">{sub}</div>}
    </div>
  )
}
