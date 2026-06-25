export default function StatCard({ label, value, sub, color = 'soc-accent', icon, onClick }) {
  const colorMap = {
    'soc-accent':  'text-cyan-400 border-cyan-400/20',
    'soc-green':   'text-emerald-400 border-emerald-400/20',
    'soc-red':     'text-rose-400 border-rose-400/20',
    'soc-yellow':  'text-amber-400 border-amber-400/20',
    'soc-purple':  'text-purple-400 border-purple-400/20',
  }
  const cls = colorMap[color] || colorMap['soc-accent']

  return (
    <div 
      onClick={onClick}
      className={`bg-soc-panel border ${cls} rounded-lg p-4 flex flex-col gap-1 ${onClick ? 'cursor-pointer hover:bg-white/[0.02] transition-colors hover:shadow-lg' : ''}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500 uppercase tracking-widest">{label}</span>
        {icon && <span className="text-slate-600">{icon}</span>}
      </div>
      <div className={`text-2xl font-bold ${cls.split(' ')[0]}`}>{value ?? '—'}</div>
      {sub && <div className="text-xs text-slate-500">{sub}</div>}
    </div>
  )
}
