export default function ModelStatus({ health }) {
  if (!health) return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4">
      <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest mb-2">Model Status</div>
      <div className="text-slate-600 text-sm">Connecting...</div>
    </div>
  )

  const trained = health.model_trained
  const nslKdd  = health.nsl_kdd_trained

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-4 space-y-3">
      <div className="text-xs font-bold text-cyan-400 uppercase tracking-widest">AI Model Status</div>

      <div className="flex flex-col gap-2">
        <ModelRow
          label="IsolationForest"
          desc="Zero-day / unknown anomalies"
          active={trained}
          tag="UNSUPERVISED"
          tagColor="cyan"
        />
        <ModelRow
          label="XGBoost + NSL-KDD (41 features)"
          desc="Known attack classification (DoS/Probe/R2L/U2R)"
          active={nslKdd}
          tag="SUPERVISED"
          tagColor="purple"
          accuracy="~99.7%"
        />
      </div>

      <div className="border-t border-soc-border pt-2 space-y-1 text-[10px] text-slate-500">
        <div>Training samples: <span className="text-cyan-400">{(health.training_samples || 0).toLocaleString()}</span></div>
        <div>ES connected: <span className={health.es_connected ? 'text-emerald-400' : 'text-rose-400'}>
          {health.es_connected ? 'YES' : 'NO'}
        </span></div>
        {health.trained_at && (
          <div>Last trained: <span className="text-slate-400">{health.trained_at.slice(0, 19).replace('T', ' ')} UTC</span></div>
        )}
      </div>
    </div>
  )
}

function ModelRow({ label, desc, active, tag, tagColor, accuracy }) {
  const tagCls = {
    cyan:   'bg-cyan-400/10 text-cyan-400 border-cyan-400/20',
    purple: 'bg-purple-400/10 text-purple-400 border-purple-400/20',
  }
  return (
    <div className={`rounded p-2 border text-xs ${active ? 'border-soc-border bg-black/[0.02] dark:bg-white/[0.02]' : 'border-slate-200 dark:border-slate-800 opacity-50'}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${active ? 'bg-emerald-400' : 'bg-slate-600'}`} />
          <span className="font-semibold text-slate-700 dark:text-slate-200">{label}</span>
        </div>
        <div className="flex gap-1">
          {accuracy && <span className="text-[9px] text-emerald-400">{accuracy}</span>}
          <span className={`text-[9px] px-1 rounded border ${tagCls[tagColor]}`}>{tag}</span>
        </div>
      </div>
      <div className="text-slate-500 text-[10px] mt-0.5 pl-4">{desc}</div>
    </div>
  )
}
