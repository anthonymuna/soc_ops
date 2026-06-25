import { useState } from 'react'
import { FileText } from 'lucide-react'
import { getToken } from '../auth'

export default function ReportGenerator({ stats, alerts, history, health }) {
  const [loading, setLoading] = useState(false)
  const [hours, setHours] = useState(24)

  async function generate() {
    setLoading(true)
    try {
      const token = getToken()
      const r = await fetch(`/api/reports/?hours=${hours}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ngao_soc_report_${new Date().toISOString().slice(0, 10)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      alert(`Report failed: ${e.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center gap-1">
      <select
        value={hours}
        onChange={e => setHours(Number(e.target.value))}
        className="bg-soc-panel border border-soc-border text-slate-400 text-[10px] rounded px-1 py-1"
      >
        <option value={1}>1h</option>
        <option value={6}>6h</option>
        <option value={24}>24h</option>
        <option value={48}>48h</option>
        <option value={168}>7d</option>
      </select>
      <button
        onClick={generate}
        disabled={loading}
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 rounded transition-colors disabled:opacity-50"
        title="Generate PDF report from Elasticsearch data"
      >
        <FileText className="w-3.5 h-3.5" />
        {loading ? 'GENERATING…' : 'REPORT'}
      </button>
    </div>
  )
}
