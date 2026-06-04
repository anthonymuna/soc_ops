import { useState, useEffect, useCallback } from 'react'
import { getToken, clearToken } from '../auth'

const ML_API = import.meta.env.VITE_ML_API || '/api'

async function fetchJson(url, onUnauth) {
  const token = getToken()
  const r = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  })
  if (r.status === 401 && onUnauth) {
    onUnauth()
    throw new Error('Unauthorized')
  }
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

export function useSOC(refreshMs = 10000, onUnauth) {
  const [health,   setHealth]   = useState(null)
  const [stats,    setStats]    = useState(null)
  const [alerts,   setAlerts]   = useState([])
  const [history,  setHistory]  = useState([])
  const [error,    setError]    = useState(null)
  const [lastTick, setLastTick] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [h, s, a] = await Promise.allSettled([
        fetchJson(`${ML_API}/health`,                onUnauth),
        fetchJson(`${ML_API}/stats`,                 onUnauth),
        fetchJson(`${ML_API}/alerts?limit=200&minutes=360`, onUnauth),
      ])
      if (h.status === 'fulfilled') setHealth(h.value)
      if (s.status === 'fulfilled') setStats(s.value)
      if (a.status === 'fulfilled') {
        const incoming = a.value.alerts || []
        setAlerts(incoming)
        setHistory(prev => {
          const combined = [...incoming, ...prev]
          const seen = new Set()
          return combined.filter(x => {
            const key = `${x.ml_detected_at}${x.src_ip}${x.event_type}`
            if (seen.has(key)) return false
            seen.add(key)
            return true
          }).slice(0, 500)
        })
      }
      setError(null)
      setLastTick(new Date())
    } catch (e) {
      setError(e.message)
    }
  }, [onUnauth])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, refreshMs)
    return () => clearInterval(id)
  }, [refresh, refreshMs])

  return { health, stats, alerts, history, error, lastTick, refresh }
}
