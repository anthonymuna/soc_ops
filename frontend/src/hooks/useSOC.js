import { useState, useEffect, useCallback } from 'react'
import { getToken, clearToken } from '../auth'

export const ML_API = import.meta.env.VITE_ML_API || '/api'

export async function fetchJson(url, onUnauth) {
  const token = getToken()
  const r = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  })
  if (r.status === 401 && onUnauth) {
    onUnauth()
    throw new Error('Unauthorized')
  }
  let data;
  try { data = await r.json() } catch(e) {}
  if (!r.ok) {
    throw new Error(data?.error || `HTTP ${r.status}`)
  }
  return data
}

export function useSOC(refreshMs = 10000, onUnauth, selectedConnector, timeframe = 'live') {
  const [health,   setHealth]   = useState(null)
  const [stats,    setStats]    = useState(null)
  const [alerts,   setAlerts]   = useState([])
  const [history,  setHistory]  = useState([])
  const [error,    setError]    = useState(null)
  const [lastTick, setLastTick] = useState(null)
  const [prevTimeframe, setPrevTimeframe] = useState(timeframe)

  const refresh = useCallback(async () => {
    try {
      if (timeframe !== prevTimeframe) {
        setHistory([])
        setPrevTimeframe(timeframe)
      }

      const qs = selectedConnector ? `?connector=${encodeURIComponent(selectedConnector)}` : ''
      const limit = 1000
      const minutes = timeframe === 'live' ? 1440 : 100800
      let alertQs = `?limit=${limit}&minutes=${minutes}&timeframe=${encodeURIComponent(timeframe)}`
      if (selectedConnector) {
        alertQs += `&connector=${encodeURIComponent(selectedConnector)}`
      }

      const [h, s, a] = await Promise.allSettled([
        fetchJson(`${ML_API}/health/`, onUnauth),
        fetchJson(`${ML_API}/stats/${qs}`, onUnauth),
        fetchJson(`${ML_API}/alerts/${alertQs}`, onUnauth),
      ])
      if (h.status === 'fulfilled') setHealth(h.value)
      if (s.status === 'fulfilled') setStats(s.value)
      if (a.status === 'fulfilled') {
        const incoming = a.value.alerts || []
        setAlerts(incoming)
        setHistory(prev => {
          // If timeframe changed midway, start fresh
          const currentPrev = timeframe !== prevTimeframe ? [] : prev
          const combined = [...incoming, ...currentPrev]
          const seen = new Set()
          return combined.filter(x => {
            const key = `${x.ml_detected_at}${x.src_ip}${x.event_type}`
            if (seen.has(key)) return false
            seen.add(key)
            return true
          }).slice(0, Math.max(500, limit))
        })
      }
      setError(null)
      setLastTick(new Date())
    } catch (e) {
      setError(e.message)
    }
  }, [onUnauth, selectedConnector, timeframe, prevTimeframe])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, refreshMs)
    return () => clearInterval(id)
  }, [refresh, refreshMs])

  return { health, stats, alerts, history, error, lastTick, refresh }
}
