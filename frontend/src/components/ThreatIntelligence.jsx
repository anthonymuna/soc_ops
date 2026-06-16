import React, { useState, useEffect } from 'react';
import useSOC from '../hooks/useSOC';

const ThreatIntelligence = ({ onUnauth }) => {
  const [intel, setIntel] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { fetchWithAuth } = useSOC(onUnauth);

  const fetchIntel = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchWithAuth('/api/alerts/threat-intelligence/');
      if (data.error) {
        setError(data.error);
      } else {
        setIntel(data.intelligence || []);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntel();
  }, []);

  const getThreatColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'text-red-500 border-red-500/30 bg-red-500/10';
      case 'high': return 'text-amber-500 border-amber-500/30 bg-amber-500/10';
      case 'medium': return 'text-yellow-500 border-yellow-500/30 bg-yellow-500/10';
      case 'low': return 'text-green-500 border-green-500/30 bg-green-500/10';
      default: return 'text-slate-400 border-slate-700 bg-soc-bg';
    }
  };

  return (
    <div className="flex flex-col h-full bg-soc-bg text-slate-200 overflow-hidden">
      <div className="flex justify-between items-center p-4 border-b border-soc-border shrink-0">
        <h2 className="text-lg font-semibold text-soc-accent">Threat Intelligence Overview</h2>
        <button
          onClick={fetchIntel}
          disabled={loading}
          className="px-4 py-2 bg-soc-accent text-black rounded hover:bg-cyan-400 disabled:opacity-50 font-semibold"
        >
          {loading ? 'Analyzing...' : 'Re-Analyze'}
        </button>
      </div>
      
      <div className="p-4 overflow-y-auto flex-1">
        {loading ? (
          <div className="flex justify-center mt-10">
            <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-soc-accent"></div>
          </div>
        ) : error ? (
          <div className="p-4 bg-red-900/50 border border-red-500 text-red-200 rounded">
            Error: {error}
          </div>
        ) : intel.length === 0 ? (
          <div className="text-center text-slate-400 mt-10">
            No threat intelligence data found for the last 24 hours.
          </div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {intel.map((item, idx) => (
              <div key={idx} className="bg-soc-panel border border-soc-border rounded p-4 flex flex-col gap-3">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="font-mono text-soc-accent text-lg">{item.ip}</div>
                    <div className="text-xs text-slate-400 mt-1">Events: {item.count}</div>
                  </div>
                  <div className={`px-2 py-1 text-xs font-bold uppercase rounded border ${getThreatColor(item.threat_level)}`}>
                    {item.threat_level || 'UNKNOWN'}
                  </div>
                </div>
                
                <div className="text-sm">
                  <span className="text-slate-500">Attacker Type:</span>{' '}
                  <span className="text-slate-300 font-medium">{item.attacker_type || 'Unknown'}</span>
                </div>
                
                <div>
                  <div className="text-xs text-slate-500 mb-1">MITRE Techniques:</div>
                  <div className="flex flex-wrap gap-2">
                    {(item.mitre_techniques || []).map((t, i) => (
                      <span key={i} className="text-xs bg-cyan-900/50 text-cyan-400 border border-cyan-800 rounded px-2 py-0.5">
                        {t}
                      </span>
                    ))}
                    {(!item.mitre_techniques || item.mitre_techniques.length === 0) && (
                      <span className="text-xs text-slate-600">None detected</span>
                    )}
                  </div>
                </div>
                
                <div className="mt-auto pt-2 border-t border-soc-border">
                  <div className="text-xs text-slate-500 mb-1">Recommendation:</div>
                  <div className="text-sm text-slate-300">{item.recommendation}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatIntelligence;
