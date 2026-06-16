import React, { useState, useEffect } from 'react';
import { fetchJson, ML_API } from '../hooks/useSOC';

const ThreatIntelligence = ({ onUnauth }) => {
  const [intel, setIntel] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchIntel = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchJson(`${ML_API}/alerts/threat-intelligence/`, onUnauth);
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
    <div className="flex flex-col min-h-[500px] bg-white text-slate-800 rounded-lg shadow-md border border-slate-200 p-8">
      <div className="flex justify-between items-center mb-6 shrink-0">
        <h2 className="text-2xl font-bold text-slate-900">Threat Intelligence Overview</h2>
        <button
          onClick={fetchIntel}
          disabled={loading}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm transition-colors flex items-center gap-2 disabled:opacity-50"
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
          <div className="text-center text-slate-500 mt-10 text-lg">
            No threat intelligence data found.
          </div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {intel.map((item, idx) => (
              <div key={idx} className="bg-slate-50 border border-slate-200 rounded-lg p-5 flex flex-col gap-3 shadow-sm hover:shadow-md transition-shadow">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="font-mono text-indigo-600 font-bold text-lg">{item.ip}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{item.location || 'Unknown Location'}</div>
                    <div className="text-sm text-slate-600 mt-1 font-medium">Events: {item.count}</div>
                  </div>
                  <div className={`px-2 py-1 text-xs font-bold uppercase rounded border ${getThreatColor(item.threat_level)}`}>
                    {item.threat_level || 'UNKNOWN'}
                  </div>
                </div>
                
                <div className="text-sm">
                  <span className="text-slate-500 font-semibold">Attacker Type:</span>{' '}
                  <span className="text-slate-800 font-medium">{item.attacker_type || 'Unknown'}</span>
                </div>
                
                <div>
                  <div className="text-xs text-slate-500 font-semibold mb-1">MITRE Techniques:</div>
                  <div className="flex flex-wrap gap-2">
                    {(item.mitre_techniques || []).map((t, i) => (
                      <span key={i} className="text-xs bg-indigo-100 text-indigo-700 border border-indigo-200 rounded px-2 py-0.5 font-medium">
                        {t}
                      </span>
                    ))}
                    {(!item.mitre_techniques || item.mitre_techniques.length === 0) && (
                      <span className="text-xs text-slate-400">None detected</span>
                    )}
                  </div>
                </div>
                
                <div className="mt-auto pt-3 border-t border-slate-200">
                  <div className="text-xs text-slate-500 font-semibold mb-1">Recommendation:</div>
                  <div className="text-sm text-slate-800">{item.recommendation}</div>
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
