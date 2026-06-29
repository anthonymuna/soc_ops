import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, Globe, Search, RefreshCw, Check, Clipboard, Ban, Clock, 
  AlertTriangle, CheckCircle, Info, ExternalLink, Activity
} from 'lucide-react';
import { getToken } from '../auth';

const ABUSE_CATEGORIES = {
  3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
  6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
  9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
  12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
  15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
  18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
  21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
};

const ThreatIntelligence = ({ onUnauth }) => {
  const [intel, setIntel] = useState([]);
  const [summary, setSummary] = useState({
    total_ips: 0,
    critical_count: 0,
    high_count: 0,
    pending_count: 0,
    top_countries: []
  });
  const [selectedIp, setSelectedIp] = useState(null);
  const [selectedProfile, setSelectedProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortBy, setSortBy] = useState('score'); // score | last_seen | events
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [secondsSinceUpdate, setSecondsSinceUpdate] = useState(0);

  const fetchIntel = async (showLoading = false) => {
    if (showLoading) setLoading(true);
    const token = getToken();
    if (!token) {
      if (onUnauth) onUnauth();
      return;
    }
    try {
      const resp = await fetch('/api/alerts/threat-intelligence/', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      if (resp.status === 401) {
        if (onUnauth) onUnauth();
        return;
      }
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || 'Failed to fetch threat intelligence');
      }
      setIntel(data.intelligence || []);
      if (data.summary) {
        setSummary(data.summary);
      }
      setLastUpdated(new Date());
      setSecondsSinceUpdate(0);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  const fetchDetail = useCallback(async (ip) => {
    setDetailLoading(true);
    const token = getToken();
    if (!token) return;
    try {
      const resp = await fetch(`/api/alerts/threat-intelligence/${ip}/`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (resp.ok) {
        const data = await resp.json();
        setSelectedProfile(data);
      }
    } catch (err) {
      console.error("Error fetching detail for IP:", ip, err);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  // Poll intervals
  useEffect(() => {
    fetchIntel(true);
    const timer = setInterval(() => fetchIntel(false), 60000);
    return () => clearInterval(timer);
  }, []);

  // Seconds elapsed ticker
  useEffect(() => {
    const elapsedTimer = setInterval(() => {
      setSecondsSinceUpdate(Math.floor((new Date() - lastUpdated) / 1000));
    }, 1000);
    return () => clearInterval(elapsedTimer);
  }, [lastUpdated]);

  // Fetch detail when IP changes
  useEffect(() => {
    if (selectedIp) {
      fetchDetail(selectedIp);
    } else {
      setSelectedProfile(null);
    }
  }, [selectedIp, fetchDetail]);

  // Select first IP if none selected
  useEffect(() => {
    if (intel.length > 0 && !selectedIp) {
      setSelectedIp(intel[0].ip);
    }
  }, [intel, selectedIp]);

  // Whitelist IP
  const handleWhitelist = async (ip) => {
    const token = getToken();
    if (!token) return;
    try {
      const resp = await fetch(`/api/alerts/threat-intelligence/${ip}/whitelist/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (resp.ok) {
        fetchIntel(false);
        setSelectedIp(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Re-Enrich IP
  const handleReenrich = async (ip) => {
    const token = getToken();
    if (!token) return;
    try {
      const resp = await fetch(`/api/alerts/threat-intelligence/enrich/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip })
      });
      if (resp.ok) {
        alert(`Enrichment queue requested for ${ip}. Updates will process in the background.`);
        fetchIntel(false);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Propose Firewall Block IP
  const handleBlockIp = async (profile) => {
    const token = getToken();
    if (!token) return;
    try {
      const resp = await fetch('/api/brain/chat/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: `Propose block list action for malicious source IP ${profile.ip} located in ${profile.location || 'Unknown'} due to threat activity class ${profile.attack_classes?.join(', ') || 'anomalous scans'}.`
        })
      });
      if (resp.ok) {
        alert(`Block request successfully submitted to NGAO Brain HITL queue.`);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Export JSON
  const handleExport = (profile) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(profile, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute("href", dataStr);
    dlAnchorElem.setAttribute("download", `threat_actor_${profile.ip}.json`);
    dlAnchorElem.click();
  };

  const getThreatColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'text-[#ff2e63]';
      case 'high': return 'text-[#f9d342]';
      case 'medium': return 'text-violet-400';
      case 'low': return 'text-[#00e5ff]';
      default: return 'text-slate-400';
    }
  };

  const getThreatBgClass = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'bg-[#ff2e63]/10 border-[#ff2e63]/25';
      case 'high': return 'bg-[#f9d342]/10 border-[#f9d342]/25';
      case 'medium': return 'bg-violet-500/10 border-violet-500/25';
      case 'low': return 'bg-[#00e5ff]/10 border-[#00e5ff]/25';
      default: return 'bg-slate-800/30 border-slate-700/50';
    }
  };

  // Filtering / Sorting logic
  const filteredIntel = intel
    .filter(item => {
      const matchSearch = item.ip.includes(searchQuery) || (item.location || '').toLowerCase().includes(searchQuery.toLowerCase());
      const matchSeverity = severityFilter === 'all' || item.threat_level === severityFilter;
      return matchSearch && matchSeverity;
    })
    .sort((a, b) => {
      if (sortBy === 'score') return b.composite_score - a.composite_score;
      if (sortBy === 'last_seen') return new Date(b.last_seen) - new Date(a.last_seen);
      if (sortBy === 'events') return b.total_events - a.total_events;
      return 0;
    });

  return (
    <div className="flex flex-col min-h-screen bg-[#090d16] text-slate-100 font-sans space-y-6">
      
      {/* Header Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex items-center justify-between">
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Total Tracked IPs</h4>
            <span className="text-2xl font-bold font-mono text-cyan-400 mt-1 block">{summary.total_ips}</span>
          </div>
          <Globe className="w-8 h-8 text-cyan-500/30" />
        </div>
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex items-center justify-between">
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Critical Threat Level</h4>
            <span className={`text-2xl font-bold font-mono mt-1 block ${summary.critical_count > 0 ? 'text-[#ff2e63] animate-pulse' : 'text-slate-400'}`}>
              {summary.critical_count}
            </span>
          </div>
          <AlertTriangle className={`w-8 h-8 ${summary.critical_count > 0 ? 'text-[#ff2e63]/30' : 'text-slate-500/30'}`} />
        </div>
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex items-center justify-between">
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">High Threat Level</h4>
            <span className="text-2xl font-bold font-mono text-[#f9d342] mt-1 block">{summary.high_count}</span>
          </div>
          <Shield className="w-8 h-8 text-[#f9d342]/30" />
        </div>
        <div className="glass-panel p-5 rounded-xl border-slate-800 flex items-center justify-between">
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Pending Enrichment</h4>
            <span className="text-2xl font-bold font-mono text-slate-400 mt-1 block flex items-center gap-2">
              {summary.pending_count}
              {summary.pending_count > 0 && <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />}
            </span>
          </div>
          <Clock className="w-8 h-8 text-slate-500/30" />
        </div>
      </div>

      {/* Main Panel Layout */}
      <div className="grid grid-cols-12 gap-6 flex-1 items-stretch min-h-[70vh]">
        
        {/* Left Panel: IP List */}
        <div className="col-span-12 lg:col-span-5 glass-panel p-5 rounded-xl border-slate-800 flex flex-col h-[70vh]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Target IP Directory</h3>
            <span className="text-[10px] text-slate-500 flex items-center gap-1.5 font-mono">
              <Clock className="w-3 h-3" /> Updated {secondsSinceUpdate}s ago
            </span>
          </div>

          {/* Filters */}
          <div className="space-y-3 mb-4 shrink-0">
            <div className="relative">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search IP address or country..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-[#121824] border border-slate-800 rounded-md pl-10 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 placeholder-slate-600"
              />
            </div>
            
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 bg-[#121824] p-1 rounded-md border border-slate-800">
                {['all', 'critical', 'high', 'medium', 'low'].map(s => (
                  <button
                    key={s}
                    onClick={() => setSeverityFilter(s)}
                    className={`px-2.5 py-1 text-[9px] font-bold uppercase rounded transition-colors ${
                      severityFilter === s 
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'text-slate-500 hover:text-slate-300'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>

              <select
                value={sortBy}
                onChange={e => setSortBy(e.target.value)}
                className="bg-[#121824] border border-slate-800 rounded px-2.5 py-1 text-[10px] font-bold uppercase text-slate-400 focus:outline-none cursor-pointer"
              >
                <option value="score">Sort: Threat Score</option>
                <option value="last_seen">Sort: Last Seen</option>
                <option value="events">Sort: Event Count</option>
              </select>
            </div>
          </div>

          {/* IP List */}
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {error && (
              <div className="p-3 bg-rose-950/20 border border-rose-500/20 rounded-lg text-rose-400 text-xs font-mono mb-3">
                API Error: {error}
              </div>
            )}
            {loading ? (
              <div className="flex items-center justify-center h-full">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              </div>
            ) : filteredIntel.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs py-20">
                No threat indicators matching criteria.
              </div>
            ) : (
              filteredIntel.map(item => {
                const isSelected = selectedIp === item.ip;
                return (
                  <div
                    key={item.ip}
                    onClick={() => setSelectedIp(item.ip)}
                    className={`border p-3 rounded-lg flex items-center justify-between cursor-pointer transition-all ${
                      isSelected 
                        ? 'bg-[#151e2e]/90 border-cyan-500/40 shadow-lg shadow-cyan-500/5' 
                        : 'bg-slate-900/30 border-slate-800/80 hover:bg-[#121824] hover:border-slate-700/60'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`w-1 h-8 rounded-full ${
                        item.threat_level === 'critical' ? 'bg-[#ff2e63]' :
                        item.threat_level === 'high' ? 'bg-[#f9d342]' :
                        item.threat_level === 'medium' ? 'bg-violet-500' :
                        'bg-[#00e5ff]'
                      }`} />
                      <div>
                        <div className="font-mono text-xs font-bold text-slate-200">{item.ip}</div>
                        <div className="text-[10px] text-slate-500 flex items-center gap-1 mt-0.5">
                          <span>{item.location || 'Unknown Location'}</span>
                          {item.is_tor && <span className="text-red-400 font-bold uppercase text-[8px] bg-red-950/20 px-1 border border-red-500/20 rounded">Tor</span>}
                          {item.is_proxy && <span className="text-amber-400 font-bold uppercase text-[8px] bg-amber-950/20 px-1 border border-amber-500/20 rounded">Proxy</span>}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <span className="text-[10px] text-slate-500 font-mono block">Events: {item.total_events}</span>
                        <span className="text-[9px] text-slate-600 uppercase font-semibold block mt-0.5">{item.attacker_type || 'Unknown'}</span>
                      </div>
                      <div className={`w-8 h-8 rounded-full border flex items-center justify-center text-xs font-mono font-bold ${getThreatBgClass(item.threat_level)} ${getThreatColor(item.threat_level)}`}>
                        {item.composite_score}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Panel: Selected IP Details */}
        <div className="col-span-12 lg:col-span-7 glass-panel p-6 rounded-xl border-slate-800 flex flex-col h-[70vh] overflow-y-auto">
          {detailLoading ? (
            <div className="flex flex-col items-center justify-center h-full space-y-3">
              <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
              <span className="text-xs text-slate-500 font-mono">Enriching threat actor parameters...</span>
            </div>
          ) : !selectedProfile ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-2">
              <Shield className="w-12 h-12 text-slate-700" />
              <span className="text-xs uppercase font-bold tracking-widest text-slate-600">No Target Selected</span>
              <p className="text-[10px] text-slate-600">Select an IP address from the directory list to display threat indicators.</p>
            </div>
          ) : (
            <div className="space-y-6">
              
              {/* Identity & Circular Threat Score */}
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800 pb-5">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <h2 className="text-2xl font-bold font-mono text-slate-100">{selectedProfile.ip}</h2>
                    <button 
                      onClick={() => {
                        navigator.clipboard.writeText(selectedProfile.ip);
                        alert("IP Address copied to clipboard.");
                      }}
                      className="text-slate-500 hover:text-cyan-400 p-1 transition-colors"
                      title="Copy IP"
                    >
                      <Clipboard className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider font-mono ${getThreatBgClass(selectedProfile.threat_level)} ${getThreatColor(selectedProfile.threat_level)}`}>
                      {selectedProfile.threat_level || 'UNKNOWN'}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded border border-slate-700 bg-slate-800/30 text-slate-300 uppercase tracking-wider font-mono">
                      {selectedProfile.attacker_type || 'Unknown Attacker Type'}
                    </span>
                    {selectedProfile.campaign_name && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded border border-cyan-500/20 bg-cyan-500/10 text-cyan-400 uppercase tracking-wider font-mono animate-pulse">
                        Campaign: {selectedProfile.campaign_name}
                      </span>
                    )}
                  </div>
                </div>

                {/* Circular Score Gauge */}
                <div className="flex items-center gap-3 bg-slate-900/40 border border-slate-800 rounded-xl p-3 shrink-0">
                  <div className="relative w-14 h-14">
                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                      <path
                        className="text-slate-800"
                        strokeWidth="3.5"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                      <path
                        className={
                          selectedProfile.composite_score >= 70 ? 'text-[#ff2e63]' :
                          selectedProfile.composite_score >= 40 ? 'text-[#f9d342]' :
                          'text-[#00e5ff]'
                        }
                        strokeDasharray={`${selectedProfile.composite_score}, 100`}
                        strokeWidth="3.5"
                        strokeLinecap="round"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <span className="text-sm font-bold font-mono">{selectedProfile.composite_score}</span>
                    </div>
                  </div>
                  <div className="text-left">
                    <span className="text-[9px] text-slate-500 uppercase tracking-widest block font-bold">Threat Index</span>
                    <span className="text-xs text-slate-300 block font-mono">Composite Rating</span>
                  </div>
                </div>
              </div>

              {/* Threat Summary Banner */}
              {selectedProfile.threat_summary && (
                <div className="bg-[#121824]/60 border-l-4 border-cyan-400 p-4 rounded-r-lg space-y-1">
                  <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest flex items-center gap-1">
                    <Info className="w-3.5 h-3.5" /> Threat Analysis Summary
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed font-mono italic">
                    "{selectedProfile.threat_summary}"
                  </p>
                </div>
              )}

              {/* Feed Intel Blocks (Grid) */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                
                {/* MaxMind details */}
                <div className="bg-[#121824]/30 border border-slate-800 rounded-lg p-4 space-y-3">
                  <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-slate-800 pb-1.5 shrink-0">
                    <Globe className="w-3.5 h-3.5 text-cyan-400" /> MaxMind GeoIP
                  </h4>
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Location</span>
                      <span className="text-slate-300 truncate max-w-[120px]" title={selectedProfile.location}>{selectedProfile.location || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">ASN</span>
                      <span className="text-cyan-400 font-bold">{selectedProfile.asn || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">ISP</span>
                      <span className="text-slate-300 truncate max-w-[120px]" title={selectedProfile.isp}>{selectedProfile.isp || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Type</span>
                      <span className="text-slate-300">{selectedProfile.connection_type || 'N/A'}</span>
                    </div>
                  </div>
                  {/* Warning Badges */}
                  <div className="flex flex-wrap gap-1 pt-1 border-t border-slate-800/40">
                    {selectedProfile.is_tor && <span className="bg-[#ff2e63]/10 border border-[#ff2e63]/30 text-[#ff2e63] text-[9px] font-bold uppercase px-1.5 py-0.5 rounded">Tor exit</span>}
                    {selectedProfile.is_proxy && <span className="bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded">Proxy exit</span>}
                    {selectedProfile.is_hosting && <span className="bg-violet-500/10 border border-violet-500/30 text-violet-400 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded">Hosting provider</span>}
                  </div>
                </div>

                {/* AbuseIPDB details */}
                <div className="bg-[#121824]/30 border border-slate-800 rounded-lg p-4 space-y-3 flex flex-col justify-between">
                  <div className="space-y-3">
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-slate-800 pb-1.5">
                      <Activity className="w-3.5 h-3.5 text-[#f9d342]" /> AbuseIPDB Feed
                    </h4>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-500">Confidence Score</span>
                        <span className={`font-bold ${selectedProfile.abuse_score >= 50 ? 'text-[#ff2e63]' : 'text-slate-300'}`}>{selectedProfile.abuse_score}%</span>
                      </div>
                      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden border border-slate-700/50">
                        <div 
                          className={`h-full ${selectedProfile.abuse_score >= 50 ? 'bg-[#ff2e63]' : 'bg-[#f9d342]'}`} 
                          style={{ width: `${selectedProfile.abuse_score}%` }} 
                        />
                      </div>
                    </div>
                  </div>
                  <div className="space-y-1 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Reports Count</span>
                      <span className="text-slate-300">{selectedProfile.abuse_reports}</span>
                    </div>
                    {selectedProfile.abuse_last_reported && (
                      <div className="flex justify-between text-[10px]">
                        <span className="text-slate-500">Last Reported</span>
                        <span className="text-slate-400">{new Date(selectedProfile.abuse_last_reported).toLocaleDateString()}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* VirusTotal details */}
                <div className="bg-[#121824]/30 border border-slate-800 rounded-lg p-4 space-y-3 flex flex-col justify-between">
                  <div>
                    <h4 className="text-[10px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-slate-800 pb-1.5">
                      <Shield className="w-3.5 h-3.5 text-rose-500" /> VirusTotal Feed
                    </h4>
                    <div className="grid grid-cols-2 gap-2 pt-2">
                      <div className="bg-slate-950/40 border border-slate-800/80 rounded p-2 text-center">
                        <span className="text-[9px] text-slate-500 uppercase block font-semibold">Malicious</span>
                        <span className={`text-base font-bold font-mono ${selectedProfile.vt_malicious > 0 ? 'text-[#ff2e63]' : 'text-slate-400'}`}>{selectedProfile.vt_malicious}</span>
                      </div>
                      <div className="bg-slate-950/40 border border-slate-800/80 rounded p-2 text-center">
                        <span className="text-[9px] text-slate-500 uppercase block font-semibold">Suspicious</span>
                        <span className={`text-base font-bold font-mono ${selectedProfile.vt_suspicious > 0 ? 'text-amber-400' : 'text-slate-400'}`}>{selectedProfile.vt_suspicious}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-[9px] text-slate-600 font-mono text-center">
                    {selectedProfile.vt_malicious > 0 || selectedProfile.vt_suspicious > 0 
                      ? "Flagged by security vendor engines" 
                      : "No active VirusTotal detections"
                    }
                  </div>
                </div>

              </div>

              {/* NGAO SOC Activity & MITRE Techniques */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Internal telemetry */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5">NGAO SOC Activity</h4>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between">
                      <span className="text-slate-500">First Observed</span>
                      <span className="text-slate-300">{selectedProfile.first_seen ? new Date(selectedProfile.first_seen).toLocaleString() : 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Last Observed</span>
                      <span className="text-slate-300">{selectedProfile.last_seen ? new Date(selectedProfile.last_seen).toLocaleString() : 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Total Scan Events</span>
                      <span className="text-cyan-400 font-bold">{selectedProfile.total_events}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Active Connectors</span>
                      <span className="text-slate-300 uppercase truncate max-w-[150px]">{selectedProfile.connectors_seen?.join(', ') || 'wazuh'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Targeted Hosts</span>
                      <span className="text-slate-300 truncate max-w-[150px]" title={selectedProfile.targeted_agents?.join(', ')}>{selectedProfile.targeted_agents?.join(', ') || 'N/A'}</span>
                    </div>
                  </div>
                </div>

                {/* MITRE Techniques */}
                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-1.5">MITRE ATT&CK Correlation</h4>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {(selectedProfile.mitre_techniques || []).map((t, idx) => (
                      <a
                        key={idx}
                        href={`https://attack.mitre.org/techniques/${t.split('.')[0]}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="bg-cyan-500/10 hover:bg-cyan-500/25 border border-cyan-500/30 hover:border-cyan-400 text-cyan-400 px-2 py-0.5 rounded text-[10px] font-mono flex items-center gap-1 transition-all"
                      >
                        {t} <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    ))}
                    {(!selectedProfile.mitre_techniques || selectedProfile.mitre_techniques.length === 0) && (
                      <span className="text-xs text-slate-600 font-mono italic">No MITRE techniques mapped.</span>
                    )}
                  </div>
                  {selectedProfile.attack_classes && selectedProfile.attack_classes.length > 0 && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 uppercase tracking-widest font-bold block mb-1">Attack Classification</span>
                      <div className="flex flex-wrap gap-1.5">
                        {(selectedProfile.attack_classes || []).map((ac, idx) => (
                          <span key={idx} className="bg-slate-800 border border-slate-700/60 text-slate-300 px-1.5 py-0.5 rounded text-[10px] font-mono uppercase">
                            {ac}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

              </div>

              {/* Collapsible Analyst Notes Block (Qwen Output) */}
              {selectedProfile.analyst_notes && (
                <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/15">
                  <div className="bg-[#121824]/50 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" /> Analyst Intelligence Notes
                    </span>
                    <span className="text-[9px] text-slate-500 font-mono">Qwen Engine • {selectedProfile.qwen_analyzed_at ? new Date(selectedProfile.qwen_analyzed_at).toLocaleDateString() : 'N/A'}</span>
                  </div>
                  <div className="p-4 space-y-4">
                    
                    {/* Notes text */}
                    <div className="text-xs text-slate-300 leading-relaxed font-mono whitespace-pre-wrap border-b border-slate-800/40 pb-4">
                      {selectedProfile.analyst_notes}
                    </div>

                    {/* Recommended defensive actions */}
                    {selectedProfile.recommended_actions && selectedProfile.recommended_actions.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">Recommended Defensive Actions</span>
                        <div className="space-y-1.5">
                          {(selectedProfile.recommended_actions || []).map((act, idx) => (
                            <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300 font-mono">
                              <span className="text-cyan-500 font-bold shrink-0">{idx + 1}.</span>
                              <span>{act}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                  </div>
                </div>
              )}

              {/* Action Bar */}
              <div className="flex flex-wrap items-center justify-between gap-4 border-t border-slate-800 pt-5">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleBlockIp(selectedProfile)}
                    disabled={selectedProfile.is_blocked}
                    className="bg-[#ff2e63]/10 hover:bg-[#ff2e63]/25 border border-[#ff2e63]/30 hover:border-[#ff2e63] text-[#ff2e63] text-[10px] font-bold tracking-wider uppercase px-4 py-2 rounded transition-all flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <Ban className="w-3.5 h-3.5" /> {selectedProfile.is_blocked ? 'Proposed Blocked' : 'Propose Block IP'}
                  </button>
                  <button
                    onClick={() => handleWhitelist(selectedProfile.ip)}
                    className="bg-[#00e5ff]/10 hover:bg-[#00e5ff]/25 border border-[#00e5ff]/30 hover:border-[#00e5ff] text-[#00e5ff] text-[10px] font-bold tracking-wider uppercase px-4 py-2 rounded transition-all flex items-center gap-1.5"
                  >
                    <CheckCircle className="w-3.5 h-3.5" /> Whitelist IP
                  </button>
                </div>
                
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleReenrich(selectedProfile.ip)}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 text-[10px] font-bold tracking-wider uppercase px-4 py-2 rounded transition-all flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" /> Re-Enrich Intel
                  </button>
                  <button
                    onClick={() => handleExport(selectedProfile)}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 text-[10px] font-bold tracking-wider uppercase px-4 py-2 rounded transition-all flex items-center gap-1.5"
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> Export JSON
                  </button>
                </div>
              </div>

            </div>
          )}
        </div>

      </div>

    </div>
  );
};

export default ThreatIntelligence;
