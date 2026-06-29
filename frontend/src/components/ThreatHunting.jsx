import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, Play, Terminal, Database, Activity, Folder, Brain, Plus, 
  Search, CheckCircle, AlertTriangle, AlertCircle, RefreshCw, Trash2, 
  X, ChevronRight, BookOpen, Clock, Globe, ArrowRight, Save, Check
} from 'lucide-react';
import { getToken } from '../auth';

const ThreatHunting = ({ onUnauth }) => {
  const [activeTab, setActiveTab] = useState('workbench'); // workbench | hypotheses | baselines | campaigns | ai_assistant
  
  // Workbench States
  const [index, setIndex] = useState('syndicate4-ml-alerts');
  const [queryMode, setQueryMode] = useState('visual'); // visual | dsl
  const [visualFilters, setVisualFilters] = useState({
    event_type: '',
    src_ip: '',
    dst_ip: '',
    ml_severity: '',
  });
  const [rawDsl, setRawDsl] = useState('{\n  "query": {\n    "match_all": {}\n  }\n}');
  const [timeRange, setTimeRange] = useState('24h');
  const [size, setSize] = useState(200);
  const [workbenchLoading, setWorkbenchLoading] = useState(false);
  const [workbenchResults, setWorkbenchResults] = useState(null);
  const [savedQueries, setSavedQueries] = useState([]);
  const [saveQueryModalOpen, setSaveQueryModalOpen] = useState(false);
  const [newQueryName, setNewQueryName] = useState('');
  const [newQueryDesc, setNewQueryDesc] = useState('');

  // Hypotheses States
  const [hypotheses, setHypotheses] = useState([]);
  const [hypothesesLoading, setHypothesesLoading] = useState(false);
  const [selectedHypothesis, setSelectedHypothesis] = useState(null);
  const [hypothesisResults, setHypothesisResults] = useState(null);
  const [hypFilterTactic, setHypFilterTactic] = useState('all');
  const [hypFilterSeverity, setHypFilterSeverity] = useState('all');

  // Baselines States
  const [baselines, setBaselines] = useState([]);
  const [deviations, setDeviations] = useState([]);
  const [baselinesLoading, setBaselinesLoading] = useState(false);
  const [selectedBaseline, setSelectedBaseline] = useState(null);

  // Campaigns States
  const [campaigns, setCampaigns] = useState([]);
  const [campaignsLoading, setCampaignsLoading] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [newCampaignOpen, setNewCampaignOpen] = useState(false);
  const [newCampaignData, setNewCampaignData] = useState({
    name: '',
    description: '',
    hypothesis: '',
    target_agents: '',
    target_ips: '',
  });
  const [newFindingOpen, setNewFindingOpen] = useState(false);
  const [newFindingData, setNewFindingData] = useState({
    title: '',
    verdict: 'suspicious',
    description: '',
    analyst_notes: '',
    src_ip: '',
    agent_name: '',
    event_type: ''
  });

  // AI Assistant States
  const [aiPrompt, setAiPrompt] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState(null);
  const [aiSaveName, setAiSaveName] = useState('');

  // General Notification Error
  const [error, setError] = useState(null);

  // Helpers
  const getSeverityColor = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'text-rose-500 border-rose-500/20 bg-rose-500/10';
      case 'high': return 'text-orange-500 border-orange-500/20 bg-orange-500/10';
      case 'medium': return 'text-yellow-500 border-yellow-500/20 bg-yellow-500/10';
      case 'low': return 'text-emerald-500 border-emerald-500/20 bg-emerald-500/10';
      default: return 'text-slate-400 border-slate-700 bg-slate-800/30';
    }
  };

  const getTacticLabel = (tac) => {
    return tac?.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase()) || 'Unknown';
  };

  // --- API OPERATIONS ---

  // Fetch Saved Queries
  const fetchSavedQueries = async () => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch('/api/hunt/queries/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        const data = await r.json();
        setSavedQueries(data);
      }
    } catch (e) { console.error(e); }
  };

  // Fetch Hypotheses
  const fetchHypotheses = async () => {
    setHypothesesLoading(true);
    const token = getToken();
    if (!token) return;
    try {
      let url = '/api/hunt/hypotheses/';
      const params = [];
      if (hypFilterTactic !== 'all') params.push(`tactic=${hypFilterTactic}`);
      if (hypFilterSeverity !== 'all') params.push(`severity=${hypFilterSeverity}`);
      if (params.length > 0) url += `?${params.join('&')}`;

      const r = await fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        const data = await r.json();
        setHypotheses(data);
      }
    } catch (e) { console.error(e); }
    finally { setHypothesesLoading(false); }
  };

  // Fetch Baselines & Deviations
  const fetchBaselines = async () => {
    setBaselinesLoading(true);
    const token = getToken();
    if (!token) return;
    try {
      const r1 = await fetch('/api/hunt/baselines/', { headers: { 'Authorization': `Bearer ${token}` } });
      const r2 = await fetch('/api/hunt/deviations/', { headers: { 'Authorization': `Bearer ${token}` } });
      if (r1.ok) setBaselines(await r1.json());
      if (r2.ok) setDeviations(await r2.json());
    } catch (e) { console.error(e); }
    finally { setBaselinesLoading(false); }
  };

  // Fetch Campaigns
  const fetchCampaigns = async () => {
    setCampaignsLoading(true);
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch('/api/hunt/campaigns/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        setCampaigns(await r.json());
      }
    } catch (e) { console.error(e); }
    finally { setCampaignsLoading(false); }
  };

  // Trigger Workbench search
  const handleRunWorkbench = async (dslPayload = null) => {
    setWorkbenchLoading(true);
    setError(null);
    const token = getToken();
    if (!token) return;

    let payloadQuery = {};
    if (dslPayload) {
      payloadQuery = dslPayload;
    } else if (queryMode === 'dsl') {
      try {
        payloadQuery = JSON.parse(rawDsl);
      } catch (e) {
        setError("Invalid JSON format in Raw DSL Query editor.");
        setWorkbenchLoading(false);
        return;
      }
    } else {
      // Build Visual Query
      const must = [];
      if (visualFilters.event_type) must.push({ "term": { "event_type.keyword": visualFilters.event_type } });
      if (visualFilters.src_ip) must.push({ "term": { "src_ip": visualFilters.src_ip } });
      if (visualFilters.dst_ip) must.push({ "term": { "dst_ip": visualFilters.dst_ip } });
      if (visualFilters.ml_severity) must.push({ "term": { "ml_severity.keyword": visualFilters.ml_severity } });
      
      payloadQuery = {
        "query": must.length > 0 ? { "bool": { "must": must } } : { "match_all": {} },
        "sort": [{ "ml_detected_at": { "order": "desc" } }]
      };
    }

    try {
      const r = await fetch('/api/hunt/workbench/run/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          index,
          query: payloadQuery,
          time_range: timeRange,
          size
        })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Query failed');
      setWorkbenchResults(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setWorkbenchLoading(false);
    }
  };

  // Run Saved Query
  const handleRunSavedQuery = async (queryId) => {
    setWorkbenchLoading(true);
    setError(null);
    const token = getToken();
    if (!token) return;

    try {
      const r = await fetch(`/api/hunt/queries/${queryId}/run/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ time_range: timeRange, size })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Execution failed');
      setWorkbenchResults(data);
      fetchSavedQueries(); // Refresh run count
    } catch (e) {
      setError(e.message);
    } finally {
      setWorkbenchLoading(false);
    }
  };

  // Delete Saved Query
  const handleDeleteQuery = async (queryId) => {
    const token = getToken();
    if (!token) return;
    if (!confirm("Are you sure you want to delete this query?")) return;
    try {
      const r = await fetch(`/api/hunt/queries/${queryId}/`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        fetchSavedQueries();
      }
    } catch (e) { console.error(e); }
  };

  // Save Query Modal trigger
  const handleSaveQuery = async () => {
    const token = getToken();
    if (!token) return;
    let payloadQuery = {};
    if (queryMode === 'dsl') {
      try { payloadQuery = JSON.parse(rawDsl); } catch (e) { return; }
    } else {
      const must = [];
      if (visualFilters.event_type) must.push({ "term": { "event_type.keyword": visualFilters.event_type } });
      if (visualFilters.src_ip) must.push({ "term": { "src_ip": visualFilters.src_ip } });
      if (visualFilters.dst_ip) must.push({ "term": { "dst_ip": visualFilters.dst_ip } });
      if (visualFilters.ml_severity) must.push({ "term": { "ml_severity.keyword": visualFilters.ml_severity } });
      payloadQuery = {
        "query": must.length > 0 ? { "bool": { "must": must } } : { "match_all": {} },
        "sort": [{ "ml_detected_at": { "order": "desc" } }]
      };
    }

    try {
      const r = await fetch('/api/hunt/queries/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: newQueryName,
          description: newQueryDesc,
          es_index: index,
          es_query: payloadQuery,
          filters: visualFilters,
          tags: [index]
        })
      });
      if (r.ok) {
        setSaveQueryModalOpen(false);
        setNewQueryName('');
        setNewQueryDesc('');
        fetchSavedQueries();
      }
    } catch (e) { console.error(e); }
  };

  // Execute Playbook Hypothesis
  const handleRunHypothesis = async (hyp) => {
    setHypothesesLoading(true);
    setHypothesisResults(null);
    const token = getToken();
    if (!token) return;

    try {
      const r = await fetch(`/api/hunt/hypotheses/${hyp.id}/run/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ time_range: timeRange, size })
      });
      const data = await r.json();
      if (r.ok) {
        setHypothesisResults(data);
        fetchHypotheses(); // Refresh run count
      }
    } catch (e) { console.error(e); }
    finally { setHypothesesLoading(false); }
  };

  // Acknowledge Deviation lead
  const handleAcknowledgeDeviation = async (devId) => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`/api/hunt/deviations/${devId}/acknowledge/`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        fetchBaselines();
      }
    } catch (e) { console.error(e); }
  };

  // Create Campaign
  const handleCreateCampaign = async () => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch('/api/hunt/campaigns/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: newCampaignData.name,
          description: newCampaignData.description,
          hypothesis: newCampaignData.hypothesis || null,
          target_agents: newCampaignData.target_agents ? newCampaignData.target_agents.split(',').map(s => s.trim()) : [],
          target_ips: newCampaignData.target_ips ? newCampaignData.target_ips.split(',').map(s => s.trim()) : [],
        })
      });
      if (r.ok) {
        setNewCampaignOpen(false);
        setNewCampaignData({ name: '', description: '', hypothesis: '', target_agents: '', target_ips: '' });
        fetchCampaigns();
      }
    } catch (e) { console.error(e); }
  };

  // Fetch single campaign details
  const fetchCampaignDetail = async (id) => {
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`/api/hunt/campaigns/${id}/`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        setSelectedCampaign(await r.json());
      }
    } catch (e) { console.error(e); }
  };

  // Save Campaign Notes
  const handleSaveCampaignNotes = async () => {
    if (!selectedCampaign) return;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`/api/hunt/campaigns/${selectedCampaign.id}/`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ notes: selectedCampaign.notes, status: selectedCampaign.status })
      });
      if (r.ok) {
        alert("Campaign status and notes saved successfully.");
        fetchCampaigns();
      }
    } catch (e) { console.error(e); }
  };

  // Add Finding to Campaign
  const handleAddFinding = async () => {
    if (!selectedCampaign) return;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch(`/api/hunt/campaigns/${selectedCampaign.id}/findings/`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newFindingData)
      });
      if (r.ok) {
        setNewFindingOpen(false);
        setNewFindingData({ title: '', verdict: 'suspicious', description: '', analyst_notes: '', src_ip: '', agent_name: '', event_type: '' });
        fetchCampaignDetail(selectedCampaign.id);
      }
    } catch (e) { console.error(e); }
  };

  // Generate AI Hunt DSL with Qwen
  const handleAIGenerate = async () => {
    setAiLoading(true);
    setAiResult(null);
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch('/api/hunt/ai/generate/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ prompt: aiPrompt })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Generation failed');
      setAiResult(data);
    } catch (e) {
      alert(`AI Hunt Generation failed: ${e.message}`);
    } finally {
      setAiLoading(false);
    }
  };

  // Save AI Query
  const handleSaveAIQuery = async () => {
    if (!aiResult) return;
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch('/api/hunt/ai/save/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: aiSaveName || "AI Query - " + new Date().toLocaleDateString(),
          es_query: aiResult.es_query,
          description: aiResult.reasoning,
          mitre_techniques: aiResult.mitre_techniques
        })
      });
      if (r.ok) {
        alert("AI generated query saved to workbench directory.");
        setAiSaveName('');
        fetchSavedQueries();
      }
    } catch (e) { console.error(e); }
  };

  // Initial loads
  useEffect(() => {
    if (activeTab === 'workbench') {
      fetchSavedQueries();
    } else if (activeTab === 'hypotheses') {
      fetchHypotheses();
    } else if (activeTab === 'baselines') {
      fetchBaselines();
    } else if (activeTab === 'campaigns') {
      fetchCampaigns();
    }
  }, [activeTab, hypFilterTactic, hypFilterSeverity]);

  return (
    <div className="flex flex-col min-h-screen bg-[#0a0f1a] text-slate-200 font-sans space-y-6">
      
      {/* Tab Navigation header */}
      <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-4">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-cyan-400" />
          <h1 className="text-xl font-bold tracking-widest text-slate-100 uppercase">Threat Hunting Command</h1>
        </div>
        
        <div className="flex gap-2 bg-[#0d1520] p-1 rounded-lg border border-[#1e2d3d]">
          {[
            { id: 'workbench', icon: <Terminal className="w-4 h-4" />, label: 'Workbench' },
            { id: 'hypotheses', icon: <BookOpen className="w-4 h-4" />, label: 'Hypotheses' },
            { id: 'baselines', icon: <Activity className="w-4 h-4" />, label: 'Baselines' },
            { id: 'campaigns', icon: <Folder className="w-4 h-4" />, label: 'Campaigns' },
            { id: 'ai_assistant', icon: <Brain className="w-4 h-4" />, label: 'AI Hunt' },
          ].map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2 text-xs font-bold uppercase tracking-wider rounded-md transition-all ${
                activeTab === t.id 
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {t.icon}
              <span>{t.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Tab Panel Rendering */}
      <div className="flex-1 min-h-[70vh]">

        {/* 1. WORKBENCH TAB */}
        {activeTab === 'workbench' && (
          <div className="grid grid-cols-12 gap-6 items-stretch">
            
            {/* Left side query builder & saved list */}
            <div className="col-span-12 lg:col-span-4 space-y-6">
              
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d]">
                <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-3 mb-4">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">DSL Workbench Builder</span>
                  <div className="flex bg-[#121b28] p-0.5 rounded border border-[#1e2d3d]">
                    <button
                      onClick={() => setQueryMode('visual')}
                      className={`px-2 py-1 text-[10px] font-bold uppercase rounded ${queryMode === 'visual' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-500'}`}
                    >
                      Visual
                    </button>
                    <button
                      onClick={() => setQueryMode('dsl')}
                      className={`px-2 py-1 text-[10px] font-bold uppercase rounded ${queryMode === 'dsl' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-500'}`}
                    >
                      Raw DSL
                    </button>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Target Index</label>
                    <select
                      value={index}
                      onChange={e => setIndex(e.target.value)}
                      className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                    >
                      <option value="syndicate4-ml-alerts">syndicate4-ml-alerts (ML Alerts)</option>
                      <option value="syndicate4-logs-*">syndicate4-logs-* (Raw Wazuh logs)</option>
                    </select>
                  </div>

                  {queryMode === 'visual' ? (
                    <div className="space-y-3">
                      <div>
                        <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Event Type Filter</label>
                        <input
                          type="text"
                          placeholder="e.g. port_scan, brute_force"
                          value={visualFilters.event_type}
                          onChange={e => setVisualFilters({ ...visualFilters, event_type: e.target.value })}
                          className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 font-mono text-slate-200"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Source IP Address</label>
                        <input
                          type="text"
                          placeholder="e.g. 10.101.1.1"
                          value={visualFilters.src_ip}
                          onChange={e => setVisualFilters({ ...visualFilters, src_ip: e.target.value })}
                          className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 font-mono text-slate-200"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Destination IP Address</label>
                        <input
                          type="text"
                          placeholder="e.g. 172.20.0.7"
                          value={visualFilters.dst_ip}
                          onChange={e => setVisualFilters({ ...visualFilters, dst_ip: e.target.value })}
                          className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 font-mono text-slate-200"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Alert Severity</label>
                        <select
                          value={visualFilters.ml_severity}
                          onChange={e => setVisualFilters({ ...visualFilters, ml_severity: e.target.value })}
                          className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                        >
                          <option value="">All Severities</option>
                          <option value="critical">Critical</option>
                          <option value="high">High</option>
                          <option value="medium">Medium</option>
                          <option value="low">Low</option>
                        </select>
                      </div>
                    </div>
                  ) : (
                    <div>
                      <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Elasticsearch DSL Body</label>
                      <textarea
                        value={rawDsl}
                        onChange={e => setRawDsl(e.target.value)}
                        rows={10}
                        className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 font-mono text-slate-200 leading-relaxed"
                      />
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-3 pt-2">
                    <div>
                      <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Time Range</label>
                      <select
                        value={timeRange}
                        onChange={e => setTimeRange(e.target.value)}
                        className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                      >
                        <option value="1h">Last 1 Hour</option>
                        <option value="24h">Last 24 Hours</option>
                        <option value="7d">Last 7 Days</option>
                        <option value="30d">Last 30 Days</option>
                        <option value="all">All Time</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Max Size</label>
                      <input
                        type="number"
                        min={10}
                        max={1000}
                        value={size}
                        onChange={e => setSize(e.target.value)}
                        className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 font-mono text-slate-200"
                      />
                    </div>
                  </div>

                  <div className="flex gap-2 pt-4">
                    <button
                      onClick={() => handleRunWorkbench()}
                      disabled={workbenchLoading}
                      className="flex-1 bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider py-2.5 rounded-md transition-all flex items-center justify-center gap-2"
                    >
                      {workbenchLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                      Execute search
                    </button>
                    <button
                      onClick={() => setSaveQueryModalOpen(true)}
                      className="bg-[#121b28] hover:bg-[#1c2738] border border-[#1e2d3d] text-slate-300 font-bold text-xs uppercase tracking-wider px-3 rounded-md transition-all"
                      title="Save Query"
                    >
                      <Save className="w-4 h-4" />
                    </button>
                  </div>

                </div>
              </div>

              {/* Saved Query Directory */}
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] max-h-[350px] overflow-y-auto">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block border-b border-[#1e2d3d] pb-2 mb-3">Saved Hunt Directories</span>
                <div className="space-y-2">
                  {savedQueries.length === 0 ? (
                    <span className="text-[10px] text-slate-500 font-mono block text-center py-4">No saved queries.</span>
                  ) : (
                    savedQueries.map(q => (
                      <div key={q.id} className="bg-[#121b28]/60 border border-[#1e2d3d] hover:border-slate-700 rounded-md p-3 flex items-start justify-between gap-3 relative group">
                        <div className="space-y-1.5 flex-1 min-w-0">
                          <span className="text-xs font-bold text-slate-200 block truncate cursor-pointer hover:text-cyan-400" onClick={() => handleRunSavedQuery(q.id)}>
                            {q.name}
                          </span>
                          <span className="text-[10px] text-slate-500 block truncate">{q.description || "No description provided."}</span>
                          <div className="flex items-center gap-3 text-[9px] text-slate-500 font-mono">
                            <span>Index: {q.es_index}</span>
                            <span>Runs: {q.run_count}</span>
                            <span>Hits: {q.last_hit_count}</span>
                          </div>
                        </div>
                        <button
                          onClick={() => handleDeleteQuery(q.id)}
                          className="text-slate-600 hover:text-rose-500 transition-colors"
                          title="Delete Saved Query"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

            </div>

            {/* Right side results view */}
            <div className="col-span-12 lg:col-span-8 glass-panel p-6 rounded-xl border-[#1e2d3d] flex flex-col min-h-[500px]">
              
              <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-3 mb-4 shrink-0">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Hunt Results Table</span>
                {workbenchResults && (
                  <span className="text-[10px] text-slate-500 font-mono">
                    Returned {workbenchResults.hits.length} records of {workbenchResults.total} hits ({workbenchResults.took_ms}ms)
                  </span>
                )}
              </div>

              {error && (
                <div className="mb-4 p-3 bg-rose-950/20 border border-rose-500/20 rounded-md text-rose-400 text-xs font-mono">
                  Execution Error: {error}
                </div>
              )}

              <div className="flex-1 overflow-x-auto min-h-[350px]">
                {!workbenchResults ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-600 space-y-2 py-20">
                    <Database className="w-12 h-12 text-slate-800" />
                    <span className="text-xs uppercase font-bold tracking-widest">Workbench Idle</span>
                    <span className="text-[10px] text-slate-700">Enter filters and click Execute Search to query Elasticsearch.</span>
                  </div>
                ) : workbenchResults.hits.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs py-20">
                    No logs returned matching query filters.
                  </div>
                ) : (
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#1e2d3d] text-slate-500 font-semibold uppercase tracking-wider text-[10px]">
                        <th className="pb-3">Timestamp</th>
                        <th className="pb-3">Agent</th>
                        <th className="pb-3">Event Type</th>
                        <th className="pb-3">Source IP</th>
                        <th className="pb-3">Dest IP</th>
                        <th className="pb-3">Severity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d3d]/50 font-mono">
                      {workbenchResults.hits.map((hit, idx) => (
                        <tr key={idx} className="hover:bg-[#121b28]/35 transition-colors">
                          <td className="py-3 text-slate-400 whitespace-nowrap">
                            {hit.ml_detected_at ? new Date(hit.ml_detected_at).toLocaleString() : new Date(hit.timestamp || hit['@timestamp']).toLocaleString()}
                          </td>
                          <td className="py-3 text-slate-300 font-semibold">{hit.agent_name || hit.agent?.name || 'unknown'}</td>
                          <td className="py-3 text-cyan-400 font-bold">{hit.event_type || hit.location || 'syscheck'}</td>
                          <td className="py-3 text-slate-300">{hit.src_ip || 'N/A'}</td>
                          <td className="py-3 text-slate-300">{hit.dst_ip || 'N/A'}</td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase ${getSeverityColor(hit.ml_severity || hit.severity)}`}>
                              {hit.ml_severity || hit.severity || 'low'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

          </div>
        )}

        {/* 2. HYPOTHESES PLAYBOOKS TAB */}
        {activeTab === 'hypotheses' && (
          <div className="grid grid-cols-12 gap-6 items-start">
            
            {/* Playbook list left */}
            <div className="col-span-12 lg:col-span-5 space-y-4">
              
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] space-y-4">
                <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-3 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">SIGMA Hypotheses Matrix</span>
                  
                  <div className="flex items-center gap-2">
                    <select 
                      value={hypFilterTactic} 
                      onChange={e => setHypFilterTactic(e.target.value)}
                      className="bg-[#121b28] border border-[#1e2d3d] rounded px-2 py-1 text-[10px] font-bold text-slate-400 focus:outline-none"
                    >
                      <option value="all">All Tactics</option>
                      <option value="initial_access">Initial Access</option>
                      <option value="discovery">Discovery</option>
                      <option value="credential_access">Credential Access</option>
                      <option value="lateral_movement">Lateral Movement</option>
                      <option value="command_and_control">Command & Control</option>
                      <option value="exfiltration">Exfiltration</option>
                      <option value="privilege_escalation">Privilege Escalation</option>
                      <option value="impact">Impact</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
                  {hypothesesLoading && hypotheses.length === 0 ? (
                    <div className="flex justify-center py-10">
                      <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
                    </div>
                  ) : hypotheses.length === 0 ? (
                    <span className="text-xs text-slate-500 font-mono block text-center py-4">No playbooks found.</span>
                  ) : (
                    hypotheses.map(hyp => {
                      const isSelected = selectedHypothesis?.id === hyp.id;
                      return (
                        <div
                          key={hyp.id}
                          onClick={() => {
                            setSelectedHypothesis(hyp);
                            setHypothesisResults(null);
                          }}
                          className={`border p-3.5 rounded-lg flex items-center justify-between cursor-pointer transition-all ${
                            isSelected 
                              ? 'bg-[#151e2e]/90 border-cyan-500/40 shadow-lg shadow-cyan-500/5' 
                              : 'bg-slate-900/30 border-[#1e2d3d] hover:bg-[#121824] hover:border-slate-700/60'
                          }`}
                        >
                          <div className="space-y-1 flex-1 min-w-0 pr-2">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-cyan-400 font-mono font-bold">{hyp.hypothesis_id}</span>
                              <span className="text-xs font-bold text-slate-200 block truncate">{hyp.name}</span>
                            </div>
                            <span className="text-[10px] text-slate-500 block truncate">{hyp.description}</span>
                            <div className="flex items-center gap-2 text-[9px] text-slate-500 font-mono">
                              <span className="uppercase text-slate-400">{getTacticLabel(hyp.tactic)}</span>
                              <span>•</span>
                              <span>Technique: {hyp.mitre_technique}</span>
                            </div>
                          </div>
                          
                          <div className="flex flex-col items-end gap-1.5 shrink-0">
                            <span className={`px-1.5 py-0.5 rounded border text-[8px] font-bold uppercase ${getSeverityColor(hyp.severity)}`}>
                              {hyp.severity}
                            </span>
                            <span className="text-[9px] text-slate-500 font-mono">Hits: {hyp.last_hit_count}</span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

            </div>

            {/* Playbook Detail pane right */}
            <div className="col-span-12 lg:col-span-7 glass-panel p-6 rounded-xl border-[#1e2d3d] min-h-[500px]">
              {!selectedHypothesis ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-2 py-20">
                  <BookOpen className="w-12 h-12 text-slate-700" />
                  <span className="text-xs uppercase font-bold tracking-widest text-slate-600">Select Playbook</span>
                  <p className="text-[10px] text-slate-600">Select a hypothesis playbook from the list to display recommended steps and run queries.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  
                  <div className="flex items-start justify-between border-b border-[#1e2d3d] pb-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-cyan-400 font-mono uppercase bg-cyan-950/20 px-2 py-0.5 border border-cyan-500/20 rounded">{selectedHypothesis.hypothesis_id}</span>
                        <h2 className="text-lg font-bold text-slate-100">{selectedHypothesis.name}</h2>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed font-mono italic">
                        "{selectedHypothesis.description}"
                      </p>
                    </div>

                    <button
                      onClick={() => handleRunHypothesis(selectedHypothesis)}
                      className="bg-cyan-500 hover:bg-cyan-600 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider px-4 py-2.5 rounded-md transition-all flex items-center gap-1.5 shrink-0"
                    >
                      <Play className="w-3.5 h-3.5 fill-[#0a0f1a]" /> Execute Hunt
                    </button>
                  </div>

                  {/* Playbook Steps Checklist */}
                  <div className="space-y-3">
                    <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">Recommended Hunt Steps</span>
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-4 space-y-2.5">
                      {selectedHypothesis.hunt_steps.map((step, idx) => (
                        <div key={idx} className="flex items-start gap-3">
                          <input type="checkbox" className="mt-0.5 cursor-pointer rounded border-[#1e2d3d] text-cyan-500 focus:ring-0 focus:ring-offset-0 bg-[#0d1520]" />
                          <span className="text-xs text-slate-300 font-mono leading-relaxed">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Execution results table below */}
                  {hypothesisResults && (
                    <div className="space-y-3 pt-3 border-t border-[#1e2d3d]">
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest">Active Hunt Hits ({hypothesisResults.total} total)</span>
                        <span className="text-[9px] text-slate-500 font-mono">Query Time: {hypothesisResults.took_ms}ms</span>
                      </div>
                      <div className="overflow-x-auto max-h-[300px] border border-[#1e2d3d] rounded-lg">
                        {hypothesisResults.hits.length === 0 ? (
                          <div className="text-center text-xs text-slate-500 font-mono py-8 bg-[#121b28]/10">No alerts triggered for this hypothesis.</div>
                        ) : (
                          <table className="w-full text-left text-xs border-collapse">
                            <thead className="bg-[#121b28]/80 text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
                              <tr>
                                <th className="p-2.5">Timestamp</th>
                                <th className="p-2.5">Agent</th>
                                <th className="p-2.5">Source IP</th>
                                <th className="p-2.5">Tactic Class</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-[#1e2d3d]/50 font-mono text-[11px]">
                              {hypothesisResults.hits.slice(0, 10).map((h, i) => (
                                <tr key={i} className="hover:bg-[#121b28]/30">
                                  <td className="p-2.5 text-slate-400 whitespace-nowrap">{h.ml_detected_at ? new Date(h.ml_detected_at).toLocaleString() : 'N/A'}</td>
                                  <td className="p-2.5 text-slate-300 font-semibold">{h.agent_name || 'unknown'}</td>
                                  <td className="p-2.5 text-slate-300">{h.src_ip || 'N/A'}</td>
                                  <td className="p-2.5 text-cyan-400 font-bold uppercase">{h.ml_rf_class || 'probe'}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </div>
                    </div>
                  )}

                </div>
              )}
            </div>

          </div>
        )}

        {/* 3. BASELINES TAB */}
        {activeTab === 'baselines' && (
          <div className="grid grid-cols-12 gap-6 items-start">
            
            {/* Agent Baselines List */}
            <div className="col-span-12 lg:col-span-6 space-y-4">
              
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] space-y-4">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block border-b border-[#1e2d3d] pb-2 mb-2">Agent Baselines telemetry</span>
                
                <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
                  {baselines.length === 0 ? (
                    <span className="text-xs text-slate-500 font-mono block text-center py-4">No baselines computed yet.</span>
                  ) : (
                    baselines.map(base => {
                      const isSelected = selectedBaseline?.id === base.id;
                      return (
                        <div
                          key={base.id}
                          onClick={() => setSelectedBaseline(base)}
                          className={`border p-3.5 rounded-lg flex items-center justify-between cursor-pointer transition-all ${
                            isSelected 
                              ? 'bg-[#151e2e]/90 border-cyan-500/40 shadow-lg shadow-cyan-500/5' 
                              : 'bg-slate-900/30 border-[#1e2d3d] hover:bg-[#121824] hover:border-slate-700/60'
                          }`}
                        >
                          <div className="space-y-1.5 flex-1 min-w-0 pr-2">
                            <span className="text-xs font-bold text-slate-200 block truncate">{base.agent_name}</span>
                            <div className="flex items-center gap-3 text-[9px] text-slate-500 font-mono">
                              <span>Hourly rate: {base.avg_hourly_events.toFixed(1)}/hr</span>
                              <span>Daily rate: {base.avg_daily_events.toFixed(0)}/day</span>
                              <span>Data period: {base.data_days} days</span>
                            </div>
                          </div>
                          
                          <div className="text-right">
                            <span className="text-[10px] text-slate-500 font-mono block">Computed:</span>
                            <span className="text-[9px] text-slate-600 block">{new Date(base.computed_at).toLocaleDateString()}</span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

            </div>

            {/* Baseline Detail & Deviation List right */}
            <div className="col-span-12 lg:col-span-6 space-y-6">
              
              {/* Deviations / leads list */}
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] space-y-4">
                <span className="text-xs font-bold uppercase tracking-wider text-rose-400 block border-b border-[#1e2d3d] pb-2 mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-500" /> Actionable Deviation Leads
                </span>

                <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">
                  {deviations.length === 0 ? (
                    <div className="text-center py-6 text-xs text-slate-500 font-mono">No active baseline deviations. Agent behavior is normal.</div>
                  ) : (
                    deviations.map(dev => (
                      <div key={dev.id} className="bg-slate-900/40 border border-slate-800 rounded-lg p-4 space-y-2 relative">
                        <div className="flex justify-between items-start">
                          <div className="space-y-1.5 flex-1 min-w-0 pr-2">
                            <span className="text-xs font-bold text-slate-200 block">{dev.title}</span>
                            <p className="text-[10px] text-slate-400 leading-relaxed font-mono">{dev.description}</p>
                          </div>
                          <span className={`px-1.5 py-0.5 rounded border text-[8px] font-bold uppercase shrink-0 ${getSeverityColor(dev.severity)}`}>
                            {dev.severity}
                          </span>
                        </div>

                        <div className="flex items-center justify-between pt-1 border-t border-slate-800/40 text-[9px] font-mono">
                          <div className="flex items-center gap-3 text-slate-500">
                            <span>Observed: <span className="text-slate-300 font-bold">{dev.observed_value}</span></span>
                            <span>Baseline: <span className="text-slate-400">{dev.baseline_value}</span></span>
                          </div>

                          <button
                            onClick={() => handleAcknowledgeDeviation(dev.id)}
                            className="bg-emerald-500/10 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-400 font-bold uppercase text-[9px] px-2.5 py-1 rounded transition-colors flex items-center gap-1"
                          >
                            <Check className="w-3 h-3" /> Acknowledge
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Selected Baseline Parameters */}
              {selectedBaseline && (
                <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] space-y-4">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block border-b border-[#1e2d3d] pb-2 mb-2">
                    Behavior Metrics: {selectedBaseline.agent_name}
                  </span>

                  <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-3 space-y-1">
                      <span className="text-slate-500 text-[10px] uppercase">Active Hours (EAT)</span>
                      <span className="text-slate-300 block truncate">{selectedBaseline.active_hours?.join(', ') || 'N/A'}</span>
                    </div>
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-3 space-y-1">
                      <span className="text-slate-500 text-[10px] uppercase">Top Src Country Codes</span>
                      <span className="text-slate-300 block truncate">{selectedBaseline.top_countries?.join(', ') || 'N/A'}</span>
                    </div>
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-3 space-y-1">
                      <span className="text-slate-500 text-[10px] uppercase">Top Target Ports</span>
                      <span className="text-slate-300 block truncate">{selectedBaseline.top_dst_ports?.join(', ') || 'N/A'}</span>
                    </div>
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-3 space-y-1">
                      <span className="text-slate-500 text-[10px] uppercase">Typical Attack Classes</span>
                      <span className="text-cyan-400 block truncate font-bold uppercase">{selectedBaseline.top_attack_classes?.join(', ') || 'N/A'}</span>
                    </div>
                  </div>
                </div>
              )}

            </div>

          </div>
        )}

        {/* 4. CAMPAIGNS TAB */}
        {activeTab === 'campaigns' && (
          <div className="grid grid-cols-12 gap-6 items-start">
            
            {/* Campaign folder list left */}
            <div className="col-span-12 lg:col-span-4 space-y-4">
              
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] space-y-4">
                <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-3 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Investigation folders</span>
                  
                  <button
                    onClick={() => setNewCampaignOpen(true)}
                    className="bg-cyan-500/10 hover:bg-cyan-500/25 border border-cyan-500/30 hover:border-cyan-400 text-cyan-400 font-bold uppercase text-[9px] px-2.5 py-1 rounded transition-all flex items-center gap-1"
                  >
                    <Plus className="w-3.5 h-3.5" /> New Campaign
                  </button>
                </div>

                <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
                  {campaigns.length === 0 ? (
                    <span className="text-xs text-slate-500 font-mono block text-center py-4">No active hunting campaigns.</span>
                  ) : (
                    campaigns.map(c => {
                      const isSelected = selectedCampaign?.id === c.id;
                      return (
                        <div
                          key={c.id}
                          onClick={() => fetchCampaignDetail(c.id)}
                          className={`border p-3.5 rounded-lg flex items-center justify-between cursor-pointer transition-all ${
                            isSelected 
                              ? 'bg-[#151e2e]/90 border-cyan-500/40 shadow-lg shadow-cyan-500/5' 
                              : 'bg-slate-900/30 border-[#1e2d3d] hover:bg-[#121824] hover:border-slate-700/60'
                          }`}
                        >
                          <div className="space-y-1 flex-1 min-w-0 pr-2">
                            <span className="text-xs font-bold text-slate-200 block truncate">{c.name}</span>
                            <span className="text-[10px] text-slate-500 block truncate">{c.description || 'No description.'}</span>
                            <div className="flex items-center gap-2 text-[9px] text-slate-500 font-mono">
                              <span className="uppercase text-slate-400">{c.status?.replace('_', ' ')}</span>
                              <span>•</span>
                              <span>Findings: {c.findings_count}</span>
                            </div>
                          </div>
                          
                          <ChevronRight className="w-4 h-4 text-slate-600 shrink-0" />
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

            </div>

            {/* Campaign details right */}
            <div className="col-span-12 lg:col-span-8 glass-panel p-6 rounded-xl border-[#1e2d3d] min-h-[500px]">
              {!selectedCampaign ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-2 py-20">
                  <Folder className="w-12 h-12 text-slate-700" />
                  <span className="text-xs uppercase font-bold tracking-widest text-slate-600">Select Campaign Folder</span>
                  <p className="text-[10px] text-slate-600">Select an investigation folder from the list to display details, notes, and findings.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  
                  <div className="flex items-start justify-between border-b border-[#1e2d3d] pb-4">
                    <div className="space-y-1.5 flex-1 pr-4">
                      <h2 className="text-lg font-bold text-slate-100">{selectedCampaign.name}</h2>
                      <p className="text-xs text-slate-400 leading-relaxed font-mono italic">
                        "{selectedCampaign.description || 'No description provided.'}"
                      </p>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <select
                        value={selectedCampaign.status}
                        onChange={e => setSelectedCampaign({ ...selectedCampaign, status: e.target.value })}
                        className="bg-[#121b28] border border-[#1e2d3d] rounded px-3 py-1.5 text-xs text-slate-300 focus:outline-none"
                      >
                        <option value="active">Active</option>
                        <option value="paused">Paused</option>
                        <option value="closed_threat">Closed - Threat Confirmed</option>
                        <option value="closed_fp">Closed - False Positive</option>
                        <option value="escalated">Escalated to Incident</option>
                      </select>
                      <button
                        onClick={() => handleSaveCampaignNotes()}
                        className="bg-cyan-500 hover:bg-cyan-600 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider px-3.5 py-1.5 rounded transition-all"
                      >
                        Save Notes
                      </button>
                    </div>
                  </div>

                  {/* Targeted Scopes */}
                  <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-3 space-y-1">
                      <span className="text-slate-500 text-[10px] uppercase">Scope Wazuh Agents</span>
                      <span className="text-slate-300 block truncate">{selectedCampaign.target_agents?.join(', ') || 'All agents in network'}</span>
                    </div>
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-3 space-y-1">
                      <span className="text-slate-500 text-[10px] uppercase">Scope Target IPs</span>
                      <span className="text-slate-300 block truncate">{selectedCampaign.target_ips?.join(', ') || 'All IPs in network'}</span>
                    </div>
                  </div>

                  {/* Findings Checklist */}
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest">Evidence & Findings ({selectedCampaign.findings?.length || 0})</span>
                      <button
                        onClick={() => setNewFindingOpen(true)}
                        className="text-cyan-400 hover:text-cyan-300 font-bold uppercase text-[9px] flex items-center gap-1"
                      >
                        <Plus className="w-3.5 h-3.5" /> Add Evidence
                      </button>
                    </div>

                    <div className="space-y-3">
                      {!selectedCampaign.findings || selectedCampaign.findings.length === 0 ? (
                        <div className="text-center py-6 text-xs text-slate-500 font-mono border border-dashed border-[#1e2d3d] rounded-lg">
                          No evidence findings recorded yet.
                        </div>
                      ) : (
                        selectedCampaign.findings.map(f => (
                          <div key={f.id} className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-4 space-y-2">
                            <div className="flex justify-between items-start">
                              <div className="space-y-1">
                                <span className="text-xs font-bold text-slate-200 block">{f.title}</span>
                                <p className="text-[11px] text-slate-400 leading-relaxed font-mono">{f.description}</p>
                              </div>
                              <span className={`px-2 py-0.5 rounded border text-[8px] font-bold uppercase tracking-wider shrink-0 ${
                                f.verdict === 'threat' ? 'text-rose-500 border-rose-500/20 bg-rose-500/10' :
                                f.verdict === 'suspicious' ? 'text-orange-500 border-orange-500/20 bg-orange-500/10' :
                                f.verdict === 'false_positive' ? 'text-emerald-500 border-emerald-500/20 bg-emerald-500/10' :
                                'text-slate-400 border-slate-700 bg-slate-800/30'
                              }`}>
                                {f.verdict?.replace('_', ' ')}
                              </span>
                            </div>
                            {f.analyst_notes && (
                              <div className="bg-[#0d1520] p-2.5 rounded text-[10px] text-slate-500 font-mono border border-[#1e2d3d]/50">
                                <span className="text-slate-400 font-bold block mb-1">Analyst Notes:</span>
                                "{f.analyst_notes}"
                              </div>
                            )}
                            <div className="flex items-center gap-4 pt-1.5 border-t border-slate-800/40 text-[9px] text-slate-500 font-mono">
                              <span>Agent: {f.agent_name || 'N/A'}</span>
                              <span>Source IP: {f.src_ip || 'N/A'}</span>
                              <span>Registered by: {f.created_by_username || 'system'}</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Freeform Notes Markdown Editor */}
                  <div className="space-y-2 pt-3 border-t border-[#1e2d3d]">
                    <label className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">Analyst Notes & Logbook</label>
                    <textarea
                      rows={6}
                      value={selectedCampaign.notes || ''}
                      onChange={e => setSelectedCampaign({ ...selectedCampaign, notes: e.target.value })}
                      placeholder="Use this space to document hunt timestamps, query modifications, pivot paths, and remediation recommendations..."
                      className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 font-mono text-slate-200 leading-relaxed"
                    />
                  </div>

                </div>
              )}
            </div>

          </div>
        )}

        {/* 5. AI HUNT ASSISTANT TAB */}
        {activeTab === 'ai_assistant' && (
          <div className="grid grid-cols-12 gap-6 items-start">
            
            {/* Input pane left */}
            <div className="col-span-12 lg:col-span-5 space-y-6">
              
              <div className="glass-panel p-5 rounded-xl border-[#1e2d3d] space-y-4">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block border-b border-[#1e2d3d] pb-2 mb-2">Qwen SOC Hunt Generator</span>
                
                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Search Objective</label>
                    <textarea
                      rows={5}
                      value={aiPrompt}
                      onChange={e => setAiPrompt(e.target.value)}
                      placeholder="e.g. Find lateral movement from 10.100.120.18 over RDP or SSH in the last 7 days..."
                      className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200 leading-relaxed"
                    />
                  </div>

                  <button
                    onClick={() => handleAIGenerate()}
                    disabled={aiLoading || !aiPrompt}
                    className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider py-2.5 rounded-md transition-all flex items-center justify-center gap-2"
                  >
                    {aiLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
                    Generate Playbook
                  </button>
                </div>
              </div>

            </div>

            {/* Generated results pane right */}
            <div className="col-span-12 lg:col-span-7 glass-panel p-6 rounded-xl border-[#1e2d3d] min-h-[500px]">
              {aiLoading ? (
                <div className="flex flex-col items-center justify-center h-full space-y-3 py-20">
                  <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
                  <span className="text-xs text-slate-500 font-mono">Qwen compiling hunt playbook DSL...</span>
                </div>
              ) : !aiResult ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-2 py-20">
                  <Brain className="w-12 h-12 text-slate-700" />
                  <span className="text-xs uppercase font-bold tracking-widest text-slate-600">AI Engine Ready</span>
                  <p className="text-[10px] text-slate-600">Enter a description of what you want to hunt for. Qwen will output a structured ES query DSL and checklist.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  
                  <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-4">
                    <span className="text-xs font-bold text-cyan-400 uppercase tracking-widest flex items-center gap-1.5"><Brain className="w-4 h-4" /> AI Playbook Proposal</span>
                    
                    <button
                      onClick={() => handleRunWorkbench(aiResult.es_query)}
                      className="bg-cyan-500 hover:bg-cyan-600 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider px-4 py-2.5 rounded-md transition-all flex items-center gap-1.5"
                    >
                      <Play className="w-3.5 h-3.5 fill-[#0a0f1a]" /> Run AI Hunt
                    </button>
                  </div>

                  {/* Reasoning block */}
                  <div className="bg-[#121b28]/60 border-l-4 border-cyan-400 p-4 rounded-r-lg space-y-1">
                    <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest flex items-center gap-1">
                      <Info className="w-3.5 h-3.5" /> Hunt Strategy
                    </span>
                    <p className="text-xs text-slate-300 leading-relaxed font-mono italic">
                      "{aiResult.reasoning}"
                    </p>
                  </div>

                  {/* ES query code block */}
                  <div className="space-y-2">
                    <span className="text-[10px] text-slate-500 uppercase tracking-widest block font-bold">Generated ES Query DSL</span>
                    <pre className="bg-slate-950 p-4 rounded-lg text-xs font-mono text-cyan-400 border border-[#1e2d3d]/50 overflow-x-auto max-h-[250px] leading-relaxed">
                      {JSON.stringify(aiResult.es_query, null, 2)}
                    </pre>
                  </div>

                  {/* Playbook Steps Checklist */}
                  <div className="space-y-3">
                    <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-widest block">Recommended Hunt Steps</span>
                    <div className="bg-[#121b28]/30 border border-[#1e2d3d] rounded-lg p-4 space-y-2">
                      {aiResult.hunt_steps?.map((step, idx) => (
                        <div key={idx} className="flex items-start gap-2.5 text-xs text-slate-300 font-mono">
                          <span className="text-cyan-500 font-bold shrink-0">{idx + 1}.</span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Save query bar */}
                  <div className="flex items-center gap-3 pt-4 border-t border-[#1e2d3d]">
                    <input
                      type="text"
                      placeholder="Enter query name to save..."
                      value={aiSaveName}
                      onChange={e => setAiSaveName(e.target.value)}
                      className="flex-1 bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                    />
                    <button
                      onClick={() => handleSaveAIQuery()}
                      className="bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 text-xs font-bold uppercase tracking-wider px-4 py-2.5 rounded transition-all flex items-center gap-1.5"
                    >
                      <Save className="w-3.5 h-3.5" /> Save to Workbench
                    </button>
                  </div>

                </div>
              )}
            </div>

          </div>
        )}

      </div>

      {/* --- MODALS & POPUPS --- */}

      {/* 1. Save query modal */}
      {saveQueryModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#0e1522] border border-[#1e2d3d] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl relative">
            <button onClick={() => setSaveQueryModalOpen(false)} className="absolute top-4 right-4 text-slate-500 hover:text-slate-300">
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-[#1e2d3d] pb-2">Save Hunting Query</h3>
            
            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Query Name</label>
                <input
                  type="text"
                  placeholder="e.g. Lateral movement RDP detection"
                  value={newQueryName}
                  onChange={e => setNewQueryName(e.target.value)}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Description</label>
                <textarea
                  rows={3}
                  placeholder="Describe the target hypothesis of this query..."
                  value={newQueryDesc}
                  onChange={e => setNewQueryDesc(e.target.value)}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200 leading-relaxed"
                />
              </div>

              <button
                onClick={() => handleSaveQuery()}
                disabled={!newQueryName}
                className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider py-2.5 rounded transition-all"
              >
                Save Query
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 2. Create Campaign modal */}
      {newCampaignOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#0e1522] border border-[#1e2d3d] rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl relative">
            <button onClick={() => setNewCampaignOpen(false)} className="absolute top-4 right-4 text-slate-500 hover:text-slate-300">
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-[#1e2d3d] pb-2">Create Hunt Campaign</h3>
            
            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Campaign Name</label>
                <input
                  type="text"
                  placeholder="e.g. Investigation of Mombasa SSH Spike"
                  value={newCampaignData.name}
                  onChange={e => setNewCampaignData({ ...newCampaignData, name: e.target.value })}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Description</label>
                <textarea
                  rows={3}
                  placeholder="Provide scope, context and objective for this investigation folder..."
                  value={newCampaignData.description}
                  onChange={e => setNewCampaignData({ ...newCampaignData, description: e.target.value })}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200 leading-relaxed"
                />
              </div>
              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Link Hypothesis TTP</label>
                <select
                  value={newCampaignData.hypothesis}
                  onChange={e => setNewCampaignData({ ...newCampaignData, hypothesis: e.target.value })}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                >
                  <option value="">No Link Playbook</option>
                  {hypotheses.map(h => (
                    <option key={h.id} value={h.id}>{h.hypothesis_id}: {h.name}</option>
                  ))}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 uppercase block mb-1">Scope Agents (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="e.g. agent01, agent02"
                    value={newCampaignData.target_agents}
                    onChange={e => setNewCampaignData({ ...newCampaignData, target_agents: e.target.value })}
                    className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 uppercase block mb-1">Scope IPs (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="e.g. 10.100.12.1"
                    value={newCampaignData.target_ips}
                    onChange={e => setNewCampaignData({ ...newCampaignData, target_ips: e.target.value })}
                    className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                  />
                </div>
              </div>

              <button
                onClick={() => handleCreateCampaign()}
                disabled={!newCampaignData.name}
                className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider py-2.5 rounded transition-all"
              >
                Create Campaign
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 3. Add Evidence/Finding modal */}
      {newFindingOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#0e1522] border border-[#1e2d3d] rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl relative">
            <button onClick={() => setNewFindingOpen(false)} className="absolute top-4 right-4 text-slate-500 hover:text-slate-300">
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-[#1e2d3d] pb-2">Record Evidence Finding</h3>
            
            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Finding Title</label>
                <input
                  type="text"
                  placeholder="e.g. Malicious SSH process running from internal subnet"
                  value={newFindingData.title}
                  onChange={e => setNewFindingData({ ...newFindingData, title: e.target.value })}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 uppercase block mb-1">Verdict Classification</label>
                  <select
                    value={newFindingData.verdict}
                    onChange={e => setNewFindingData({ ...newFindingData, verdict: e.target.value })}
                    className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                  >
                    <option value="threat">Confirmed Threat</option>
                    <option value="suspicious">Suspicious - Needs Review</option>
                    <option value="false_positive">False Positive</option>
                    <option value="informational">Informational</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 uppercase block mb-1">Target Agent</label>
                  <input
                    type="text"
                    placeholder="e.g. KE-HQ-WIN01"
                    value={newFindingData.agent_name}
                    onChange={e => setNewFindingData({ ...newFindingData, agent_name: e.target.value })}
                    className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 uppercase block mb-1">Source IP</label>
                  <input
                    type="text"
                    placeholder="e.g. 192.168.10.12"
                    value={newFindingData.src_ip}
                    onChange={e => setNewFindingData({ ...newFindingData, src_ip: e.target.value })}
                    className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 uppercase block mb-1">Event Type</label>
                  <input
                    type="text"
                    placeholder="e.g. ssh_login"
                    value={newFindingData.event_type}
                    onChange={e => setNewFindingData({ ...newFindingData, event_type: e.target.value })}
                    className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Evidence Description</label>
                <textarea
                  rows={2}
                  placeholder="Detail the anomalous indicators observed..."
                  value={newFindingData.description}
                  onChange={e => setNewFindingData({ ...newFindingData, description: e.target.value })}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200 leading-relaxed"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase block mb-1">Analyst Notes & Mitigation</label>
                <textarea
                  rows={2}
                  placeholder="Remediation actions taken, recommendations..."
                  value={newFindingData.analyst_notes}
                  onChange={e => setNewFindingData({ ...newFindingData, analyst_notes: e.target.value })}
                  className="w-full bg-[#121b28] border border-[#1e2d3d] rounded-md px-3 py-2 text-xs focus:outline-none focus:border-cyan-500/50 text-slate-200 leading-relaxed"
                />
              </div>

              <button
                onClick={() => handleAddFinding()}
                disabled={!newFindingData.title || !newFindingData.description}
                className="w-full bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider py-2.5 rounded transition-all"
              >
                Add Evidence to Campaign
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default ThreatHunting;
