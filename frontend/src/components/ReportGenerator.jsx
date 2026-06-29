import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { 
  FileText, Calendar, Brain, Plus, RefreshCw, Trash2, 
  Download, Clock, User, AlertCircle, Info, Shield, BarChart2
} from 'lucide-react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell
} from 'recharts';
import { getToken } from '../auth';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#10b981', '#8b5cf6'];

export default function ReportGenerator({ onUnauth }) {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [selectedReport, setSelectedReport] = useState(null);
  const [hours, setHours] = useState(24);
  const [downloading, setDownloading] = useState(false);

  // Fetch all daily reports
  const fetchReports = async (selectLatest = false) => {
    setListLoading(true);
    const token = getToken();
    if (!token) {
      if (onUnauth) onUnauth();
      return;
    }
    try {
      const r = await fetch('/api/reports/daily/', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        const data = await r.json();
        setReports(data);
        if (data.length > 0) {
          if (selectLatest || !selectedReport) {
            setSelectedReport(data[0]);
          } else {
            // Update selected report if it is in the list
            const current = data.find(rep => rep.id === selectedReport.id);
            if (current) setSelectedReport(current);
          }
        } else {
          setSelectedReport(null);
        }
      }
    } catch (e) {
      console.error("Failed to fetch reports:", e);
    } finally {
      setListLoading(false);
    }
  };

  // Generate Daily AI Report
  const handleGenerateReport = async () => {
    setLoading(true);
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetch('/api/reports/daily/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hours })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'Generation failed');
      await fetchReports(true);
    } catch (e) {
      alert(`AI Report Generation failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Delete Report
  const handleDeleteReport = async (id) => {
    const token = getToken();
    if (!token) return;
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      const r = await fetch(`/api/reports/daily/${id}/`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        fetchReports(false);
      }
    } catch (e) {
      console.error("Failed to delete report:", e);
    }
  };

  // Download PDF
  const handleDownloadPdf = async () => {
    const element = document.getElementById('daily-report-markdown-content');
    if (!element) return;
    
    setDownloading(true);
    try {
      const canvas = await html2canvas(element, { scale: 2, useCORS: true });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      
      const imgWidth = 210;
      const pageHeight = 297;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }
      
      pdf.save(`NGAO_SOC_Executive_Report_${new Date(selectedReport.generated_at).toISOString().slice(0, 10)}.pdf`);
    } catch (err) {
      console.error("Failed to generate PDF", err);
    } finally {
      setDownloading(false);
    }
  };

  useEffect(() => {
    fetchReports(true);
  }, []);

  const renderCharts = () => {
    if (!selectedReport || !selectedReport.chart_data || !selectedReport.chart_data.time_series) return null;
    const { time_series, severities, classes } = selectedReport.chart_data;
    
    if (time_series.length === 0) return null;

    // Format time for X-Axis
    const formattedTimeSeries = time_series.map(d => ({
      ...d,
      displayTime: new Date(d.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }));

    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8 border-b border-slate-800 pb-8">
        
        {/* Timeline Chart */}
        <div className="col-span-1 md:col-span-2 bg-[#0d1520] border border-slate-800/80 p-4 rounded-xl">
          <div className="flex items-center gap-2 mb-4 text-cyan-400">
            <BarChart2 className="w-4 h-4" />
            <h3 className="text-xs font-bold uppercase tracking-widest">Anomaly Detection Timeline</h3>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={formattedTimeSeries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="displayTime" stroke="#64748b" fontSize={10} tickMargin={10} />
                <YAxis stroke="#64748b" fontSize={10} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '12px' }}
                  itemStyle={{ color: '#22d3ee' }}
                />
                <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={3} dot={false} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution Pie Chart */}
        <div className="col-span-1 bg-[#0d1520] border border-slate-800/80 p-4 rounded-xl">
          <div className="flex items-center gap-2 mb-4 text-rose-400">
            <AlertCircle className="w-4 h-4" />
            <h3 className="text-xs font-bold uppercase tracking-widest">Severity Breakdown</h3>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severities}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severities.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>
    );
  };

  return (
    <div className="flex flex-col min-h-screen bg-[#0a0f1a] text-slate-200 font-sans space-y-6">
      
      {/* Top Header Summary */}
      <div className="flex items-center justify-between border-b border-[#1e2d3d] pb-4 shrink-0">
        <div className="flex items-center gap-3">
          <FileText className="w-6 h-6 text-cyan-400" />
          <h1 className="text-xl font-bold tracking-widest text-slate-100 uppercase">Executive Security Reports</h1>
        </div>

        <div className="flex items-center gap-3 bg-[#0d1520] p-1.5 rounded-lg border border-[#1e2d3d]">
          <span className="text-[10px] text-slate-500 font-mono font-bold uppercase pl-2">Time Window:</span>
          <select
            value={hours}
            onChange={e => setHours(Number(e.target.value))}
            className="bg-[#121b28] border border-[#1e2d3d] rounded px-2.5 py-1 text-xs text-slate-300 focus:outline-none"
          >
            <option value={24}>Last 24 Hours (Daily)</option>
            <option value={168}>Last 7 Days (Weekly)</option>
            <option value={720}>Last 30 Days (Monthly)</option>
          </select>

          <button
            onClick={handleGenerateReport}
            disabled={loading}
            className="bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider px-4 py-1.5 rounded transition-all flex items-center gap-1.5"
          >
            {loading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Brain className="w-3.5 h-3.5" />
            )}
            Compile AI Report
          </button>
        </div>
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-12 gap-6 items-stretch flex-1">
        
        {/* Left Side: Report Directory */}
        <div className="col-span-12 lg:col-span-4 glass-panel p-5 rounded-xl border border-slate-800/80 bg-[#0d1520]/80 flex flex-col h-[70vh]">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300 block border-b border-slate-800 pb-2 mb-3">Report Directory</span>
          
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {listLoading && reports.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              </div>
            ) : reports.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500 font-mono text-xs py-20 text-center">
                No reports compiled yet. Click Compile AI Report above to generate one.
              </div>
            ) : (
              reports.map(rep => {
                const isSelected = selectedReport?.id === rep.id;
                return (
                  <div
                    key={rep.id}
                    onClick={() => setSelectedReport(rep)}
                    className={`border p-3.5 rounded-lg flex items-center justify-between cursor-pointer transition-all ${
                      isSelected 
                        ? 'bg-[#151e2e]/90 border-cyan-500/40 shadow-lg shadow-cyan-500/5' 
                        : 'bg-slate-900/30 border-slate-800/80 hover:bg-[#121824] hover:border-slate-700/60'
                    }`}
                  >
                    <div className="space-y-1.5 flex-1 min-w-0 pr-2">
                      <span className="text-xs font-bold text-slate-200 block truncate">{rep.title}</span>
                      <div className="flex items-center gap-3 text-[9px] text-slate-500 font-mono">
                        <span className="flex items-center gap-1"><Calendar className="w-3 h-3" /> {new Date(rep.generated_at).toLocaleDateString()}</span>
                        <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {rep.hours_covered}h range</span>
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteReport(rep.id);
                      }}
                      className="text-slate-600 hover:text-rose-500 transition-colors p-1"
                      title="Delete Report"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Side: Report Detailed Content */}
        <div className="col-span-12 lg:col-span-8 glass-panel p-6 rounded-xl border border-slate-800/80 bg-[#0d1520]/80 flex flex-col h-[70vh]">
          {!selectedReport ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-2 py-20">
              <FileText className="w-12 h-12 text-slate-800" />
              <span className="text-xs uppercase font-bold tracking-widest text-slate-700">Select Report</span>
              <p className="text-[10px] text-slate-700">Select a compiled daily report from the directory to review and download.</p>
            </div>
          ) : (
            <div className="flex flex-col h-full space-y-4">
              
              {/* Report Header Actions */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 shrink-0">
                <div className="space-y-1.5">
                  <h2 className="text-base font-bold text-slate-200">{selectedReport.title}</h2>
                  <div className="flex items-center gap-4 text-[10px] text-slate-500 font-mono">
                    <span className="flex items-center gap-1"><User className="w-3.5 h-3.5 text-cyan-400" /> Analyst: {selectedReport.generated_by_username || 'System AI'}</span>
                    <span>•</span>
                    <span>Compiled: {new Date(selectedReport.generated_at).toLocaleString()}</span>
                  </div>
                </div>

                <button
                  onClick={handleDownloadPdf}
                  disabled={downloading}
                  className="bg-slate-900/60 hover:bg-slate-800/80 text-slate-300 border border-slate-850 px-4 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 disabled:opacity-50"
                >
                  {downloading ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Download className="w-3.5 h-3.5" />
                  )}
                  Export PDF
                </button>
              </div>

              {/* Report Text Markdown View */}
              <div className="flex-1 overflow-y-auto pr-1" id="daily-report-markdown-content">
                
                {/* Embedded Analytics Charts */}
                {renderCharts()}

                <div className="prose prose-invert max-w-none text-slate-300 text-xs font-mono leading-relaxed bg-[#0a0f1a]/50 p-4 rounded-lg">
                  <ReactMarkdown>{selectedReport.content}</ReactMarkdown>
                </div>
              </div>

            </div>
          )}
        </div>

      </div>

    </div>
  );
}
