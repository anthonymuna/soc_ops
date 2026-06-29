import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { fetchJson, ML_API } from '../hooks/useSOC';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { Brain, RefreshCw, Download } from 'lucide-react';

export default function PredictiveAnalysis({ onUnauth }) {
  const [analysis, setAnalysis] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(false);

  const handleDownloadPdf = async () => {
    const element = document.getElementById('predictive-analysis-content');
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
      
      pdf.save('Predictive_Threat_Analysis.pdf');
    } catch (err) {
      console.error("Failed to generate PDF", err);
    } finally {
      setDownloading(false);
    }
  };

  const fetchAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchJson(`${ML_API}/alerts/predictive-analysis/`, onUnauth);
      if (data.error) {
        setError(data.error);
      } else {
        setAnalysis(data.analysis || 'No analysis available.');
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch predictive analysis.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalysis();
  }, []);

  return (
    <div className="glass-panel p-8 rounded-xl border border-slate-800/80 bg-[#0d1520]/80 shadow-xl min-h-[500px]">
      <div className="flex justify-between items-center mb-6 border-b border-slate-800 pb-4">
        <h2 className="text-lg font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2.5">
          <Brain className="w-5 h-5 text-cyan-400" />
          Predictive Threat Analysis
        </h2>
        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadPdf}
            disabled={loading || downloading || !analysis}
            className="bg-slate-900/60 hover:bg-slate-800/80 text-slate-300 border border-slate-800 px-4 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 disabled:opacity-50"
          >
            {downloading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Generating PDF...
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5" />
                Download PDF
              </>
            )}
          </button>
          <button
            onClick={fetchAnalysis}
            disabled={loading || downloading}
            className="bg-cyan-500 hover:bg-cyan-600 text-[#0a0f1a] px-4 py-2 rounded-md text-xs font-bold uppercase tracking-wider transition-all flex items-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#0a0f1a]" />
                Analyzing...
              </>
            ) : (
              'Re-Analyze'
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/20 border border-rose-500/20 text-rose-400 p-4 rounded-md mb-6 text-xs font-mono">
          {error}
        </div>
      )}

      <div id="predictive-analysis-content" className="prose prose-invert max-w-none text-slate-300 text-sm font-mono leading-relaxed bg-[#0a0f1a]/50 border border-slate-800/80 p-6 rounded-lg shadow-inner">
        {loading && !analysis ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-500 space-y-4">
            <RefreshCw className="animate-spin h-8 w-8 text-cyan-400" />
            <p className="text-xs uppercase font-bold tracking-widest text-slate-400">Gathering latest alerts and predicting attacker intent...</p>
            <p className="text-[10px] text-slate-600 font-mono">This may take up to 45 seconds.</p>
          </div>
        ) : (
          <ReactMarkdown>{analysis}</ReactMarkdown>
        )}
      </div>
    </div>
  );
}
