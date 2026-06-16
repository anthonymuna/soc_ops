import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import { fetchJson, ML_API } from '../hooks/useSOC';

export default function PredictiveAnalysis({ onUnauth }) {
  const [analysis, setAnalysis] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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
    <div className="bg-white rounded-lg p-8 border border-slate-200 shadow-md min-h-[500px]">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-slate-900 flex items-center gap-2">
          <svg className="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          AI Predictive Threat Analysis
        </h2>
        <button
          onClick={fetchAnalysis}
          disabled={loading}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md text-sm transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          {loading ? (
            <>
              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Analyzing...
            </>
          ) : (
            'Re-Analyze'
          )}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500/50 text-red-200 p-4 rounded-md mb-6 text-sm">
          {error}
        </div>
      )}

      <div className="prose prose-indigo max-w-none text-slate-800 text-lg">
        {loading && !analysis ? (
          <div className="flex flex-col items-center justify-center py-12 text-slate-500">
            <svg className="animate-spin h-10 w-10 mb-4 text-indigo-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <p>Gathering latest alerts and predicting attacker intent...</p>
            <p className="text-xs opacity-50 mt-2">This may take up to 45 seconds.</p>
          </div>
        ) : (
          <ReactMarkdown>{analysis}</ReactMarkdown>
        )}
      </div>
    </div>
  );
}
