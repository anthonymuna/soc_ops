import React from 'react';

export default function SystemHealth({ status, logsScanned }) {
  const gauges = [
    { label: 'SOC AI', value: status.qwen ? 96 : 0, color: 'text-teal-400', glow: 'drop-shadow-[0_0_12px_rgba(45,212,191,0.5)]' },
    { label: 'OK', value: status.status === 'ok' ? 96 : 40, color: 'text-teal-400', glow: 'drop-shadow-[0_0_12px_rgba(45,212,191,0.5)]' },
    { label: 'Sensor Coverage', value: status.es ? 98 : 0, color: 'text-teal-400', glow: 'drop-shadow-[0_0_12px_rgba(45,212,191,0.5)]' },
    { label: 'SIEM Latency', value: '1.2s', color: 'text-teal-400', glow: 'drop-shadow-[0_0_12px_rgba(45,212,191,0.5)]', isText: true },
    { label: 'Network Flow', value: logsScanned > 0 ? 92 : 0, color: 'text-teal-400', glow: 'drop-shadow-[0_0_12px_rgba(45,212,191,0.5)]' }
  ];

  return (
    <div className="glass-panel p-6 rounded-xl flex flex-col h-full border-slate-800">
      <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-[0.2em] mb-8">System Health</h3>
      
      <div className="flex flex-wrap gap-4 items-center justify-center w-full mt-2">
        {gauges.map((g, idx) => (
          <div key={idx} className="flex flex-col items-center justify-center relative w-[80px]">
            <svg viewBox="0 0 100 50" className="w-16 overflow-visible">
              <path
                d="M 10 50 A 40 40 0 0 1 90 50"
                fill="none"
                stroke="rgba(255,255,255,0.05)"
                strokeWidth="8"
                strokeLinecap="round"
              />
              <path
                d="M 10 50 A 40 40 0 0 1 90 50"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeLinecap="round"
                className={`${g.color} ${g.glow} transition-all duration-1000 ease-out`}
                strokeDasharray="125.6"
                strokeDashoffset={125.6 - (125.6 * (g.isText ? 100 : g.value)) / 100}
              />
            </svg>
            <div className="absolute top-[20px] flex flex-col items-center">
              <span className={`text-sm font-mono ${g.color} ${g.glow}`}>
                {g.isText ? g.value : `${g.value}%`}
              </span>
            </div>
            <span className="text-[9px] text-slate-400 uppercase tracking-wider mt-2 text-center leading-tight">{g.label}</span>
          </div>
        ))}
      </div>

      <div className="mt-6 border-t border-slate-800 pt-4 flex-1 overflow-y-auto">
        <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-[0.1em] mb-3">Container Health</h4>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2">
          {[
            { name: 'Elastic Search', state: status.es_connected ? 'ONLINE' : 'OFFLINE' },
            { name: 'Kafka', state: status.es_connected ? 'ONLINE' : 'OFFLINE' },
            { name: 'Machine Learning', state: status.model_trained ? 'ONLINE' : 'OFFLINE' },
            { name: 'Django', state: 'ONLINE' },
            { name: 'Brain', state: 'ONLINE' },
            { name: 'Wazuh Connector', state: 'ONLINE' },
          ].map((container, i) => (
            <div key={i} className="flex items-center justify-between bg-slate-900/30 px-2 py-1.5 rounded border border-slate-800">
              <span className="text-[10px] text-slate-300 font-mono truncate mr-2" title={container.name}>{container.name}</span>
              <div className="flex items-center gap-1.5 shrink-0">
                <div className={`w-1.5 h-1.5 rounded-full ${container.state === 'ONLINE' ? 'bg-teal-400' : 'bg-rose-500'}`}></div>
                <span className={`text-[9px] font-bold tracking-wider ${container.state === 'ONLINE' ? 'text-teal-400' : 'text-rose-500'}`}>{container.state}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
