import React from 'react';

export default function SystemHealth({ status, logsScanned }) {
  const components = [
    { name: 'Elastic Search', isOnline: status.es_connected },
    { name: 'Machine Learning', isOnline: status.status === 'ok' },
    { name: 'Kafka', isOnline: status.kafka_connected },
    { name: 'Django API', isOnline: status.django_connected },
    { name: 'NGAO Brain', isOnline: status.brain_connected },
    { name: 'Wazuh', isOnline: status.wazuh_connected },
    // { name: 'FortiSIEM', isOnline: status.fortisiem_connected },
    // { name: 'Cisco Umbrella', isOnline: status.umbrella_connected }
  ];

  const gauges = components.map(c => ({
    label: c.name,
    value: c.isOnline ? 100 : 0,
    color: c.isOnline ? 'text-teal-400' : 'text-rose-500',
    glow: c.isOnline ? 'drop-shadow-[0_0_12px_rgba(45,212,191,0.5)]' : 'drop-shadow-[0_0_12px_rgba(244,63,94,0.5)]',
    stateText: c.isOnline ? 'UP' : 'DOWN'
  }));

  return (
    <div className="glass-panel p-6 rounded-xl flex flex-col h-full border-slate-800">
      <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-[0.2em] mb-4">Health Status</h3>
      
      <div className="flex flex-wrap gap-x-4 gap-y-10 items-center justify-evenly w-full mt-4 flex-1">
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
                strokeDashoffset={125.6 - (125.6 * g.value) / 100}
              />
            </svg>
            <div className="absolute top-[20px] flex flex-col items-center">
              <span className={`text-sm font-mono font-bold ${g.color} ${g.glow}`}>
                {g.stateText}
              </span>
            </div>
            <span className="text-[9px] text-slate-400 uppercase tracking-wider mt-3 text-center leading-tight whitespace-nowrap">{g.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
