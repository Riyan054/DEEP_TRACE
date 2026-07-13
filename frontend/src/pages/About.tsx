import React from 'react';
import { Info, ShieldAlert, Cpu, Database, Network, GitBranch } from 'lucide-react';

export const About: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">System Architecture</h1>
        <p className="text-slate-400 text-sm">Review design patterns, engineering components, and pipeline dataflows.</p>
      </div>

      {/* Engineering Design */}
      <div className="cyber-panel p-6 space-y-4">
        <h2 className="text-md font-semibold text-white flex items-center gap-1.5">
          <Network size={18} className="text-cyber-cyan" /> Core Pipeline Flow
        </h2>
        <p className="text-xs text-slate-400 leading-relaxed">
          The Network Anomaly Detection System (NADS) captures real-time packets, extracts numerical metadata features, classifies them using machine learning predictors, and streams telemetry values to subscriber clients.
        </p>

        {/* Visual flow chart */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-3 text-center">
          <div className="p-3 bg-slate-900/60 border border-white/5 rounded-xl space-y-1.5">
            <div className="text-cyber-cyan font-bold text-xs uppercase">01. Capture</div>
            <div className="text-[10px] text-slate-400 leading-normal">
              Scapy socket bindings sniffs ingress packets on interface or uses generator fallback.
            </div>
          </div>
          
          <div className="p-3 bg-slate-900/60 border border-white/5 rounded-xl space-y-1.5">
            <div className="text-indigo-400 font-bold text-xs uppercase">02. Extractor</div>
            <div className="text-[10px] text-slate-400 leading-normal">
              Feature vector engine translates protocol headers into an 8-dimensional numerical float space.
            </div>
          </div>

          <div className="p-3 bg-slate-900/60 border border-white/5 rounded-xl space-y-1.5">
            <div className="text-cyber-rose font-bold text-xs uppercase">03. Inference</div>
            <div className="text-[10px] text-slate-400 leading-normal">
              Classifiers (SVM, Forest) compute anomaly ratios and flag potential malicious payloads.
            </div>
          </div>

          <div className="p-3 bg-slate-900/60 border border-white/5 rounded-xl space-y-1.5">
            <div className="text-cyber-amber font-bold text-xs uppercase">04. Log DB</div>
            <div className="text-[10px] text-slate-400 leading-normal">
              Transactional SQLite sessions commits packet headers, system alerts, and audit logs.
            </div>
          </div>

          <div className="p-3 bg-slate-900/60 border border-white/5 rounded-xl space-y-1.5">
            <div className="text-cyber-emerald font-bold text-xs uppercase">05. Broadcast</div>
            <div className="text-[10px] text-slate-400 leading-normal">
              WebSocket manager broadcasts unified state update payloads to react dashboard clients.
            </div>
          </div>
        </div>
      </div>

      {/* Directory structure summary */}
      <div className="cyber-panel p-6 space-y-4">
        <h2 className="text-md font-semibold text-white flex items-center gap-1.5">
          <GitBranch size={18} className="text-cyber-cyan" /> Repository Architecture Map
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs leading-relaxed font-mono">
          <div className="space-y-2 p-3 bg-slate-900/40 border border-white/5 rounded-xl">
            <div className="font-bold text-slate-200">/backend</div>
            <ul className="list-disc list-inside text-slate-400 space-y-1 pl-2">
              <li><b>/api</b> : FastAPI endpoints and WS channels</li>
              <li><b>/database</b> : SQLAlchemy session factories</li>
              <li><b>/models</b> : Table models for packet records</li>
              <li><b>/ml</b> : Isolation Forest, Random Forest models</li>
              <li><b>/sniffer</b> : Thread-safe Scapy packet sniffer</li>
              <li><b>/reports</b> : ReportLab PDF layout generator</li>
            </ul>
          </div>

          <div className="space-y-2 p-3 bg-slate-900/40 border border-white/5 rounded-xl">
            <div className="font-bold text-slate-200">/frontend</div>
            <ul className="list-disc list-inside text-slate-400 space-y-1 pl-2">
              <li><b>/src/components</b> : Core chart renderers</li>
              <li><b>/src/context</b> : WebSocket contexts</li>
              <li><b>/src/pages</b> : Visual modular screens</li>
              <li><b>/src/services</b> : Axios API client interfaces</li>
              <li><b>/src/styles</b> : Glassmorphism Tailwind themes</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
export default About;
