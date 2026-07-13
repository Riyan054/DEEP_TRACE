import React from 'react';
import { api } from '../services/api';
import { useWebSocket } from '../context/WebSocketContext';
import { 
  FileText, Download, ShieldCheck, AlertCircle, 
  HelpCircle, ChevronRight, FileCode, TableProperties
} from 'lucide-react';

export const Reports: React.FC = () => {
  const { stats, addToast } = useWebSocket();

  const handleDownload = (type: 'pdf' | 'csv' | 'json') => {
    addToast("Generating Report", `Building ${type.toUpperCase()} file...`, "info");
    const downloadUrl = api.getReportDownloadUrl(type);
    
    // Create an anchor element to trigger download programmatically
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', `nads_security_report.${type}`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Assessment & Reports</h1>
        <p className="text-slate-400 text-sm">Download executive audits, export CSV log datasets, or review threat resolutions.</p>
      </div>

      {/* Reports Card Options */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* PDF */}
        <div className="cyber-panel p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="p-3 bg-cyan-500/10 text-cyber-cyan rounded-xl w-fit">
              <FileText size={24} />
            </div>
            <h3 className="text-md font-bold text-white font-outfit">Executive Assessment Report</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Formatted PDF report containing traffic summary charts, protocol distributions, flagged alert logs, and remediation instructions.
            </p>
          </div>
          <button 
            onClick={() => handleDownload('pdf')}
            className="cyber-btn-primary w-full"
          >
            <Download size={14} /> Download PDF
          </button>
        </div>

        {/* CSV */}
        <div className="cyber-panel p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-xl w-fit">
              <TableProperties size={24} />
            </div>
            <h3 className="text-md font-bold text-white font-outfit">Security Incidents CSV</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Row-by-row table dump of all flagged threat anomalies, including timestamps, classifications, source IPs, and descriptions.
            </p>
          </div>
          <button 
            onClick={() => handleDownload('csv')}
            className="cyber-btn-secondary w-full"
          >
            <Download size={14} /> Export CSV List
          </button>
        </div>

        {/* JSON */}
        <div className="cyber-panel p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="p-3 bg-amber-500/10 text-cyber-amber rounded-xl w-fit">
              <FileCode size={24} />
            </div>
            <h3 className="text-md font-bold text-white font-outfit">Full Metrics JSON</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Structured raw telemetry schema. Great for ingesting into SIEM appliances, Grafana instances, or external analysis scripts.
            </p>
          </div>
          <button 
            onClick={() => handleDownload('json')}
            className="cyber-btn-secondary w-full"
          >
            <Download size={14} /> Fetch JSON Payload
          </button>
        </div>
      </div>

      {/* Compliance Box */}
      <div className="cyber-panel p-5 space-y-3">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
          <ShieldCheck size={14} className="text-cyber-emerald" /> Network Compliance Status
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Based on the recent inspection of <b>{stats.total_captured}</b> packets:
        </p>
        <div className="flex gap-4 items-center">
          <div className="text-3xl font-extrabold text-cyber-emerald font-outfit">
            {stats.network_health}%
          </div>
          <div className="text-xs text-slate-500 font-mono">
            <div>Health Score (Target &gt; 90%)</div>
            <div>Threat Level ratio: <span className="text-cyber-rose">{stats.threat_level}%</span></div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default Reports;
