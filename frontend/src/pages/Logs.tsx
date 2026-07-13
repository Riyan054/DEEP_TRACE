import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useWebSocket } from '../context/WebSocketContext';
import { 
  Terminal, ShieldCheck, Search, RefreshCw, 
  Settings, UserCheck, AlertCircle, Info, Calendar
} from 'lucide-react';

interface LogItem {
  id: number;
  timestamp: number;
  level?: string; // System log
  component?: string; // System log
  message?: string; // System log
  user_action?: string; // Audit log
  details?: string; // Audit log
}

export const Logs: React.FC = () => {
  const { addToast } = useWebSocket();
  const [activeTab, setActiveTab] = useState<'system' | 'audit'>('system');
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      if (activeTab === 'system') {
        const data = await api.getSystemLogs(100);
        setLogs(data);
      } else {
        const data = await api.getAuditLogs(100);
        setLogs(data);
      }
    } catch(e) {
      addToast("Logs Query Failed", "Failed to retrieve logs from DB.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [activeTab]);

  const filteredLogs = logs.filter(log => {
    const term = search.toLowerCase();
    if (activeTab === 'system') {
      return (
        log.message?.toLowerCase().includes(term) ||
        log.component?.toLowerCase().includes(term) ||
        log.level?.toLowerCase().includes(term)
      );
    } else {
      return (
        log.user_action?.toLowerCase().includes(term) ||
        log.details?.toLowerCase().includes(term)
      );
    }
  });

  const getLogLevelStyle = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'ERROR': return 'text-cyber-rose bg-cyber-rose/10 border-cyber-rose/25';
      case 'WARNING': return 'text-cyber-amber bg-cyber-amber/10 border-cyber-amber/25';
      default: return 'text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/25';
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Console Logs & Audits</h1>
          <p className="text-slate-400 text-sm">Review backend diagnostic events or inspect user action audit trails.</p>
        </div>
        <button 
          onClick={fetchLogs}
          className="cyber-btn-secondary"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh Logs
        </button>
      </div>

      {/* Tabs and Search Panel */}
      <div className="cyber-panel p-4 flex flex-wrap gap-4 justify-between items-center">
        {/* Tabs */}
        <div className="flex bg-slate-900 border border-slate-800 p-1 rounded-lg">
          <button 
            onClick={() => setActiveTab('system')}
            className={`px-4 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeTab === 'system' 
                ? 'bg-cyber-cyan text-slate-900 font-bold' 
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Terminal size={14} /> System Diagnostics
          </button>
          <button 
            onClick={() => setActiveTab('audit')}
            className={`px-4 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-all ${
              activeTab === 'audit' 
                ? 'bg-cyber-cyan text-slate-900 font-bold' 
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <UserCheck size={14} /> Operational Audits
          </button>
        </div>

        {/* Search Input */}
        <div className="relative w-72">
          <input 
            type="text" 
            placeholder={`Filter ${activeTab} log events...`} 
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="cyber-input pl-8 w-full" 
          />
          <Search size={14} className="absolute left-2.5 top-3 text-slate-500" />
        </div>
      </div>

      {/* Logs Console Container */}
      <div className="cyber-panel overflow-hidden">
        {loading && logs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">Querying database event logs...</div>
        ) : filteredLogs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">No matching log statements recorded.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-900/80 text-[10px] uppercase font-bold text-slate-400 border-b border-slate-800">
                  <th className="py-3 px-4 w-44">Time</th>
                  {activeTab === 'system' ? (
                    <>
                      <th className="py-3 px-3 w-28">Severity</th>
                      <th className="py-3 px-3 w-32">Component</th>
                      <th className="py-3 px-3">Message</th>
                    </>
                  ) : (
                    <>
                      <th className="py-3 px-3 w-48">Action Category</th>
                      <th className="py-3 px-3">Operation Details</th>
                    </>
                  )}
                </tr>
              </thead>
              <tbody className="text-xs divide-y divide-slate-800/40 font-mono">
                {filteredLogs.map(log => (
                  <tr key={log.id} className="hover:bg-slate-800/20">
                    <td className="py-2.5 px-4 text-slate-500 text-[11px] whitespace-nowrap">
                      {new Date(log.timestamp * 1000).toLocaleString()}
                    </td>
                    {activeTab === 'system' ? (
                      <>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${getLogLevelStyle(log.level || '')}`}>
                            {log.level}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-semibold text-slate-300">{log.component}</td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-pre-wrap">{log.message}</td>
                      </>
                    ) : (
                      <>
                        <td className="py-2.5 px-3 font-semibold text-cyber-cyan">{log.user_action}</td>
                        <td className="py-2.5 px-3 text-slate-400">{log.details || '-'}</td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
export default Logs;
