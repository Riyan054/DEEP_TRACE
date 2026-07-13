import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useWebSocket } from '../context/WebSocketContext';
import { 
  ShieldAlert, ShieldCheck, Filter, Search, Clock, 
  Trash2, AlertOctagon, CheckCircle2, ChevronRight
} from 'lucide-react';

interface SecurityAlert {
  id: number;
  timestamp: number;
  severity: string;
  attack_type: string;
  reason: string;
  src_ip: string | null;
  dst_ip: string | null;
  is_resolved: boolean;
}

export const ThreatDetection: React.FC = () => {
  const { addToast } = useWebSocket();
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);

  // Filter conditions
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('All');
  const [filterResolved, setFilterResolved] = useState('Unresolved');

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      // Build request params
      const params: any = {};
      if (filterSeverity !== 'All') params.severity = filterSeverity;
      if (filterResolved === 'Resolved') params.resolved = true;
      if (filterResolved === 'Unresolved') params.resolved = false;
      
      const data = await api.getAlerts(params);
      setAlerts(data);
    } catch (e) {
      addToast("Fetch Failed", "Could not retrieve historical alerts list.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    // Poll alerts every 4 seconds to catch new ones in background
    const interval = setInterval(fetchAlerts, 4000);
    return () => clearInterval(interval);
  }, [filterSeverity, filterResolved]);

  const handleResolve = async (id: number) => {
    try {
      await api.resolveAlert(id);
      addToast("Incident Resolved", `Threat Alert #${id} marked as resolved.`, "info");
      // Update local state immediately
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, is_resolved: true } : a));
    } catch(e) {
      addToast("Action Failed", "Could not resolve alert.", "error");
    }
  };

  // Local filtering by search text
  const filteredAlerts = alerts.filter(alert => {
    const textMatch = searchQuery === '' || 
      alert.attack_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.src_ip?.includes(searchQuery) ||
      alert.dst_ip?.includes(searchQuery);
    return textMatch;
  });

  const getSeverityStyles = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return { bg: 'bg-rose-500/10', border: 'border-cyber-rose/30', text: 'text-cyber-rose', label: 'CRITICAL' };
      case 'Warning':
        return { bg: 'bg-amber-500/10', border: 'border-cyber-amber/30', text: 'text-cyber-amber', label: 'WARNING' };
      default:
        return { bg: 'bg-cyan-500/10', border: 'border-cyan-500/20', text: 'text-cyber-cyan', label: 'INFO' };
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Intrusion & Threat Detection</h1>
        <p className="text-slate-400 text-sm">Review real-time intrusion warnings, trace offending hosts, and sign-off events.</p>
      </div>

      {/* Stats Summary row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="cyber-panel p-4 flex items-center gap-3">
          <div className="p-3 bg-cyber-rose/10 text-cyber-rose rounded-xl">
            <AlertOctagon size={24} />
          </div>
          <div>
            <div className="text-[10px] text-slate-500 font-bold uppercase">Active Critical Risks</div>
            <div className="text-2xl font-bold text-white font-outfit">
              {alerts.filter(a => a.severity === 'Critical' && !a.is_resolved).length}
            </div>
          </div>
        </div>

        <div className="cyber-panel p-4 flex items-center gap-3">
          <div className="p-3 bg-cyber-amber/10 text-cyber-amber rounded-xl">
            <ShieldAlert size={24} />
          </div>
          <div>
            <div className="text-[10px] text-slate-500 font-bold uppercase">Active Warnings</div>
            <div className="text-2xl font-bold text-white font-outfit">
              {alerts.filter(a => a.severity === 'Warning' && !a.is_resolved).length}
            </div>
          </div>
        </div>

        <div className="cyber-panel p-4 flex items-center gap-3">
          <div className="p-3 bg-cyber-emerald/10 text-cyber-emerald rounded-xl">
            <CheckCircle2 size={24} />
          </div>
          <div>
            <div className="text-[10px] text-slate-500 font-bold uppercase">Resolved Threats</div>
            <div className="text-2xl font-bold text-white font-outfit">
              {alerts.filter(a => a.is_resolved).length}
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-panel p-4 flex flex-wrap gap-4 items-center justify-between">
        {/* Search */}
        <div className="relative w-80">
          <input 
            type="text" 
            placeholder="Search by IP, Type or Details..." 
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="cyber-input pl-8 w-full" 
          />
          <Search size={14} className="absolute left-2.5 top-3 text-slate-500" />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-4 items-center">
          {/* Severity */}
          <div className="flex items-center gap-2">
            <Filter size={12} className="text-slate-500" />
            <select 
              value={filterSeverity} 
              onChange={e => setFilterSeverity(e.target.value)}
              className="cyber-input py-1.5 w-32 bg-slate-950"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical Only</option>
              <option value="Warning">Warning Only</option>
              <option value="Info">Info Only</option>
            </select>
          </div>

          {/* Status */}
          <select 
            value={filterResolved} 
            onChange={e => setFilterResolved(e.target.value)}
            className="cyber-input py-1.5 w-32 bg-slate-950"
          >
            <option value="All">All Items</option>
            <option value="Unresolved">Unresolved</option>
            <option value="Resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Alerts Grid */}
      <div className="cyber-panel overflow-hidden">
        {loading && alerts.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">Querying alerts history...</div>
        ) : filteredAlerts.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">No matching alert records found.</div>
        ) : (
          <div className="divide-y divide-slate-800/40">
            {filteredAlerts.map(alert => {
              const styles = getSeverityStyles(alert.severity);
              return (
                <div key={alert.id} className="p-4 hover:bg-slate-900/20 flex flex-col md:flex-row gap-4 justify-between items-start md:items-center transition-colors">
                  {/* Alert Details */}
                  <div className="space-y-1.5 max-w-2xl">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${styles.bg} ${styles.text} ${styles.border}`}>
                        {styles.label}
                      </span>
                      <span className="font-semibold text-sm text-slate-200">{alert.attack_type}</span>
                      {alert.is_resolved && (
                        <span className="flex items-center gap-1 text-[10px] text-cyber-emerald font-bold">
                          <CheckCircle2 size={10} /> RESOLVED
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{alert.reason}</p>
                    <div className="flex items-center gap-4 text-[10px] text-slate-500 font-mono">
                      <span>Source: <b className="text-slate-400">{alert.src_ip || 'N/A'}</b></span>
                      <span>Target: <b className="text-slate-400">{alert.dst_ip || 'N/A'}</b></span>
                    </div>
                  </div>

                  {/* Actions & Timings */}
                  <div className="flex md:flex-col items-center md:items-end justify-between w-full md:w-auto shrink-0 gap-3 border-t border-slate-800 md:border-none pt-2.5 md:pt-0">
                    <div className="flex items-center gap-1.5 text-slate-500 text-[10px] font-mono">
                      <Clock size={12} />
                      {new Date(alert.timestamp * 1000).toLocaleString()}
                    </div>
                    
                    {!alert.is_resolved && (
                      <button 
                        onClick={() => handleResolve(alert.id)}
                        className="cyber-btn-secondary py-1 px-3 text-[10px] hover:bg-cyber-emerald/10 hover:border-cyber-emerald/20 hover:text-cyber-emerald"
                      >
                        Resolve Alert
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
export default ThreatDetection;
