import React, { useEffect, useState } from 'react';
import { useWebSocket } from '../context/WebSocketContext';
import { api } from '../services/api';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { 
  Activity, ShieldAlert, Heart, HardDrive, Cpu, 
  Terminal, Database, Play, Square, RotateCcw, AlertCircle, ArrowUpRight, ArrowDownLeft
} from 'lucide-react';

const COLORS = ['#06b6d4', '#6366f1', '#a855f7', '#ec4899', '#f59e0b', '#10b981'];

export const Dashboard: React.FC = () => {
  const { connected, stats, resources, addToast, clearPacketCache } = useWebSocket();
  
  const handleStart = async () => {
    try {
      await api.controlSniffer('start', resources.active_interface || 'en0');
      addToast("Capture Started", `Sniffing active on interface ${resources.active_interface || 'en0'}`, "info");
    } catch(e) {
      addToast("Control Failure", "Failed to start sniffer.", "error");
    }
  };

  const handleStop = async () => {
    try {
      await api.controlSniffer('stop');
      addToast("Capture Stopped", "Sniffer engine turned off.", "info");
    } catch(e) {
      addToast("Control Failure", "Failed to stop sniffer.", "error");
    }
  };

  const handleReset = async () => {
    if (window.confirm("Purge all recorded packets and alerts?")) {
      try {
        await api.resetDashboard();
        clearPacketCache();
        addToast("Dashboard Reset", "All packet history deleted from database.", "info");
      } catch(e) {
        addToast("Reset Failed", "Failed to purge database.", "error");
      }
    }
  };
  const [trafficHistory, setTrafficHistory] = useState<Array<{ time: string; pps: number; kbps: number }>>([]);

  // Log traffic rates into rolling history chart
  useEffect(() => {
    const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setTrafficHistory(prev => {
      const updated = [...prev, { time: nowStr, pps: stats.pps, kbps: stats.kbps }];
      return updated.slice(-15); // Maintain last 15 seconds
    });
  }, [stats.pps, stats.kbps]);

  // Format protocols for Pie Chart
  const protoData = Object.entries(stats.protocols).map(([name, value]) => ({
    name,
    value
  }));

  // Helper for status badge color
  const getStatusColor = (status: string) => {
    switch(status) {
      case 'running': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'paused': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* System Status Banner */}
      <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Network Anomaly Detection System</h1>
          <p className="text-slate-400 text-sm">Real-time intrusion detection and packet telemetry dashboard.</p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          {/* Quick controls */}
          <button onClick={handleStart} className="cyber-btn-primary py-1.5 px-3 text-xs flex items-center gap-1.5 shadow-md shadow-cyber-cyan/5">
            <Play size={12} /> Start Capture
          </button>
          <button onClick={handleStop} className="cyber-btn-secondary py-1.5 px-3 text-xs text-cyber-rose hover:bg-cyber-rose/10 flex items-center gap-1.5">
            <Square size={12} /> Stop Capture
          </button>
          <button onClick={handleReset} className="cyber-btn-danger py-1.5 px-3 text-xs flex items-center gap-1.5">
            <RotateCcw size={12} /> Reset Dashboard
          </button>
          
          <span className="w-px h-6 bg-slate-800 mx-1 hidden sm:inline" />

          {/* WS Status */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border ${
            connected ? 'bg-cyan-500/10 text-cyber-cyan border-cyan-500/20' : 'bg-rose-500/10 text-cyber-rose border-rose-500/20'
          }`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-cyber-cyan pulse-bullet' : 'bg-cyber-rose'} `} />
            {connected ? 'WS LIVEFEED CONNECTED' : 'WS OFFLINE'}
          </div>
          
          {/* Sniffer Status */}
          <div className={`px-3 py-1.5 rounded-full text-xs font-semibold border ${getStatusColor(resources.sniffer_status || 'stopped')}`}>
            ENGINE: {(resources.sniffer_status || 'stopped').toUpperCase()}
          </div>

          {/* Strategy Status */}
          <div className="px-3 py-1.5 rounded-full text-xs font-semibold border bg-indigo-500/10 text-indigo-400 border-indigo-500/20">
            STRATEGY: SIGNATURES
          </div>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Threat Meter */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">THREAT LEVEL</span>
            <div className="text-3xl font-bold font-outfit text-cyber-rose">
              {stats.threat_level}%
            </div>
            <p className="text-xs text-slate-500">Based on anomalous ratios.</p>
          </div>
          <div className={`p-3 rounded-xl ${stats.threat_level > 30 ? 'bg-cyber-rose/10 text-cyber-rose' : stats.threat_level > 10 ? 'bg-cyber-amber/10 text-cyber-amber' : 'bg-slate-800 text-slate-400'}`}>
            <ShieldAlert size={28} />
          </div>
        </div>

        {/* Network Health */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">NETWORK HEALTH</span>
            <div className="text-3xl font-bold font-outfit text-cyber-emerald">
              {stats.network_health}%
            </div>
            <p className="text-xs text-slate-500">Normal traffic consistency.</p>
          </div>
          <div className="p-3 rounded-xl bg-cyber-emerald/10 text-cyber-emerald">
            <Heart size={28} />
          </div>
        </div>

        {/* Live PPS */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">PACKETS / SECOND</span>
            <div className="text-3xl font-bold font-outfit text-cyber-cyan">
              {stats.pps} <span className="text-sm font-normal text-slate-500">pps</span>
            </div>
            <p className="text-xs text-slate-500">Recent injection rates.</p>
          </div>
          <div className="p-3 rounded-xl bg-cyber-cyan/10 text-cyber-cyan">
            <Activity size={28} />
          </div>
        </div>

        {/* Live Bandwidth */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">BANDWIDTH IN USE</span>
            <div className="text-3xl font-bold font-outfit text-indigo-400">
              {stats.kbps} <span className="text-sm font-normal text-slate-500">Kbps</span>
            </div>
            <p className="text-xs text-slate-500">Live throughput stream.</p>
          </div>
          <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400">
            <Terminal size={28} />
          </div>
        </div>
      </div>

      {/* Main Charts & Indicators */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Traffic Chart */}
        <div className="cyber-panel p-5 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-md font-semibold text-white">Live Traffic Velocity</h2>
              <p className="text-xs text-slate-400">Rolling throughput & packets rate.</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-semibold">
              <span className="flex items-center gap-1.5 text-cyber-cyan">
                <span className="w-2.5 h-2.5 rounded bg-cyber-cyan" /> PPS
              </span>
              <span className="flex items-center gap-1.5 text-indigo-400">
                <span className="w-2.5 h-2.5 rounded bg-indigo-500" /> Kbps
              </span>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficHistory} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.25}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorKbps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25}/>
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255, 255, 255, 0.08)', borderRadius: '8px' }} 
                  labelStyle={{ color: '#94a3b8', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="pps" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorPps)" />
                <Area type="monotone" dataKey="kbps" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#colorKbps)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="cyber-panel p-5 space-y-4">
          <div>
            <h2 className="text-md font-semibold text-white">Protocols In Use</h2>
            <p className="text-xs text-slate-400">Distribution analysis of incoming flows.</p>
          </div>
          <div className="h-56 flex items-center justify-center">
            {protoData.length === 0 ? (
              <div className="text-slate-500 text-xs">Awaiting captured packets...</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protoData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {protoData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255, 255, 255, 0.08)', borderRadius: '8px' }}
                  />
                  <Legend 
                    layout="horizontal" 
                    verticalAlign="bottom" 
                    align="center"
                    iconSize={10}
                    iconType="circle"
                    formatter={(value) => <span className="text-xs text-slate-300 font-medium">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Telemetry & Talkers Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Hardware Telemetry */}
        <div className="cyber-panel p-5 space-y-6">
          <div>
            <h2 className="text-md font-semibold text-white">System Resource Diagnostics</h2>
            <p className="text-xs text-slate-400">Host server resource allocation.</p>
          </div>
          
          <div className="space-y-4">
            {/* CPU */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-semibold">
                <span className="flex items-center gap-1.5 text-slate-400"><Cpu size={14} /> CPU Utiization</span>
                <span className="text-white">{resources.cpu_usage}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-cyber-cyan transition-all duration-500" style={{ width: `${resources.cpu_usage}%` }} />
              </div>
            </div>

            {/* RAM */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-semibold">
                <span className="flex items-center gap-1.5 text-slate-400"><Database size={14} /> Memory Allocation</span>
                <span className="text-white">{resources.ram_usage}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-indigo-400 transition-all duration-500" style={{ width: `${resources.ram_usage}%` }} />
              </div>
            </div>

            {/* Disk */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-semibold">
                <span className="flex items-center gap-1.5 text-slate-400"><HardDrive size={14} /> Storage Volume</span>
                <span className="text-white">{resources.disk_usage}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-amber-400 transition-all duration-500" style={{ width: `${resources.disk_usage}%` }} />
              </div>
            </div>
          </div>
          
          <div className="pt-2 text-[10px] text-slate-500 border-t border-slate-800 flex justify-between">
            <span>Uptime: {Math.floor(resources.uptime / 60)}m {Math.floor(resources.uptime % 60)}s</span>
            <span>Interface: {resources.active_interface}</span>
          </div>
        </div>

        {/* Top Talkers */}
        <div className="cyber-panel p-5 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-md font-semibold text-white">Top Flow Talkers</h2>
              <p className="text-xs text-slate-400">Most active IP sources and destination targets.</p>
            </div>
            <Activity size={18} className="text-cyber-cyan" />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
            {/* Top Source IPs */}
            <div className="space-y-2">
              <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                <ArrowUpRight size={14} className="text-cyber-cyan" /> ORIGIN SOURCES
              </div>
              <div className="space-y-1.5">
                {stats.top_sources.length === 0 ? (
                  <div className="text-slate-500 text-xs py-2">No packet flow detected</div>
                ) : (
                  stats.top_sources.map((item, idx) => (
                    <div key={idx} className="flex justify-between items-center text-xs py-1.5 px-2 bg-slate-900/40 border border-white/5 rounded-lg">
                      <span className="font-mono text-slate-300">{item.ip}</span>
                      <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyber-cyan font-bold">{item.count} pkts</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Top Destination IPs */}
            <div className="space-y-2">
              <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                <ArrowDownLeft size={14} className="text-indigo-400" /> DESTINATION TARGETS
              </div>
              <div className="space-y-1.5">
                {stats.top_destinations.length === 0 ? (
                  <div className="text-slate-500 text-xs py-2">No packet flow detected</div>
                ) : (
                  stats.top_destinations.map((item, idx) => (
                    <div key={idx} className="flex justify-between items-center text-xs py-1.5 px-2 bg-slate-900/40 border border-white/5 rounded-lg">
                      <span className="font-mono text-slate-300">{item.ip}</span>
                      <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 font-bold">{item.count} pkts</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Threats alert log */}
      <div className="cyber-panel p-5 space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-md font-semibold text-white">Live Threat Stream</h2>
            <p className="text-xs text-slate-400">Most recent security incidents flagged by signature detection rules.</p>
          </div>
          <span className="px-2 py-0.5 rounded bg-cyber-rose/15 text-cyber-rose text-xs font-bold uppercase tracking-wider pulse-bullet">
            Active Alerts feed
          </span>
        </div>

        <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
          {stats.alerts.length === 0 ? (
            <div className="text-center py-6 border border-dashed border-slate-800 rounded-xl">
              <AlertCircle size={24} className="mx-auto text-slate-500 mb-1.5" />
              <div className="text-slate-400 text-xs font-semibold">Zero Unresolved Threat Alerts</div>
              <div className="text-slate-600 text-[10px]">Your network looks safe and healthy.</div>
            </div>
          ) : (
            stats.alerts.map((alert) => (
              <div 
                key={alert.id} 
                className={`flex flex-col sm:flex-row justify-between gap-2 p-3 border-l-4 rounded-r-lg text-xs bg-slate-900/60 ${
                  alert.severity === 'Critical' ? 'border-cyber-rose bg-rose-950/5' : 'border-cyber-amber bg-amber-950/5'
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      alert.severity === 'Critical' ? 'bg-cyber-rose/20 text-cyber-rose' : 'bg-cyber-amber/20 text-cyber-amber'
                    }`}>
                      {alert.severity}
                    </span>
                    <span className="font-bold text-slate-200">{alert.attack_type}</span>
                  </div>
                  <div className="text-slate-400">{alert.reason}</div>
                </div>
                <div className="flex sm:flex-col items-start sm:items-end justify-between sm:justify-center text-slate-500 font-mono text-[10px]">
                  <span>Origin: {alert.src_ip || 'N/A'}</span>
                  <span>{new Date(alert.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
export default Dashboard;
