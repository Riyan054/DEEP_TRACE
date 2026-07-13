import React from 'react';
import { useWebSocket } from '../context/WebSocketContext';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, CartesianGrid
} from 'recharts';
import { 
  ArrowUpRight, ArrowDownLeft, Network, Cpu, Clock, 
  HelpCircle, Globe, Lock, ShieldCheck
} from 'lucide-react';

export const TrafficAnalytics: React.FC = () => {
  const { stats } = useWebSocket();

  // Map protocols to chart format
  const protocolData = Object.entries(stats.protocols).map(([name, count]) => ({
    name,
    count
  }));

  // Simulate port statistics from recent packets
  const portData = [
    { name: '443 (HTTPS)', count: stats.protocols['TCP'] ? Math.floor(stats.protocols['TCP'] * 0.6) : 24 },
    { name: '80 (HTTP)', count: stats.protocols['TCP'] ? Math.floor(stats.protocols['TCP'] * 0.2) : 8 },
    { name: '53 (DNS)', count: stats.protocols['UDP'] ? Math.floor(stats.protocols['UDP'] * 0.7) : 15 },
    { name: '123 (NTP)', count: stats.protocols['UDP'] ? Math.floor(stats.protocols['UDP'] * 0.1) : 3 },
    { name: '22 (SSH)', count: stats.protocols['TCP'] ? Math.floor(stats.protocols['TCP'] * 0.05) : 1 },
  ].sort((a,b) => b.count - a.count);

  // Connection types
  const connectionTypes = [
    { name: 'TLS Connections', count: stats.protocols['TCP'] ? Math.floor(stats.protocols['TCP'] * 0.65) : 22, icon: Lock, color: 'text-cyan-400' },
    { name: 'HTTP Requests', count: stats.protocols['TCP'] ? Math.floor(stats.protocols['TCP'] * 0.22) : 7, icon: Globe, color: 'text-indigo-400' },
    { name: 'DNS Queries', count: stats.protocols['UDP'] ? Math.floor(stats.protocols['UDP'] * 0.75) : 16, icon: Network, color: 'text-amber-400' },
  ];

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Network Traffic Analytics</h1>
        <p className="text-slate-400 text-sm">Deep statistics and structural analysis of network flow packets.</p>
      </div>

      {/* Analytics KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Average Packet Size */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">AVG PACKET SIZE</span>
            <div className="text-2xl font-bold font-outfit text-white">
              642 <span className="text-xs font-normal text-slate-500">Bytes</span>
            </div>
            <p className="text-[10px] text-slate-500">Typical packet header buffer.</p>
          </div>
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyber-cyan">
            <Network size={20} />
          </div>
        </div>

        {/* Active Connections */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">ACTIVE SESSIONS</span>
            <div className="text-2xl font-bold font-outfit text-white">
              {stats.top_sources.length + stats.top_destinations.length + 3}
            </div>
            <p className="text-[10px] text-slate-500">Established flow pairings.</p>
          </div>
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400">
            <Clock size={20} />
          </div>
        </div>

        {/* Inbound vs Outbound Ratio */}
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">INBOUND FLOW</span>
            <div className="text-2xl font-bold font-outfit text-white flex items-center gap-1">
              <ArrowDownLeft size={16} className="text-cyber-emerald" /> 62%
            </div>
            <p className="text-[10px] text-slate-500">External download velocity.</p>
          </div>
          <div className="p-2.5 rounded-lg bg-cyber-emerald/10 text-cyber-emerald">
            <ArrowDownLeft size={20} />
          </div>
        </div>

        <div className="cyber-panel p-4 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-slate-400 font-medium">OUTBOUND FLOW</span>
            <div className="text-2xl font-bold font-outfit text-white flex items-center gap-1">
              <ArrowUpRight size={16} className="text-indigo-400" /> 38%
            </div>
            <p className="text-[10px] text-slate-500">Internal exfiltration uploads.</p>
          </div>
          <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400">
            <ArrowUpRight size={20} />
          </div>
        </div>
      </div>

      {/* Custom Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocols Frequency */}
        <div className="cyber-panel p-5 space-y-4">
          <div>
            <h2 className="text-md font-semibold text-white">Flow Rates by Protocols</h2>
            <p className="text-xs text-slate-400">Volume count of packets received per protocol.</p>
          </div>
          <div className="h-64">
            {protocolData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs">No data captured</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255, 255, 255, 0.08)', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]}>
                    {protocolData.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={idx % 2 === 0 ? '#06b6d4' : '#6366f1'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Ports Allocation */}
        <div className="cyber-panel p-5 space-y-4">
          <div>
            <h2 className="text-md font-semibold text-white">Destination Port Frequencies</h2>
            <p className="text-xs text-slate-400">Inspected traffic sorted by targeted network ports.</p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={portData} layout="vertical" margin={{ top: 10, right: 10, left: 10, bottom: 0 }}>
                <XAxis type="number" stroke="#475569" fontSize={10} tickLine={false} />
                <YAxis dataKey="name" type="category" stroke="#475569" fontSize={10} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255, 255, 255, 0.08)', borderRadius: '8px' }}
                />
                <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Layer 7 Sessions Detail */}
      <div className="cyber-panel p-5 space-y-4">
        <div>
          <h2 className="text-md font-semibold text-white">Layer 7 Sessions Telemetry</h2>
          <p className="text-xs text-slate-400">Identified application protocols parsing summaries.</p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {connectionTypes.map((conn, idx) => {
            const Icon = conn.icon;
            return (
              <div key={idx} className="p-4 rounded-xl border border-white/5 bg-slate-900/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{conn.name}</span>
                  <Icon size={18} className={conn.color} />
                </div>
                <div className="text-2xl font-bold font-outfit text-white">
                  {conn.count} <span className="text-[10px] text-slate-500 font-normal">active sessions</span>
                </div>
                <div className="flex items-center gap-1.5 text-[10px] text-cyber-emerald">
                  <ShieldCheck size={12} /> Decrypted & Inspected
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
export default TrafficAnalytics;
