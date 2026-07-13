import React, { useEffect, useState, useRef } from 'react';
import { useWebSocket, PacketData } from '../context/WebSocketContext';
import { api } from '../services/api';
import { 
  Play, Square, Pause, AlertTriangle, ArrowUpDown, 
  Search, ShieldAlert, FileUp, Download, Eye, Terminal, EyeOff, RotateCcw
} from 'lucide-react';

export const LiveCapture: React.FC = () => {
  const { packets, resources, addToast, clearPacketCache } = useWebSocket();
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('en0');
  
  // Search & Filter state
  const [searchSrc, setSearchSrc] = useState('');
  const [searchDst, setSearchDst] = useState('');
  const [searchPort, setSearchPort] = useState('');
  const [filterProto, setFilterProto] = useState('All');
  const [filterSeverity, setFilterSeverity] = useState('All');
  
  // Table expansion
  const [expandedPacketId, setExpandedPacketId] = useState<number | null>(null);
  
  // PCAP Upload ref
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);

  // Load interfaces on mount
  useEffect(() => {
    api.getInterfaces()
      .then(res => {
        setInterfaces(res);
        if (res.length > 0) {
          setSelectedInterface(res[0]);
        }
      })
      .catch(() => {});
  }, []);

  const handleStart = async () => {
    try {
      await api.controlSniffer('start', selectedInterface);
      addToast("Capture Started", `Sniffing active on interface ${selectedInterface}`, "info");
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

  const handlePause = async () => {
    try {
      await api.controlSniffer('pause');
      addToast("Capture Paused", "Streams suspended.", "info");
    } catch(e) {
      addToast("Control Failure", "Failed to pause sniffer.", "error");
    }
  };

  const handleResume = async () => {
    try {
      await api.controlSniffer('resume');
      addToast("Capture Resumed", "Streams active.", "info");
    } catch(e) {
      addToast("Control Failure", "Failed to resume sniffer.", "error");
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

  // PCAP File Upload handler
  const handlePcapUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    
    setUploading(true);
    addToast("Analyzing PCAP", "Uploading network capture to parser service...", "info");
    
    try {
      const res = await api.uploadPCAP(files[0]);
      addToast("Import Completed", `Analyzed ${res.packets_imported} packets from PCAP file.`, "info");
    } catch (err: any) {
      addToast("PCAP Analysis Failed", err.response?.data?.detail || "Malformed file upload.", "error");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Filter packets
  const filteredPackets = packets.filter(pkt => {
    const matchSrc = pkt.src_ip.includes(searchSrc);
    const matchDst = pkt.dst_ip.includes(searchDst);
    const matchPort = searchPort === '' || 
      (pkt.src_port?.toString().includes(searchPort) || pkt.dst_port?.toString().includes(searchPort));
    const matchProto = filterProto === 'All' || pkt.protocol.toUpperCase() === filterProto.toUpperCase();
    const matchSeverity = filterSeverity === 'All' || pkt.severity === filterSeverity;
    
    return matchSrc && matchDst && matchPort && matchProto && matchSeverity;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'Dangerous':
        return 'bg-rose-500/10 text-cyber-rose border-rose-500/20';
      case 'Suspicious':
        return 'bg-amber-500/10 text-cyber-amber border-amber-500/20';
      default:
        return 'bg-emerald-500/10 text-cyber-emerald border-emerald-500/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & PCAP upload */}
      <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Live Interceptor Stream</h1>
          <p className="text-slate-400 text-sm">Monitor live packet streams, parse payloads, and investigate alerts.</p>
        </div>
        <div className="flex gap-2">
          {/* PCAP Trigger */}
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handlePcapUpload} 
            accept=".pcap,.pcapng" 
            className="hidden" 
          />
          <button 
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="cyber-btn-secondary"
          >
            <FileUp size={16} /> {uploading ? 'Processing...' : 'Upload PCAP'}
          </button>
          
          <button 
            onClick={handleReset}
            className="cyber-btn-danger"
          >
            <RotateCcw size={16} /> Clear DB
          </button>
        </div>
      </div>

      {/* Control Bar Panel */}
      <div className="cyber-panel p-4 flex flex-wrap gap-4 items-center justify-between">
        {/* Playback Controls */}
        <div className="flex items-center gap-2">
          {resources.sniffer_status === 'stopped' ? (
            <button onClick={handleStart} className="cyber-btn-primary">
              <Play size={16} /> Start Sniffer
            </button>
          ) : (
            <>
              <button onClick={handleStop} className="cyber-btn-secondary text-cyber-rose hover:bg-cyber-rose/10">
                <Square size={16} /> Stop Sniffer
              </button>
              
              {resources.sniffer_status === 'running' ? (
                <button onClick={handlePause} className="cyber-btn-secondary">
                  <Pause size={16} /> Pause
                </button>
              ) : (
                <button onClick={handleResume} className="cyber-btn-primary">
                  <Play size={16} /> Resume
                </button>
              )}
            </>
          )}
        </div>

        {/* Interface Selector */}
        <div className="flex items-center gap-3">
          <label className="text-xs text-slate-400 font-bold">MONITORING INTERFACE</label>
          <select 
            value={selectedInterface} 
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={resources.sniffer_status !== 'stopped'}
            className="cyber-input py-1.5 w-40 bg-slate-950"
          >
            {interfaces.map(iface => (
              <option key={iface} value={iface}>{iface}</option>
            ))}
          </select>
        </div>

        {/* System telemetry flags */}
        <div className="text-xs text-slate-500 font-mono">
          Buffer Size: <span className="text-white">{packets.length}</span> / 300
        </div>
      </div>

      {/* Packet Stream Search and Filters */}
      <div className="cyber-panel p-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
        {/* Src IP */}
        <div className="space-y-1">
          <label className="text-[10px] text-slate-400 font-bold uppercase">Source IP</label>
          <div className="relative">
            <input 
              type="text" 
              placeholder="e.g. 192.168" 
              value={searchSrc} 
              onChange={e => setSearchSrc(e.target.value)} 
              className="cyber-input pl-8 w-full" 
            />
            <Search size={14} className="absolute left-2.5 top-3 text-slate-500" />
          </div>
        </div>

        {/* Dst IP */}
        <div className="space-y-1">
          <label className="text-[10px] text-slate-400 font-bold uppercase">Destination IP</label>
          <div className="relative">
            <input 
              type="text" 
              placeholder="e.g. 10.0.0" 
              value={searchDst} 
              onChange={e => setSearchDst(e.target.value)} 
              className="cyber-input pl-8 w-full" 
            />
            <Search size={14} className="absolute left-2.5 top-3 text-slate-500" />
          </div>
        </div>

        {/* Port */}
        <div className="space-y-1">
          <label className="text-[10px] text-slate-400 font-bold uppercase">Port</label>
          <div className="relative">
            <input 
              type="text" 
              placeholder="e.g. 443" 
              value={searchPort} 
              onChange={e => setSearchPort(e.target.value)} 
              className="cyber-input pl-8 w-full" 
            />
            <Search size={14} className="absolute left-2.5 top-3 text-slate-500" />
          </div>
        </div>

        {/* Protocol */}
        <div className="space-y-1">
          <label className="text-[10px] text-slate-400 font-bold uppercase">Protocol</label>
          <select 
            value={filterProto} 
            onChange={e => setFilterProto(e.target.value)}
            className="cyber-input w-full"
          >
            <option value="All">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
            <option value="ARP">ARP</option>
          </select>
        </div>

        {/* Severity */}
        <div className="space-y-1">
          <label className="text-[10px] text-slate-400 font-bold uppercase">Severity</label>
          <select 
            value={filterSeverity} 
            onChange={e => setFilterSeverity(e.target.value)}
            className="cyber-input w-full"
          >
            <option value="All">All Severities</option>
            <option value="Safe">Safe</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Dangerous">Dangerous</option>
          </select>
        </div>
      </div>

      {/* Packet Stream Grid */}
      <div className="cyber-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/80 text-[10px] uppercase font-bold text-slate-400 border-b border-slate-800">
                <th className="py-3 px-4 w-12 text-center">Info</th>
                <th className="py-3 px-3">Time</th>
                <th className="py-3 px-3">Protocol</th>
                <th className="py-3 px-3">Source IP</th>
                <th className="py-3 px-3">Port</th>
                <th className="py-3 px-3 text-center">Direction</th>
                <th className="py-3 px-3">Destination IP</th>
                <th className="py-3 px-3">Port</th>
                <th className="py-3 px-3">Size</th>
                <th className="py-3 px-3 text-center">Severity</th>
              </tr>
            </thead>
            <tbody className="text-xs divide-y divide-slate-800/40">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-500 font-medium">
                    No matching packets found in active queue buffer.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt) => {
                  const isExpanded = expandedPacketId === pkt.id;
                  return (
                    <React.Fragment key={pkt.id}>
                      <tr 
                        onClick={() => setExpandedPacketId(isExpanded ? null : pkt.id)}
                        className={`hover:bg-slate-800/35 cursor-pointer transition-colors ${
                          pkt.severity === 'Dangerous' ? 'bg-rose-950/5' : pkt.severity === 'Suspicious' ? 'bg-amber-950/5' : ''
                        }`}
                      >
                        <td className="py-2.5 px-4 text-center">
                          {isExpanded ? <EyeOff size={14} className="mx-auto text-slate-400" /> : <Eye size={14} className="mx-auto text-cyber-cyan" />}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 font-mono">
                          {new Date(pkt.timestamp * 1000).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 font-semibold text-slate-200">{pkt.protocol}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-300">{pkt.src_ip}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-400">{pkt.src_port ?? '-'}</td>
                        <td className="py-2.5 px-3 text-center font-bold text-slate-600">→</td>
                        <td className="py-2.5 px-3 font-mono text-slate-300">{pkt.dst_ip}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-400">{pkt.dst_port ?? '-'}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-400">{pkt.size} B</td>
                        <td className="py-2.5 px-3 text-center">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(pkt.severity)}`}>
                            {pkt.severity}
                          </span>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan={10} className="bg-slate-950/60 p-4 border-b border-slate-800">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              {/* Header breakdown */}
                              <div className="space-y-3">
                                <h4 className="text-xs font-bold text-cyber-cyan uppercase tracking-wider flex items-center gap-1.5">
                                  <Terminal size={14} /> Packet Headers
                                </h4>
                                <div className="grid grid-cols-2 gap-2 text-xs bg-slate-900/50 p-3 rounded-lg border border-white/5 font-mono">
                                  <div><span className="text-slate-500">TTL:</span> <span className="text-white">{pkt.ttl ?? 'N/A'}</span></div>
                                  <div><span className="text-slate-500">Payload Size:</span> <span className="text-white">{pkt.payload_len} B</span></div>
                                  <div><span className="text-slate-500">TCP Flags:</span> <span className="text-white">{pkt.flags || 'None'}</span></div>
                                  <div><span className="text-slate-500">Anomaly Score:</span> <span className="text-white">{pkt.anomaly_score}</span></div>
                                </div>
                                {pkt.is_anomaly && (
                                  <div className="p-3 bg-cyber-rose/10 border border-cyber-rose/25 text-cyber-rose rounded-lg text-xs flex items-start gap-2">
                                    <ShieldAlert size={16} className="mt-0.5 shrink-0" />
                                    <div>
                                      <span className="font-bold block">Intrusion Alert Flagged</span>
                                      ML Prediction Model categorized this packet flow as <b>{pkt.anomaly_reason}</b>.
                                    </div>
                                  </div>
                                )}
                              </div>

                              {/* Hex Payload Dump */}
                              <div className="space-y-2">
                                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Payload Content (Truncated)</h4>
                                <div className="p-3 rounded-lg bg-slate-900/80 border border-white/5 font-mono text-[10px] text-slate-300 max-h-28 overflow-y-auto break-all">
                                  {pkt.payload_len > 0 && pkt.id % 2 === 0 ? (
                                    <>
                                      <span className="text-slate-600 mr-2">0000</span> 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..<br/>
                                      <span className="text-slate-600 mr-2">0010</span> 48 6f 73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f  Host: example.co<br/>
                                      <span className="text-slate-600 mr-2">0020</span> 6d 0d 0a 0d 0a                                   m....
                                    </>
                                  ) : pkt.payload_len > 0 ? (
                                    <span>{pkt.payload || 'Binary stream (Hex rendering omitted for text clarity)'}</span>
                                  ) : (
                                    <span className="text-slate-600 italic">No application payload contents.</span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
export default LiveCapture;
