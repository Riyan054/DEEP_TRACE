import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useWebSocket } from '../context/WebSocketContext';
import { 
  Settings as SettingsIcon, Save, RefreshCw, Cpu, 
  Terminal, ShieldCheck, Database, ToggleLeft, ToggleRight
} from 'lucide-react';

export const Settings: React.FC = () => {
  const { addToast } = useWebSocket();
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  // Form State
  const [mockMode, setMockMode] = useState(true);
  const [selectedInterface, setSelectedInterface] = useState('en0');
  const [packetLimit, setPacketLimit] = useState(5000);
  const [activeModel, setActiveModel] = useState('Isolation Forest');
  const [notificationToggle, setNotificationToggle] = useState(true);

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const [settingsData, ifsData] = await Promise.all([
        api.getSettings(),
        api.getInterfaces()
      ]);
      
      setMockMode(settingsData.mock_mode);
      setSelectedInterface(settingsData.interface);
      setPacketLimit(settingsData.packet_limit);
      setActiveModel(settingsData.active_model);
      setNotificationToggle(settingsData.notification_toggle);
      
      setInterfaces(ifsData);
    } catch(e) {
      addToast("Fetch Failed", "Could not load global settings payload.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.updateSettings({
        mock_mode: mockMode,
        refresh_rate: 1.0,
        packet_limit: packetLimit,
        active_model: activeModel,
        interface: selectedInterface,
        notification_toggle: notificationToggle
      });
      addToast("Settings Updated", "Configuration saved and applied in backend.", "info");
    } catch(err: any) {
      addToast("Save Failed", err.response?.data?.detail || "Could not update settings.", "error");
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="pb-2 border-b border-slate-800">
        <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">System Configuration</h1>
        <p className="text-slate-400 text-sm">Fine tune network packet buffer thresholds, toggle simulator fallbacks, or re-route interfaces.</p>
      </div>

      {loading ? (
        <div className="cyber-panel p-6 text-center text-slate-500 text-xs">Querying settings config...</div>
      ) : (
        <form onSubmit={handleSave} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main settings form */}
          <div className="cyber-panel p-5 lg:col-span-2 space-y-6">
            <h2 className="text-md font-semibold text-white flex items-center gap-1.5 border-b border-slate-800 pb-3">
              <SettingsIcon size={18} className="text-cyber-cyan" /> General System Settings
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Mock traffic generator toggle */}
              <div className="space-y-2 p-3 rounded-lg bg-slate-900/30 border border-white/5 flex flex-col justify-between">
                <div>
                  <label className="text-xs font-bold text-slate-200 block">Traffic Simulator Fallback</label>
                  <span className="text-[10px] text-slate-500 leading-relaxed">
                    Runs simulated traffic (DDoS bursts, port scanning, HTTP normal patterns) if raw sockets lack root permissions.
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setMockMode(!mockMode)}
                  className={`mt-3 flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold border ${
                    mockMode 
                      ? 'bg-cyber-cyan/10 border-cyber-cyan/30 text-cyber-cyan' 
                      : 'bg-slate-900 border-slate-800 text-slate-400'
                  }`}
                >
                  STATUS: {mockMode ? 'SIMULATOR ACTIVE' : 'LIVE PCAP/SOCKET CAPTURE'}
                  {mockMode ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                </button>
              </div>

              {/* Notification Toggles */}
              <div className="space-y-2 p-3 rounded-lg bg-slate-900/30 border border-white/5 flex flex-col justify-between">
                <div>
                  <label className="text-xs font-bold text-slate-200 block">Intrusion Alert Toasts</label>
                  <span className="text-[10px] text-slate-500 leading-relaxed">
                    Trigger slide-in notifications when suspicious anomaly scores are parsed in the socket.
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setNotificationToggle(!notificationToggle)}
                  className={`mt-3 flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold border ${
                    notificationToggle 
                      ? 'bg-cyber-cyan/10 border-cyber-cyan/30 text-cyber-cyan' 
                      : 'bg-slate-900 border-slate-800 text-slate-400'
                  }`}
                >
                  SYSTEM TOASTS: {notificationToggle ? 'ENABLED' : 'MUTED'}
                  {notificationToggle ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                </button>
              </div>

              {/* Interfaces dropdown */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-300 block">Ingress Network Interface</label>
                <select 
                  value={selectedInterface} 
                  onChange={e => setSelectedInterface(e.target.value)}
                  className="cyber-input w-full bg-slate-950"
                >
                  {interfaces.map(iface => (
                    <option key={iface} value={iface}>{iface}</option>
                  ))}
                </select>
                <span className="text-[10px] text-slate-500 block">Needs root permissions for live captures.</span>
              </div>



              {/* Limit input */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-300 block">Database Packet Storage Cap</label>
                <input 
                  type="number" 
                  value={packetLimit} 
                  onChange={e => setPacketLimit(parseInt(e.target.value) || 1000)}
                  min={100}
                  max={50000}
                  className="cyber-input w-full" 
                />
                <span className="text-[10px] text-slate-500 block">Prunes DB automatically beyond this limit (max 50K).</span>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800/60 flex justify-end">
              <button type="submit" className="cyber-btn-primary">
                <Save size={16} /> Save Configurations
              </button>
            </div>
          </div>

          {/* Diagnostics checklist */}
          <div className="cyber-panel p-5 space-y-6">
            <h2 className="text-md font-semibold text-white border-b border-slate-800 pb-3 flex items-center gap-1.5">
              <Cpu size={18} className="text-cyber-cyan" /> Engine Diagnostics
            </h2>

            <div className="space-y-4">
              <div className="flex justify-between items-center text-xs py-1.5 px-2 bg-slate-900/40 rounded-lg">
                <span className="text-slate-400 font-medium flex items-center gap-1.5">
                  <Terminal size={14} /> Sniffer Engine
                </span>
                <span className="text-cyber-emerald font-bold">ACTIVE</span>
              </div>

              <div className="flex justify-between items-center text-xs py-1.5 px-2 bg-slate-900/40 rounded-lg">
                <span className="text-slate-400 font-medium flex items-center gap-1.5">
                  <Database size={14} /> SQLite Connector
                </span>
                <span className="text-cyber-emerald font-bold">CONNECTED</span>
              </div>


            </div>
          </div>
        </form>
      )}
    </div>
  );
};
export default Settings;
