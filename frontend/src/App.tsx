import React, { useState } from 'react';
import { useWebSocket, WebSocketProvider } from './context/WebSocketContext';
import Dashboard from './pages/Dashboard';
import LiveCapture from './pages/LiveCapture';
import TrafficAnalytics from './pages/TrafficAnalytics';
import ThreatDetection from './pages/ThreatDetection';
import Reports from './pages/Reports';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import About from './pages/About';
import { 
  Activity, ShieldAlert, Heart, HardDrive, Cpu, 
  Terminal, ShieldCheck, Play, Info, AlertTriangle, 
  Grid, Compass, BarChart3, AlertOctagon, 
  Files, Settings as SettingsIcon, HelpCircle, X
} from 'lucide-react';

const AppContent: React.FC = () => {
  const { connected, toasts, removeToast } = useWebSocket();
  const [activePage, setActivePage] = useState<string>('dashboard');

  const renderActivePage = () => {
    switch (activePage) {
      case 'dashboard': return <Dashboard />;
      case 'live_capture': return <LiveCapture />;
      case 'analytics': return <TrafficAnalytics />;
      case 'threat_detection': return <ThreatDetection />;
      case 'reports': return <Reports />;
      case 'logs': return <Logs />;
      case 'settings': return <Settings />;
      case 'about': return <About />;
      default: return <Dashboard />;
    }
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Grid },
    { id: 'live_capture', label: 'Live Capture', icon: Compass },
    { id: 'analytics', label: 'Traffic Analytics', icon: BarChart3 },
    { id: 'threat_detection', label: 'Threat Detection', icon: AlertOctagon },
    { id: 'reports', label: 'Reports', icon: Files },
    { id: 'logs', label: 'Console Logs', icon: Terminal },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
    { id: 'about', label: 'About', icon: HelpCircle },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-cyber-dark text-slate-100 font-sans">
      {/* 1. Left Sidebar Navigation */}
      <aside className="w-64 border-r border-slate-800 bg-slate-950/60 backdrop-blur-cyber flex flex-col justify-between shrink-0 h-full z-20">
        <div>
          {/* Logo Brand */}
          <div className="p-5 border-b border-slate-800/80 flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyber-cyan/10 text-cyber-cyan pulse-border-glow">
              <ShieldCheck size={20} />
            </div>
            <div>
              <span className="font-bold tracking-wider font-outfit text-white text-sm">DEEP TRACE</span>
              <span className="text-[10px] text-slate-500 font-mono block">ENTERPRISE SEC OPS</span>
            </div>
          </div>

          {/* Links list */}
          <nav className="p-4 space-y-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActivePage(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                    isActive 
                      ? 'bg-cyber-cyan text-slate-900 shadow-md shadow-cyber-cyan/15 font-bold scale-[1.02]' 
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/50'
                  }`}
                >
                  <Icon size={16} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer info & Connection Status */}
        <div className="p-4 border-t border-slate-850 bg-slate-950/40">
          <div className="flex items-center justify-between text-[10px] font-semibold tracking-wider font-mono text-slate-500">
            <span>VERSION 1.0.0</span>
            <span className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-cyber-cyan pulse-bullet' : 'bg-cyber-rose'}`} />
          </div>
        </div>
      </aside>

      {/* 2. Main Content Area Panel */}
      <main className="flex-1 overflow-y-auto h-full p-6 relative">
        <div className="max-w-7xl mx-auto pb-12">
          {renderActivePage()}
        </div>

        {/* Floating Toast Notification Containers */}
        <div className="fixed top-4 right-4 z-50 space-y-2.5 w-80">
          {toasts.map((toast) => (
            <div 
              key={toast.id}
              className={`cyber-panel p-3 border-l-4 flex justify-between gap-3 shadow-2xl relative ${
                toast.type === 'error' 
                  ? 'border-cyber-rose bg-rose-950/20' 
                  : toast.type === 'warning' 
                  ? 'border-cyber-amber bg-amber-950/20' 
                  : 'border-cyber-cyan bg-cyan-950/20'
              }`}
            >
              <div className="space-y-0.5">
                <h4 className="text-[11px] font-extrabold text-white tracking-wider uppercase">{toast.title}</h4>
                <p className="text-[10px] text-slate-300 font-medium leading-normal">{toast.desc}</p>
              </div>
              <button 
                onClick={() => removeToast(toast.id)}
                className="text-slate-500 hover:text-slate-300 shrink-0 self-start mt-0.5"
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
};

// Root App wrapper
export const App: React.FC = () => {
  return (
    <React.StrictMode>
      <WebSocketProvider>
        <AppContent />
      </WebSocketProvider>
    </React.StrictMode>
  );
};

export default App;
