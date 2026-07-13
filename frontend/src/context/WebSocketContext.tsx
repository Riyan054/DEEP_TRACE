import React, { createContext, useContext, useEffect, useState, useRef } from 'react';

export interface PacketData {
  id: number;
  timestamp: number;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  size: number;
  ttl: number | null;
  flags: string | null;
  payload_len: number;
  payload: string | null;
  is_anomaly: boolean;
  anomaly_score: number;
  anomaly_reason: string | null;
  severity: 'Safe' | 'Suspicious' | 'Dangerous';
}

export interface ResourceMetrics {
  cpu_usage: number;
  ram_usage: number;
  disk_usage: number;
  uptime: number;
  sniffer_status: 'running' | 'paused' | 'stopped';
  db_status: 'connected' | 'error';
  ml_status: 'trained' | 'untrained' | 'error';
  active_interface: string;
}

export interface LiveStats {
  pps: number;
  kbps: number;
  network_health: number;
  threat_level: number;
  protocols: Record<string, number>;
  severities: { Safe: number; Suspicious: number; Dangerous: number };
  top_sources: Array<{ ip: string; count: number }>;
  top_destinations: Array<{ ip: string; count: number }>;
  alerts: Array<{
    id: number;
    timestamp: number;
    severity: string;
    attack_type: string;
    reason: string;
    src_ip: string;
    dst_ip: string;
  }>;
  total_captured: number;
}

interface WSContextType {
  connected: boolean;
  packets: PacketData[];
  resources: ResourceMetrics;
  stats: LiveStats;
  toasts: Array<{ id: string; title: string; desc: string; type: 'error' | 'warning' | 'info' }>;
  removeToast: (id: string) => void;
  addToast: (title: string, desc: string, type: 'error' | 'warning' | 'info') => void;
  clearPacketCache: () => void;
}

const WebSocketContext = createContext<WSContextType | undefined>(undefined);

const initialResources: ResourceMetrics = {
  cpu_usage: 0.0,
  ram_usage: 0.0,
  disk_usage: 0.0,
  uptime: 0.0,
  sniffer_status: 'stopped',
  db_status: 'connected',
  ml_status: 'untrained',
  active_interface: 'en0'
};

const initialStats: LiveStats = {
  pps: 0.0,
  kbps: 0.0,
  network_health: 100,
  threat_level: 0,
  protocols: {},
  severities: { Safe: 0, Suspicious: 0, Dangerous: 0 },
  top_sources: [],
  top_destinations: [],
  alerts: [],
  total_captured: 0
};

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [connected, setConnected] = useState(false);
  const [packets, setPackets] = useState<PacketData[]>([]);
  const [resources, setResources] = useState<ResourceMetrics>(initialResources);
  const [stats, setStats] = useState<LiveStats>(initialStats);
  const [toasts, setToasts] = useState<Array<{ id: string; title: string; desc: string; type: 'error' | 'warning' | 'info' }>>([]);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  const addToast = (title: string, desc: string, type: 'error' | 'warning' | 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, title, desc, type }]);
    
    // Auto-remove after 4 seconds
    setTimeout(() => {
      removeToast(id);
    }, 4000);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const clearPacketCache = () => {
    setPackets([]);
  };

  const connectWS = () => {
    if (wsRef.current) return;

    // Use standard absolute location mapping
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = import.meta.env.VITE_WS_URL || `${wsProto}//${window.location.hostname}:8000/ws`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        addToast("System Connected", "Real-time websocket feed active.", "info");
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current);
          reconnectTimeoutRef.current = null;
        }
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'dashboard_update') {
            const { packets: newPackets, resources: newResources, stats: newStats } = payload;

            // 1. Process new packets
            if (newPackets && newPackets.length > 0) {
              setPackets((prev) => {
                // Combine and keep max 200 packets for in-memory virtual table rendering
                const merged = [...newPackets, ...prev];
                return merged.slice(0, 300);
              });

              // Check for malicious anomalies to trigger system toast alerts
              newPackets.forEach((pkt: PacketData) => {
                if (pkt.is_anomaly) {
                  const threatStr = pkt.anomaly_reason || "Malicious Traffic";
                  const isDangerous = pkt.severity === 'Dangerous';
                  addToast(
                    isDangerous ? "Critical Security Alert" : "Threat Warning Detected",
                    `${threatStr} flagged from ${pkt.src_ip}:${pkt.src_port || 'N/A'}`,
                    isDangerous ? "error" : "warning"
                  );
                }
              });
            }

            // 2. Set system telemetry stats
            if (newResources) setResources(newResources);
            if (newStats) setStats(newStats);
          }
        } catch (err) {
          console.error("Failed to parse websocket message:", err);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        // Try to reconnect in 3 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWS();
        }, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch (err) {
      console.error("Failed to construct WebSocket connection:", err);
      setConnected(false);
      wsRef.current = null;
      // Try to reconnect in 5 seconds
      reconnectTimeoutRef.current = setTimeout(() => {
        connectWS();
      }, 5000);
    }
  };

  useEffect(() => {
    connectWS();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{
      connected, packets, resources, stats, toasts,
      removeToast, addToast, clearPacketCache
    }}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};
