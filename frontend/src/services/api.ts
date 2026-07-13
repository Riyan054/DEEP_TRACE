import axios from 'axios';

const API_BASE_URL = `http://${window.location.hostname}:8000/api`;

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  // Interfaces
  getInterfaces: async (): Promise<string[]> => {
    const res = await apiClient.get('/interfaces');
    return res.data;
  },

  // Sniffer Control
  controlSniffer: async (action: 'start' | 'stop' | 'pause' | 'resume', interfaceName?: string): Promise<any> => {
    const res = await apiClient.post('/sniffer/control', {
      action,
      interface: interfaceName,
    });
    return res.data;
  },

  getSnifferStatus: async (): Promise<any> => {
    const res = await apiClient.get('/sniffer/status');
    return res.data;
  },

  // Packets Search/Filters
  getPackets: async (params: {
    page: number;
    limit: number;
    src_ip?: string;
    dst_ip?: string;
    port?: number;
    protocol?: string;
    severity?: string;
    is_anomaly?: boolean;
  }): Promise<{ total: number; page: number; limit: number; packets: any[] }> => {
    const res = await apiClient.get('/packets', { params });
    return res.data;
  },

  // Alerts
  getAlerts: async (params?: {
    severity?: string;
    attack_type?: string;
    resolved?: boolean;
  }): Promise<any[]> => {
    const res = await apiClient.get('/alerts', { params });
    return res.data;
  },

  resolveAlert: async (alertId: number): Promise<any> => {
    const res = await apiClient.post(`/alerts/${alertId}/resolve`);
    return res.data;
  },

  // ML Models
  getMLMetrics: async (): Promise<any> => {
    const res = await apiClient.get('/ml/metrics');
    return res.data;
  },

  selectModel: async (modelName: string): Promise<any> => {
    const res = await apiClient.post('/ml/select', { model_name: modelName });
    return res.data;
  },

  trainModels: async (): Promise<any> => {
    const res = await apiClient.post('/ml/train');
    return res.data;
  },

  // Settings
  getSettings: async (): Promise<any> => {
    const res = await apiClient.get('/settings');
    return res.data;
  },

  updateSettings: async (settings: {
    mock_mode: boolean;
    refresh_rate: number;
    packet_limit: number;
    active_model: string;
    interface: string;
    notification_toggle: boolean;
  }): Promise<any> => {
    const res = await apiClient.post('/settings/update', settings);
    return res.data;
  },

  // Reset Dashboard data
  resetDashboard: async (): Promise<any> => {
    const res = await apiClient.post('/dashboard/reset');
    return res.data;
  },

  // PCAP Import
  uploadPCAP: async (file: File): Promise<any> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post('/pcap/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return res.data;
  },

  // PCAP Replay
  replayPCAP: async (filename: string, speed: number = 1.0): Promise<any> => {
    const res = await apiClient.post('/pcap/replay', { filename, speed });
    return res.data;
  },

  // System Resource Telemetry
  getSystemMetrics: async (): Promise<any> => {
    const res = await apiClient.get('/system/metrics');
    return res.data;
  },

  // Reports download utility URL
  getReportDownloadUrl: (type: 'pdf' | 'csv' | 'json'): string => {
    return `${API_BASE_URL}/reports/generate?type=${type}`;
  },

  // Log retrieval
  getSystemLogs: async (limit: number = 50): Promise<any[]> => {
    const res = await apiClient.get('/logs/system', { params: { limit } });
    return res.data;
  },

  getAuditLogs: async (limit: number = 50): Promise<any[]> => {
    const res = await apiClient.get('/logs/audit', { params: { limit } });
    return res.data;
  },
};
export default api;
