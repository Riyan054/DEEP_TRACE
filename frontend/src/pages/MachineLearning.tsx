import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useWebSocket } from '../context/WebSocketContext';
import { 
  Brain, CheckCircle2, AlertTriangle, RefreshCw, 
  TrendingUp, Activity, Cpu, Layers, HelpCircle
} from 'lucide-react';

interface ModelMetrics {
  model_name: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  training_time: number;
  trained_at: number;
  samples_count: number;
}

export const MachineLearning: React.FC = () => {
  const { addToast } = useWebSocket();
  const [activeModel, setActiveModel] = useState('Isolation Forest');
  const [modelsList, setModelsList] = useState<ModelMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [training, setTraining] = useState(false);

  const fetchMLInfo = async () => {
    setLoading(true);
    try {
      const data = await api.getMLMetrics();
      setModelsList(data.models || []);
      setActiveModel(data.active_model || 'Isolation Forest');
    } catch(e) {
      addToast("Failed to Fetch", "Could not obtain ML model telemetry.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMLInfo();
  }, []);

  const handleSelectModel = async (name: string) => {
    try {
      await api.selectModel(name);
      setActiveModel(name);
      addToast("Model Activated", `Active classification engine swapped to: ${name}`, "info");
    } catch(err: any) {
      addToast("Activation Failed", err.response?.data?.detail || "Could not set active model.", "error");
    }
  };

  const handleRetrain = async () => {
    setTraining(true);
    addToast("Model Retraining Initiated", "Rebuilding vectors from packet logs. Please hold...", "info");
    try {
      const data = await api.trainModels();
      setModelsList(data.metrics.models || []);
      setActiveModel(data.metrics.active_model || activeModel);
      addToast("Retraining Successful", "All ML model classifiers rebuilt and optimized.", "info");
    } catch (e: any) {
      addToast("Retraining Failed", e.response?.data?.detail || "Could not complete ML pipeline training.", "error");
    } finally {
      setTraining(false);
    }
  };

  const formatPercent = (val: number) => {
    return `${(val * 100).toFixed(1)}%`;
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight font-outfit text-white">Machine Learning Telemetry</h1>
          <p className="text-slate-400 text-sm">Review classifier accuracy, switch prediction models, or trigger retraining cycles.</p>
        </div>
        <button 
          onClick={handleRetrain}
          disabled={training}
          className="cyber-btn-primary"
        >
          <RefreshCw size={16} className={training ? 'animate-spin' : ''} />
          {training ? 'RETRAINING...' : 'RETRAIN ALL MODELS'}
        </button>
      </div>

      {/* Model Information */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* active status */}
        <div className="cyber-panel p-5 flex items-start gap-4">
          <div className="p-3 bg-cyber-indigo/10 text-cyber-indigo rounded-xl shrink-0">
            <Brain size={32} className="pulse-border-glow rounded-full" />
          </div>
          <div className="space-y-1.5">
            <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Active Classification Engine</h3>
            <div className="text-xl font-bold text-white font-outfit">{activeModel}</div>
            <p className="text-xs text-slate-500">
              This engine processes live packet feature vectors dynamically to predict security severity labels.
            </p>
          </div>
        </div>

        {/* pipeline status */}
        <div className="cyber-panel p-5 flex items-start gap-4">
          <div className="p-3 bg-cyber-cyan/10 text-cyber-cyan rounded-xl shrink-0">
            <Activity size={32} />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">ML Pipeline Statistics</h3>
            <div className="grid grid-cols-2 gap-2 text-xs pt-1 font-mono">
              <div><span className="text-slate-500">Feature Count:</span> <span className="text-white">8 Vectors</span></div>
              <div><span className="text-slate-500">Contamination:</span> <span className="text-white">10.0%</span></div>
              <div><span className="text-slate-500">Saved Models:</span> <span className="text-white">3 Engines</span></div>
              <div><span className="text-slate-500">Status:</span> <span className="text-cyber-emerald">Normal</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Models Comparative Grid */}
      <div>
        <h2 className="text-md font-semibold text-white mb-4">Model Performance Comparisons</h2>
        {loading && modelsList.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">Querying model weights data...</div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {modelsList.map(model => {
              const isActive = model.model_name === activeModel;
              return (
                <div 
                  key={model.model_name}
                  className={`cyber-panel p-5 space-y-4 flex flex-col justify-between ${
                    isActive ? 'pulse-border-glow bg-cyan-950/5' : ''
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex justify-between items-start">
                      <h3 className="text-md font-bold text-white font-outfit">{model.model_name}</h3>
                      {isActive && (
                        <span className="flex items-center gap-1 text-[9px] font-bold bg-cyber-cyan/20 border border-cyber-cyan/35 text-cyber-cyan px-2 py-0.5 rounded-full uppercase">
                          <CheckCircle2 size={10} /> Active
                        </span>
                      )}
                    </div>
                    
                    <p className="text-xs text-slate-400">
                      {model.model_name === 'Isolation Forest' && 'Unsupervised isolation anomaly trees.'}
                      {model.model_name === 'Random Forest' && 'Supervised ensemble forest decision classifier.'}
                      {model.model_name === 'One-Class SVM' && 'Support vector model modeling boundary space.'}
                    </p>
                  </div>

                  {/* Metrics meters */}
                  <div className="space-y-2.5 pt-2 border-t border-slate-800/60 font-mono text-xs">
                    {/* Accuracy */}
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500 text-[11px]">Accuracy:</span>
                      <span className="text-white font-bold">{formatPercent(model.accuracy)}</span>
                    </div>
                    {/* Precision */}
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500 text-[11px]">Precision:</span>
                      <span className="text-white font-bold">{formatPercent(model.precision)}</span>
                    </div>
                    {/* Recall */}
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500 text-[11px]">Recall:</span>
                      <span className="text-white font-bold">{formatPercent(model.recall)}</span>
                    </div>
                    {/* F1 */}
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500 text-[11px]">F1-Score:</span>
                      <span className="text-cyber-cyan font-bold">{formatPercent(model.f1_score)}</span>
                    </div>
                  </div>

                  {/* Telemetry info */}
                  <div className="pt-3 border-t border-slate-800/60 flex justify-between items-center text-[10px] text-slate-500 font-mono">
                    <div>
                      <div>Samples: <span className="text-slate-300">{model.samples_count}</span></div>
                      <div>Fit Time: <span className="text-slate-300">{model.training_time.toFixed(3)}s</span></div>
                    </div>
                    {!isActive && (
                      <button 
                        onClick={() => handleSelectModel(model.model_name)}
                        className="cyber-btn-secondary py-1.5 px-3 text-[10px]"
                      >
                        Activate
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Feature explanation info */}
      <div className="cyber-panel p-5 space-y-3">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
          <Layers size={14} className="text-cyber-cyan" /> Feature Vectors Breakdown
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          The models process the network flow metadata in real-time. The feature extractor converts packets into an 8-dimensional space containing:
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono bg-slate-900/30 p-4 rounded-xl border border-white/5">
          <div><b className="text-cyber-cyan">01.</b> Protocol Category</div>
          <div><b className="text-cyber-cyan">02.</b> Origin Port</div>
          <div><b className="text-cyber-cyan">03.</b> Target Port</div>
          <div><b className="text-cyber-cyan">04.</b> Packet Size</div>
          <div><b className="text-cyber-cyan">05.</b> Header TTL</div>
          <div><b className="text-cyber-cyan">06.</b> TCP Flag Bits</div>
          <div><b className="text-cyber-cyan">07.</b> Payload Bytes</div>
          <div><b className="text-cyber-cyan">08.</b> Flow Rate</div>
        </div>
      </div>
    </div>
  );
};
export default MachineLearning;
