import { useState, useEffect, useRef } from 'react';
import { ShieldAlert, Activity, ShieldCheck, Server, AlertTriangle, Terminal, Database, Shield, History } from 'lucide-react';
import axios from 'axios';

// Demo-only shared secret — MUST match OMNISHIELD_API_KEY on the backend.
// For anything beyond a hackathon demo, this belongs in a proper auth flow,
// not a frontend constant (anyone can read this in devtools).
const API_KEY = 'omnishield-dev-key-2026';

// Helper function to format raw bytes into KB, MB, GB
const formatBytes = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export default function App() {
  const [logs, setLogs] = useState([]);
  const [aiAlert, setAiAlert] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [eventsScanned, setEventsScanned] = useState(0);
  const [systemStatus, setSystemStatus] = useState('SECURE'); // SECURE, AT_RISK, NEUTRALIZED
  const [isIsolating, setIsIsolating] = useState(false); // guards against duplicate/concurrent block-ip calls
  const [triggerZScore, setTriggerZScore] = useState(null);
  const [activeTargetIp, setActiveTargetIp] = useState('185.199.108.153'); 
  const [incidents, setIncidents] = useState([]); // RESTORED STATE
  const logsEndRef = useRef(null);

  // Keep a ref mirror of systemStatus so the WebSocket's onmessage handler
  // (created once, on mount) can always read the LATEST status without
  // needing systemStatus in the effect's dependency array.
  const systemStatusRef = useRef(systemStatus);
  useEffect(() => {
    systemStatusRef.current = systemStatus;
  }, [systemStatus]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Connect to the WebSocket exactly once. Do NOT put systemStatus (or any
  // frequently-changing state) in this dependency array — doing so tears
  // down and reopens the socket every time that state changes.
  useEffect(() => {
    const ws = new WebSocket('ws://127.0.0.1:8000/ws/network-stream');

    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => setIsConnected(false);

    ws.onmessage = (event) => {
      const log = JSON.parse(event.data);
      setLogs((prev) => [...prev.slice(-49), log]);
      setEventsScanned((prev) => prev + 1);

      // Flag stream anomalies z >= 3.0, but only escalate to AI if payload exceeds 500 KB
      if (log.is_anomaly && log.bytes_transferred > 500000 && systemStatusRef.current !== 'NEUTRALIZED') {
        setSystemStatus('AT_RISK');
        setActiveTargetIp(log.destination_ip || log.source_ip);
        triggerAiAnalysis(log);
      }
    };

    return () => ws.close();
  }, []); // <-- empty array: connect once, stay connected

  // Load the incident log once on mount so history persists across refreshes.
  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/incidents?limit=10');
      setIncidents(response.data.incidents);
    } catch (error) {
      console.error("Failed to fetch incident log:", error);
    }
  };

  const triggerAiAnalysis = async (anomalyLog) => {
    setIsAnalyzing(true);
    setTriggerZScore(anomalyLog.anomaly_score ?? null);
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/attribute-attack', {
        anomaly_description: anomalyLog.anomaly_description,
        source_ip: anomalyLog.source_ip,
        anomaly_score: anomalyLog.anomaly_score ?? null
      });
      setAiAlert(response.data);
    } catch (error) {
      console.error("AI Analysis failed:", error);
    }
    setIsAnalyzing(false);
  };

  // RESTORED FUNCTION
  const isolateNetwork = async () => {
    if (isIsolating || systemStatus === 'NEUTRALIZED') return;

    setIsIsolating(true);
    try {
      await axios.post(
        'http://127.0.0.1:8000/api/block-ip',
        { target_ip: activeTargetIp },
        { headers: { 'X-API-Key': API_KEY } }
      );

      setSystemStatus('NEUTRALIZED');
      setAiAlert(null);
      alert(`Windows Defender Firewall Rule Injected: Target IP ${activeTargetIp} Blocked.`);
      fetchIncidents();
    } catch (error) {
      console.error("Failed to execute SOAR playbook:", error);
      if (error.response?.status === 401) {
        alert("Error: API key rejected. Check that OMNISHIELD_API_KEY matches on frontend and backend.");
      } else {
        alert("Error: Backend must be running as Administrator to modify firewall rules.");
      }
    } finally {
      setIsIsolating(false);
    }
  };

  const statusBadgeClasses = (status) => {
    if (status === 'success') return 'bg-emerald-950/50 text-emerald-400 border-emerald-900/50';
    if (status === 'partial_failure') return 'bg-yellow-950/50 text-yellow-400 border-yellow-900/50';
    return 'bg-red-950/50 text-red-400 border-red-900/50';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 p-6 font-mono selection:bg-blue-900">

      {/* HEADER */}
      <header className="flex justify-between items-center mb-6 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <Shield className="text-blue-500 w-8 h-8" />
          <h1 className="text-2xl font-bold text-white tracking-wider">OmniShield <span className="text-slate-500">SOC</span></h1>
        </div>
        <div className="flex items-center gap-2 text-sm bg-slate-900 px-4 py-2 rounded-full border border-slate-800">
          <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`}></div>
          <span className="font-semibold">{isConnected ? 'LIVE TELEMETRY ACTIVE' : 'CONNECTION LOST'}</span>
        </div>
      </header>

      {/* KPI METRICS ROW */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex items-center gap-4">
          <div className="p-3 bg-blue-950/50 rounded-lg text-blue-500"><Activity /></div>
          <div>
            <p className="text-slate-500 text-xs uppercase font-bold">Events Scanned</p>
            <p className="text-2xl font-bold text-white">{eventsScanned.toLocaleString()}</p>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex items-center gap-4">
          <div className="p-3 bg-purple-950/50 rounded-lg text-purple-500"><Server /></div>
          <div>
            <p className="text-slate-500 text-xs uppercase font-bold">AI Engine (Local)</p>
            <p className="text-lg font-bold text-white">Llama 3.1 (8B) + RAG</p>
          </div>
        </div>
        <div className={`border rounded-lg p-4 flex items-center gap-4 transition-colors ${
          systemStatus === 'SECURE' ? 'bg-slate-900 border-slate-800' :
          systemStatus === 'AT_RISK' ? 'bg-red-950/30 border-red-900/50' :
          'bg-emerald-950/30 border-emerald-900/50'
        }`}>
          <div className={`p-3 rounded-lg ${
            systemStatus === 'SECURE' ? 'bg-emerald-950/50 text-emerald-500' :
            systemStatus === 'AT_RISK' ? 'bg-red-950/50 text-red-500 animate-pulse' :
            'bg-emerald-950/50 text-emerald-500'
          }`}>
            {systemStatus === 'AT_RISK' ? <ShieldAlert /> : <ShieldCheck />}
          </div>
          <div>
            <p className="text-slate-500 text-xs uppercase font-bold">Network Status</p>
            <p className={`text-xl font-bold ${
              systemStatus === 'SECURE' ? 'text-emerald-500' :
              systemStatus === 'AT_RISK' ? 'text-red-500' :
              'text-emerald-500'
            }`}>{systemStatus}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">

        {/* LEFT COLUMN: LIVE LOGS */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col h-[60vh]">
          <div className="flex items-center gap-2 mb-4 text-slate-400 border-b border-slate-800 pb-2">
            <Database className="w-5 h-5 text-blue-500" />
            <h2 className="font-semibold text-lg">Packet Inspection Stream</h2>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 pr-2 text-sm custom-scrollbar">
            {logs.length === 0 && <p className="text-slate-600 italic">Awaiting network handshake...</p>}

            {logs.map((log, index) => (
              <div key={index} className={`p-2 rounded border flex items-center justify-between ${
                log.is_anomaly ? 'bg-red-950/30 border-red-900/50 text-red-400' : 'bg-slate-950 border-slate-800 hover:bg-slate-900'
              }`}>
                <div className="flex items-center gap-4">
                  <span className="text-slate-500">[{log.timestamp}]</span>
                  <span>
                    <span className="text-blue-400">{log.source_ip}</span>
                    <span className="text-slate-600 mx-2">→</span>
                    <span className="text-emerald-400">{log.destination_ip}</span>
                  </span>
                </div>
                <div className="flex items-center gap-4">
                  <span className={log.is_anomaly ? 'text-red-400 font-bold' : 'text-slate-500'}>
                    {formatBytes(log.bytes_transferred)}
                  </span>
                  {log.is_anomaly && (
                    <span className="text-xs bg-red-900/50 text-red-300 px-2 py-1 rounded animate-pulse">
                      THREAT DETECTED{typeof log.anomaly_score === 'number' && log.anomaly_score > 0 ? ` · z=${log.anomaly_score}` : ''}
                    </span>
                  )}
                </div>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* RIGHT COLUMN: AI ATTRIBUTION */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col h-[60vh]">
          <div className="flex items-center gap-2 mb-4 text-slate-400 border-b border-slate-800 pb-2">
            <Terminal className="w-5 h-5 text-purple-500" />
            <h2 className="font-semibold text-lg">AI Threat Intelligence</h2>
          </div>

          {systemStatus === 'NEUTRALIZED' ? (
            <div className="flex flex-col items-center justify-center h-full text-emerald-500 space-y-4">
              <div className="p-4 bg-emerald-950/50 rounded-full">
                <ShieldCheck className="w-16 h-16" />
              </div>
              <h3 className="text-xl font-bold text-white">Threat Neutralized</h3>
              <p className="text-slate-400 text-center text-sm">Container isolated successfully via SOAR playbook. Network integrity restored.</p>
            </div>
          ) : isAnalyzing ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-4">
              <Server className="w-12 h-12 animate-pulse text-purple-500" />
              <p className="animate-pulse text-sm uppercase tracking-wider font-bold">Querying Vector Database...</p>
            </div>
          ) : aiAlert && !aiAlert.parse_error ? (
            <div className="flex flex-col h-full space-y-4 animate-in fade-in zoom-in duration-300">
              <div className="bg-gradient-to-r from-red-950/80 to-transparent border-l-4 border-red-500 p-4 rounded flex items-start gap-3">
                <AlertTriangle className="text-red-500 w-6 h-6 flex-shrink-0" />
                <div>
                  <h3 className="text-red-400 font-bold text-lg leading-none mb-1">CRITICAL THREAT</h3>
                  <p className="text-slate-300 text-sm">AI Confidence: <span className="font-bold text-white">{aiAlert.confidence_score}%</span></p>
                  {typeof triggerZScore === 'number' && triggerZScore > 0 && (
                    <p className="text-slate-500 text-xs mt-1">Flagged by rolling detector: z-score {triggerZScore} (≥3.0 threshold)</p>
                  )}
                </div>
              </div>

              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex-1 shadow-inner">
                <h4 className="text-slate-500 text-xs uppercase mb-1 font-bold">MITRE ATT&CK Framework</h4>
                <p className="text-blue-400 font-bold mb-6 text-lg border-b border-slate-800 pb-2">
                  {aiAlert.matched_technique_id} - {aiAlert.technique_name}
                </p>

                <h4 className="text-slate-500 text-xs uppercase mb-2 font-bold">AI Recommended Action</h4>
                <p className="text-slate-300 text-sm leading-relaxed">{aiAlert.recommended_action}</p>
              </div>

              <button
                onClick={isolateNetwork}
                disabled={isIsolating}
                className={`w-full font-bold py-4 rounded-lg transition-all flex items-center justify-center gap-2 ${
                  isIsolating
                    ? 'bg-red-900/50 text-red-300 cursor-not-allowed'
                    : 'bg-red-600 hover:bg-red-500 active:bg-red-700 text-white shadow-[0_0_20px_rgba(220,38,38,0.4)] hover:shadow-[0_0_30px_rgba(220,38,38,0.6)]'
                }`}>
                <ShieldAlert className="w-5 h-5" />
                {isIsolating ? 'ISOLATING...' : 'EXECUTE SOAR ISOLATION'}
              </button>
            </div>
          ) : aiAlert && aiAlert.parse_error ? (
            <div className="flex flex-col items-center justify-center h-full text-yellow-500 space-y-3 text-center px-4">
              <AlertTriangle className="w-12 h-12" />
              <h3 className="text-lg font-bold text-white">AI Classification Failed</h3>
              <p className="text-slate-400 text-sm">{aiAlert.recommended_action || "The model didn't return a valid response. Manual review recommended."}</p>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-slate-600">
              <Shield className="w-16 h-16 mb-4 text-slate-800" />
              <p className="text-sm uppercase tracking-widest font-bold">System Secure</p>
            </div>
          )}
        </div>

      </div>

      {/* INCIDENT LOG (full width) */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-4 text-slate-400 border-b border-slate-800 pb-2">
          <History className="w-5 h-5 text-blue-500" />
          <h2 className="font-semibold text-lg">Incident Log</h2>
        </div>

        {incidents.length === 0 ? (
          <p className="text-slate-600 italic text-sm">No SOAR actions recorded yet.</p>
        ) : (
          <div className="space-y-2 text-sm">
            {incidents.map((incident) => (
              <div key={incident.id} className="flex items-center justify-between p-2 rounded border border-slate-800 bg-slate-950">
                <div className="flex items-center gap-4">
                  <span className="text-slate-500">{incident.timestamp}</span>
                  <span className="text-blue-400">{incident.target_ip}</span>
                  <span className="text-slate-400">{incident.action}</span>
                </div>
                <span className={`text-xs px-2 py-1 rounded border ${statusBadgeClasses(incident.status)}`}>
                  {incident.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}