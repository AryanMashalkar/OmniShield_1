import { useState, useEffect, useRef } from 'react';
import { ShieldAlert, Activity, ShieldCheck, Server, AlertTriangle, Terminal, Database, Shield, History, GitBranch, Crosshair } from 'lucide-react';
import axios from 'axios';

// API key is read from the Vite environment (frontend/.env ->
// VITE_OMNISHIELD_API_KEY) and MUST match OMNISHIELD_API_KEY on the backend.
// It is no longer hard-coded in source. NOTE: any key shipped to a browser is
// readable in devtools — for production this should be replaced by a real
// user-auth flow (this env var is a dev/demo convenience only).
const API_KEY = import.meta.env.VITE_OMNISHIELD_API_KEY || '';
if (!API_KEY) {
  console.warn(
    'VITE_OMNISHIELD_API_KEY is not set. SOAR isolation calls will be rejected. ' +
    'Create frontend/.env from frontend/.env.example and set it to match the backend.'
  );
}

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
  const [triggerDetector, setTriggerDetector] = useState(null);
  const [triggerMvScore, setTriggerMvScore] = useState(null);
  const [activeTargetIp, setActiveTargetIp] = useState('185.199.108.153'); 
  const [incidents, setIncidents] = useState([]); // RESTORED STATE
  const [campaigns, setCampaigns] = useState([]); // correlated incidents (per-host stories)
  const [detStats, setDetStats] = useState({ labeled: 0, correct: 0 }); // live accuracy (replay ground truth)
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

      // Live self-scoring: in replay mode every frame carries ground truth, so we
      // can show detection accuracy on screen in real time.
      if (typeof log.detection_correct === 'boolean') {
        setDetStats((prev) => ({
          labeled: prev.labeled + 1,
          correct: prev.correct + (log.detection_correct ? 1 : 0),
        }));
      }

      // Escalate to AI attribution ONLY when transitioning from a calm state.
      // Once an alert is pinned (AT_RISK) or contained (NEUTRALIZED) the live
      // stream must never overwrite it — that back-to-back re-triggering was
      // what made the panel flash and disappear. A pinned alert stays until the
      // analyst dismisses it (or isolates), then the next anomaly can escalate.
      const isEscalatable = log.is_anomaly && (log.mv_flag || log.bytes_transferred > 500000);
      if (isEscalatable && systemStatusRef.current === 'SECURE') {
        // Pin synchronously so any packets arriving in the same tick can't
        // double-trigger before React re-renders and updates the ref.
        systemStatusRef.current = 'AT_RISK';
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

  // Poll the correlation engine so the Active Incidents panel updates live.
  useEffect(() => {
    const fetchCampaigns = async () => {
      try {
        const r = await axios.get('http://127.0.0.1:8000/api/campaigns?limit=6');
        setCampaigns(r.data.campaigns || []);
      } catch (e) { /* backend not up yet */ }
    };
    fetchCampaigns();
    const id = setInterval(fetchCampaigns, 3000);
    return () => clearInterval(id);
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
    setTriggerDetector(anomalyLog.detector ?? null);
    setTriggerMvScore(anomalyLog.mv_score ?? null);
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/attribute-attack', {
        anomaly_description: anomalyLog.anomaly_description,
        source_ip: anomalyLog.source_ip,
        anomaly_score: anomalyLog.anomaly_score ?? null,
        // Send raw byte volume so the backend's semantic-translation layer can
        // rule out physically-impossible attributions (0 bytes != exfiltration).
        bytes_transferred: anomalyLog.bytes_transferred ?? null
      });
      setAiAlert(response.data);
    } catch (error) {
      console.error("AI Analysis failed:", error);
    }
    setIsAnalyzing(false);
  };

  // Clear the pinned Threat Intelligence panel and resume live monitoring.
  // This is the ONLY way (besides isolation) that a displayed alert goes away —
  // normal background traffic can never clear it.
  const dismissAlert = () => {
    setAiAlert(null);
    setIsAnalyzing(false);
    setTriggerZScore(null);
    setTriggerDetector(null);
    setTriggerMvScore(null);
    systemStatusRef.current = 'SECURE';
    setSystemStatus('SECURE');
  };

  // RESTORED FUNCTION
  const isolateNetwork = async () => {
    if (isIsolating || systemStatus === 'NEUTRALIZED') return;

    setIsIsolating(true);
    try {
      await axios.post(
        'http://127.0.0.1:8000/api/block-ip',
        // analyst_confirmed=true: clicking this button IS the human-in-the-loop
        // authorisation the backend requires before executing containment.
        { target_ip: activeTargetIp, analyst_confirmed: true },
        { headers: { 'X-API-Key': API_KEY } }
      );

      setSystemStatus('NEUTRALIZED');
      systemStatusRef.current = 'NEUTRALIZED';
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
            {detStats.labeled > 0 && (
              <p className="text-[11px] text-emerald-400 font-semibold">
                Detection accuracy {((detStats.correct / detStats.labeled) * 100).toFixed(1)}% · MTTD &lt;1s
                <span className="text-slate-600"> ({detStats.labeled} labeled)</span>
              </p>
            )}
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
            <span className="ml-auto text-[10px] uppercase tracking-wider text-slate-500 bg-slate-950 border border-slate-800 rounded px-2 py-1">
              Detection: z-score + IsolationForest
            </span>
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
                <div className="flex items-center gap-3">
                  <span className={log.is_anomaly ? 'text-red-400 font-bold' : 'text-slate-500'}>
                    {formatBytes(log.bytes_transferred)}
                  </span>
                  {log.is_anomaly && (
                    <span className="text-xs bg-red-900/50 text-red-300 px-2 py-1 rounded animate-pulse">
                      THREAT · {log.mv_flag ? 'IForest' : 'z-score'}
                    </span>
                  )}
                  {log.ground_truth_label && (
                    <span className={`text-[10px] px-2 py-1 rounded border whitespace-nowrap ${
                      log.ground_truth_label === 'normal'
                        ? 'border-slate-700 text-slate-500'
                        : 'border-amber-800/60 text-amber-400 bg-amber-950/20'
                    }`} title="Ground-truth label from the NSL-KDD benchmark (replay mode)">
                      truth: {log.ground_truth_label}
                      {typeof log.detection_correct === 'boolean' && (
                        <span className={log.detection_correct ? 'text-emerald-400 ml-1 font-bold' : 'text-red-400 ml-1 font-bold'}>
                          {log.detection_correct ? '✓' : '✗'}
                        </span>
                      )}
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
              <button
                onClick={dismissAlert}
                className="mt-2 px-4 py-2 rounded-lg text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700">
                Resume Monitoring
              </button>
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
                  {triggerDetector === 'IsolationForest' ? (
                    <p className="text-slate-500 text-xs mt-1">Flagged by multivariate IsolationForest{typeof triggerMvScore === 'number' ? ` (anomaly score ${triggerMvScore})` : ''} — behavioural profile, not byte volume</p>
                  ) : (typeof triggerZScore === 'number' && triggerZScore > 0 && (
                    <p className="text-slate-500 text-xs mt-1">Flagged by rolling z-score {triggerZScore} (≥3.0 threshold)</p>
                  ))}
                </div>
              </div>

              <div className="flex-1 overflow-y-auto space-y-4 pr-1 custom-scrollbar">
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 shadow-inner">
                  <h4 className="text-slate-500 text-xs uppercase mb-1 font-bold">MITRE ATT&CK Framework</h4>
                  <p className="text-blue-400 font-bold mb-6 text-lg border-b border-slate-800 pb-2">
                    {aiAlert.matched_technique_id} - {aiAlert.technique_name}
                  </p>

                  <h4 className="text-slate-500 text-xs uppercase mb-2 font-bold">AI Recommended Action</h4>
                  <p className="text-slate-300 text-sm leading-relaxed">{aiAlert.recommended_action}</p>
                </div>

                {aiAlert.next_moves && (
                  <div className="bg-slate-950 p-4 rounded-lg border border-amber-900/40 shadow-inner">
                    <div className="flex items-center gap-2 mb-2">
                      <GitBranch className="w-4 h-4 text-amber-400" />
                      <h4 className="text-amber-400/90 text-xs uppercase font-bold tracking-wide">Predicted Attacker Next Moves</h4>
                    </div>
                    {aiAlert.next_moves.terminal ? (
                      <p className="text-amber-400 text-sm leading-relaxed">
                        ⚠ Terminal <span className="font-bold">Impact</span> stage — this is the objective. Isolate now and verify backup / recovery readiness.
                      </p>
                    ) : aiAlert.next_moves.predictions?.length ? (
                      <div className="space-y-3">
                        <p className="text-slate-500 text-[11px] mb-1">
                          Current stage: <span className="text-slate-300 font-semibold uppercase">{aiAlert.next_moves.current_tactic}</span> — kill-chain forecast:
                        </p>
                        {aiAlert.next_moves.predictions.map((p, i) => (
                          <div key={i} className="border-l-2 border-amber-800/50 pl-3">
                            <p className="text-amber-400 text-xs font-bold uppercase">{i + 1}. {p.tactic}</p>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {p.techniques.map((t) => (
                                <span key={t.id} title={t.name}
                                  className="text-[10px] bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-slate-300">
                                  {t.id}
                                </span>
                              ))}
                            </div>
                            <p className="text-slate-500 text-[10px] mt-1">↳ {p.defence}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-slate-500 text-sm">{aiAlert.next_moves.message}</p>
                    )}
                  </div>
                )}
              </div>

              <div className="space-y-2">
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
                <button
                  onClick={dismissAlert}
                  disabled={isIsolating}
                  className="w-full py-2 rounded-lg text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 disabled:opacity-50">
                  Dismiss &amp; resume monitoring
                </button>
              </div>
            </div>
          ) : aiAlert && aiAlert.parse_error ? (
            <div className="flex flex-col items-center justify-center h-full text-yellow-500 space-y-3 text-center px-4">
              <AlertTriangle className="w-12 h-12" />
              <h3 className="text-lg font-bold text-white">AI Classification Failed</h3>
              <p className="text-slate-400 text-sm">{aiAlert.recommended_action || "The model didn't return a valid response. Manual review recommended."}</p>
              <button
                onClick={dismissAlert}
                className="mt-2 px-4 py-2 rounded-lg text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700">
                Dismiss &amp; resume monitoring
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-slate-600">
              <Shield className="w-16 h-16 mb-4 text-slate-800" />
              <p className="text-sm uppercase tracking-widest font-bold">System Secure</p>
            </div>
          )}
        </div>

      </div>

      {/* ACTIVE INCIDENTS — correlated per-host campaigns */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 mb-6">
        <div className="flex items-center gap-2 mb-4 text-slate-400 border-b border-slate-800 pb-2">
          <Crosshair className="w-5 h-5 text-amber-500" />
          <h2 className="font-semibold text-lg">Active Incidents <span className="text-slate-600 text-sm font-normal">· correlated by host</span></h2>
          {campaigns.length > 0 && (
            <span className="ml-auto text-xs bg-amber-950/40 text-amber-400 border border-amber-900/50 rounded-full px-3 py-1">{campaigns.length} active</span>
          )}
        </div>

        {campaigns.length === 0 ? (
          <p className="text-slate-600 italic text-sm">No correlated incidents yet — weak signals are grouped by source host as they arrive.</p>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {campaigns.map((c) => {
              const nm = c.forecast || {};
              const nextTactics = (nm.predictions || []).map((p) => p.tactic);
              return (
                <div key={c.entity} className={`p-3 rounded border bg-slate-950 ${c.stage_span >= 2 ? 'border-amber-900/50' : 'border-slate-800'}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-blue-400 font-bold">{c.entity}</span>
                    <span className="text-[10px] text-slate-500">{c.anomaly_count} anomalies · {c.duration_sec}s</span>
                  </div>

                  {c.stages && c.stages.length > 0 ? (
                    <div className="flex flex-wrap items-center gap-1 mb-2">
                      {c.stages.map((s, i) => (
                        <span key={i} className="flex items-center gap-1">
                          <span className="text-[10px] uppercase bg-red-950/40 text-red-300 border border-red-900/50 rounded px-2 py-0.5">{s}</span>
                          {i < c.stages.length - 1 && <span className="text-slate-600 text-xs">→</span>}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500 text-xs mb-2">Repeated anomalies — no attributed technique yet.{c.categories?.length ? ` (${c.categories.join(', ')})` : ''}</p>
                  )}

                  {nm.terminal ? (
                    <p className="text-amber-400 text-xs"><GitBranch className="w-3 h-3 inline mr-1" />Terminal Impact stage — isolate now.</p>
                  ) : nextTactics.length > 0 ? (
                    <p className="text-amber-400/90 text-xs">
                      <GitBranch className="w-3 h-3 inline mr-1" />Forecast next: <span className="font-semibold">{nextTactics.join(' → ')}</span>
                    </p>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
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