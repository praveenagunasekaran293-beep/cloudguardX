import React, { useState, useEffect } from "react";
import {
  Sliders,
  Terminal,
  RotateCcw,
  CheckCircle2,
  Database,
  Server,
  Sparkles,
  ShieldAlert,
  Play,
  Layers,
  Info,
} from "lucide-react";
import { api } from "../services/api";
import { ScenarioItem } from "../types";
import { NavTab } from "../components/Sidebar";

interface SettingsPageProps {
  onNavigate: (tab: NavTab, incidentId?: string) => void;
  onScenarioLoaded?: (name: string) => void;
}

export const SettingsPage: React.FC<SettingsPageProps> = ({ onNavigate, onScenarioLoaded }) => {
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [loadingScenarioId, setLoadingScenarioId] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    api.getScenarios().then((res) => {
      setScenarios(res.scenarios || []);
    }).catch(console.error);
  }, []);

  const handleLaunchScenario = async (scenarioId: string) => {
    setLoadingScenarioId(scenarioId);
    try {
      const res = await api.loadScenario(scenarioId);
      setStatusMsg(`Successfully activated scenario: ${res.scenarioName}. Telemetry and incident records populated.`);
      if (onScenarioLoaded) onScenarioLoaded(res.scenarioName);
      setTimeout(() => setStatusMsg(null), 5000);
      onNavigate("investigation", res.incidentId);
    } catch (err: any) {
      console.error(err);
      setStatusMsg("Failed to activate scenario.");
    } finally {
      setLoadingScenarioId(null);
    }
  };

  const handleResetBaseline = async () => {
    if (confirm("Reset CyberSentinel X SQLite database to baseline synthetic demonstration data?")) {
      setResetting(true);
      try {
        await api.resetBaseline();
        setStatusMsg("Database restored to baseline state.");
        if (onScenarioLoaded) onScenarioLoaded("Baseline");
        setTimeout(() => setStatusMsg(null), 4000);
      } catch (err) {
        console.error(err);
      } finally {
        setResetting(false);
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          Synthetic Demo Scenario Engine & Environment Controls
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Pre-calibrated attack lifecycle simulations for undergraduate cybersecurity portfolio demonstration.
        </p>
      </div>

      {statusMsg && (
        <div className="bg-emerald-950/80 border border-emerald-700/60 text-emerald-300 p-3.5 rounded-xl text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{statusMsg}</span>
        </div>
      )}

      {/* Safety & Defensive Policy Box */}
      <div className="bg-slate-950 border border-cyan-900/50 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-cyan-300">Defensive Portfolio Architecture Notice:</span>
          <p className="text-slate-400 leading-relaxed">
            This platform is strictly designed as a defensive Security Operations Center (SOC) intelligence dashboard. 
            All scenarios populate synthetic telemetry across endpoints, identity providers, and network boundaries without generating live exploit traffic, credential exfiltration, malware payload drops, or external network attacks.
          </p>
        </div>
      </div>

      {/* 6 Scenarios Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" /> Required Capstone Demonstration Scenarios (6)
          </h2>
          <span className="text-xs text-slate-500">Atomic injection into SQLite database</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((scen, idx) => (
            <div
              key={scen.id}
              className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4 hover:border-slate-700 transition flex flex-col justify-between"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-cyan-400 font-bold">Scenario #{idx + 1}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-slate-950 text-slate-300 border border-slate-800">
                    {scen.category}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white leading-snug">{scen.name}</h3>
                <p className="text-xs text-slate-300 leading-relaxed">{scen.description}</p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] text-slate-500">All-in-one telemetry injection</span>
                <button
                  onClick={() => handleLaunchScenario(scen.id)}
                  disabled={loadingScenarioId === scen.id}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 transition shadow-sm"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>{loadingScenarioId === scen.id ? "Injecting..." : "Launch Scenario"}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* System Infrastructure & Reset Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4 text-xs">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Database className="w-4 h-4 text-cyan-400" /> Platform Infrastructure & Storage
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-medium">Local Database Engine:</span>
            <div className="font-mono text-cyan-300 font-bold">SQLite (@libsql/client)</div>
            <div className="text-[11px] text-slate-500">file:cyber_sentinel.db</div>
          </div>

          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-medium">AI Copilot Model:</span>
            <div className="font-mono text-cyan-300 font-bold">gemini-3.8-flash</div>
            <div className="text-[11px] text-slate-500">Server-Side @google/genai SDK</div>
          </div>

          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-1">
            <span className="text-slate-400 block font-medium">Backend Application Server:</span>
            <div className="font-mono text-cyan-300 font-bold">Express + TypeScript (Node.js)</div>
            <div className="text-[11px] text-slate-500">Port 3000 Dev Middleware</div>
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
          <span className="text-slate-400">
            Need to clear all simulated events, active incidents, and response approvals?
          </span>
          <button
            onClick={handleResetBaseline}
            disabled={resetting}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800/60 flex items-center gap-1.5 transition"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${resetting ? "animate-spin" : ""}`} />
            <span>Reset Database to Baseline</span>
          </button>
        </div>
      </div>
    </div>
  );
};
