
import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  Terminal,
  RotateCcw,
  Sparkles,
  ChevronDown,
  Server,
  CheckCircle2,
  LogOut,
} from "lucide-react";
import { api } from "../services/api";
import { ScenarioItem } from "../types";

interface HeaderProps {
  onScenarioLoaded?: (scenarioName: string) => void;
  activeIncidentId?: string;
  onLogout?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onScenarioLoaded,
  onLogout,
}) => {
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>("");
  const [loadingScenario, setLoadingScenario] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    api
      .getScenarios()
      .then((res) => {
        setScenarios(res.scenarios || []);
      })
      .catch(console.error);
  }, []);

  const handleSelectScenario = async (id: string) => {
    if (!id) return;

    setSelectedScenario(id);
    setLoadingScenario(true);

    try {
      const res = await api.loadScenario(id);
      setMessage(`Activated Scenario: ${res.scenarioName}`);

      onScenarioLoaded?.(res.scenarioName);

      setTimeout(() => setMessage(null), 4000);
    } catch (err) {
      console.error(err);
      setMessage("Failed to load scenario.");
      setTimeout(() => setMessage(null), 4000);
    } finally {
      setLoadingScenario(false);
    }
  };

  const handleReset = async () => {
    const confirmed = window.confirm(
      "Reset CyberSentinel X database to baseline synthetic SOC state?"
    );

    if (!confirmed) return;

    setResetting(true);

    try {
      await api.resetBaseline();
      setMessage("Baseline synthetic SOC environment restored.");

      onScenarioLoaded?.("Baseline");

      setTimeout(() => setMessage(null), 3000);
    } catch (err) {
      console.error(err);
      setMessage("Failed to reset baseline.");
      setTimeout(() => setMessage(null), 3000);
    } finally {
      setResetting(false);
    }
  };

  const handleLogout = () => {
    const confirmed = window.confirm(
      "Are you sure you want to log out of CyberSentinel X?"
    );

    if (confirmed) {
      onLogout?.();
    }
  };

  return (
    <header className="bg-slate-900 border-b border-slate-800 text-slate-100 sticky top-0 z-30 shadow-md">
      {/* Top Defensive Compliance Banner */}
      <div className="bg-slate-950 border-b border-slate-800/80 px-4 py-1 text-xs flex flex-wrap items-center justify-between gap-2 text-slate-400">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="font-semibold text-slate-300">
            DEFENSIVE SOC MODE:
          </span>
          <span>
            Synthetic Security Telemetry & Safe Defensive Simulations
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">
            Undergraduate Cybersecurity Capstone Portfolio
          </span>
        </div>

        <div className="flex items-center gap-4 text-[11px]">
          <span className="text-cyan-400 flex items-center gap-1">
            <Sparkles className="w-3 h-3" />
            Gemini 3.8 Server Engine
          </span>

          <span className="text-slate-500">|</span>

          <span className="text-slate-400 flex items-center gap-1">
            <Server className="w-3 h-3" />
            SQLite Local Store
          </span>
        </div>
      </div>

      {/* Main Navbar */}
      <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center shadow-lg shadow-cyan-950/50 border border-cyan-400/30">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-black text-xl tracking-tight text-white">
                CyberSentinel <span className="text-cyan-400">X</span>
              </span>

              <span className="px-2 py-0.5 text-[10px] uppercase font-bold tracking-wider rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
                SOC v1.0
              </span>
            </div>

            <p className="text-xs text-slate-400 font-medium">
              Autonomous Cyber Defense, Threat Intelligence & SOC Intelligence
              Platform
            </p>
          </div>
        </div>

        {/* Action Controls & Demo Scenarios */}
        <div className="flex flex-wrap items-center gap-3">
          {message && (
            <div className="text-xs px-3 py-1.5 rounded bg-emerald-950/80 border border-emerald-700/60 text-emerald-300 flex items-center gap-1.5 animate-in fade-in">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {message}
            </div>
          )}

          {/* Scenario Engine Selector */}
          <div className="flex items-center gap-2 bg-slate-950/80 border border-slate-750 rounded-lg px-2.5 py-1.5">
            <Terminal className="w-4 h-4 text-cyan-400" />

            <span className="text-xs text-slate-400 font-medium whitespace-nowrap">
              Demo Scenario:
            </span>

            <div className="relative">
              <select
                aria-label="Select Demo Scenario"
                value={selectedScenario}
                disabled={loadingScenario}
                onChange={(e) => handleSelectScenario(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-xs rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer pr-7 appearance-none"
              >
                <option value="">-- Load Scenario Engine --</option>

                {scenarios.map((scen) => (
                  <option key={scen.id} value={scen.id}>
                    {scen.name}
                  </option>
                ))}
              </select>

              <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2 top-2 pointer-events-none" />
            </div>
          </div>

          {/* Reset Baseline */}
          <button
            type="button"
            onClick={handleReset}
            disabled={resetting}
            title="Reset to baseline simulated SOC data"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition disabled:opacity-50"
          >
            <RotateCcw
              className={`w-3.5 h-3.5 ${
                resetting ? "animate-spin" : ""
              }`}
            />
            <span>{resetting ? "Resetting..." : "Reset Baseline"}</span>
          </button>

          {/* Logout */}
          <button
            type="button"
            onClick={handleLogout}
            disabled={!onLogout}
            title="Log out of CyberSentinel X"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-800/70 transition focus:outline-none focus:ring-2 focus:ring-red-500/50 disabled:opacity-50"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
};
