import React, { useState, useEffect } from "react";
import {
  Clock,
  ShieldAlert,
  ArrowRight,
  User,
  Monitor,
  CheckCircle,
  AlertTriangle,
  Radio,
  Sparkles,
  Layers,
  ChevronDown,
} from "lucide-react";
import { api } from "../services/api";
import { Incident, SeverityLevel } from "../types";
import { NavTab } from "../components/Sidebar";
import { IncidentIndicatorEnrichment } from "../components/IncidentIndicatorEnrichment";

interface InvestigationPageProps {
  initialIncidentId?: string;
  onNavigate: (tab: NavTab, incidentId?: string) => void;
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({
  initialIncidentId,
  onNavigate,
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string>(initialIncidentId || "");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getIncidents().then((res) => {
      const list = res.incidents || [];
      setIncidents(list);
      if (!selectedId && list.length > 0) {
        setSelectedId(list[0].incidentId);
      }
      setLoading(false);
    }).catch(console.error);
  }, []);

  useEffect(() => {
    if (initialIncidentId) {
      setSelectedId(initialIncidentId);
    }
  }, [initialIncidentId]);

  const activeIncident = incidents.find((i) => i.incidentId === selectedId) || incidents[0];

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border border-red-500/40";
      case "High":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/40";
      case "Medium":
        return "bg-amber-500/20 text-amber-300 border border-amber-500/40";
      case "Low":
        return "bg-blue-500/20 text-blue-400 border border-blue-500/40";
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Incident Investigation Timeline
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Chronological multi-stage attack lifecycle reconstruction and artifact provenance.
          </p>
        </div>

        {/* Incident Select Dropdown */}
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs">
          <span className="text-slate-400 font-medium">Select Incident:</span>
          <select
            aria-label="Select incident for timeline investigation"
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono cursor-pointer"
          >
            {incidents.map((inc) => (
              <option key={inc.incidentId} value={inc.incidentId}>
                {inc.incidentId} - {inc.title.slice(0, 42)}... ({inc.severity})
              </option>
            ))}
          </select>
        </div>
      </div>

      {activeIncident ? (
        <div className="space-y-6">
          {/* Active Incident Summary Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-cyan-400 font-bold text-sm">{activeIncident.incidentId}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(activeIncident.severity)}`}>
                    {activeIncident.severity}
                  </span>
                  <span className="text-xs text-slate-400">Status: {activeIncident.status}</span>
                </div>
                <h2 className="text-lg font-bold text-white">{activeIncident.title}</h2>
                <p className="text-xs text-slate-300 max-w-4xl">{activeIncident.description}</p>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Risk Score</div>
                  <div className="font-mono text-2xl font-black text-red-400">{activeIncident.riskScore}/100</div>
                </div>

                <button
                  onClick={() => onNavigate("copilot", activeIncident.incidentId)}
                  className="px-3 py-2 text-xs font-semibold rounded-lg bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/60 flex items-center gap-1.5 transition"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Analyze with Copilot</span>
                </button>
              </div>
            </div>

            {/* Assets and Indicators */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-slate-800 text-xs">
              <div className="space-y-1">
                <span className="text-slate-400 font-medium">Affected Assets & Identities:</span>
                <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                  <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-200 border border-slate-800">
                    User: {activeIncident.affectedUser || "system"}
                  </span>
                  {(activeIncident.affectedAssets || []).map((a, i) => (
                    <span key={i} className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                      {a}
                    </span>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-slate-400 font-medium">Correlated Indicators:</span>
                <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                  {(activeIncident.indicators || []).map((ind, i) => (
                    <span key={i} className="px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-cyan-900/50">
                      {ind}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Real-time Indicator Threat Intelligence Enrichment */}
          <IncidentIndicatorEnrichment
            indicators={activeIncident.indicators || []}
            incidentId={activeIncident.incidentId}
            onNavigateToIncident={(id) => setSelectedId(id)}
            onNavigateToThreatIntel={(search) => onNavigate("threat-intel")}
          />

          {/* Chronological Vertical Timeline */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm space-y-6">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" /> Chronological Intrusion Milestones
            </h3>

            <div className="relative pl-6 space-y-8 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {(activeIncident.timeline || []).map((item, idx) => {
                const nodeColor =
                  item.severity === "Critical"
                    ? "bg-red-500 ring-red-500/20"
                    : item.severity === "High"
                    ? "bg-orange-500 ring-orange-500/20"
                    : item.severity === "Medium"
                    ? "bg-amber-500 ring-amber-500/20"
                    : "bg-blue-500 ring-blue-500/20";

                return (
                  <div key={idx} className="relative group">
                    {/* Node Dot */}
                    <div
                      className={`absolute -left-[27px] top-1.5 w-3 h-3 rounded-full ring-4 ${nodeColor}`}
                    />

                    <div className="bg-slate-950 border border-slate-800/90 rounded-xl p-4 space-y-2 hover:border-slate-700 transition">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="font-mono font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/50">
                            {item.time}
                          </span>
                          <span className="text-slate-400">•</span>
                          <span className="text-slate-300 font-semibold">{item.source}</span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(item.severity)}`}>
                          {item.severity}
                        </span>
                      </div>

                      <p className="text-xs text-slate-200 font-medium">{item.event}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-xs">
          Loading investigation details...
        </div>
      )}
    </div>
  );
};
