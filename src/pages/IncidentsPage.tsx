import React, { useState, useEffect } from "react";
import {
  AlertTriangle,
  ShieldCheck,
  CheckCircle,
  Clock,
  ArrowRight,
  User,
  Layers,
  Sparkles,
  Scale,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import { api } from "../services/api";
import { Incident, IncidentStatus, SeverityLevel } from "../types";
import { NavTab } from "../components/Sidebar";

interface IncidentsPageProps {
  onNavigate: (tab: NavTab, incidentId?: string) => void;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({ onNavigate }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("all");
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const loadIncidents = async () => {
    try {
      const data = await api.getIncidents();
      setIncidents(data.incidents || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  const handleStatusChange = async (incidentId: string, newStatus: IncidentStatus) => {
    setUpdatingId(incidentId);
    try {
      await api.updateIncidentStatus(incidentId, newStatus);
      setIncidents((prev) =>
        prev.map((inc) => (inc.incidentId === incidentId ? { ...inc, status: newStatus } : inc))
      );
    } catch (err) {
      console.error(err);
    } finally {
      setUpdatingId(null);
    }
  };

  const filtered = incidents.filter((inc) => {
    if (statusFilter === "all") return true;
    return inc.status === statusFilter;
  });

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
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Incident Management & Triage
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Prioritized defensive SOC incident tracking across multi-stage cyber attack kill chains.
          </p>
        </div>

        {/* Status filter tabs */}
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs">
          {["all", "Open", "Investigating", "Resolved", "Closed"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1.5 rounded-md font-medium capitalize transition ${
                statusFilter === s
                  ? "bg-cyan-600 text-white shadow-xs"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20 text-slate-400 gap-2">
          <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
          Loading incidents queue...
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
          No incidents found under status "{statusFilter}".
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filtered.map((inc) => (
            <div
              key={inc.incidentId}
              className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm hover:border-slate-700 transition space-y-4"
            >
              {/* Top row */}
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-cyan-400 font-bold text-sm">{inc.incidentId}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                    <span className="text-xs text-slate-400 flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      Created {new Date(inc.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white">{inc.title}</h3>
                  <p className="text-xs text-slate-300 max-w-4xl">{inc.description}</p>
                </div>

                {/* Score & Lifecycle Action */}
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-[10px] uppercase font-semibold text-slate-400">Risk Index</div>
                    <div className="flex items-center gap-1 justify-end font-mono">
                      <span className={`text-xl font-black ${inc.riskScore >= 80 ? "text-red-400" : inc.riskScore >= 60 ? "text-amber-400" : "text-emerald-400"}`}>
                        {inc.riskScore}
                      </span>
                      <span className="text-xs text-slate-500">/100</span>
                    </div>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-1.5 flex items-center gap-1.5">
                    <span className="text-[11px] text-slate-400 px-1 font-medium">Status:</span>
                    <select
                      aria-label={`Update status for ${inc.incidentId}`}
                      value={inc.status}
                      disabled={updatingId === inc.incidentId}
                      onChange={(e) => handleStatusChange(inc.incidentId, e.target.value as IncidentStatus)}
                      className="bg-slate-900 border border-slate-700 text-xs rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
                    >
                      <option value="Open">Open</option>
                      <option value="Investigating">Investigating</option>
                      <option value="Resolved">Resolved</option>
                      <option value="Closed">Closed</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Context badges */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-slate-800/80 text-xs">
                <div>
                  <span className="text-slate-400 block mb-1 font-medium">Affected User Identity:</span>
                  <div className="font-mono text-slate-200 flex items-center gap-1">
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    {inc.affectedUser || "system / unassigned"}
                  </div>
                </div>

                <div>
                  <span className="text-slate-400 block mb-1 font-medium">Affected Infrastructure Assets:</span>
                  <div className="flex flex-wrap gap-1">
                    {(inc.affectedAssets || []).map((asset, i) => (
                      <span key={i} className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                        {asset}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-slate-400 block mb-1 font-medium">Mapped MITRE Techniques:</span>
                  <div className="flex flex-wrap gap-1">
                    {(inc.mitreTechniques || []).slice(0, 3).map((m, i) => (
                      <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/70 text-cyan-300 border border-cyan-800/50">
                        {m.id} ({m.tactic})
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/60">
                <div className="text-[11px] text-slate-400">
                  <span>{inc.timeline?.length || 0} Chronological timeline milestones</span>
                  <span className="mx-2">•</span>
                  <span>{inc.recommendations?.length || 0} Action recommendations</span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onNavigate("risk-scoring", inc.incidentId)}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1 transition"
                  >
                    <Scale className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Risk Factors</span>
                  </button>

                  <button
                    onClick={() => onNavigate("copilot", inc.incidentId)}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/60 flex items-center gap-1 transition"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Ask Copilot</span>
                  </button>

                  <button
                    onClick={() => onNavigate("investigation", inc.incidentId)}
                    className="px-3 py-1 text-xs font-semibold rounded bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1 transition shadow-xs"
                  >
                    <span>Full Timeline Investigation</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
