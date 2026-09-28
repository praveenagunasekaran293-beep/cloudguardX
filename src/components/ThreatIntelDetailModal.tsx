import React, { useState } from "react";
import {
  X,
  Globe2,
  Server,
  Link as LinkIcon,
  Hash,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Database,
  Tag,
  Copy,
  Check,
  ExternalLink,
  Layers,
  Info,
  Calendar,
  Sparkles,
} from "lucide-react";
import { ThreatIndicator, IndicatorType, IndicatorReputation } from "../types";

interface ThreatIntelDetailModalProps {
  indicator: ThreatIndicator | null;
  isOpen: boolean;
  onClose: () => void;
  onNavigateToIncident?: (incidentId: string) => void;
}

export const ThreatIntelDetailModal: React.FC<ThreatIntelDetailModalProps> = ({
  indicator,
  isOpen,
  onClose,
  onNavigateToIncident,
}) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !indicator) return null;

  const handleCopy = () => {
    navigator.clipboard?.writeText(indicator.indicator);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getTypeIcon = (type: IndicatorType) => {
    switch (type) {
      case "IP":
        return <Server className="w-4 h-4 text-blue-400" />;
      case "Domain":
        return <Globe2 className="w-4 h-4 text-cyan-400" />;
      case "URL":
        return <LinkIcon className="w-4 h-4 text-amber-400" />;
      case "SHA-256":
        return <Hash className="w-4 h-4 text-purple-400" />;
      default:
        return <Tag className="w-4 h-4 text-slate-400" />;
    }
  };

  const getReputationBadge = (rep: IndicatorReputation) => {
    switch (rep) {
      case "Malicious":
        return {
          badge: "bg-red-500/20 text-red-300 border-red-500/40",
          icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
          label: "Malicious",
        };
      case "Suspicious":
        return {
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
          label: "Suspicious",
        };
      case "Benign":
        return {
          badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
          label: "Benign",
        };
      default:
        return {
          badge: "bg-slate-700 text-slate-300 border-slate-600",
          icon: <Info className="w-4 h-4 text-slate-400" />,
          label: "Unknown / Unrated",
        };
    }
  };

  const repBadge = getReputationBadge(indicator.reputation);

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-750 rounded-2xl max-w-2xl w-full my-auto shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center">
              {getTypeIcon(indicator.type)}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                  {indicator.type}
                </span>
                <span className="text-slate-500">•</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/50 uppercase font-mono">
                  Synthetic Demo Intel
                </span>
              </div>
              <h2 className="text-base font-bold text-white mt-0.5">
                Threat Intelligence Context Profile
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs max-h-[80vh]">
          {/* Synthetic Demo Disclaimer Banner */}
          <div className="bg-slate-950 border border-cyan-900/60 rounded-xl p-3.5 flex items-start gap-2.5 text-slate-300">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold text-cyan-300">Synthetic Defense Simulation Telemetry</span>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                This indicator profile is generated strictly from the CyberSentinel X synthetic threat intelligence engine (RFC 5737 testbed / demo models). It is not real-world compromised infrastructure.
              </p>
            </div>
          </div>

          {/* Indicator Value Card with Copy */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-slate-400">
              <span className="font-semibold uppercase tracking-wider text-[10px]">Observable Indicator Value</span>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? "Copied!" : "Copy"}</span>
              </button>
            </div>
            <div className="font-mono text-sm text-cyan-300 font-bold break-all selection:bg-cyan-500/30">
              {indicator.indicator}
            </div>
          </div>

          {/* 4-Panel Core Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Reputation */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-400 block">Reputation</span>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border ${repBadge.badge}`}
              >
                {repBadge.icon}
                {indicator.reputation}
              </span>
            </div>

            {/* Confidence */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <div className="flex justify-between items-center text-[10px] uppercase font-semibold text-slate-400">
                <span>Confidence</span>
                <span className="font-mono font-bold text-cyan-400">{indicator.confidence}%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden mt-2">
                <div
                  className="bg-cyan-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${indicator.confidence}%` }}
                />
              </div>
              <span className="text-[9px] text-slate-500 block">Feed Reliability Index</span>
            </div>

            {/* Type */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-400 block">Indicator Type</span>
              <div className="flex items-center gap-1.5 pt-0.5">
                {getTypeIcon(indicator.type)}
                <span className="font-bold text-slate-200">{indicator.type}</span>
              </div>
            </div>

            {/* Threat Group */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-400 block">Adversary Emulation</span>
              <div className="text-xs font-semibold text-slate-200 line-clamp-1 pt-0.5" title={indicator.threatGroup}>
                {indicator.threatGroup || "Unattributed"}
              </div>
            </div>
          </div>

          {/* Source Feed & Observation Timestamps */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1">
              <span className="text-slate-400 font-medium flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-cyan-400" /> Source Threat Feed:
              </span>
              <div className="font-semibold text-slate-200 pl-5">{indicator.source}</div>
              <span className="text-[10px] text-slate-500 pl-5 block">
                Integrated via modular SyntheticDemoThreatIntelProvider
              </span>
            </div>

            <div className="space-y-1">
              <span className="text-slate-400 font-medium flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" /> Observation Timeline:
              </span>
              <div className="font-mono text-slate-300 pl-5 space-y-0.5">
                <div>
                  <span className="text-slate-500">First Seen: </span>
                  {new Date(indicator.firstSeen).toLocaleDateString()}{" "}
                  {new Date(indicator.firstSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </div>
                <div>
                  <span className="text-slate-500">Last Seen: </span>
                  {new Date(indicator.lastSeen).toLocaleDateString()}{" "}
                  {new Date(indicator.lastSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </div>
              </div>
            </div>
          </div>

          {/* Related Incidents */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Correlated SOC Incidents ({indicator.relatedIncidents?.length || 0})
              </span>
              <span className="text-[10px] text-slate-500">Cross-incident telemetry match</span>
            </div>

            {indicator.relatedIncidents && indicator.relatedIncidents.length > 0 ? (
              <div className="flex flex-wrap gap-2 pt-1">
                {indicator.relatedIncidents.map((incId) => (
                  <button
                    key={incId}
                    onClick={() => {
                      if (onNavigateToIncident) {
                        onClose();
                        onNavigateToIncident(incId);
                      }
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-cyan-950 text-cyan-300 hover:text-cyan-200 border border-slate-800 hover:border-cyan-700/60 font-mono font-bold transition cursor-pointer"
                  >
                    <span>{incId}</span>
                    <ExternalLink className="w-3 h-3 text-cyan-400" />
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-slate-500 italic py-1">
                No active SOC incidents currently reference this indicator in their correlated telemetry.
              </p>
            )}
          </div>

          {/* Tags & Context Notes */}
          {(indicator.tags?.length > 0 || indicator.notes) && (
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
              {indicator.tags && indicator.tags.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Threat Taxonomy Tags</span>
                  <div className="flex flex-wrap gap-1.5">
                    {indicator.tags.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-mono text-[10px]"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {indicator.notes && (
                <div className="space-y-1 pt-1 border-t border-slate-900">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Analyst Intelligence Notes</span>
                  <p className="text-slate-300 leading-relaxed bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80">
                    {indicator.notes}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Provider: SyntheticDemoThreatIntelProvider</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition"
          >
            Close Profile
          </button>
        </div>
      </div>
    </div>
  );
};
