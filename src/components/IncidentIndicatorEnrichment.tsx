import React, { useState, useEffect } from "react";
import {
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
  RefreshCw,
  Search,
  Sparkles,
  Maximize2,
} from "lucide-react";
import { api } from "../services/api";
import { ThreatIndicator, IndicatorType, IndicatorReputation } from "../types";
import { ThreatIntelDetailModal } from "./ThreatIntelDetailModal";

interface IncidentIndicatorEnrichmentProps {
  indicators: string[];
  incidentId: string;
  onNavigateToIncident?: (incidentId: string) => void;
  onNavigateToThreatIntel?: (searchQuery?: string) => void;
}

export const IncidentIndicatorEnrichment: React.FC<IncidentIndicatorEnrichmentProps> = ({
  indicators,
  incidentId,
  onNavigateToIncident,
  onNavigateToThreatIntel,
}) => {
  const [selectedIndicator, setSelectedIndicator] = useState<string>("");
  const [enrichment, setEnrichment] = useState<ThreatIndicator | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showFullModal, setShowFullModal] = useState(false);

  // Set default selection when indicators change
  useEffect(() => {
    if (indicators && indicators.length > 0) {
      if (!indicators.includes(selectedIndicator)) {
        setSelectedIndicator(indicators[0]);
      }
    } else {
      setSelectedIndicator("");
      setEnrichment(null);
    }
  }, [indicators]);

  // Fetch threat intelligence enrichment whenever selectedIndicator changes
  useEffect(() => {
    if (!selectedIndicator) {
      setEnrichment(null);
      setError(null);
      return;
    }

    let isMounted = true;
    const fetchEnrichment = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.lookupThreatIntel(selectedIndicator);
        if (isMounted) {
          if (res.found && res.indicator) {
            setEnrichment(res.indicator);
          } else {
            // Indicator not found in threat database - construct informative clean profile
            setEnrichment({
              id: `NOT-FOUND-${Date.now()}`,
              indicator: selectedIndicator,
              type: detectQuickType(selectedIndicator),
              reputation: "Unknown",
              status: "Uncatalogued Indicator (Synthetic Testbed)",
              confidence: 20,
              firstSeen: new Date().toISOString(),
              lastSeen: new Date().toISOString(),
              source: "Synthetic Dynamic Evaluator",
              relatedIncidents: [incidentId],
              threatGroup: "No Prior Known Attribution",
              tags: ["uncatalogued", "dynamic-query"],
              notes: res.message || "Indicator not currently listed in active synthetic threat intelligence database.",
              isSyntheticDemo: true,
            });
          }
        }
      } catch (err: any) {
        if (isMounted) {
          console.error("Enrichment lookup failed:", err);
          setError(err?.message || "Failed to query threat intelligence provider.");
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchEnrichment();
    return () => {
      isMounted = false;
    };
  }, [selectedIndicator, incidentId]);

  const detectQuickType = (ind: string): IndicatorType => {
    const clean = ind.trim();
    if (/^[a-fA-F0-9]{64}$/.test(clean) || clean.toLowerCase().startsWith("sha256:")) {
      return "SHA-256";
    }
    if (clean.startsWith("http://") || clean.startsWith("https://") || clean.includes("/")) {
      return "URL";
    }
    if (/^(?:\d{1,3}\.){3}\d{1,3}/.test(clean)) {
      return "IP";
    }
    return "Domain";
  };

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getTypeIcon = (type: IndicatorType) => {
    switch (type) {
      case "IP":
        return <Server className="w-3.5 h-3.5 text-blue-400" />;
      case "Domain":
        return <Globe2 className="w-3.5 h-3.5 text-cyan-400" />;
      case "URL":
        return <LinkIcon className="w-3.5 h-3.5 text-amber-400" />;
      case "SHA-256":
        return <Hash className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <Tag className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const getReputationBadge = (rep: IndicatorReputation) => {
    switch (rep) {
      case "Malicious":
        return {
          badge: "bg-red-500/20 text-red-300 border-red-500/40",
          icon: <ShieldAlert className="w-3.5 h-3.5 text-red-400" />,
          label: "Malicious",
        };
      case "Suspicious":
        return {
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />,
          label: "Suspicious",
        };
      case "Benign":
        return {
          badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          icon: <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />,
          label: "Benign",
        };
      default:
        return {
          badge: "bg-slate-800 text-slate-300 border-slate-700",
          icon: <Info className="w-3.5 h-3.5 text-slate-400" />,
          label: "Unknown / Low Risk",
        };
    }
  };

  // 1. Empty State: No indicators on incident
  if (!indicators || indicators.length === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-center space-y-2">
        <div className="w-10 h-10 rounded-full bg-slate-950 border border-slate-800 mx-auto flex items-center justify-center text-slate-500">
          <Database className="w-5 h-5" />
        </div>
        <h4 className="text-xs font-semibold text-slate-300">No Threat Indicators Extracted</h4>
        <p className="text-[11px] text-slate-500 max-w-md mx-auto">
          This incident does not currently have correlated IP addresses, domain names, URLs, or SHA-256 file hashes linked to its investigation timeline.
        </p>
      </div>
    );
  }

  const repBadge = enrichment ? getReputationBadge(enrichment.reputation) : null;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      {/* Header and Indicator Switcher Pills */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              Threat Intelligence Indicator Enrichment
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/50 font-mono">
              Synthetic Demo Intel
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Real-time reputation, confidence scoring, and cross-incident correlation from the modular threat intel provider.
          </p>
        </div>

        {/* Indicator Switcher Chips */}
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-[10px] uppercase font-semibold text-slate-500 mr-1">Select Observable:</span>
          {indicators.map((ind, i) => {
            const isSelected = ind === selectedIndicator;
            const type = detectQuickType(ind);
            return (
              <button
                key={i}
                onClick={() => setSelectedIndicator(ind)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-medium transition cursor-pointer border ${
                  isSelected
                    ? "bg-cyan-950 text-cyan-300 border-cyan-500/60 shadow-xs"
                    : "bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700"
                }`}
              >
                {getTypeIcon(type)}
                <span className="max-w-[130px] truncate" title={ind}>
                  {ind}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* 2. Loading State */}
      {loading && (
        <div className="py-10 flex flex-col items-center justify-center space-y-3">
          <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
          <div className="text-center">
            <div className="text-xs font-semibold text-slate-300">
              Querying Threat Intelligence Provider for:{" "}
              <span className="font-mono text-cyan-400">{selectedIndicator}</span>
            </div>
            <p className="text-[10px] text-slate-500 mt-0.5">
              Evaluating reputation, confidence, source feeds, and cross-incident correlation...
            </p>
          </div>
        </div>
      )}

      {/* 3. Error State */}
      {!loading && error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/30 text-xs space-y-2">
          <div className="flex items-center gap-2 text-red-400 font-semibold">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Enrichment Lookup Failed</span>
          </div>
          <p className="text-slate-300 font-mono text-[11px] bg-black/40 p-2.5 rounded border border-red-900/30">
            {error}
          </p>
          <div className="flex justify-end pt-1">
            <button
              onClick={() => setSelectedIndicator(selectedIndicator)}
              className="px-3 py-1 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-[11px] flex items-center gap-1.5 transition"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Retry Lookup</span>
            </button>
          </div>
        </div>
      )}

      {/* 4. Loaded Enrichment Profile */}
      {!loading && !error && enrichment && (
        <div className="space-y-4">
          {/* Main Indicator Info Strip */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center shrink-0">
                {getTypeIcon(enrichment.type)}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase font-bold text-slate-500">{enrichment.type} Indicator</span>
                  <span className="text-slate-600">•</span>
                  <span className="text-[10px] font-mono text-slate-400">{enrichment.source}</span>
                </div>
                <div className="font-mono text-xs sm:text-sm font-bold text-cyan-300 break-all select-all flex items-center gap-2 mt-0.5">
                  <span>{enrichment.indicator}</span>
                  <button
                    onClick={() => handleCopy(enrichment.indicator)}
                    title="Copy indicator value"
                    className="text-slate-500 hover:text-cyan-300 p-0.5 transition cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowFullModal(true)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 flex items-center gap-1.5 transition cursor-pointer"
              >
                <Maximize2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>View Full Profile</span>
              </button>
              {onNavigateToThreatIntel && (
                <button
                  onClick={() => onNavigateToThreatIntel(enrichment.indicator)}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/60 flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>Search in Feed</span>
                </button>
              )}
            </div>
          </div>

          {/* Core Indicator Parameters Grid (All Required Fields) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            {/* Reputation */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-500 block">Reputation</span>
              {repBadge && (
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border ${repBadge.badge}`}
                >
                  {repBadge.icon}
                  {enrichment.reputation}
                </span>
              )}
            </div>

            {/* Confidence */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <div className="flex justify-between items-center text-[10px] uppercase font-semibold text-slate-500">
                <span>Confidence</span>
                <span className="font-mono font-bold text-cyan-400">{enrichment.confidence}%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden mt-1.5">
                <div
                  className="bg-cyan-400 h-full rounded-full transition-all duration-500"
                  style={{ width: `${enrichment.confidence}%` }}
                />
              </div>
              <span className="text-[9px] text-slate-500 block">Synthetic Reliability</span>
            </div>

            {/* First Seen */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" /> First Seen
              </span>
              <div className="font-mono text-slate-300 text-[11px] pt-0.5">
                {new Date(enrichment.firstSeen).toLocaleDateString()}
              </div>
              <span className="text-[9px] text-slate-500 block">
                {new Date(enrichment.firstSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
              </span>
            </div>

            {/* Last Seen */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" /> Last Seen
              </span>
              <div className="font-mono text-slate-300 text-[11px] pt-0.5">
                {new Date(enrichment.lastSeen).toLocaleDateString()}
              </div>
              <span className="text-[9px] text-slate-500 block">
                {new Date(enrichment.lastSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
              </span>
            </div>
          </div>

          {/* Related Incidents & Attribution Context */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {/* Related Incidents */}
            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  Related Incidents ({enrichment.relatedIncidents?.length || 0})
                </span>
                <span className="text-[10px] text-slate-500">Cross-incident match</span>
              </div>

              {enrichment.relatedIncidents && enrichment.relatedIncidents.length > 0 ? (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {enrichment.relatedIncidents.map((incId) => (
                    <button
                      key={incId}
                      onClick={() => onNavigateToIncident && onNavigateToIncident(incId)}
                      className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold transition cursor-pointer border ${
                        incId === incidentId
                          ? "bg-cyan-950 text-cyan-300 border-cyan-800"
                          : "bg-slate-900 hover:bg-slate-850 text-slate-300 hover:text-white border-slate-800"
                      }`}
                      title={incId === incidentId ? "Current active incident" : "Pivot to incident"}
                    >
                      <span>{incId}</span>
                      {incId === incidentId ? (
                        <span className="text-[9px] text-cyan-400 font-sans">(current)</span>
                      ) : (
                        <ExternalLink className="w-2.5 h-2.5 text-slate-400" />
                      )}
                    </button>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-slate-500 italic">
                  No other active incidents currently share this observable.
                </p>
              )}
            </div>

            {/* Attribution Emulation & Context */}
            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <span className="text-[10px] uppercase font-semibold text-slate-500 block">
                Threat Attribution & Intel Notes
              </span>
              <div className="text-xs font-semibold text-slate-200">
                {enrichment.threatGroup || "Synthetic Telemetry Emulation"}
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-2">
                {enrichment.notes || "Synthetic threat intelligence artifact used for defensive testing."}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Full Detail Modal */}
      {enrichment && (
        <ThreatIntelDetailModal
          indicator={enrichment}
          isOpen={showFullModal}
          onClose={() => setShowFullModal(false)}
          onNavigateToIncident={onNavigateToIncident}
        />
      )}
    </div>
  );
};
