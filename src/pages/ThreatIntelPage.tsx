import React, { useState, useEffect } from "react";
import {
  Globe2,
  Search,
  ShieldAlert,
  ShieldCheck,
  Hash,
  Link as LinkIcon,
  Server,
  Filter,
  Info,
  CheckCircle,
  AlertCircle,
  AlertTriangle,
  Tag,
  RefreshCw,
  Copy,
  Check,
  ExternalLink,
  Layers,
  Clock,
  Database,
  Cpu,
  Maximize2,
} from "lucide-react";
import { api } from "../services/api";
import { ThreatIndicator, IndicatorType, IndicatorReputation } from "../types";
import { ThreatIntelDetailModal } from "../components/ThreatIntelDetailModal";

interface ThreatIntelPageProps {
  onNavigate?: (tab: any, incidentId?: string) => void;
}

export const ThreatIntelPage: React.FC<ThreatIntelPageProps> = ({ onNavigate }) => {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState("all");
  const [reputationFilter, setReputationFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeProviderName, setActiveProviderName] = useState("Synthetic Demo Intelligence Engine");
  
  // Interactive Lookup State
  const [lookupQuery, setLookupQuery] = useState("");
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [lookingUp, setLookingUp] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Inspector modal state
  const [inspectIndicator, setInspectIndicator] = useState<ThreatIndicator | null>(null);

  const loadIndicators = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getThreatIntel({
        type: typeFilter,
        reputation: reputationFilter,
        search: searchQuery,
      });
      setIndicators(res.indicators || []);
      if (res.activeProvider) {
        setActiveProviderName(res.activeProvider);
      }
    } catch (err: any) {
      console.error(err);
      setError(err?.message || "Failed to load threat intelligence feed.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIndicators();
  }, [typeFilter, reputationFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadIndicators();
  };

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;
    setLookingUp(true);
    setLookupError(null);
    try {
      const res = await api.lookupThreatIntel(lookupQuery.trim());
      setLookupResult(res);
    } catch (err: any) {
      console.error(err);
      setLookupError(err?.message || "Failed to complete threat intelligence query.");
    } finally {
      setLookingUp(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "IP":
        return <Server className="w-3.5 h-3.5 text-blue-400" />;
      case "Domain":
        return <Globe2 className="w-3.5 h-3.5 text-cyan-400" />;
      case "URL":
        return <LinkIcon className="w-3.5 h-3.5 text-amber-400" />;
      case "SHA-256":
      case "File Hash (SHA256)":
        return <Hash className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <Tag className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const getReputationBadge = (reputation?: string) => {
    switch (reputation) {
      case "Malicious":
        return {
          badge: "bg-red-500/20 text-red-300 border-red-500/40",
          icon: <ShieldAlert className="w-3 h-3 text-red-400" />,
          label: "Malicious",
        };
      case "Suspicious":
        return {
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          icon: <AlertTriangle className="w-3 h-3 text-amber-400" />,
          label: "Suspicious",
        };
      case "Benign":
        return {
          badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          icon: <ShieldCheck className="w-3 h-3 text-emerald-400" />,
          label: "Benign",
        };
      default:
        return {
          badge: "bg-slate-800 text-slate-300 border-slate-700",
          icon: <Info className="w-3 h-3 text-slate-400" />,
          label: "Unknown / Low Risk",
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Provider Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Threat Intelligence & IOC Correlation Feed
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Modular threat intelligence service abstraction managing IP, Domain, URL, and SHA-256 observables with cross-incident correlation.
          </p>
        </div>

        {/* Active Provider Tag */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-slate-400">Provider Abstraction:</span>
          <span className="font-mono text-cyan-300 font-semibold">{activeProviderName}</span>
        </div>
      </div>

      {/* Synthetic Disclaimer Banner */}
      <div className="bg-slate-950 border border-cyan-900/60 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-cyan-300">Synthetic Threat Data Clarification & Disclaimers</span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/60 font-mono">
              RFC 5737 / Synthetic Sandbox
            </span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            All IP addresses (using IETF RFC 5737 TEST-NET-1: 192.0.2.0/24, TEST-NET-2: 198.51.100.0/24, TEST-NET-3: 203.0.113.0/24), domain names, URLs, and file hashes in this intelligence feed are purely synthetic models generated strictly for defensive SOC education, research, and portfolio demonstration. They do not represent real-world compromised infrastructure.
          </p>
        </div>
      </div>

      {/* Interactive Search & Live Indicator Lookup Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-cyan-400" />
            Interactive Threat Intelligence Lookup
          </h3>
          <span className="text-[10px] text-slate-500 font-mono">
            Supports: IP, Domain, URL, SHA-256
          </span>
        </div>

        <form onSubmit={handleLookup} className="flex flex-wrap items-center gap-3">
          <div className="flex-1 min-w-[280px] relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Query any IP (e.g. 198.51.100.44), Domain (payroll-update-secure.top), URL, or SHA-256 hash..."
              className="w-full bg-slate-950 border border-slate-750 text-xs rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={lookingUp || !lookupQuery.trim()}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
          >
            {lookingUp ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>Lookup Indicator</span>
          </button>
        </form>

        {/* Lookup Loading State */}
        {lookingUp && (
          <div className="py-6 flex items-center justify-center gap-2 text-xs text-slate-400 bg-slate-950 rounded-lg border border-slate-800">
            <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>Querying active threat intelligence provider abstraction...</span>
          </div>
        )}

        {/* Lookup Error State */}
        {!lookingUp && lookupError && (
          <div className="p-3.5 bg-red-950/40 border border-red-500/30 rounded-lg text-xs text-red-300 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{lookupError}</span>
            </div>
            <button
              onClick={() => setLookupError(null)}
              className="text-[11px] text-red-400 hover:text-red-200 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Lookup Result Box */}
        {!lookingUp && lookupResult && (
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="font-semibold text-slate-300 flex items-center gap-2">
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                Live Indicator Correlation Response:
              </span>
              <button
                onClick={() => setLookupResult(null)}
                className="text-[11px] text-slate-500 hover:text-slate-300 cursor-pointer"
              >
                Clear
              </button>
            </div>

            {lookupResult.found && lookupResult.indicator ? (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-red-400 font-bold flex items-center gap-1.5">
                      <AlertCircle className="w-4 h-4" />
                      MATCH CONFIRMED: Synthetic Threat Intelligence Profile
                    </span>
                    <span className="text-slate-500">•</span>
                    <span className="font-mono text-cyan-300">{lookupResult.indicator.indicator}</span>
                  </div>

                  <button
                    onClick={() => setInspectIndicator(lookupResult.indicator)}
                    className="px-2.5 py-1 text-xs font-semibold rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/60 flex items-center gap-1 transition cursor-pointer"
                  >
                    <Maximize2 className="w-3 h-3" />
                    <span>Open Full Profile</span>
                  </button>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-slate-300 pt-1">
                  <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] uppercase font-semibold text-slate-500 block">Reputation</span>
                    <div className="pt-0.5">
                      <span className="text-red-400 font-bold">{lookupResult.indicator.reputation}</span>
                    </div>
                  </div>

                  <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] uppercase font-semibold text-slate-500 block">Confidence</span>
                    <div className="pt-0.5">
                      <span className="font-mono text-cyan-400 font-bold">{lookupResult.indicator.confidence}%</span>
                    </div>
                  </div>

                  <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] uppercase font-semibold text-slate-500 block">Indicator Type</span>
                    <div className="pt-0.5 font-bold text-slate-200">{lookupResult.indicator.type}</div>
                  </div>

                  <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] uppercase font-semibold text-slate-500 block">Related Incidents</span>
                    <div className="pt-0.5 font-mono text-cyan-300">
                      {lookupResult.indicator.relatedIncidents?.length > 0
                        ? lookupResult.indicator.relatedIncidents.join(", ")
                        : "None recorded"}
                    </div>
                  </div>
                </div>

                <p className="text-[11px] text-slate-400 bg-slate-900/40 p-2.5 rounded border border-slate-850">
                  <span className="font-semibold text-slate-300">Analyst Notes: </span>
                  {lookupResult.indicator.notes || "Synthetic testbed indicator profile."}
                </p>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-slate-400 py-1">
                <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                <div>
                  <span className="font-semibold text-slate-300">
                    {lookupResult.message || "Indicator not listed in synthetic threat database."}
                  </span>
                  <span className="text-[11px] text-slate-500 block">
                    No active synthetic adversary associations found for "{lookupResult.query}".
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Main Table Filter & Search Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[260px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search indicator, threat group, tags, or feed..."
            className="w-full bg-slate-950 border border-slate-750 text-xs rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          {/* Indicator Type Filter */}
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Type:</span>
            <select
              aria-label="Filter by indicator type"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="all">All Indicator Types</option>
              <option value="IP">IP Addresses</option>
              <option value="Domain">Domains</option>
              <option value="URL">URLs</option>
              <option value="SHA-256">SHA-256 Hashes</option>
            </select>
          </div>

          {/* Reputation Filter */}
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Reputation:</span>
            <select
              aria-label="Filter by reputation"
              value={reputationFilter}
              onChange={(e) => setReputationFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="all">All Reputations</option>
              <option value="Malicious">Malicious</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Benign">Benign</option>
              <option value="Unknown">Unknown</option>
            </select>
          </div>

          <button
            onClick={loadIndicators}
            disabled={loading}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition cursor-pointer"
            title="Refresh threat intelligence feed"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Main Indicators Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-3">Indicator Observable</th>
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3">Reputation</th>
                <th className="py-3 px-3">Confidence</th>
                <th className="py-3 px-3">Source Feed</th>
                <th className="py-3 px-3">First Seen / Last Seen</th>
                <th className="py-3 px-3">Related Incidents</th>
                <th className="py-3 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">
              {/* Loading State */}
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 inline mr-2" />
                    Loading modular threat intelligence database...
                  </td>
                </tr>
              ) : error ? (
                /* Error State */
                <tr>
                  <td colSpan={8} className="py-8 text-center text-red-400">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      <span>{error}</span>
                      <button
                        onClick={loadIndicators}
                        className="px-3 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-white"
                      >
                        Retry
                      </button>
                    </div>
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                /* Empty State */
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <Database className="w-6 h-6 text-slate-600 mx-auto mb-2" />
                    No threat indicators match the selected type, reputation, or search query.
                  </td>
                </tr>
              ) : (
                /* Indicator Rows */
                indicators.map((ind) => {
                  const rep = getReputationBadge(ind.reputation);
                  return (
                    <tr
                      key={ind.id}
                      onClick={() => setInspectIndicator(ind)}
                      className="hover:bg-slate-800/40 cursor-pointer transition"
                    >
                      {/* Indicator */}
                      <td className="py-3 px-3 font-mono font-bold text-slate-100 max-w-xs truncate">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(ind.indicator);
                            }}
                            title="Copy indicator"
                            className="text-slate-500 hover:text-cyan-400 transition"
                          >
                            {copiedText === ind.indicator ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                          <span className="truncate" title={ind.indicator}>
                            {ind.indicator}
                          </span>
                        </div>
                      </td>

                      {/* Type */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 font-mono text-[10px]">
                          {getTypeIcon(ind.type)}
                          <span>{ind.type}</span>
                        </span>
                      </td>

                      {/* Reputation */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${rep.badge}`}
                        >
                          {rep.icon}
                          {ind.reputation}
                        </span>
                      </td>

                      {/* Confidence */}
                      <td className="py-3 px-3 font-mono whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <div className="w-12 bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                            <div
                              className="bg-cyan-500 h-full rounded-full"
                              style={{ width: `${ind.confidence}%` }}
                            />
                          </div>
                          <span className="font-bold text-cyan-400">{ind.confidence}%</span>
                        </div>
                      </td>

                      {/* Source */}
                      <td className="py-3 px-3 text-slate-400 text-[11px] max-w-[180px] truncate" title={ind.source}>
                        {ind.source}
                      </td>

                      {/* First Seen / Last Seen */}
                      <td className="py-3 px-3 text-slate-400 whitespace-nowrap font-mono text-[10px]">
                        <div>Last: {new Date(ind.lastSeen).toLocaleDateString()}</div>
                        <div className="text-slate-500">First: {new Date(ind.firstSeen).toLocaleDateString()}</div>
                      </td>

                      {/* Related Incidents */}
                      <td className="py-3 px-3">
                        <div className="flex flex-wrap gap-1 max-w-[160px]">
                          {ind.relatedIncidents && ind.relatedIncidents.length > 0 ? (
                            ind.relatedIncidents.map((incId) => (
                              <button
                                key={incId}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (onNavigate) {
                                    onNavigate("investigation", incId);
                                  }
                                }}
                                className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-950 hover:bg-cyan-950 text-cyan-300 border border-slate-800 hover:border-cyan-800 transition cursor-pointer"
                                title={`Pivot to ${incId}`}
                              >
                                {incId}
                              </button>
                            ))
                          ) : (
                            <span className="text-[10px] text-slate-500 italic">None</span>
                          )}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setInspectIndicator(ind);
                          }}
                          className="px-2.5 py-1 text-[11px] font-semibold rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition cursor-pointer"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Inspection Modal */}
      {inspectIndicator && (
        <ThreatIntelDetailModal
          indicator={inspectIndicator}
          isOpen={!!inspectIndicator}
          onClose={() => setInspectIndicator(null)}
          onNavigateToIncident={(id) => {
            if (onNavigate) {
              onNavigate("investigation", id);
            }
          }}
        />
      )}
    </div>
  );
};
