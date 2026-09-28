import React, { useState } from "react";
import {
  Link2,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  Server,
  Code,
  Send,
  Sparkles,
  ExternalLink,
  PlusCircle,
  Copy,
  Check,
  RotateCcw,
  Layers,
  Database,
  ArrowRight,
  Globe2,
  Hash,
  Clock,
  Terminal,
  FileSearch,
} from "lucide-react";
import { api } from "../services/api";
import { UrlAnalysisResult, ExtractedUrlIndicator } from "../types";
import { NavTab } from "../components/Sidebar";

const SAMPLE_URLS = [
  {
    name: "IP-Based Phishing Host",
    category: "IP Evasion",
    url: "http://198.51.100.44/auth/login?redirect=portal",
  },
  {
    name: "High-Abuse TLD & Credential Path",
    category: "TLD / Auth Path",
    url: "https://payroll-update-secure.top/auth/verify?session=99281a",
  },
  {
    name: "Subdomain Nesting & Length Obfuscation",
    category: "Subdomain / Length",
    url: "https://corporate-sso-gateway.service-update-token.xyz/login/verify/oauth2/authorize?client_id=corporate_auth_token_99812481029481204810284019284019284091824091824091824",
  },
  {
    name: "Userinfo Destination Spoofing (@)",
    category: "Host Spoofing",
    url: "https://google.com@malicious-login-harvest.cc/webscr",
  },
  {
    name: "Double Percent-Encoding & Traversal",
    category: "Encoding / Evasion",
    url: "https://portal.bank-security.online/download/invoice.pdf.exe?redirect=https://evil.top&payload=%252e%252e%252fadmin",
  },
  {
    name: "Clean Standard Corporate Portal",
    category: "Benign Baseline",
    url: "https://intranet.enterprise-corp.com/security/guidelines",
  },
];

interface UrlAnalyzerPageProps {
  onNavigate?: (tab: NavTab, incidentId?: string) => void;
}

export const UrlAnalyzerPage: React.FC<UrlAnalyzerPageProps> = ({ onNavigate }) => {
  const [inputUrl, setInputUrl] = useState(SAMPLE_URLS[0].url);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  // Incident creation state
  const [showIncidentModal, setShowIncidentModal] = useState(false);
  const [creatingIncident, setCreatingIncident] = useState(false);
  const [customTitle, setCustomTitle] = useState("");
  const [affectedUser, setAffectedUser] = useState("perimeter-gateway@enterprise-corp.internal");
  const [analystNotes, setAnalystNotes] = useState("");
  const [createdIncidentResult, setCreatedIncidentResult] = useState<{
    incidentId: string;
    title: string;
    severity: string;
    riskScore: number;
    indicatorsCount: number;
    timelineMilestonesCount: number;
  } | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;
    setLoading(true);
    setError(null);
    setCreatedIncidentResult(null);
    try {
      const data = await api.analyzeUrl(inputUrl);
      setResult(data);
      const host = data.structuralDetails?.hostname || "Unknown Host";
      setCustomTitle(`Suspicious URL Detected: ${host}`);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || "Failed to execute defensive URL analysis.");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSample = (sample: typeof SAMPLE_URLS[0]) => {
    setInputUrl(sample.url);
    setResult(null);
    setError(null);
    setCreatedIncidentResult(null);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndicator(text);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!result) return;
    setCreatingIncident(true);
    try {
      const resp = await api.createIncidentFromUrl(result, {
        customTitle: customTitle.trim() || undefined,
        affectedUser: affectedUser.trim() || undefined,
        analystNotes: analystNotes.trim() || undefined,
      });

      setCreatedIncidentResult(resp);
      setShowIncidentModal(false);
    } catch (err: any) {
      console.error(err);
      alert(err?.message || "Failed to create incident from URL analysis.");
    } finally {
      setCreatingIncident(false);
    }
  };

  const checks = result?.checks || [];
  const filteredChecks = categoryFilter === "all"
    ? checks
    : checks.filter((c) => c.category === categoryFilter);

  const dangerCount = checks.filter((c) => c.status === "danger").length;
  const warningCount = checks.filter((c) => c.status === "warning").length;
  const safeCount = checks.filter((c) => c.status === "safe").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
              <Link2 className="w-6 h-6 text-cyan-400" />
              Defensive URL Structural Analysis Module
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
              Zero Outbound Probes
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Strictly passive lexical and syntactic analysis: decomposes URL length, protocol transport, IP-based host evasions,
            subdomain nesting & Shannon entropy, suspicious characters, encoding patterns, path structures, and query parameters.
            Cross-referenced with CyberSentinel X Threat Intelligence and active incident databases.
          </p>
        </div>

        {result && (
          <button
            type="button"
            onClick={() => setShowIncidentModal(true)}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white flex items-center gap-2 shadow-sm transition shrink-0"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Create Incident from URL</span>
          </button>
        )}
      </div>

      {/* Safety Notice */}
      <div className="bg-slate-950 border border-cyan-900/50 rounded-xl p-3.5 flex items-start gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="font-semibold text-cyan-300">Defensive Passive Safety Guarantee: </span>
          <span className="text-slate-400">
            This module evaluates only the supplied URL string and available application data. No HTTP requests, TCP handshakes,
            DNS probes, or active web scans are dispatched to the target host. Safe for air-gapped SOC environments and active threat triage.
          </span>
        </div>
      </div>

      {/* Created Incident Success Banner */}
      {createdIncidentResult && (
        <div className="bg-emerald-950/40 border border-emerald-500/50 rounded-xl p-4 animate-in fade-in space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              <div>
                <h4 className="text-sm font-bold text-emerald-200">
                  Incident {createdIncidentResult.incidentId} Created Successfully
                </h4>
                <p className="text-xs text-emerald-300/80">
                  {createdIncidentResult.title} • Severity: {createdIncidentResult.severity} • Risk Score: {createdIncidentResult.riskScore}/100
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {onNavigate && (
                <>
                  <button
                    onClick={() => onNavigate("investigation", createdIncidentResult.incidentId)}
                    className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 shadow transition"
                  >
                    <span>Pivot to Investigation Console</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => onNavigate("incidents")}
                    className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                  >
                    View in Incidents List
                  </button>
                  <button
                    onClick={() => onNavigate("dashboard")}
                    className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                  >
                    View Updated Dashboard
                  </button>
                </>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-emerald-900/50 text-[11px] text-emerald-300/90 font-mono">
            <div>
              <span className="text-slate-400">Indicators Stored: </span>
              <span className="font-bold text-white">{createdIncidentResult.indicatorsCount}</span>
            </div>
            <div>
              <span className="text-slate-400">Timeline Milestones: </span>
              <span className="font-bold text-white">{createdIncidentResult.timelineMilestonesCount}</span>
            </div>
            <div>
              <span className="text-slate-400">Threat Intel Table: </span>
              <span className="font-bold text-white">Updated & Synced</span>
            </div>
            <div>
              <span className="text-slate-400">Audit Log: </span>
              <span className="font-bold text-white">Logged & Verified</span>
            </div>
          </div>
        </div>
      )}

      {/* Preset Test URLs */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-slate-300 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            Preset Test Scenarios (Demonstrating Each Structural Check):
          </span>
          <span className="text-[11px] text-slate-500">Click to populate input</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {SAMPLE_URLS.map((s, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleLoadSample(s)}
              className={`p-2.5 rounded-lg border text-left transition flex flex-col justify-between ${
                inputUrl === s.url
                  ? "bg-cyan-950/40 border-cyan-600 text-cyan-200"
                  : "bg-slate-950 hover:bg-slate-800/80 border-slate-800 text-slate-300"
              }`}
            >
              <div className="flex items-center justify-between gap-1 mb-1">
                <span className="font-semibold text-xs text-white truncate">{s.name}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                  {s.category}
                </span>
              </div>
              <div className="font-mono text-[11px] text-slate-400 truncate w-full">
                {s.url}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Analyzer Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <form onSubmit={handleAnalyze} className="space-y-3">
          <label className="text-xs font-semibold text-slate-300 block flex items-center justify-between">
            <span>Target URL String for Defensive Passive Examination:</span>
            <span className="text-[11px] text-slate-400 font-normal">
              Accepts full URLs or raw host strings
            </span>
          </label>
          <div className="flex flex-wrap gap-2">
            <div className="relative flex-1 min-w-[300px]">
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                placeholder="e.g. https://payroll-update-secure.top/auth/verify?session=99281a"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
              {inputUrl && (
                <button
                  type="button"
                  onClick={() => setInputUrl("")}
                  className="absolute right-2.5 top-2.5 text-slate-500 hover:text-slate-300 text-xs"
                >
                  Clear
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-2 shadow-sm transition disabled:opacity-50"
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Evaluating Structure...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Execute Passive Analysis</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="p-3 bg-red-950/40 border border-red-800 rounded-lg text-xs text-red-300 flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Output Section */}
      {result && (
        <div className="space-y-6 animate-in fade-in">
          {/* Classification & Score Header Banner */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-wrap items-center justify-between gap-6">
            <div className="space-y-1.5 max-w-2xl">
              <div className="flex items-center gap-2.5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Structural Threat Classification
                </span>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                    result.classification === "Malicious" || result.riskScore >= 70
                      ? "bg-red-500/10 text-red-400 border-red-500/30"
                      : result.classification === "Suspicious" || result.riskScore >= 40
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                      : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                  }`}
                >
                  {result.classification}
                </span>
                {result.engine && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                    Engine: {result.engine}
                  </span>
                )}
              </div>

              <div className="font-mono text-sm text-slate-200 break-all bg-slate-950/60 p-2 rounded-lg border border-slate-800/80 flex items-center justify-between gap-2">
                <span>{result.url}</span>
                <button
                  type="button"
                  onClick={() => handleCopy(result.url || "")}
                  className="text-slate-400 hover:text-slate-200 shrink-0"
                  title="Copy URL"
                >
                  {copiedIndicator === result.url ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>

              <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 pt-1">
                <span>Rule Findings:</span>
                <span className="text-red-400 font-bold">{dangerCount} Danger</span>
                <span className="text-amber-400 font-bold">{warningCount} Warning</span>
                <span className="text-emerald-400 font-bold">{safeCount} Safe</span>
              </div>
            </div>

            {/* Score Dial & Action */}
            <div className="flex items-center gap-5">
              <div className="text-right">
                <div className="text-[10px] uppercase font-bold text-slate-400">Calculated Structural Risk</div>
                <div className="font-mono text-4xl font-black">
                  <span
                    className={
                      result.riskScore >= 70
                        ? "text-red-400"
                        : result.riskScore >= 40
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }
                  >
                    {result.riskScore}
                  </span>
                  <span className="text-xs text-slate-500 font-normal">/100</span>
                </div>
                <span className="text-[11px] text-slate-400">
                  {result.riskScore >= 70 ? "Elevated Threat" : result.riskScore >= 40 ? "Suspicious Vectors" : "Clean Baseline"}
                </span>
              </div>

              <button
                type="button"
                onClick={() => setShowIncidentModal(true)}
                className="px-4 py-2.5 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white flex items-center gap-2 shadow-sm transition"
              >
                <PlusCircle className="w-4 h-4" />
                <span>Create Incident</span>
              </button>
            </div>
          </div>

          {/* Explanation & AI Assessment Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Explanation & Gemini Assessment (2 Cols) */}
            <div className="lg:col-span-2 space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-cyan-400" />
                    Transparent Explanation & Adversary Vector Assessment
                  </h3>
                  <span className="text-[10px] font-mono text-cyan-400">
                    {result.engine === "gemini" ? "Gemini 3.8 Flash Grounded" : "Deterministic Heuristic Engine"}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-300 leading-relaxed space-y-2">
                  <div className="font-semibold text-slate-200">Executive Summary:</div>
                  <p className="text-slate-300">{result.explanation?.summary}</p>
                </div>

                {result.explanation?.geminiAssessment && (
                  <div className="p-4 bg-slate-950/80 rounded-lg border border-slate-800/80 text-xs text-slate-300 leading-relaxed space-y-2">
                    <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                      Detailed Vector Analysis & TTP Correlation:
                    </div>
                    <div className="whitespace-pre-line text-slate-300 text-xs font-sans">
                      {result.explanation.geminiAssessment}
                    </div>
                  </div>
                )}

                {/* Score Factor Breakdown */}
                {result.explanation?.factors && result.explanation.factors.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <div className="text-xs font-bold text-slate-300">Point Score Factor Contributions:</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {result.explanation.factors.map((f, i) => (
                        <div
                          key={i}
                          className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-center justify-between gap-2"
                        >
                          <div className="space-y-0.5 truncate">
                            <span className="font-semibold text-slate-200 block truncate">{f.factor}</span>
                            <span className="text-[11px] text-slate-400 block truncate">{f.reason}</span>
                          </div>
                          <span className="font-mono text-xs font-bold text-red-400 shrink-0">
                            +{f.points} pts
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Extracted Indicators Section */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FileSearch className="w-4 h-4 text-cyan-400" />
                    Extracted Observables & Indicators ({result.indicators?.length || 0})
                  </h3>
                  <span className="text-[11px] text-slate-400">Correlated observables</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {(result.indicators || []).map((ind, i) => {
                    const badgeClass =
                      ind.severity === "Critical"
                        ? "bg-red-500/10 text-red-400 border-red-500/30"
                        : ind.severity === "High"
                        ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                        : ind.severity === "Medium"
                        ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
                        : "bg-slate-800 text-slate-300 border-slate-700";

                    return (
                      <div
                        key={i}
                        className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 text-xs"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 truncate">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}`}>
                              {ind.type}
                            </span>
                            <span className="font-mono text-xs font-semibold text-slate-200 truncate">
                              {ind.indicator}
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleCopy(ind.indicator)}
                            className="text-slate-400 hover:text-slate-200 shrink-0"
                            title="Copy indicator"
                          >
                            {copiedIndicator === ind.indicator ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                        <p className="text-[11px] text-slate-400">{ind.description}</p>
                        {ind.isThreatIntelMatch && (
                          <div className="flex items-center gap-2 pt-1 border-t border-slate-800/80 text-[10px] text-red-400 font-mono">
                            <Database className="w-3 h-3 text-red-400 shrink-0" />
                            <span>Matched TI Database ({ind.reputation} • {ind.confidence}%)</span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Right Column: Threat Intel Correlation & Syntactic Dissection */}
            <div className="space-y-6">
              {/* Threat Intel & Incident Correlation Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3.5">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  Available Application Data Correlation
                </h3>

                <div className="space-y-2 text-xs">
                  {/* TI Matches */}
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 block">
                      CyberSentinel Threat Intelligence Match:
                    </span>
                    {result.explanation?.threatIntelCorrelation?.matchedIndicators &&
                    result.explanation.threatIntelCorrelation.matchedIndicators.length > 0 ? (
                      <div className="space-y-1">
                        {result.explanation.threatIntelCorrelation.matchedIndicators.map((m, idx) => (
                          <div key={idx} className="flex items-center justify-between text-xs font-mono">
                            <span className="text-red-400 font-semibold">{m.indicator}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                              {m.reputation} ({m.confidence}%)
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 italic block">
                        No prior records matched in local threat intelligence table.
                      </span>
                    )}
                  </div>

                  {/* Active Incidents Cross-Link */}
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                    <span className="text-[11px] font-semibold text-slate-400 block">
                      Active Incidents Cross-Correlation:
                    </span>
                    {result.explanation?.threatIntelCorrelation?.relatedIncidents &&
                    result.explanation.threatIntelCorrelation.relatedIncidents.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {result.explanation.threatIntelCorrelation.relatedIncidents.map((inc, idx) => (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => onNavigate && onNavigate("investigation", inc)}
                            className="px-2 py-1 rounded bg-red-950 hover:bg-red-900 text-red-300 font-mono text-[11px] border border-red-800 flex items-center gap-1 transition"
                          >
                            <span>{inc}</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 italic block">
                        Indicator has not appeared in prior recorded incidents.
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Syntactic Component Dissection */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Code className="w-4 h-4 text-cyan-400" />
                  Syntactic Component Dissection
                </h3>

                {result.structuralDetails ? (
                  <div className="bg-slate-950 rounded-lg border border-slate-800 p-3.5 space-y-2 text-xs font-mono">
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Scheme:</span>
                      <span className={result.structuralDetails.protocol === "https:" ? "text-emerald-400" : "text-amber-400"}>
                        {result.structuralDetails.protocol}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Hostname:</span>
                      <span className="text-cyan-300 font-bold truncate max-w-[180px]">{result.structuralDetails.hostname}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Host Type:</span>
                      <span className={result.structuralDetails.isIpHost ? "text-red-400 font-bold" : "text-slate-300"}>
                        {result.structuralDetails.isIpHost ? "Raw IP Host" : "Domain FQDN"}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Subdomains:</span>
                      <span className="text-slate-300">
                        {result.structuralDetails.subdomainsCount || 0} levels
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Shannon Entropy:</span>
                      <span className={(result.structuralDetails.entropyScore || 0) > 3.8 ? "text-amber-400" : "text-slate-300"}>
                        {result.structuralDetails.entropyScore || 0} bits/char
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Path URI:</span>
                      <span className="text-slate-300 truncate max-w-[180px]">{result.structuralDetails.pathname || "/"}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Query Parameters:</span>
                      <span className="text-slate-300 truncate max-w-[180px]">{result.structuralDetails.search || "(none)"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Total Length:</span>
                      <span className="text-slate-300">{result.structuralDetails.length} characters</span>
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-red-400">{result.error}</div>
                )}
              </div>

              {/* Recommended Investigation Steps */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  Recommended SOC Investigation Steps
                </h3>

                <ul className="space-y-2 text-xs text-slate-300">
                  {(result.recommendedInvestigation || []).map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-slate-950 p-2.5 rounded-lg border border-slate-800/80">
                      <span className="text-cyan-400 font-bold shrink-0">{idx + 1}.</span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* 8 Specific Checks Detailed Breakdown */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  Structural Heuristic Rules Breakdown ({checks.length} Rules Evaluated)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Covers URL length, HTTPS, IP-based host, subdomain complexity, suspicious characters, encoding patterns, path structure, and query parameters.
                </p>
              </div>

              {/* Category Filter Pills */}
              <div className="flex flex-wrap gap-1 text-xs">
                {[
                  { id: "all", label: "All" },
                  { id: "length", label: "Length" },
                  { id: "protocol", label: "HTTPS" },
                  { id: "ip_host", label: "IP Host" },
                  { id: "subdomain", label: "Subdomain" },
                  { id: "characters", label: "Characters" },
                  { id: "encoding", label: "Encoding" },
                  { id: "path", label: "Path" },
                  { id: "query", label: "Query" },
                  { id: "threat_intel", label: "Threat Intel" },
                ].map((cat) => (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => setCategoryFilter(cat.id)}
                    className={`px-2 py-1 rounded-md text-[11px] font-medium transition ${
                      categoryFilter === cat.id
                        ? "bg-cyan-600 text-white font-bold"
                        : "bg-slate-950 text-slate-400 hover:bg-slate-800"
                    }`}
                  >
                    {cat.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
              {filteredChecks.map((c, i) => {
                const icon =
                  c.status === "danger" ? (
                    <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  ) : c.status === "warning" ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  );

                const border =
                  c.status === "danger"
                    ? "border-red-500/30 bg-red-500/5"
                    : c.status === "warning"
                    ? "border-amber-500/30 bg-amber-500/5"
                    : "border-slate-800 bg-slate-950/60";

                return (
                  <div key={i} className={`p-3.5 rounded-lg border ${border} text-xs space-y-1.5`}>
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 font-semibold text-slate-200">
                        {icon}
                        <span>{c.name}</span>
                      </div>
                      <span
                        className={`font-mono text-[11px] font-bold ${
                          c.points > 0 ? "text-red-400" : "text-emerald-400"
                        }`}
                      >
                        {c.points > 0 ? `+${c.points} pts` : `${c.points} pts`}
                      </span>
                    </div>
                    <p className="text-slate-400 pl-6 text-[11px] leading-relaxed">{c.details}</p>
                    {c.category && (
                      <div className="pl-6 pt-1">
                        <span className="text-[10px] font-mono uppercase text-slate-500">
                          Check: {c.category}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Create Incident Modal */}
      {showIncidentModal && result && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <PlusCircle className="w-5 h-5 text-red-400" />
                <h3 className="text-base font-bold text-white">
                  Create Incident from URL Analysis
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowIncidentModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕ Close
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1">
                <div className="flex justify-between font-mono">
                  <span className="text-slate-400">Target URL:</span>
                  <span className="text-cyan-400 truncate max-w-[280px]">{result.url}</span>
                </div>
                <div className="flex justify-between font-mono">
                  <span className="text-slate-400">Calculated Score:</span>
                  <span className="font-bold text-red-400">{result.riskScore}/100 ({result.classification})</span>
                </div>
                <div className="flex justify-between font-mono">
                  <span className="text-slate-400">Correlated Indicators:</span>
                  <span className="text-slate-300">{result.indicators?.length || 0} observables</span>
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Incident Title:
                </label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-red-500 font-medium"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Affected User / Gateway Sensor:
                </label>
                <input
                  type="text"
                  value={affectedUser}
                  onChange={(e) => setAffectedUser(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-red-500 font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Analyst Escalation Notes:
                </label>
                <textarea
                  rows={3}
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  placeholder="e.g. Host requested via boundary web gateway proxy. Dispatched perimeter sinkhole."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-red-500 resize-none"
                />
              </div>

              <div className="p-3 bg-red-950/20 border border-red-900/40 rounded-lg text-[11px] text-slate-300 space-y-1">
                <span className="font-semibold text-red-300 block">Automated Incident Pipeline Actions:</span>
                <ul className="list-disc pl-4 space-y-0.5 text-slate-400">
                  <li>Creates active formal incident record with severity and timeline milestones.</li>
                  <li>Inserts URL and domain into the Threat Intelligence database.</li>
                  <li>Records SOC action in the immutable Audit Log.</li>
                  <li>Updates Dashboard metrics and high-risk incident tallies.</li>
                </ul>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowIncidentModal(false)}
                  className="px-3.5 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingIncident}
                  className="px-4 py-2 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white flex items-center gap-1.5 shadow transition disabled:opacity-50"
                >
                  {creatingIncident ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                      <span>Creating Incident...</span>
                    </>
                  ) : (
                    <>
                      <PlusCircle className="w-3.5 h-3.5" />
                      <span>Confirm & Escalate Incident</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
