import React, { useState, useEffect } from "react";
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Brain,
  Sparkles,
  Terminal,
  Database,
  Cpu,
  RefreshCw,
  Copy,
  Check,
  CheckCircle2,
  ListChecks,
  Info,
  ChevronRight,
} from "lucide-react";
import { SecurityEvent, AIThreatDetectionResult, ThreatClassification } from "../types";
import { api } from "../services/api";

interface AIThreatAnalysisModalProps {
  event: SecurityEvent;
  isOpen: boolean;
  onClose: () => void;
  onNavigateToCopilot?: (question: string) => void;
}

export const AIThreatAnalysisModal: React.FC<AIThreatAnalysisModalProps> = ({
  event,
  isOpen,
  onClose,
  onNavigateToCopilot,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AIThreatDetectionResult | null>(null);
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  const fetchAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.analyzeSecurityEvent(event.eventId, event);
      setAnalysis(result);
    } catch (err: any) {
      console.error("AI Threat Analysis failed:", err);
      setError(err?.message || "Failed to complete AI threat detection. Please check backend connectivity.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && event) {
      fetchAnalysis();
    } else {
      setAnalysis(null);
      setError(null);
    }
  }, [isOpen, event.eventId]);

  if (!isOpen) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedIndicator(text);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const getClassificationBadge = (classification?: ThreatClassification) => {
    switch (classification) {
      case "MALICIOUS":
        return {
          bg: "bg-red-500/20 text-red-300 border-red-500/40",
          icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
          label: "MALICIOUS",
        };
      case "SUSPICIOUS":
        return {
          bg: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          icon: <AlertTriangle className="w-4 h-4 text-amber-400" />,
          label: "SUSPICIOUS",
        };
      case "NORMAL":
        return {
          bg: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
          label: "NORMAL",
        };
      default:
        return {
          bg: "bg-slate-700 text-slate-300 border-slate-600",
          icon: <Info className="w-4 h-4 text-slate-400" />,
          label: "PENDING",
        };
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border border-red-500/40";
      case "High":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/40";
      case "Medium":
        return "bg-amber-500/20 text-amber-300 border border-amber-500/40";
      case "Low":
        return "bg-blue-500/20 text-blue-400 border border-blue-500/40";
      default:
        return "bg-slate-700 text-slate-300";
    }
  };

  const classBadge = getClassificationBadge(analysis?.classification);

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-750 rounded-2xl max-w-4xl w-full my-auto shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center">
              <Brain className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-cyan-400">{event.eventId}</span>
                <span className="text-slate-500">•</span>
                <span className="text-xs text-slate-400 font-mono">
                  {new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {event.source}
                </span>
              </div>
              <h2 className="text-base font-bold text-white flex items-center gap-2 mt-0.5">
                AI Threat Detection & Investigation Panel
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchAnalysis}
              disabled={loading}
              title="Re-run AI Analysis"
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 disabled:opacity-50 transition"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* Loading State */}
          {loading && (
            <div className="py-16 flex flex-col items-center justify-center space-y-4">
              <div className="relative">
                <div className="w-14 h-14 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin" />
                <Brain className="w-6 h-6 text-cyan-400 absolute inset-0 m-auto animate-pulse" />
              </div>
              <div className="text-center">
                <h4 className="text-sm font-semibold text-slate-200">Executing Server-Side AI Threat Detection</h4>
                <p className="text-xs text-slate-400 mt-1 max-w-sm">
                  Correlating event telemetry, evaluating deterministic heuristics, checking application threat intelligence, and synthesizing Gemini threat inference...
                </p>
              </div>
            </div>
          )}

          {/* Error State */}
          {!loading && error && (
            <div className="p-5 rounded-xl bg-red-950/40 border border-red-500/30 text-left space-y-3">
              <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
                <span>AI Threat Detection Encountered an Error</span>
              </div>
              <p className="text-xs text-slate-300 font-mono bg-black/40 p-3 rounded border border-red-900/40">
                {error}
              </p>
              <div className="flex justify-end pt-1">
                <button
                  onClick={fetchAnalysis}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white transition flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Retry Analysis</span>
                </button>
              </div>
            </div>
          )}

          {/* Success / Loaded Analysis */}
          {!loading && !error && analysis && (
            <>
              {/* Top Analytical Classification Banner */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-950 border border-slate-800">
                {/* Classification */}
                <div className="space-y-1">
                  <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1">
                    Classification
                  </span>
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border ${classBadge.bg}`}
                    >
                      {classBadge.icon}
                      {analysis.classification}
                    </span>
                  </div>
                </div>

                {/* Severity & Threat Category */}
                <div className="space-y-1">
                  <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                    Severity & Category
                  </span>
                  <div className="flex flex-col gap-1">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase w-fit ${getSeverityBadge(
                        analysis.severity
                      )}`}
                    >
                      {analysis.severity} Severity
                    </span>
                    <span className="text-xs font-semibold text-slate-200 line-clamp-1">
                      {analysis.threatCategory}
                    </span>
                  </div>
                </div>

                {/* Risk Score */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                    <span>Defensive Risk Score</span>
                    <span
                      className={`font-mono font-bold ${
                        analysis.riskScore >= 75
                          ? "text-red-400"
                          : analysis.riskScore >= 45
                          ? "text-amber-400"
                          : "text-emerald-400"
                      }`}
                    >
                      {analysis.riskScore}/100
                    </span>
                  </div>
                  <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        analysis.riskScore >= 75
                          ? "bg-red-500"
                          : analysis.riskScore >= 45
                          ? "bg-amber-500"
                          : "bg-emerald-500"
                      }`}
                      style={{ width: `${analysis.riskScore}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-slate-500 block">
                    Calculated from event telemetry + application context
                  </span>
                </div>

                {/* Confidence & Engine */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                    <span>Engine Confidence</span>
                    <span className="font-mono font-bold text-cyan-400">{analysis.confidence}%</span>
                  </div>
                  <div className="flex items-center gap-1.5 pt-1">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/60 text-[10px] font-mono text-cyan-300">
                      {analysis.engine === "gemini" ? (
                        <>
                          <Sparkles className="w-3 h-3 text-cyan-400" />
                          Gemini 3.8 Flash AI
                        </>
                      ) : (
                        <>
                          <Cpu className="w-3 h-3 text-amber-400" />
                          Rule & Heuristic Engine
                        </>
                      )}
                    </span>
                  </div>
                </div>
              </div>

              {/* Distinction Architecture Cards */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                    Layered Threat Intelligence Breakdown
                  </h3>
                  <span className="text-[10px] text-slate-500 font-mono">
                    Strict boundary isolation • No external invented intelligence
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Card 1: AI Inference */}
                  <div className="bg-slate-950/70 border border-cyan-900/40 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400">
                        <Sparkles className="w-3.5 h-3.5" />
                        1. AI Inference Engine Analysis
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/50 uppercase font-mono">
                        AI Inference
                      </span>
                    </div>
                    <p className="text-xs text-slate-200 leading-relaxed font-sans">
                      {analysis.explanation.aiInference}
                    </p>
                    <div className="text-[11px] text-slate-400 bg-slate-900/60 p-2.5 rounded border border-slate-800">
                      <span className="font-semibold text-slate-300">Executive Summary: </span>
                      {analysis.explanation.summary}
                    </div>
                  </div>

                  {/* Card 2: Deterministic Rules */}
                  <div className="bg-slate-950/70 border border-amber-900/40 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400">
                        <Terminal className="w-3.5 h-3.5" />
                        2. Deterministic Rule Matching
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800/50 uppercase font-mono">
                        Static Heuristics
                      </span>
                    </div>
                    {analysis.explanation.deterministicRules.length > 0 ? (
                      <div className="space-y-1.5">
                        {analysis.explanation.deterministicRules.map((rule, idx) => (
                          <div
                            key={idx}
                            className="text-xs font-mono bg-slate-900 p-2 rounded border border-amber-500/20 text-amber-200/90 flex items-start gap-2"
                          >
                            <span className="text-amber-400 mt-0.5">▶</span>
                            <span>{rule}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-400 p-3 rounded bg-slate-900/50 border border-slate-800 italic">
                        No deterministic heuristic rules triggered for this specific event pattern. Classification driven primarily by telemetry anomaly correlation.
                      </div>
                    )}
                  </div>

                  {/* Card 3: Synthetic Telemetry Context */}
                  <div className="bg-slate-950/70 border border-blue-900/40 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400">
                        <Cpu className="w-3.5 h-3.5" />
                        3. Synthetic Telemetry Origin
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800/50 uppercase font-mono">
                        Synthetic Data
                      </span>
                    </div>
                    <div className="text-xs font-mono text-slate-300 bg-slate-900/80 p-3 rounded border border-slate-800 overflow-x-auto">
                      {analysis.explanation.syntheticTelemetryContext}
                    </div>
                    <p className="text-[11px] text-slate-500">
                      Simulated defensive sensor telemetry ingested for training and verification. No live production endpoints or offensive implants active.
                    </p>
                  </div>

                  {/* Card 4: Threat Intelligence Context */}
                  <div className="bg-slate-950/70 border border-purple-900/40 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-purple-400">
                        <Database className="w-3.5 h-3.5" />
                        4. Application Threat Intelligence Match
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/50 uppercase font-mono">
                        Internal Synthetic Intel
                      </span>
                    </div>
                    <div className="text-xs font-mono text-slate-300 bg-slate-900/80 p-3 rounded border border-slate-800 overflow-x-auto">
                      {analysis.explanation.externalIntelligenceContext}
                    </div>
                    <p className="text-[11px] text-slate-500">
                      Matches strictly queried from CyberSentinel X synthetic threat intelligence database. No fabricated external threat intelligence feeds.
                    </p>
                  </div>
                </div>
              </div>

              {/* Evidence Locker */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    Observed Artifact & Indicator Evidence ({analysis.evidence.length})
                  </h4>
                  <span className="text-[10px] text-slate-500">Click to copy indicator to clipboard</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {analysis.evidence.map((ev, i) => (
                    <button
                      key={i}
                      onClick={() => handleCopy(ev)}
                      className="group flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-850 text-xs font-mono text-cyan-300 border border-cyan-900/50 hover:border-cyan-500/50 transition cursor-pointer"
                    >
                      <span>{ev}</span>
                      {copiedIndicator === ev ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3 text-slate-500 group-hover:text-slate-300" />
                      )}
                    </button>
                  ))}
                </div>
              </div>

              {/* Recommended Investigation Next Steps */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
                <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <ListChecks className="w-4 h-4 text-cyan-400" />
                  Recommended SOC Analyst Investigation Playbook
                </h4>
                <div className="space-y-2">
                  {analysis.recommendedInvestigation.map((step, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-2.5 text-xs text-slate-300 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80"
                    >
                      <div className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center shrink-0 text-[10px] font-bold">
                        {idx + 1}
                      </div>
                      <span className="mt-0.5 leading-relaxed">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* SOC Analyst Pivot Recommendations */}
              {onNavigateToCopilot && (
                <div className="flex items-center justify-between p-3 rounded-xl bg-gradient-to-r from-cyan-950/40 to-slate-900 border border-cyan-800/40">
                  <div className="flex items-center gap-2 text-xs text-slate-300">
                    <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Want deeper autonomous analysis or MITRE mapping?</span>
                  </div>
                  <button
                    onClick={() => {
                      onClose();
                      onNavigateToCopilot(
                        `Investigate Security Event ${event.eventId} (${event.eventType}). What adversary tactics are evident, and what containment should be prioritized?`
                      );
                    }}
                    className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 transition"
                  >
                    <span>Ask AI Copilot</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>Telemetry Sensor: {event.sourceType}</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition"
          >
            Close Panel
          </button>
        </div>
      </div>
    </div>
  );
};
