import React, { useState } from "react";
import {
  MailCheck,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Sparkles,
  Link as LinkIcon,
  Globe2,
  Clock,
  Send,
  FileText,
  RotateCcw,
  PlusCircle,
  ExternalLink,
  Layers,
  Database,
  ArrowRight,
  Info,
  Check,
  Copy,
  AlertOctagon,
  UserCheck,
  Brain,
} from "lucide-react";
import { api } from "../services/api";
import { PhishingAnalysisResult } from "../types";
import { NavTab } from "../components/Sidebar";

const SAMPLE_EMAILS = [
  {
    name: "Targeted HR Payroll Phish (High Risk)",
    sender: "hr-payroll@portal-verify.cc",
    subject: "URGENT: Verify Direct Deposit for Q3 Payroll within 24 Hours",
    content: `From: "Corporate HR Services" <hr-payroll@portal-verify.cc>
Subject: URGENT: Verify Direct Deposit for Q3 Payroll within 24 Hours
Date: Thu, 25 Sep 2026 09:12:00 +0000

Dear Employee,

Due to a scheduled system migration of our corporate payroll processor, all employees must immediately re-authenticate and verify their direct deposit banking routing information to prevent salary suspension.

Failure to complete this verification within 24 hours will cause your upcoming bi-weekly paycheck to be held indefinitely.

Please login to the secure employee portal below:
https://payroll-update-secure.top/auth/verify?session=99281a

Enter your corporate single sign-on (SSO) email, network password, and authenticate your MFA token when prompted.

Thank you,
Corporate Payroll & Benefits Department`,
  },
  {
    name: "Urgent Microsoft 365 Password Expiry (High Risk)",
    sender: "admin-notice@ms365-security-alert.xyz",
    subject: "Action Required: Your Microsoft 365 Password Expires Today",
    content: `From: "IT Support Helpdesk" <admin-notice@ms365-security-alert.xyz>
Subject: Action Required: Your Microsoft 365 Password Expires Today

Your corporate Office 365 account password will expire in 2 hours. 
To keep your current password and prevent your email inbox from being locked:

Click here to keep your current credentials:
https://login-microsoftonline-verify.click/tenant/auth

This is an automated security message. Do not reply to this email.`,
  },
  {
    name: "Legitimate Corporate Security Brief (Clean)",
    sender: "security-ops@enterprise-corp.com",
    subject: "Monthly Cyber Awareness: Recognizing Social Engineering Attacks",
    content: `From: "Cyber Security Operations" <security-ops@enterprise-corp.com>
Subject: Monthly Cyber Awareness: Recognizing Social Engineering Attacks

Team,

As part of Cybersecurity Awareness Month, our defensive security team reminds everyone to never share passwords, multi-factor codes, or click unexpected links. 

Always report suspicious emails using the "Report Phishing" button in your Outlook toolbar. If in doubt, visit the internal wiki directly at https://intranet.enterprise-corp.com/security.

Stay safe,
SOC Security Operations`,
  },
];

interface PhishingAnalyzerPageProps {
  onNavigate?: (tab: NavTab, incidentId?: string) => void;
}

export const PhishingAnalyzerPage: React.FC<PhishingAnalyzerPageProps> = ({ onNavigate }) => {
  const [sender, setSender] = useState(SAMPLE_EMAILS[0].sender);
  const [subject, setSubject] = useState(SAMPLE_EMAILS[0].subject);
  const [content, setContent] = useState(SAMPLE_EMAILS[0].content);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PhishingAnalysisResult | null>(null);

  // Incident creation state
  const [creatingIncident, setCreatingIncident] = useState(false);
  const [showIncidentModal, setShowIncidentModal] = useState(false);
  const [customTitle, setCustomTitle] = useState("");
  const [affectedUser, setAffectedUser] = useState("target.employee@enterprise-corp.internal");
  const [analystNotes, setAnalystNotes] = useState("");
  const [createdIncidentResult, setCreatedIncidentResult] = useState<{
    incidentId: string;
    title: string;
    severity: string;
    riskScore: number;
    indicatorsCount: number;
    timelineMilestonesCount: number;
  } | null>(null);

  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;
    setLoading(true);
    setError(null);
    setCreatedIncidentResult(null);
    try {
      const data = await api.analyzePhishing(content, sender, subject);
      setResult(data);
      setCustomTitle(`Targeted Phishing: ${data.subject.slice(0, 45)}`);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || "Failed to execute defensive phishing analysis.");
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSample = (sample: typeof SAMPLE_EMAILS[0]) => {
    setSender(sample.sender);
    setSubject(sample.subject);
    setContent(sample.content);
    setResult(null);
    setCreatedIncidentResult(null);
    setError(null);
  };

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedIndicator(text);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const handleCreateIncident = async () => {
    if (!result) return;
    setCreatingIncident(true);
    try {
      const res = await api.createIncidentFromPhishing(result, {
        customTitle: customTitle || undefined,
        affectedUser: affectedUser || undefined,
        analystNotes: analystNotes || undefined,
      });
      setCreatedIncidentResult(res);
      setShowIncidentModal(false);
    } catch (err: any) {
      console.error("Incident creation failed:", err);
      alert(err?.message || "Failed to create incident from phishing analysis");
    } finally {
      setCreatingIncident(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Description */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Defensive Phishing Investigation Module
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Structural header & body dissection, social engineering extraction, transparent risk scoring, threat intelligence verification, and automated SOC incident creation.
          </p>
        </div>
      </div>

      {/* Preset Samples Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center gap-2 shadow-xs">
        <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 mr-2">
          <FileText className="w-3.5 h-3.5 text-cyan-400" /> Safe Preset Samples:
        </span>
        {SAMPLE_EMAILS.map((s, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleLoadSample(s)}
            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-750 transition cursor-pointer"
          >
            {s.name}
          </button>
        ))}
      </div>

      {/* Incident Created Notification Banner */}
      {createdIncidentResult && (
        <div className="bg-emerald-950/60 border border-emerald-500/50 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 animate-in fade-in duration-300">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center shrink-0">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-emerald-300">
                  {createdIncidentResult.incidentId}
                </span>
                <span className="text-slate-400">•</span>
                <span className="text-xs font-bold text-white">Incident Successfully Created</span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                Updated <strong>Dashboard</strong>, <strong>Incidents</strong>, generated <strong>Timeline</strong> (4 milestones), inserted {createdIncidentResult.indicatorsCount} observables into <strong>Threat Intelligence</strong>, and recorded audit log.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {onNavigate && (
              <>
                <button
                  onClick={() => onNavigate("investigation", createdIncidentResult.incidentId)}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>Inspect Timeline</span>
                </button>
                <button
                  onClick={() => onNavigate("incidents")}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>View Incidents</span>
                </button>
                <button
                  onClick={() => onNavigate("threat-intel")}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition cursor-pointer"
                >
                  <Database className="w-3.5 h-3.5 text-purple-400" />
                  <span>Threat Intel Feed</span>
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Left Column: Email Input Form */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <MailCheck className="w-4 h-4 text-cyan-400" /> Inbound Email Telemetry Payload
          </h2>

          <form onSubmit={handleAnalyze} className="space-y-3.5 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1 font-medium">Sender Address (From Header):</label>
                <input
                  type="text"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  placeholder="e.g. hr-payroll@portal-verify.cc"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1 font-medium">Email Subject Line:</label>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="e.g. URGENT: Verify Direct Deposit"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-medium">
                Email Body Content / Raw Message Text:
              </label>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={12}
                placeholder="Paste safe email text, headers, and body here..."
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-[11px] leading-relaxed"
                required
              />
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <span className="text-[11px] text-slate-500">
                Safe analysis mode: embedded links are parsed structurally, not clicked.
              </span>

              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1.5 shadow-sm transition disabled:opacity-50 cursor-pointer"
              >
                {loading ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Execute Defensive Analysis</span>
              </button>
            </div>
          </form>
        </div>

        {/* Right Column: Defensive Analysis Report */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" /> Defensive Analysis Report
            </h2>

            {result && (
              <button
                onClick={() => setShowIncidentModal(true)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white flex items-center gap-1.5 shadow-xs transition cursor-pointer"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>Create Incident from Analysis</span>
              </button>
            )}
          </div>

          {/* Loading State */}
          {loading && (
            <div className="py-20 flex flex-col items-center justify-center space-y-3">
              <RotateCcw className="w-8 h-8 text-cyan-400 animate-spin" />
              <div className="text-center">
                <span className="text-xs font-semibold text-slate-200">Executing Multi-Vector Phishing Forensic Engine</span>
                <p className="text-[11px] text-slate-400 mt-1 max-w-sm">
                  Extracting urgency markers, credential requests, verifying URLs against threat intelligence, and generating Gemini forensic assessment...
                </p>
              </div>
            </div>
          )}

          {/* Error State */}
          {!loading && error && (
            <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/30 text-xs text-red-300 space-y-2">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>Phishing Analysis Failed</span>
              </div>
              <p className="font-mono text-[11px] bg-black/40 p-2.5 rounded border border-red-900/30">
                {error}
              </p>
            </div>
          )}

          {/* Empty State */}
          {!loading && !error && !result && (
            <div className="py-24 flex flex-col items-center justify-center text-slate-500 text-xs border border-dashed border-slate-800 rounded-xl p-6 text-center space-y-2">
              <MailCheck className="w-10 h-10 text-slate-700" />
              <p className="text-slate-400 font-medium">Ready for Inbound Email Telemetry</p>
              <p className="text-[11px] max-w-sm">
                Paste email text or choose one of the safe preset samples on the left to extract observables, compute transparent risk scoring, and verify indicators.
              </p>
            </div>
          )}

          {/* Success Loaded Analysis State */}
          {!loading && !error && result && (
            <div className="space-y-4 text-xs">
              {/* Score & Classification Header */}
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-[10px] uppercase font-bold text-slate-400">Classification</div>
                  <div
                    className={`text-base font-bold ${
                      result.riskScore >= 70
                        ? "text-red-400"
                        : result.riskScore >= 40
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {result.classification}
                  </div>
                  <span className="text-[10px] text-slate-500">
                    Engine: {result.engine === "gemini" ? "Gemini 3.8 Flash AI" : "Defensive Rule Heuristics"}
                  </span>
                </div>

                <div className="text-right">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Phishing Risk Score</div>
                  <div className="font-mono text-2xl font-black">
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
                    <span className="text-xs text-slate-500">/100</span>
                  </div>
                </div>
              </div>

              {/* Verified Intelligence Status Card */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-cyan-400" />
                    Threat Intelligence Verification Status
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">Strict Feed Integrity Policy</span>
                </div>

                {result.explanation?.threatIntelVerification?.verifiedIndicators &&
                result.explanation.threatIntelVerification.verifiedIndicators.length > 0 ? (
                  <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-500/30 text-red-300 space-y-1">
                    <div className="flex items-center gap-1.5 font-bold text-xs">
                      <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
                      <span>
                        VERIFIED MALICIOUS: Confirmed by Threat Intelligence Provider
                      </span>
                    </div>
                    {result.explanation.threatIntelVerification.verifiedIndicators.map((v, i) => (
                      <div key={i} className="text-[11px] font-mono text-slate-300 pl-5">
                        • {v.indicator} ({v.type}) matches {v.source} with {v.confidence}% confidence.
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-400 space-y-0.5">
                    <div className="flex items-center gap-1.5 font-semibold text-xs text-slate-300">
                      <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span>Unverified Observables Policy Enforced</span>
                    </div>
                    <p className="text-[11px] leading-relaxed">
                      Observables in this email are not verified as malicious by configured external threat feeds. They are classified based on structural heuristic rules and behavioral anomalies.
                    </p>
                  </div>
                )}
              </div>

              {/* Transparent Explainable Risk Scoring Factors */}
              {result.riskBreakdown && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">
                      Explainable Risk Score Breakdown:
                    </span>
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      Total: {result.riskScore}/100
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    {result.riskBreakdown.factors.map((f, i) => (
                      <div
                        key={i}
                        className="flex items-start justify-between gap-2 p-2 rounded-lg bg-slate-900/70 border border-slate-800 text-xs"
                      >
                        <div className="space-y-0.5">
                          <span className="font-semibold text-slate-200">{f.factor}</span>
                          <p className="text-[11px] text-slate-400">{f.reason}</p>
                        </div>
                        <span
                          className={`font-mono font-bold shrink-0 px-2 py-0.5 rounded text-[11px] ${
                            f.points > 0
                              ? "bg-red-950 text-red-300 border border-red-800/40"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {f.points > 0 ? `+${f.points}` : "0"} pts
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Social Engineering Exploitation Indicators */}
              {result.socialEngineeringIndicators && result.socialEngineeringIndicators.length > 0 && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                  <span className="font-bold text-slate-200 block flex items-center gap-1.5">
                    <Brain className="w-3.5 h-3.5 text-purple-400" />
                    Social Engineering Principles Detected:
                  </span>

                  <div className="grid grid-cols-1 gap-2">
                    {result.socialEngineeringIndicators.map((se, i) => (
                      <div
                        key={i}
                        className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800 space-y-1"
                      >
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/50 font-bold text-[10px] uppercase">
                            {se.principle}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300">
                          <span className="font-semibold text-slate-400">Evidence: </span>
                          {se.evidence}
                        </p>
                        <p className="text-[10px] text-slate-500 italic">
                          {se.explanation}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted Observables Grid (Sender, Subject, URLs, Domains) */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-3">
                <span className="font-bold text-slate-200 block">
                  Extracted Observables & Telemetry Entities:
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
                  {/* Sender */}
                  <div className="bg-slate-900 p-2 rounded border border-slate-800">
                    <span className="text-slate-500 font-sans block text-[10px]">Extracted Sender:</span>
                    <span className="text-slate-200 break-all">{result.sender}</span>
                  </div>

                  {/* Subject */}
                  <div className="bg-slate-900 p-2 rounded border border-slate-800 font-sans">
                    <span className="text-slate-500 block text-[10px]">Extracted Subject:</span>
                    <span className="text-slate-200 font-medium">{result.subject}</span>
                  </div>
                </div>

                {/* Extracted URLs */}
                <div>
                  <span className="text-slate-400 text-[11px] font-semibold block mb-1">
                    Extracted Embedded Destination URLs ({result.extractedUrls.length}):
                  </span>
                  {result.extractedUrls.length === 0 ? (
                    <span className="text-slate-500 italic text-[11px]">No embedded URLs identified in payload.</span>
                  ) : (
                    <div className="space-y-1 font-mono text-[11px]">
                      {result.extractedUrls.map((u, i) => (
                        <div
                          key={i}
                          className="bg-slate-900 p-2 rounded border border-slate-800 text-cyan-300 break-all flex items-center justify-between gap-2"
                        >
                          <div className="flex items-center gap-1.5 truncate">
                            <LinkIcon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            <span className="truncate">{u}</span>
                          </div>
                          <button
                            onClick={() => handleCopy(u)}
                            className="text-slate-500 hover:text-cyan-300 p-1 cursor-pointer shrink-0"
                            title="Copy URL"
                          >
                            {copiedIndicator === u ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Extracted Domains */}
                {result.domains && result.domains.length > 0 && (
                  <div>
                    <span className="text-slate-400 text-[11px] font-semibold block mb-1">
                      Unique Extracted Domains:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {result.domains.map((dom, i) => (
                        <span
                          key={i}
                          className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-mono text-[11px] flex items-center gap-1"
                        >
                          <Globe2 className="w-3 h-3 text-cyan-400" />
                          <span>{dom}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Gemini AI Forensic Explanation */}
              {(result.explanation?.geminiAssessment || result.aiAnalysis) && (
                <div className="bg-cyan-950/20 border border-cyan-800/40 p-4 rounded-xl space-y-2">
                  <div className="flex items-center gap-1.5 text-cyan-400 font-bold">
                    <Sparkles className="w-4 h-4" />
                    <span>Gemini Security Copilot Deep Forensic Assessment:</span>
                  </div>
                  <div className="text-slate-300 text-[11px] leading-relaxed whitespace-pre-line bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                    {result.explanation?.geminiAssessment || result.aiAnalysis}
                  </div>
                </div>
              )}

              {/* Recommended Investigation Steps */}
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                <span className="font-bold text-slate-200 block">
                  Recommended SOC Investigation & Containment Steps:
                </span>
                <div className="space-y-1.5">
                  {result.recommendedInvestigation.map((step, i) => (
                    <div key={i} className="flex items-start gap-2 text-slate-300 text-[11px]">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Bottom Incident Creation Trigger */}
              <div className="pt-2 flex justify-end">
                <button
                  onClick={() => setShowIncidentModal(true)}
                  className="px-4 py-2 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white flex items-center gap-2 shadow-sm transition cursor-pointer"
                >
                  <PlusCircle className="w-4 h-4" />
                  <span>Escalate to Active SOC Incident</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Incident Creation Modal */}
      {showIncidentModal && result && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <PlusCircle className="w-4 h-4 text-red-400" />
                  Create Incident from Phishing Analysis
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Escalates this analysis to an official SOC incident record.
                </p>
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1 font-medium">Incident Title:</label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1 font-medium">Target / Affected User:</label>
                <input
                  type="text"
                  value={affectedUser}
                  onChange={(e) => setAffectedUser(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1 font-medium">Analyst Escalation Notes:</label>
                <textarea
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  rows={3}
                  placeholder="Notes regarding targeted department, recipient response, or triage status..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
                />
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 text-[11px] text-slate-400">
                <span className="font-semibold text-slate-300 block">Automated Platform Actions upon Creation:</span>
                <div>• Generates incident record with Severity {result.riskScore >= 75 ? "Critical" : "High"} ({result.riskScore}/100)</div>
                <div>• Generates 4 chronological Timeline intrusion milestones</div>
                <div>• Populates {result.extractedUrls.length + (result.domains?.length || 0)} observables into Threat Intelligence</div>
                <div>• Updates Dashboard incident counters and recent incidents log</div>
                <div>• Records comprehensive audit log entry with analyst attribution</div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowIncidentModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleCreateIncident}
                disabled={creatingIncident}
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-red-600 hover:bg-red-500 text-white flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
              >
                {creatingIncident ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <PlusCircle className="w-3.5 h-3.5" />}
                <span>Confirm & Create Incident</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
