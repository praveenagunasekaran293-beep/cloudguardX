import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  UserCheck,
  FileCheck,
  Lock,
  RefreshCw,
  Send,
} from "lucide-react";
import { api } from "../services/api";
import { ResponseAction, SeverityLevel } from "../types";

export const ResponseWorkflowPage: React.FC = () => {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [analystName, setAnalystName] = useState("Praveena G. (Lead SOC Analyst)");
  const [justification, setJustification] = useState("");
  const [decisionType, setDecisionType] = useState<"APPROVED" | "REJECTED">("APPROVED");
  const [submitting, setSubmitting] = useState(false);

  const loadActions = async () => {
    try {
      const data = await api.getResponseActions();
      setActions(data.actions || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadActions();
  }, []);

  const handleOpenReview = (actionId: string, decision: "APPROVED" | "REJECTED") => {
    setReviewingId(actionId);
    setDecisionType(decision);
    setJustification(
      decision === "APPROVED"
        ? "Verified incident forensic telemetry and confirmed isolation matches NIST containment runbook."
        : "Action declined due to potential operational impact on critical financial transactions."
    );
  };

  const handleSubmitReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reviewingId) return;
    setSubmitting(true);
    try {
      await api.reviewResponseAction(reviewingId, decisionType, analystName, justification);
      setReviewingId(null);
      await loadActions();
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting(false);
    }
  };

  const getRiskBadge = (risk: SeverityLevel) => {
    switch (risk) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border border-red-500/40";
      case "High":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/40";
      case "Medium":
        return "bg-amber-500/20 text-amber-300 border border-amber-500/40";
      default:
        return "bg-blue-500/20 text-blue-400 border border-blue-500/40";
    }
  };

  const pending = actions.filter((a) => a.status === "PENDING");
  const completed = actions.filter((a) => a.status !== "PENDING");

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          Human-in-the-Loop Response Approval Gate
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Zero unvetted autonomous execution: AI generates defensive recommendations, while certified human analysts validate and authorize containment actions.
        </p>
      </div>

      {/* Safety Policy Explainer */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex items-center justify-between gap-4 text-xs text-slate-300">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 shrink-0">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <span className="font-bold text-cyan-300 block">Strict Human Authorization Protocol</span>
            <span className="text-slate-400">
              AI Recommendation → Analyst Review → Cryptographic/Audited Approval → Action Execution → Immutable Audit Log.
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px] bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-750">
          <span className="text-amber-400 font-bold">{pending.length}</span>
          <span className="text-slate-400">Pending Authorization</span>
        </div>
      </div>

      {/* Pending Approval Queue */}
      <div className="space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" /> Pending Action Authorization Requests
        </h2>

        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            Loading response recommendations...
          </div>
        ) : pending.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80" />
            All recommended response actions have been reviewed and decided.
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {pending.map((action) => (
              <div
                key={action.id}
                className="bg-slate-900 border border-amber-900/40 rounded-xl p-5 shadow-sm space-y-4 hover:border-amber-700/60 transition"
              >
                <div className="flex flex-wrap items-start justify-between gap-3 text-xs">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-cyan-400 font-bold">{action.id}</span>
                      <span className="text-slate-400">•</span>
                      <span className="font-mono text-slate-300 font-medium">Incident: {action.incidentId}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getRiskBadge(action.riskLevel)}`}>
                        {action.riskLevel} Operational Risk
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-white">{action.title}</h3>
                    <p className="text-xs text-slate-300 max-w-3xl">{action.description}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenReview(action.id, "REJECTED")}
                      className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800/60 transition flex items-center gap-1.5"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Reject Action</span>
                    </button>

                    <button
                      onClick={() => handleOpenReview(action.id, "APPROVED")}
                      className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition flex items-center gap-1.5"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Approve & Authorize</span>
                    </button>
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                  <span>Engine: {action.recommendedBy}</span>
                  <span>Action Type: {action.actionType}</span>
                  <span>Generated: {new Date(action.createdAt).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Decision Review Modal */}
      {reviewingId && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <form
            onSubmit={handleSubmitReview}
            className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl text-xs"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-cyan-400" /> Analyst Decision Sign-off
              </h3>
              <button
                type="button"
                onClick={() => setReviewingId(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-400 block">Decision Type:</span>
              <span
                className={`text-sm font-bold ${
                  decisionType === "APPROVED" ? "text-emerald-400" : "text-red-400"
                }`}
              >
                {decisionType === "APPROVED" ? "AUTHORIZATION APPROVED" : "ACTION REJECTED"}
              </span>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-medium">Analyst Signature / Identifier:</label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-medium">
                Operational Justification & Runbook Notes:
              </label>
              <textarea
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                rows={3}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500 text-xs"
                required
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setReviewingId(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className={`px-4 py-1.5 text-xs font-semibold rounded-lg text-white shadow-sm flex items-center gap-1.5 ${
                  decisionType === "APPROVED"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-red-600 hover:bg-red-500"
                }`}
              >
                {submitting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Record Decision to Audit Log</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* History of Decided Actions */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <FileCheck className="w-4 h-4 text-cyan-400" /> Historical Human Approvals & Audited Decisions
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Action ID</th>
                <th className="py-2.5 px-3">Incident</th>
                <th className="py-2.5 px-3">Action Title</th>
                <th className="py-2.5 px-3">Decision</th>
                <th className="py-2.5 px-3">Certified Analyst</th>
                <th className="py-2.5 px-3">Decision Timestamp</th>
                <th className="py-2.5 px-3">Justification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">
              {completed.map((a) => (
                <tr key={a.id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 px-3 font-mono font-bold text-cyan-400">{a.id}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-400">{a.incidentId}</td>
                  <td className="py-2.5 px-3 text-slate-200 font-semibold">{a.title}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        a.status === "APPROVED"
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                          : "bg-red-500/20 text-red-400 border border-red-500/40"
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{a.decidedBy || "N/A"}</td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                    {a.decidedAt ? new Date(a.decidedAt).toLocaleString() : "N/A"}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate" title={a.justification || ""}>
                    {a.justification || "Standard playbook review"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
