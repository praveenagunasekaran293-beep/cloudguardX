import React, { useState, useEffect } from "react";
import {
  Search,
  Filter,
  RefreshCw,
} from "lucide-react";

import { api } from "../services/api";
import { AuditLog } from "../types";

export const AuditLogsPage: React.FC = () => {
  // =====================================================
  // STATE
  // =====================================================

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [actionTypeFilter, setActionTypeFilter] =
    useState("all");

  // =====================================================
  // LOAD AUDIT LOGS
  // =====================================================

  const loadLogs = async () => {
    try {
      setLoading(true);

      const data = await api.getAuditLogs();

      setLogs(data.logs || []);
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    } finally {
      setLoading(false);
    }
  };

  // =====================================================
  // INITIAL LOAD
  // =====================================================

  useEffect(() => {
    loadLogs();
  }, []);

  // =====================================================
  // SEARCH AND FILTER
  // =====================================================

  const filtered = logs.filter((log) => {
    const matchesFilter =
      actionTypeFilter === "all" ||
      log.actionType === actionTypeFilter;

    const search = searchTerm.toLowerCase().trim();

    const matchesSearch =
      (log.userAction || "")
        .toLowerCase()
        .includes(search) ||
      (log.details || "")
        .toLowerCase()
        .includes(search) ||
      (log.incidentId || "")
        .toLowerCase()
        .includes(search) ||
      (log.analystDecision || "")
        .toLowerCase()
        .includes(search) ||
      (log.aiRecommendation || "")
        .toLowerCase()
        .includes(search) ||
      (log.id || "")
        .toLowerCase()
        .includes(search);

    return matchesFilter && matchesSearch;
  });

  // =====================================================
  // ACTION TYPE BADGE
  // =====================================================

  const getActionTypeBadge = (actionType: string) => {
    switch (actionType) {
      case "Human Approval":
      case "Human Response Approval":
        return "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40";

      case "AI Recommendation":
      case "AI Threat Detection":
        return "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40";

      case "Scenario Activation":
        return "bg-purple-500/20 text-purple-400 border border-purple-500/40";

      case "Incident Creation":
        return "bg-amber-500/20 text-amber-400 border border-amber-500/40";

      case "Workflow State Change":
        return "bg-blue-500/20 text-blue-400 border border-blue-500/40";

      case "Vulnerability Management":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/40";

      default:
        return "bg-slate-800 text-slate-300 border border-slate-700";
    }
  };

  // =====================================================
  // FORMAT TIMESTAMP
  // =====================================================

  const formatTimestamp = (timestamp: AuditLog["timestamp"]) => {
    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
      return "Invalid timestamp";
    }

    return date.toLocaleString([], {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  // =====================================================
  // PAGE UI
  // =====================================================

  return (
    <div className="space-y-6">

      {/* PAGE HEADER */}
      <div className="flex flex-wrap items-center justify-between gap-4">

        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Security Governance & Response Audit Log
          </h1>

          <p className="text-xs text-slate-400 mt-1">
            Audit ledger recording autonomous recommendations,
            human authorization, and incident state transitions.
          </p>
        </div>

        {/* REFRESH BUTTON */}
        <button
          type="button"
          onClick={loadLogs}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw
            className={`w-3.5 h-3.5 ${
              loading ? "animate-spin" : ""
            }`}
          />

          <span>
            {loading ? "Refreshing..." : "Refresh Ledger"}
          </span>
        </button>

      </div>

      {/* SEARCH AND FILTER */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">

        {/* SEARCH INPUT */}
        <div className="flex-1 min-w-[260px] relative">

          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />

          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search audit IDs, actions, decisions, or incidents..."
            aria-label="Search audit logs"
            className="w-full bg-slate-950 border border-slate-700 text-xs rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />

        </div>

        {/* ACTION TYPE FILTER */}
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">

          <Filter className="w-3.5 h-3.5 text-cyan-400" />

          <label htmlFor="audit-action-filter">
            Action Type:
          </label>

          <select
            id="audit-action-filter"
            aria-label="Filter audit logs by action type"
            value={actionTypeFilter}
            onChange={(e) =>
              setActionTypeFilter(e.target.value)
            }
            className="bg-slate-950 border border-slate-700 text-xs rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">
              All Action Types
            </option>

            <option value="Human Approval">
              Human Approval
            </option>

            <option value="AI Recommendation">
              AI Recommendation
            </option>

            <option value="Workflow State Change">
              Workflow State Change
            </option>

            <option value="Scenario Activation">
              Scenario Activation
            </option>

            <option value="Vulnerability Management">
              Vulnerability Management
            </option>

            <option value="AI Threat Detection">
              AI Threat Detection
            </option>

            <option value="Human Response Approval">
              Human Response Approval
            </option>

            <option value="Incident Creation">
              Incident Creation
            </option>
          </select>

        </div>

      </div>

      {/* AUDIT LOG TABLE */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">

        <div className="overflow-x-auto">

          <table className="w-full text-left text-xs">

            {/* TABLE HEADER */}
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">

              <tr>
                <th className="py-3 px-3">
                  Audit ID
                </th>

                <th className="py-3 px-3">
                  Timestamp
                </th>

                <th className="py-3 px-3">
                  Action Type
                </th>

                <th className="py-3 px-3">
                  User / System Action
                </th>

                <th className="py-3 px-3">
                  Incident
                </th>

                <th className="py-3 px-3">
                  AI Recommendation
                </th>

                <th className="py-3 px-3">
                  Analyst Decision
                </th>

                <th className="py-3 px-3">
                  Details
                </th>
              </tr>

            </thead>

            {/* TABLE BODY */}
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">

              {/* LOADING STATE */}
              {loading ? (
                <tr>
                  <td
                    colSpan={8}
                    className="py-12 text-center text-slate-400"
                  >
                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 inline mr-2" />

                    Loading audit ledger entries...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (

                /* EMPTY STATE */
                <tr>
                  <td
                    colSpan={8}
                    className="py-12 text-center text-slate-400"
                  >
                    {logs.length === 0
                      ? "No audit records available."
                      : "No audit records match the current search or filter."}
                  </td>
                </tr>

              ) : (

                /* AUDIT LOG ROWS */
                filtered.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-slate-800/40 transition"
                  >

                    {/* AUDIT ID */}
                    <td className="py-3 px-3 font-mono font-bold text-cyan-400 whitespace-nowrap">
                      {log.id || "N/A"}
                    </td>

                    {/* TIMESTAMP */}
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                      {formatTimestamp(log.timestamp)}
                    </td>

                    {/* ACTION TYPE */}
                    <td className="py-3 px-3 whitespace-nowrap">

                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${getActionTypeBadge(
                          log.actionType
                        )}`}
                      >
                        {log.actionType || "Unknown"}
                      </span>

                    </td>

                    {/* USER / SYSTEM ACTION */}
                    <td className="py-3 px-3 font-semibold text-slate-100">
                      {log.userAction || "N/A"}
                    </td>

                    {/* INCIDENT */}
                    <td className="py-3 px-3 font-mono text-cyan-400 whitespace-nowrap">
                      {log.incidentId || "N/A"}
                    </td>

                    {/* AI RECOMMENDATION */}
                    <td
                      className="py-3 px-3 text-slate-400 text-[11px] max-w-xs truncate"
                      title={log.aiRecommendation || ""}
                    >
                      {log.aiRecommendation || "—"}
                    </td>

                    {/* ANALYST DECISION */}
                    <td className="py-3 px-3 text-emerald-400/90 font-medium whitespace-nowrap">
                      {log.analystDecision || "—"}
                    </td>

                    {/* DETAILS */}
                    <td
                      className="py-3 px-3 text-slate-400 text-[11px] max-w-sm truncate"
                      title={log.details || ""}
                    >
                      {log.details || "—"}
                    </td>

                  </tr>
                ))

              )}

            </tbody>

          </table>

        </div>

      </div>

      {/* RESULT COUNT */}
      {!loading && (
        <div className="text-[11px] text-slate-500">
          Showing{" "}
          <span className="text-cyan-400 font-semibold">
            {filtered.length}
          </span>{" "}
          of{" "}
          <span className="text-slate-300 font-semibold">
            {logs.length}
          </span>{" "}
          audit records.
        </div>
      )}

    </div>
  );
};
