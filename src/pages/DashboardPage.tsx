import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Radio,
  Bug,
  Activity,
  ArrowUpRight,
  TrendingUp,
  Layers,
  ChevronRight,
  RefreshCw,
  Link2,
  MailCheck,
  Globe2,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts";
import { api } from "../services/api";
import { DashboardStats, Incident } from "../types";
import { NavTab } from "../components/Sidebar";

interface DashboardPageProps {
  onNavigate: (tab: NavTab, incidentId?: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadData = async () => {
    try {
      const [statsData, incidentsData] = await Promise.all([
        api.getStats(),
        api.getIncidents(),
      ]);
      setStats(statsData);
      setIncidents(incidentsData.incidents || []);
    } catch (err) {
      console.error("Dashboard data load error:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-3 text-slate-400">
          <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
          <p className="text-sm">Synthesizing SOC telemetry stream...</p>
        </div>
      </div>
    );
  }

  const summary = stats?.summary || {
    totalSecurityEvents: 0,
    criticalIncidents: 0,
    highRiskIncidents: 0,
    suspiciousEvents: 0,
    openIncidents: 0,
    vulnerabilities: 0,
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Enterprise SOC Intelligence Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time security telemetry correlation, explainable incident risk indexing, and defensive containment monitoring.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* 6 Key Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Events</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white">{summary.totalSecurityEvents}</div>
          <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
            <span className="text-emerald-400 font-medium">Live Telemetry</span>
            <span>synthetic ingest</span>
          </div>
          <div className="absolute -bottom-6 -right-6 w-16 h-16 rounded-full bg-cyan-500/5 pointer-events-none" />
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Critical Incidents</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-black text-red-400">{summary.criticalIncidents}</div>
          <div className="text-[11px] text-slate-400 mt-1">Immediate action required</div>
          <div className="absolute -bottom-6 -right-6 w-16 h-16 rounded-full bg-red-500/10 pointer-events-none" />
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">High Risk</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400">{summary.highRiskIncidents}</div>
          <div className="text-[11px] text-slate-400 mt-1">Risk Score &gt;= 70/100</div>
          <div className="absolute -bottom-6 -right-6 w-16 h-16 rounded-full bg-amber-500/10 pointer-events-none" />
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Suspicious Events</span>
            <Activity className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-black text-orange-400">{summary.suspiciousEvents}</div>
          <div className="text-[11px] text-slate-400 mt-1">Flagged by heuristic rules</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Open Incidents</span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-blue-400">{summary.openIncidents}</div>
          <div className="text-[11px] text-slate-400 mt-1">In analyst triage queue</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Vulnerabilities</span>
            <Bug className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-purple-400">{summary.vulnerabilities}</div>
          <div className="text-[11px] text-slate-400 mt-1">Prioritized CVE assets</div>
        </div>
      </div>

      {/* Quick Defensive Investigation Tooling */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-0.5">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>Specialized Defensive Investigation Modules</span>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              SOC Tooling
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            Execute passive structural URI decomposition or deep email social engineering investigations with automated incident escalation.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={() => onNavigate("url-analyzer")}
            className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/60 flex items-center gap-2 shadow-sm transition"
          >
            <Link2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Defensive URL Analyzer</span>
          </button>
          <button
            onClick={() => onNavigate("phishing")}
            className="px-3.5 py-2 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 flex items-center gap-2 shadow-sm transition"
          >
            <MailCheck className="w-3.5 h-3.5 text-amber-400" />
            <span>Phishing Email Analyzer</span>
          </button>
          <button
            onClick={() => onNavigate("threat-intel")}
            className="px-3.5 py-2 text-xs font-medium rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 flex items-center gap-1.5 transition"
          >
            <Globe2 className="w-3.5 h-3.5 text-slate-400" />
            <span>Threat Intelligence</span>
          </button>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Events Over Time */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" /> Security Event Telemetry Over Time
              </h2>
              <p className="text-xs text-slate-400">Aggregated hourly synthetic ingress events and correlate alerts</p>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-cyan-400 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Ingress Events
              </span>
              <span className="flex items-center gap-1.5 text-red-400 font-medium">
                <span className="w-2.5 h-2.5 rounded-full bg-red-400" /> High/Critical Alerts
              </span>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.timeTrend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Area type="monotone" dataKey="events" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorEvents)" name="Events" />
                <Area type="monotone" dataKey="alerts" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorAlerts)" name="Alerts" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution Donut */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h2 className="text-sm font-bold text-white mb-1">Severity Distribution</h2>
          <p className="text-xs text-slate-400 mb-3">Breakdown of telemetry event classifications</p>
          <div className="h-52 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={stats?.severityDistribution || []}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {(stats?.severityDistribution || []).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-slate-800 text-xs">
            {(stats?.severityDistribution || []).map((s) => (
              <div key={s.name} className="flex items-center justify-between px-2 py-1 rounded bg-slate-950/40">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
                  {s.name}
                </span>
                <span className="font-bold text-slate-200">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Second Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Incident Categories */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h2 className="text-sm font-bold text-white mb-1">Incident Category Triage</h2>
          <p className="text-xs text-slate-400 mb-4">Correlation clusters across enterprise threat vectors</p>
          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats?.incidentCategories || []} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} width={130} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} name="Incidents" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* MITRE Technique Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-1">
            <h2 className="text-sm font-bold text-white">MITRE ATT&CK Technique Frequency</h2>
            <button
              onClick={() => onNavigate("mitre")}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
            >
              View Matrix <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <p className="text-xs text-slate-400 mb-4">Top observed synthetic adversary behaviors</p>
          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats?.mitreDistribution || []} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis dataKey="technique" type="category" stroke="#94a3b8" fontSize={11} width={140} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} name="Observed Instances" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Incidents Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-white">Active Incident Management Queue</h2>
            <p className="text-xs text-slate-400">Prioritized defensive investigation queue with explainable risk scores</p>
          </div>
          <button
            onClick={() => onNavigate("incidents")}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
          >
            All Incidents <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Incident ID</th>
                <th className="py-2.5 px-3">Title & Classification</th>
                <th className="py-2.5 px-3">Affected Asset / User</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">
              {incidents.slice(0, 5).map((inc) => {
                const sevBadge =
                  inc.severity === "Critical"
                    ? "bg-red-500/20 text-red-400 border border-red-500/40"
                    : inc.severity === "High"
                    ? "bg-orange-500/20 text-orange-400 border border-orange-500/40"
                    : inc.severity === "Medium"
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                    : "bg-blue-500/20 text-blue-400 border border-blue-500/40";

                const scoreColor =
                  inc.riskScore >= 80 ? "text-red-400" : inc.riskScore >= 60 ? "text-amber-400" : "text-emerald-400";

                return (
                  <tr key={inc.incidentId} className="hover:bg-slate-800/40 transition group">
                    <td className="py-3 px-3 font-mono font-bold text-cyan-400">{inc.incidentId}</td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-100">{inc.title}</div>
                      <div className="text-[11px] text-slate-400 line-clamp-1">{inc.description}</div>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      <div className="font-mono text-[11px]">{inc.affectedUser || "system"}</div>
                      <div className="text-[10px] text-slate-400">
                        {inc.affectedAssets?.[0] || "Internal Resource"}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevBadge}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-sm font-black ${scoreColor}`}>{inc.riskScore}</span>
                        <span className="text-[10px] text-slate-400">/100</span>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                        {inc.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => onNavigate("investigation", inc.incidentId)}
                        className="px-2.5 py-1 text-[11px] font-medium rounded bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-700/60 transition inline-flex items-center gap-1"
                      >
                        Investigate <ArrowUpRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
