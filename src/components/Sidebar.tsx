import React from "react";
import {
  LayoutDashboard,
  Radio,
  AlertTriangle,
  Globe2,
  MailCheck,
  Link2,
  Bug,
  Crosshair,
  Bot,
  Clock,
  Scale,
  ShieldCheck,
  ScrollText,
  Sliders,
  Flame,
} from "lucide-react";

export type NavTab =
  | "dashboard"
  | "events"
  | "incidents"
  | "threat-intel"
  | "phishing"
  | "url-analyzer"
  | "vulnerabilities"
  | "mitre"
  | "copilot"
  | "investigation"
  | "risk-scoring"
  | "response-workflow"
  | "audit-logs"
  | "settings";

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  openIncidentsCount?: number;
  pendingApprovalsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  openIncidentsCount = 0,
  pendingApprovalsCount = 0,
}) => {
  const navSections = [
    {
      title: "OPERATIONS & TELEMETRY",
      items: [
        { id: "dashboard" as NavTab, label: "Dashboard", icon: LayoutDashboard },
        { id: "events" as NavTab, label: "Security Events", icon: Radio },
        {
          id: "incidents" as NavTab,
          label: "Incident Triage",
          icon: AlertTriangle,
          badge: openIncidentsCount > 0 ? openIncidentsCount : undefined,
          badgeColor: "bg-red-500/20 text-red-400 border border-red-500/30",
        },
        {
          id: "investigation" as NavTab,
          label: "Investigation Timeline",
          icon: Clock,
        },
      ],
    },
    {
      title: "INTELLIGENCE & ANALYSIS",
      items: [
        { id: "threat-intel" as NavTab, label: "Threat Intelligence", icon: Globe2 },
        { id: "vulnerabilities" as NavTab, label: "Vulnerabilities", icon: Bug },
        { id: "mitre" as NavTab, label: "MITRE ATT&CK", icon: Crosshair },
        { id: "phishing" as NavTab, label: "Phishing Analyzer", icon: MailCheck },
        { id: "url-analyzer" as NavTab, label: "URL Analyzer", icon: Link2 },
      ],
    },
    {
      title: "AUTONOMOUS DEFENSE & GOVERNANCE",
      items: [
        {
          id: "copilot" as NavTab,
          label: "AI Security Copilot",
          icon: Bot,
          highlight: true,
        },
        { id: "risk-scoring" as NavTab, label: "Explainable Risk Scoring", icon: Scale },
        {
          id: "response-workflow" as NavTab,
          label: "Human Approval Response",
          icon: ShieldCheck,
          badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
          badgeColor: "bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse",
        },
        { id: "audit-logs" as NavTab, label: "Audit Logs", icon: ScrollText },
        { id: "settings" as NavTab, label: "Settings & Scenarios", icon: Sliders },
      ],
    },
  ];

  return (
    <aside className="w-64 bg-slate-900/95 border-r border-slate-800 flex flex-col shrink-0 min-h-[calc(100vh-65px)]">
      <div className="p-3 space-y-6 flex-1 overflow-y-auto">
        {navSections.map((section, idx) => (
          <div key={idx} className="space-y-1">
            <h3 className="px-3 text-[10px] font-bold tracking-wider text-slate-400 uppercase">
              {section.title}
            </h3>
            <div className="mt-1 space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onSelectTab(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-lg transition group ${
                      isActive
                        ? "bg-cyan-950/70 text-cyan-300 border border-cyan-700/50 shadow-sm shadow-cyan-950"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
                    } ${item.highlight && !isActive ? "text-cyan-400/90" : ""}`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon
                        className={`w-4 h-4 transition ${
                          isActive
                            ? "text-cyan-400"
                            : item.highlight
                            ? "text-cyan-400 group-hover:text-cyan-300"
                            : "text-slate-400 group-hover:text-slate-300"
                        }`}
                      />
                      <span>{item.label}</span>
                    </div>

                    {item.badge !== undefined && (
                      <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded-full ${item.badgeColor}`}>
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* SOC Analyst Profile Footer */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/60">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-cyan-400">
            PG
          </div>
          <div className="overflow-hidden">
            <div className="text-xs font-semibold text-slate-200 truncate">Lead SOC Analyst</div>
            <div className="text-[10px] text-slate-400 truncate">Praveena G. (Security Ops)</div>
          </div>
        </div>
      </div>
    </aside>
  );
};
