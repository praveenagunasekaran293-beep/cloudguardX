
/**
 * CyberSentinel X
 * CyberSentinel X | Cloud-Based Cybersecurity Monitoring, Threat Intelligence & SOC Intelligence Platform
 * Final-year undergraduate cybersecurity portfolio project.
 */

import React, { useState, useEffect } from "react";
import { Header } from "./components/Header";
import { Sidebar, NavTab } from "./components/Sidebar";
import { DashboardPage } from "./pages/DashboardPage";
import { SecurityEventsPage } from "./pages/SecurityEventsPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { ThreatIntelPage } from "./pages/ThreatIntelPage";
import { PhishingAnalyzerPage } from "./pages/PhishingAnalyzerPage";
import { UrlAnalyzerPage } from "./pages/UrlAnalyzerPage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";
import { MitreAttackPage } from "./pages/MitreAttackPage";
import { CopilotPage } from "./pages/CopilotPage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { RiskScoringPage } from "./pages/RiskScoringPage";
import { ResponseWorkflowPage } from "./pages/ResponseWorkflowPage";
import { AuditLogsPage } from "./pages/AuditLogsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { api } from "./services/api";
import { LoginPage } from "./auth/LoginPage";

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentTab, setCurrentTab] = useState<NavTab>("dashboard");
  const [targetIncidentId, setTargetIncidentId] = useState<string | undefined>(undefined);
  const [openIncidentsCount, setOpenIncidentsCount] = useState<number>(0);
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState<number>(0);

  const refreshBadges = async () => {
    try {
      const [incRes, actRes] = await Promise.all([
        api.getIncidents(),
        api.getResponseActions(),
      ]);

      const openCount = (incRes.incidents || []).filter(
        (i) => i.status === "Open" || i.status === "Investigating"
      ).length;

      const pendingCount = (actRes.actions || []).filter(
        (a) => a.status === "PENDING"
      ).length;

      setOpenIncidentsCount(openCount);
      setPendingApprovalsCount(pendingCount);
    } catch (err) {
      console.error("Badge refresh error:", err);
    }
  };

  useEffect(() => {
    if (!isLoggedIn) return;

    refreshBadges();

    const interval = setInterval(refreshBadges, 15000);

    return () => clearInterval(interval);
  }, [isLoggedIn]);

  const handleNavigate = (tab: NavTab, incidentId?: string) => {
    if (incidentId) {
      setTargetIncidentId(incidentId);
    }

    setCurrentTab(tab);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleScenarioLoaded = (scenarioName: string) => {
    refreshBadges();
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setCurrentTab("dashboard");
    setTargetIncidentId(undefined);
  };

  // Show login screen before opening the application.
  if (!isLoggedIn) {
    return <LoginPage onLogin={() => setIsLoggedIn(true)} />;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Application Header */}
      <Header
       onScenarioLoaded={handleScenarioLoaded}
       activeIncidentId={targetIncidentId}
       onLogout={handleLogout}
      />

      <div className="flex flex-1">
        {/* Left SOC Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={(tab) => handleNavigate(tab)}
          openIncidentsCount={openIncidentsCount}
          pendingApprovalsCount={pendingApprovalsCount}
        />

        {/* Main Content Area */}
        <main className="flex-1 p-6 lg:p-8 overflow-y-auto max-w-7xl mx-auto w-full">
          {currentTab === "dashboard" && (
            <DashboardPage onNavigate={handleNavigate} />
          )}

          {currentTab === "events" && (
            <SecurityEventsPage onNavigate={handleNavigate} />
          )}

          {currentTab === "incidents" && (
            <IncidentsPage onNavigate={handleNavigate} />
          )}

          {currentTab === "investigation" && (
            <InvestigationPage
              initialIncidentId={targetIncidentId}
              onNavigate={handleNavigate}
            />
          )}

          {currentTab === "threat-intel" && (
            <ThreatIntelPage onNavigate={handleNavigate} />
          )}

          {currentTab === "vulnerabilities" && (
            <VulnerabilitiesPage />
          )}

          {currentTab === "mitre" && (
            <MitreAttackPage />
          )}

          {currentTab === "phishing" && (
            <PhishingAnalyzerPage onNavigate={handleNavigate} />
          )}

          {currentTab === "url-analyzer" && (
            <UrlAnalyzerPage onNavigate={handleNavigate} />
          )}

          {currentTab === "copilot" && (
            <CopilotPage initialIncidentId={targetIncidentId} />
          )}

          {currentTab === "risk-scoring" && (
            <RiskScoringPage initialIncidentId={targetIncidentId} />
          )}

          {currentTab === "response-workflow" && (
            <ResponseWorkflowPage />
          )}

          {currentTab === "audit-logs" && (
            <AuditLogsPage />
          )}

          {currentTab === "settings" && (
            <SettingsPage
              onNavigate={handleNavigate}
              onScenarioLoaded={handleScenarioLoaded}
            />
          )}
        </main>
      </div>
    </div>
  );
}