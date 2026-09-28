import {
  DashboardStats,
  SecurityEvent,
  Incident,
  ThreatIndicator,
  Vulnerability,
  MitreTacticGroup,
  ResponseAction,
  AuditLog,
  PhishingAnalysisResult,
  UrlAnalysisResult,
  ScenarioItem,
  AIThreatDetectionResult,
} from "../types";

export const api = {
  async getStats(): Promise<DashboardStats> {
    const res = await fetch("/api/stats");
    if (!res.ok) throw new Error("Failed to fetch SOC statistics");
    return res.json();
  },

  async getEvents(params?: { severity?: string; sourceType?: string; search?: string; limit?: number }): Promise<{ events: SecurityEvent[] }> {
    const searchParams = new URLSearchParams();
    if (params?.severity) searchParams.append("severity", params.severity);
    if (params?.sourceType) searchParams.append("sourceType", params.sourceType);
    if (params?.search) searchParams.append("search", params.search);
    if (params?.limit) searchParams.append("limit", params.limit.toString());

    const res = await fetch(`/api/events?${searchParams.toString()}`);
    if (!res.ok) throw new Error("Failed to fetch security events");
    return res.json();
  },

  async createEvent(eventData: Partial<SecurityEvent>): Promise<{ success: boolean; eventId: string }> {
    const res = await fetch("/api/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(eventData),
    });
    if (!res.ok) throw new Error("Failed to generate security event");
    return res.json();
  },

  async analyzeSecurityEvent(eventId: string, eventData?: SecurityEvent): Promise<AIThreatDetectionResult> {
    const res = await fetch(`/api/events/${eventId}/ai-analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event: eventData }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to execute AI Threat Detection for event.");
    }
    return res.json();
  },

  async getIncidents(): Promise<{ incidents: Incident[] }> {
    const res = await fetch("/api/incidents");
    if (!res.ok) throw new Error("Failed to fetch incidents");
    return res.json();
  },

  async getIncident(id: string): Promise<{ incident: Incident }> {
    const res = await fetch(`/api/incidents/${id}`);
    if (!res.ok) throw new Error(`Failed to fetch incident ${id}`);
    return res.json();
  },

  async updateIncidentStatus(id: string, status: string): Promise<{ success: boolean; status: string }> {
    const res = await fetch(`/api/incidents/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error("Failed to update incident status");
    return res.json();
  },

  async getThreatIntel(params?: { type?: string; reputation?: string; search?: string }): Promise<{
    indicators: ThreatIndicator[];
    total?: number;
    activeProvider?: string;
    isSynthetic?: boolean;
  }> {
    const query = new URLSearchParams();
    if (params?.type && params.type !== "all") query.set("type", params.type);
    if (params?.reputation && params.reputation !== "all") query.set("reputation", params.reputation);
    if (params?.search) query.set("search", params.search);

    const res = await fetch(`/api/threat-intel?${query.toString()}`);
    if (!res.ok) throw new Error("Failed to fetch threat intelligence");
    return res.json();
  },

  async lookupThreatIntel(indicator: string, typeHint?: string): Promise<{
    found: boolean;
    indicator?: ThreatIndicator;
    message?: string;
    syntheticReputation?: string;
    confidence?: number;
    isSyntheticDemo?: boolean;
  }> {
    const res = await fetch("/api/threat-intel/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indicator, typeHint }),
    });
    if (!res.ok) throw new Error("Failed to query threat intelligence");
    return res.json();
  },

  async enrichThreatIntel(indicators: string[]): Promise<{
    enriched: ThreatIndicator[];
    count: number;
    provider: string;
    isSynthetic: boolean;
  }> {
    const res = await fetch("/api/threat-intel/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indicators }),
    });
    if (!res.ok) throw new Error("Failed to enrich indicators");
    return res.json();
  },
  async searchNvdCve(cveId: string): Promise<any> {
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(
        cveId.trim()
      )}`
    );

    if (!response.ok) {
      throw new Error("Failed to fetch CVE from NVD");
    }

    const data = await response.json();

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      throw new Error(`CVE ${cveId} was not found in NVD`);
    }

    return data.vulnerabilities[0].cve;
  },
  
  async getVulnerabilities(): Promise<{ vulnerabilities: Vulnerability[] }> {
    const res = await fetch("/api/vulnerabilities");
    if (!res.ok) throw new Error("Failed to fetch vulnerabilities");
    return res.json();
  },
 
  async updateVulnerabilityStatus(id: string, remediationStatus: string): Promise<{ success: boolean }> {
    const res = await fetch(`/api/vulnerabilities/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ remediationStatus }),
    });
    if (!res.ok) throw new Error("Failed to update vulnerability status");
    return res.json();
  },

  async getMitreMatrix(): Promise<{ matrix: MitreTacticGroup[] }> {
    const res = await fetch("/api/mitre");
    if (!res.ok) throw new Error("Failed to fetch MITRE matrix");
    return res.json();
  },

  async getResponseActions(): Promise<{ actions: ResponseAction[] }> {
    const res = await fetch("/api/response-actions");
    if (!res.ok) throw new Error("Failed to fetch response actions");
    return res.json();
  },

  async reviewResponseAction(
    id: string,
    decision: "APPROVED" | "REJECTED",
    analystName: string,
    justification: string
  ): Promise<{ success: boolean }> {
    const res = await fetch(`/api/response-actions/${id}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision, analystName, justification }),
    });
    if (!res.ok) throw new Error("Failed to record response decision");
    return res.json();
  },

  async getAuditLogs(): Promise<{ logs: AuditLog[] }> {
    const res = await fetch("/api/audit-logs");
    if (!res.ok) throw new Error("Failed to fetch audit logs");
    return res.json();
  },

  async analyzePhishing(emailContent: string, sender?: string, subject?: string): Promise<PhishingAnalysisResult> {
    const res = await fetch("/api/analyze/phishing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ emailContent, sender, subject }),
    });
    if (!res.ok) throw new Error("Failed to execute phishing analysis");
    return res.json();
  },

  async createIncidentFromPhishing(
    analysis: PhishingAnalysisResult,
    options?: {
      customTitle?: string;
      affectedUser?: string;
      analystNotes?: string;
    }
  ): Promise<{
    success: boolean;
    incidentId: string;
    title: string;
    severity: string;
    riskScore: number;
    indicatorsCount: number;
    timelineMilestonesCount: number;
  }> {
    const res = await fetch("/api/phishing/create-incident", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analysis, options }),
    });
    if (!res.ok) throw new Error("Failed to create incident from phishing analysis");
    return res.json();
  },

  async analyzeUrl(url: string): Promise<UrlAnalysisResult> {
    const res = await fetch("/api/analyze/url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error("Failed to analyze URL structure");
    return res.json();
  },

  async createIncidentFromUrl(
    analysis: UrlAnalysisResult,
    options?: {
      customTitle?: string;
      affectedUser?: string;
      analystNotes?: string;
    }
  ): Promise<{
    success: boolean;
    incidentId: string;
    title: string;
    severity: string;
    riskScore: number;
    indicatorsCount: number;
    timelineMilestonesCount: number;
  }> {
    const res = await fetch("/api/url/create-incident", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analysis, options }),
    });
    if (!res.ok) throw new Error("Failed to create incident from URL analysis");
    return res.json();
  },

  async askCopilot(query: string, incidentId?: string): Promise<{
    answer: string;
    evidence: string[];
    recommendedActions: string[];
    mitreMatches: string[];
    source: "gemini" | "heuristic_fallback";
  }> {
    const res = await fetch("/api/copilot/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, incidentId }),
    });
    if (!res.ok) throw new Error("Failed to query AI Security Copilot");
    return res.json();
  },

  async getScenarios(): Promise<{ scenarios: ScenarioItem[] }> {
    const res = await fetch("/api/scenarios");
    if (!res.ok) throw new Error("Failed to fetch scenarios");
    return res.json();
  },

  async loadScenario(scenarioId: string): Promise<{ success: boolean; scenarioName: string; incidentId: string }> {
    const res = await fetch("/api/scenarios/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId }),
    });
    if (!res.ok) throw new Error("Failed to load scenario");
    return res.json();
  },

  async resetBaseline(): Promise<{ success: boolean; message: string }> {
    const res = await fetch("/api/reset", {
      method: "POST",
    });
    if (!res.ok) throw new Error("Failed to reset baseline");
    return res.json();
  },
};
