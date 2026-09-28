export type SeverityLevel = "Critical" | "High" | "Medium" | "Low";
export type IncidentStatus = "Open" | "Investigating" | "Resolved" | "Closed";
export type ActionDecision = "PENDING" | "APPROVED" | "REJECTED";
export type ThreatClassification = "NORMAL" | "SUSPICIOUS" | "MALICIOUS";

export interface AIThreatDetectionResult {
  eventId: string;
  classification: ThreatClassification;
  severity: SeverityLevel;
  riskScore: number;
  confidence: number;
  threatCategory: string;
  evidence: string[];
  explanation: {
    summary: string;
    aiInference: string;
    deterministicRules: string[];
    syntheticTelemetryContext: string;
    externalIntelligenceContext: string;
  };
  recommendedInvestigation: string[];
  engine: "gemini" | "rule_heuristic";
}

export interface SecurityEvent {
  eventId: string;
  timestamp: string;
  source: string;
  sourceType: string;
  user: string;
  ip: string;
  hostname: string;
  eventType: string;
  description: string;
  severity: SeverityLevel;
  indicators: string[];
  metadata: Record<string, any>;
}

export interface TimelineEntry {
  time: string;
  event: string;
  source: string;
  severity: SeverityLevel;
}

export interface MitreTechniqueRef {
  id: string;
  name: string;
  tactic: string;
  status: string;
}

export interface RiskFactor {
  name: string;
  points: number;
  reason: string;
}

export interface RiskBreakdown {
  factors: RiskFactor[];
  totalScore: number;
  maxScore: number;
  explanation: string;
}

export interface Incident {
  incidentId: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  riskScore: number;
  status: IncidentStatus;
  affectedUser: string;
  affectedAssets: string[];
  relatedEvents: string[];
  indicators: string[];
  timeline: TimelineEntry[];
  mitreTechniques: MitreTechniqueRef[];
  recommendations: string[];
  riskBreakdown?: RiskBreakdown;
  createdAt: string;
  updatedAt: string;
}

export type IndicatorType = "IP" | "Domain" | "URL" | "SHA-256";
export type IndicatorReputation = "Malicious" | "Suspicious" | "Benign" | "Unknown";

export interface ThreatIndicator {
  id: string;
  indicator: string;
  type: IndicatorType;
  reputation: IndicatorReputation;
  status: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  source: string;
  relatedIncidents: string[];
  threatGroup?: string;
  tags: string[];
  notes?: string;
  isSyntheticDemo?: boolean;
  metadata?: Record<string, any>;
}

export interface Vulnerability {
  cveId: string;
  asset: string;
  title: string;
  severity: SeverityLevel;
  cvss: number;
  exposure: string;
  assetImportance: string;
  priority: number;
  priorityExplanation?: string;
  remediationStatus: string;
  remediationPlaybook?: string;
  description: string;
  discoveredAt: string;
}

export interface MitreTechniqueDetailed {
  id: string;
  name: string;
  status: string;
  incidents: string[];
  reason: string;
  evidence: string;
  detectionGuidance: string;
  mitigationGuidance: string;
}

export interface MitreTacticGroup {
  tacticId: string;
  tacticName: string;
  techniques: MitreTechniqueDetailed[];
}

export interface ResponseAction {
  id: string;
  incidentId: string;
  title: string;
  actionType: string;
  description: string;
  recommendedBy: string;
  riskLevel: SeverityLevel;
  status: ActionDecision;
  decidedBy?: string | null;
  decidedAt?: string | null;
  justification?: string | null;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  userAction: string;
  actionType: string;
  incidentId?: string;
  aiRecommendation?: string;
  analystDecision?: string;
  details: string;
}

export interface PhishingRiskFactor {
  factor: string;
  points: number;
  reason: string;
  verified?: boolean;
}

export interface SocialEngineeringIndicator {
  principle: string;
  evidence: string;
  explanation: string;
}

export interface ExtractedPhishingIndicator {
  indicator: string;
  type: "Domain" | "URL" | "IP" | "Email";
  isVerifiedMalicious: boolean;
  source?: string;
}

export interface PhishingAnalysisResult {
  sender: string;
  subject: string;
  extractedUrls: string[];
  urls?: string[];
  domains?: string[];
  urgencyIndicators?: string[];
  urgencyMarkers: string[];
  credentialRequests: string[];
  suspiciousLanguage?: string[];
  socialEngineeringIndicators?: SocialEngineeringIndicator[];
  domainMismatch?: boolean;
  riskScore: number;
  classification: string;
  riskBreakdown?: {
    factors: PhishingRiskFactor[];
    totalScore: number;
    explanation: string;
  };
  reasons: string[];
  evidence?: string[];
  explanation?: {
    summary: string;
    geminiAssessment: string;
    threatIntelVerification: {
      verifiedIndicators: Array<{
        indicator: string;
        type: string;
        reputation: string;
        source: string;
        confidence: number;
      }>;
      unverifiedIndicators: Array<{
        indicator: string;
        type: string;
        reason: string;
      }>;
    };
  };
  aiAnalysis?: string | null;
  extractedIndicators?: ExtractedPhishingIndicator[];
  recommendedInvestigation: string[];
  engine?: string;
}

export interface UrlCheck {
  name: string;
  category?: string;
  status: "safe" | "warning" | "danger";
  details: string;
  points: number;
}

export interface ExtractedUrlIndicator {
  indicator: string;
  type: "Domain" | "URL" | "IP" | "Path" | "Parameter";
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  description: string;
  isThreatIntelMatch?: boolean;
  reputation?: string;
  source?: string;
  confidence?: number;
}

export interface UrlAnalysisResult {
  valid: boolean;
  error?: string;
  url?: string;
  riskScore: number;
  classification: "Malicious" | "Suspicious" | "Benign" | string;
  structuralDetails?: {
    protocol: string;
    hostname: string;
    port: string;
    pathname: string;
    search: string;
    hash: string;
    length: number;
    subdomainsCount?: number;
    subdomainList?: string[];
    entropyScore?: number;
    isIpHost?: boolean;
    isHttps?: boolean;
    hasUserinfo?: boolean;
    hasPunycode?: boolean;
    encodingFindings?: string[];
    pathFindings?: string[];
    queryFindings?: string[];
  } | null;
  checks: UrlCheck[];
  indicators?: ExtractedUrlIndicator[];
  explanation?: {
    summary: string;
    factors: Array<{ factor: string; points: number; reason: string }>;
    geminiAssessment?: string;
    threatIntelCorrelation?: {
      matchedIndicators: Array<{
        indicator: string;
        type: string;
        reputation: string;
        source: string;
        confidence: number;
      }>;
      relatedIncidents: string[];
    };
  };
  recommendedInvestigation?: string[];
  defensiveGuidance: string[];
  engine?: string;
}

export interface ScenarioItem {
  id: string;
  name: string;
  category: string;
  description: string;
}

export interface DashboardStats {
  summary: {
    totalSecurityEvents: number;
    criticalIncidents: number;
    highRiskIncidents: number;
    suspiciousEvents: number;
    openIncidents: number;
    vulnerabilities: number;
  };
  severityDistribution: { name: string; count: number; color: string }[];
  incidentCategories: { name: string; count: number }[];
  timeTrend: { time: string; events: number; alerts: number }[];
  mitreDistribution: { technique: string; count: number; tactic: string }[];
}
