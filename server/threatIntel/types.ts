export type IndicatorType = "IP" | "Domain" | "URL" | "SHA-256";

export type IndicatorReputation = "Malicious" | "Suspicious" | "Benign" | "Unknown";

export interface EnrichedIndicator {
  id: string;
  indicator: string;
  type: IndicatorType;
  reputation: IndicatorReputation;
  status: string; // backwards compatibility
  confidence: number; // 0 - 100
  source: string;
  firstSeen: string;
  lastSeen: string;
  relatedIncidents: string[];
  threatGroup?: string;
  tags: string[];
  notes?: string;
  isSyntheticDemo: boolean;
  metadata?: Record<string, any>;
}

export interface ThreatIntelFilter {
  type?: string;
  reputation?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface IndicatorLookupResult {
  found: boolean;
  indicator?: EnrichedIndicator;
  query: string;
  message: string;
  isSyntheticDemo: boolean;
}
