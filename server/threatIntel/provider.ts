import { EnrichedIndicator, IndicatorLookupResult, IndicatorType, ThreatIntelFilter } from "./types.js";

/**
 * ThreatIntelProvider
 * Clean provider abstraction interface.
 * Allows synthetic demo providers and future external providers
 * (e.g. VirusTotal, AbuseIPDB, AlienVault OTX, CrowdStrike Falcon X)
 * to be plugged in seamlessly.
 */
export interface ThreatIntelProvider {
  readonly id: string;
  readonly name: string;
  readonly isSynthetic: boolean;
  readonly description: string;

  /**
   * Look up a single indicator in the provider's threat database
   */
  lookup(indicator: string, typeHint?: IndicatorType): Promise<EnrichedIndicator | null>;

  /**
   * List or search indicators with optional filtering
   */
  list(filter?: ThreatIntelFilter): Promise<EnrichedIndicator[]>;

  /**
   * Batch enrich a collection of indicator strings
   */
  enrich(indicators: string[]): Promise<EnrichedIndicator[]>;

  /**
   * Health / test connectivity check
   */
  testConnection(): Promise<{ ok: boolean; message: string; version: string }>;
}
