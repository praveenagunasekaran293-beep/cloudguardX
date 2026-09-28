import { db } from "../db.js";
import { ThreatIntelProvider } from "./provider.js";
import { EnrichedIndicator, IndicatorReputation, IndicatorType, ThreatIntelFilter } from "./types.js";

/**
 * Autodetect indicator type based on structure
 */
export function detectIndicatorType(indicator: string): IndicatorType {
  const clean = indicator.trim();

  // SHA-256 regex (64 hex characters, optionally prefixed with SHA256:)
  const sha256Pattern = /^(?:sha256:)?([a-fA-F0-9]{64})$/i;
  if (sha256Pattern.test(clean) || (clean.length === 64 && /^[a-fA-F0-9]+$/.test(clean))) {
    return "SHA-256";
  }

  // URL regex
  if (
    clean.startsWith("http://") ||
    clean.startsWith("https://") ||
    (clean.includes("/") && (clean.includes("?") || clean.split("/").length > 2))
  ) {
    return "URL";
  }

  // IPv4 regex (including standard RFC 5737 testnets: 192.0.2.x, 198.51.100.x, 203.0.113.x, 10.x.x.x)
  const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/\d{1,2})?$/;
  if (ipv4Pattern.test(clean)) {
    return "IP";
  }

  // IPv6 check
  if (clean.includes(":") && clean.split(":").length >= 3) {
    return "IP";
  }

  // Fallback to Domain (e.g. host.domain.tld)
  return "Domain";
}

/**
 * Normalize raw status or reputation strings
 */
export function normalizeReputation(rawStatus: string, confidence: number = 50): IndicatorReputation {
  const s = (rawStatus || "").toLowerCase();
  if (s.includes("malicious") || s.includes("critical") || s.includes("infected") || confidence >= 80) {
    return "Malicious";
  }
  if (s.includes("suspicious") || s.includes("untrusted") || s.includes("anomaly") || confidence >= 50) {
    return "Suspicious";
  }
  if (s.includes("benign") || s.includes("clean") || s.includes("allowlist") || s.includes("safe")) {
    return "Benign";
  }
  return "Unknown";
}

/**
 * Normalize raw type to strict IndicatorType
 */
export function normalizeIndicatorType(rawType: string, indicator: string): IndicatorType {
  const t = (rawType || "").toLowerCase();
  if (t.includes("sha") || t.includes("hash") || t.includes("file")) {
    return "SHA-256";
  }
  if (t === "ip" || t.includes("address")) {
    return "IP";
  }
  if (t === "domain" || t.includes("host") || t.includes("fqdn")) {
    return "Domain";
  }
  if (t === "url" || t.includes("uri") || t.includes("link")) {
    return "URL";
  }
  return detectIndicatorType(indicator);
}

/**
 * Find related incidents for an indicator across the database
 */
async function findRelatedIncidents(indicator: string): Promise<string[]> {
  try {
    const clean = indicator.trim().toLowerCase();
    // Query incidents table
    const res = await db.execute({
      sql: "SELECT incidentId, indicators FROM incidents",
      args: [],
    });

    const related: string[] = [];
    for (const row of res.rows) {
      const incId = String(row.incidentId);
      const rawIndicators = row.indicators ? String(row.indicators).toLowerCase() : "";
      if (rawIndicators.includes(clean)) {
        if (!related.includes(incId)) {
          related.push(incId);
        }
      }
    }
    return related;
  } catch (err) {
    console.warn("Could not query related incidents for indicator:", err);
    return [];
  }
}

/**
 * Synthetic Demo Threat Intelligence Provider
 * Implements ThreatIntelProvider for CyberSentinel X
 */
export class SyntheticDemoThreatIntelProvider implements ThreatIntelProvider {
  readonly id = "synthetic_demo_provider";
  readonly name = "Synthetic Demo Intelligence Engine (RFC 5737 Testbed)";
  readonly isSynthetic = true;
  readonly description =
    "Defensive simulation threat intelligence provider strictly using synthetic testbed IOCs and simulated telemetry. Explicitly decoupled from production feeds.";

  async lookup(indicator: string, typeHint?: IndicatorType): Promise<EnrichedIndicator | null> {
    const clean = indicator.trim();
    if (!clean) return null;

    const lowerClean = clean.toLowerCase();
    const detectedType = typeHint || detectIndicatorType(clean);

    // 1. Search in SQLite threat_intel table (prioritize exact match)
    try {
      let res = await db.execute({
        sql: "SELECT * FROM threat_intel WHERE LOWER(indicator) = ? LIMIT 1",
        args: [lowerClean],
      });

      if (res.rows.length === 0) {
        res = await db.execute({
          sql: "SELECT * FROM threat_intel WHERE LOWER(indicator) LIKE ? LIMIT 1",
          args: [`%${lowerClean}%`],
        });
      }

      if (res.rows.length > 0) {
        const row = res.rows[0];
        const rawTags = row.tags ? (typeof row.tags === "string" ? JSON.parse(row.tags) : row.tags) : [];
        const related = await findRelatedIncidents(clean);
        const normType = normalizeIndicatorType(String(row.type), String(row.indicator));
        const reputation = normalizeReputation(String(row.status), Number(row.confidence));

        return {
          id: String(row.id),
          indicator: String(row.indicator),
          type: normType,
          reputation,
          status: String(row.status),
          confidence: Number(row.confidence) || 85,
          source: String(row.source) || "Synthetic CyberSentinel Demo Feed",
          firstSeen: String(row.firstSeen) || new Date(Date.now() - 30 * 86400000).toISOString(),
          lastSeen: String(row.lastSeen) || new Date().toISOString(),
          relatedIncidents: related,
          threatGroup: row.threatGroup ? String(row.threatGroup) : "Synthetic Threat Group Emulation",
          tags: Array.isArray(rawTags) ? rawTags : ["synthetic-indicator"],
          notes: row.notes ? String(row.notes) : "Synthetic threat intelligence artifact used for defensive testing.",
          isSyntheticDemo: true,
          metadata: {
            providerId: this.id,
            autodetectedType: detectedType,
            rfcCompliantTestnet: normType === "IP" ? clean.startsWith("198.51.100.") || clean.startsWith("203.0.113.") || clean.startsWith("192.0.2.") : undefined,
          },
        };
      }
    } catch (err) {
      console.warn("DB lookup in threat_intel failed:", err);
    }

    // 2. Fallback heuristic for known simulated scenario indicators not yet in table
    const related = await findRelatedIncidents(clean);
    const reputation = clean.includes("malware") || clean.includes("c2") || clean.includes("phish") || clean.includes("evil")
      ? "Malicious"
      : clean.includes("suspicious") || clean.includes("duckdns") || clean.includes(".top") || clean.includes(".xyz")
      ? "Suspicious"
      : "Unknown";

    const confidence = reputation === "Malicious" ? 90 : reputation === "Suspicious" ? 70 : 25;

    return {
      id: `SYN-IND-${Math.abs(clean.split("").reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) | 0, 0))}`,
      indicator: clean,
      type: detectedType,
      reputation,
      status: `${reputation} (Synthetic Query)`,
      confidence,
      source: "Synthetic Threat Intelligence Dynamic Resolver",
      firstSeen: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeen: new Date().toISOString(),
      relatedIncidents: related,
      threatGroup: "Simulated Telemetry Observation",
      tags: ["dynamic-lookup", "synthetic-simulation", detectedType.toLowerCase()],
      notes: "Dynamically evaluated synthetic indicator query. No verified external compromise recorded.",
      isSyntheticDemo: true,
      metadata: {
        providerId: this.id,
        simulatedResolver: true,
      },
    };
  }

  async list(filter?: ThreatIntelFilter): Promise<EnrichedIndicator[]> {
    try {
      const res = await db.execute("SELECT * FROM threat_intel ORDER BY confidence DESC");
      const enrichedList: EnrichedIndicator[] = [];

      for (const row of res.rows) {
        const rawTags = row.tags ? (typeof row.tags === "string" ? JSON.parse(row.tags) : row.tags) : [];
        const normType = normalizeIndicatorType(String(row.type), String(row.indicator));
        const reputation = normalizeReputation(String(row.status), Number(row.confidence));
        const related = await findRelatedIncidents(String(row.indicator));

        const item: EnrichedIndicator = {
          id: String(row.id),
          indicator: String(row.indicator),
          type: normType,
          reputation,
          status: String(row.status),
          confidence: Number(row.confidence) || 80,
          source: String(row.source) || "Synthetic Threat Feed Demo",
          firstSeen: String(row.firstSeen) || new Date(Date.now() - 30 * 86400000).toISOString(),
          lastSeen: String(row.lastSeen) || new Date().toISOString(),
          relatedIncidents: related,
          threatGroup: row.threatGroup ? String(row.threatGroup) : undefined,
          tags: Array.isArray(rawTags) ? rawTags : [],
          notes: row.notes ? String(row.notes) : undefined,
          isSyntheticDemo: true,
        };

        // Apply filters
        if (filter) {
          if (filter.type && filter.type !== "all" && item.type !== filter.type) {
            continue;
          }
          if (filter.reputation && filter.reputation !== "all" && item.reputation !== filter.reputation) {
            continue;
          }
          if (filter.search) {
            const q = filter.search.toLowerCase();
            const matches =
              item.indicator.toLowerCase().includes(q) ||
              (item.threatGroup && item.threatGroup.toLowerCase().includes(q)) ||
              item.source.toLowerCase().includes(q) ||
              item.tags.some((t) => t.toLowerCase().includes(q));
            if (!matches) continue;
          }
        }

        enrichedList.push(item);
      }

      return enrichedList;
    } catch (err) {
      console.error("Failed to list indicators in SyntheticDemoThreatIntelProvider:", err);
      return [];
    }
  }

  async enrich(indicators: string[]): Promise<EnrichedIndicator[]> {
    const results: EnrichedIndicator[] = [];
    for (const ind of indicators) {
      if (!ind || typeof ind !== "string") continue;
      const res = await this.lookup(ind);
      if (res) {
        results.push(res);
      }
    }
    return results;
  }

  async testConnection(): Promise<{ ok: boolean; message: string; version: string }> {
    return {
      ok: true,
      message: "Synthetic Demo Threat Intelligence Engine operational. 100% simulated RFC-5737 compliant testbed.",
      version: "2.1.0-synthetic-defense",
    };
  }
}
