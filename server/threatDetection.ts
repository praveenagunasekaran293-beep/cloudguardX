import { GoogleGenAI } from "@google/genai";
import { db } from "./db.js";

const apiKey = process.env.GEMINI_API_KEY || "";
const ai = new GoogleGenAI({
  apiKey: apiKey,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

export type ThreatClassification = "NORMAL" | "SUSPICIOUS" | "MALICIOUS";

export interface SecurityEventInput {
  eventId: string;
  timestamp: string;
  source: string;
  sourceType: string;
  user?: string;
  ip?: string;
  hostname?: string;
  eventType: string;
  description: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  indicators?: string[];
  metadata?: Record<string, any>;
}

export interface AIThreatDetectionResult {
  eventId: string;
  classification: ThreatClassification;
  severity: "Critical" | "High" | "Medium" | "Low";
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

export async function analyzeSecurityEvent(event: SecurityEventInput): Promise<AIThreatDetectionResult> {
  // 1. Deterministic Rule Matching (Ground truth heuristics)
  const deterministicRulesTriggered: string[] = [];
  const indicators = event.indicators || [];
  const eventDesc = (event.description || "").toLowerCase();
  const eventType = (event.eventType || "").toLowerCase();
  const meta = event.metadata || {};

  // Rule 1: Encoded PowerShell / Command Execution
  if (
    eventDesc.includes("encoded") ||
    eventDesc.includes("base64") ||
    eventType.includes("powershell") ||
    JSON.stringify(meta).toLowerCase().includes("powershell")
  ) {
    deterministicRulesTriggered.push("RULE-EX-101: Obfuscated/Base64 Command Execution detected in process parameters");
  }

  // Rule 2: Impossible Travel / Geolocation Anomaly
  if (
    eventDesc.includes("impossible travel") ||
    eventType.includes("impossible travel") ||
    meta.travelSpeedMph > 500
  ) {
    deterministicRulesTriggered.push(`RULE-IAM-204: Impossible Travel anomaly (velocity ${meta.travelSpeedMph || ">500"} mph across sequential logins)`);
  }

  // Rule 3: Phishing / Spoofed Domain
  if (
    eventType.includes("phishing") ||
    eventDesc.includes("phishing") ||
    meta.spf === "fail" ||
    indicators.some((ind) => ind.endsWith(".top") || ind.endsWith(".cc") || ind.endsWith(".xyz"))
  ) {
    deterministicRulesTriggered.push("RULE-SEG-302: Inbound message SPF/DKIM verification failure or high-abuse TLD link");
  }

  // Rule 4: Process Memory Injection
  if (
    eventDesc.includes("memory injection") ||
    eventDesc.includes("inject") ||
    eventType.includes("injection")
  ) {
    deterministicRulesTriggered.push("RULE-EDR-405: Cross-process memory handle acquisition or thread injection into legitimate binary");
  }

  // Rule 5: Internal Network Discovery / Port Sweeping
  if (
    eventType.includes("reconnaissance") ||
    eventType.includes("port scan") ||
    eventDesc.includes("reconnaissance") ||
    (meta.packetsSent && meta.packetsSent > 500)
  ) {
    deterministicRulesTriggered.push("RULE-NET-510: Horizontal internal port scan sweep targeting Active Directory / SMB (TCP 445/135)");
  }

  // Rule 6: Cloud IAM / S3 Permission Alteration
  if (
    eventType.includes("policy modification") ||
    eventDesc.includes("public read") ||
    meta.principal === "*"
  ) {
    deterministicRulesTriggered.push("RULE-CSPM-608: Unrestricted Principal wildcard (*) granted on sensitive cloud storage policy");
  }

  // Rule 7: Beaconing / C2 Pattern
  if (
    eventType.includes("beaconing") ||
    eventDesc.includes("beacon") ||
    eventDesc.includes("c2")
  ) {
    deterministicRulesTriggered.push("RULE-NIDS-712: Regular interval socket transmission (jitter <= 5s) to untrusted remote destination");
  }

  // 2. Query Application Synthetic Threat Intelligence Database (Do NOT invent external intel)
  let matchedIntel: any[] = [];
  try {
    for (const ind of indicators) {
      const clean = ind.trim().toLowerCase();
      if (!clean) continue;
      const res = await db.execute({
        sql: "SELECT * FROM threat_intel WHERE LOWER(indicator) = ? OR LOWER(indicator) LIKE ?",
        args: [clean, `%${clean}%`],
      });
      if (res.rows.length > 0) {
        matchedIntel.push(...res.rows);
      }
    }
    // Also check IP
    if (event.ip && !indicators.includes(event.ip)) {
      const res = await db.execute({
        sql: "SELECT * FROM threat_intel WHERE indicator = ?",
        args: [event.ip],
      });
      if (res.rows.length > 0) {
        matchedIntel.push(...res.rows);
      }
    }
  } catch (err) {
    console.warn("Could not query threat_intel table for event:", err);
  }

  const externalIntelligenceContext = matchedIntel.length > 0
    ? `SYNTHETIC THREAT INTEL MATCH FOUND: ${matchedIntel.map((m) => `[${m.type}: ${m.indicator} | Status: ${m.status} | Confidence: ${m.confidence}% | Group: ${m.threatGroup || "Unknown"}]`).join("; ")}. This intelligence originates strictly from the platform's internal synthetic threat intelligence database.`
    : "NO MATCH in internal synthetic threat intelligence database. No prior observed threat correlation recorded for these indicators in application state.";

  const syntheticTelemetryContext = `Event ID: ${event.eventId} | Timestamp: ${event.timestamp} | Sensor: ${event.source} (${event.sourceType}) | Identity: ${event.user || "N/A"} | Host/IP: ${event.hostname || "N/A"} (${event.ip || "N/A"}) | Classification: ${event.eventType}. Telemetry generated via synthetic defense testbed.`;

  // 3. Server-side Gemini AI Threat Analysis
  if (apiKey) {
    try {
      const systemInstruction = `You are CyberSentinel X AI Threat Detection Engine, an autonomous defensive SOC analysis system.
You analyze an incoming SecurityEvent strictly based on the provided event fields, deterministic rule matches, and synthetic threat intelligence context.

MANDATORY GUIDELINES:
1. Classify the event strictly into one of: "NORMAL", "SUSPICIOUS", "MALICIOUS".
2. Assess Severity: "Critical", "High", "Medium", or "Low".
3. Calculate a calibrated riskScore (0 to 100) and confidence (0 to 100).
4. Assign a precise MITRE/SOC threatCategory (e.g., "Initial Access: Spearphishing", "Execution: Obfuscated PowerShell", "Credential Access: Impossible Travel", "Cloud Security: IAM Misconfiguration", "Command & Control: C2 Beaconing").
5. Extract concrete Evidence items from the provided event parameters.
6. Clearly distinguish between:
   - "aiInference": Your analytical deduction regarding adversary intent, kill-chain progression, and behavioral anomalies.
   - "summary": High-level executive synthesis.
   - "recommendedInvestigation": Concrete, defensive next steps for the SOC analyst to verify and contain the event.
7. DO NOT invent fictitious external databases, CVEs, or external feeds not present in the context. Rely strictly on provided synthetic application context.
8. Output MUST be valid JSON adhering to the specified schema.`;

      const prompt = `SECURITY EVENT TELEMETRY:
${syntheticTelemetryContext}
Description: ${event.description}
Indicators: ${JSON.stringify(indicators)}
Metadata: ${JSON.stringify(meta)}
Current Assigned Severity: ${event.severity}

DETERMINISTIC RULES TRIGGERED BY SENSOR HEURISTICS:
${deterministicRulesTriggered.length > 0 ? deterministicRulesTriggered.join("\n") : "None triggered."}

INTERNAL SYNTHETIC THREAT INTELLIGENCE CONTEXT:
${externalIntelligenceContext}

Respond ONLY with valid JSON with this exact schema:
{
  "classification": "NORMAL" | "SUSPICIOUS" | "MALICIOUS",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "riskScore": number,
  "confidence": number,
  "threatCategory": string,
  "summary": string,
  "aiInference": string,
  "evidence": string[],
  "recommendedInvestigation": string[]
}`;

      const response = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          systemInstruction: systemInstruction,
          temperature: 0.1,
          responseMimeType: "application/json",
        },
      });

      const parsed = JSON.parse(response.text || "{}");

      if (parsed.classification && parsed.riskScore !== undefined) {
        return {
          eventId: event.eventId,
          classification: (parsed.classification.toUpperCase() as ThreatClassification) || "SUSPICIOUS",
          severity: parsed.severity || event.severity,
          riskScore: Math.min(Math.max(Number(parsed.riskScore) || 50, 0), 100),
          confidence: Math.min(Math.max(Number(parsed.confidence) || 85, 10), 100),
          threatCategory: parsed.threatCategory || event.eventType,
          evidence: Array.isArray(parsed.evidence) && parsed.evidence.length > 0 ? parsed.evidence : indicators,
          explanation: {
            summary: parsed.summary || `${parsed.classification} threat detected in ${event.source} telemetry.`,
            aiInference: parsed.aiInference || "Inference derived from behavioral correlation of sensor anomalies.",
            deterministicRules: deterministicRulesTriggered,
            syntheticTelemetryContext,
            externalIntelligenceContext,
          },
          recommendedInvestigation: Array.isArray(parsed.recommendedInvestigation) && parsed.recommendedInvestigation.length > 0
            ? parsed.recommendedInvestigation
            : [
                "Verify host telemetry with endpoint EDR agent.",
                "Review identity sign-on logs for anomalous geolocations.",
                "Confirm indicator presence in boundary firewall drops.",
              ],
          engine: "gemini",
        };
      }
    } catch (err: any) {
      console.warn("Gemini threat detection call failed, using deterministic rule fallback:", err?.message || err);
    }
  }

  // 4. Deterministic Heuristic Fallback Engine
  return generateDeterministicAnalysis(
    event,
    deterministicRulesTriggered,
    syntheticTelemetryContext,
    externalIntelligenceContext,
    matchedIntel
  );
}

function generateDeterministicAnalysis(
  event: SecurityEventInput,
  rules: string[],
  syntheticTelemetryContext: string,
  externalIntelligenceContext: string,
  matchedIntel: any[]
): AIThreatDetectionResult {
  let classification: ThreatClassification = "NORMAL";
  let riskScore = 20;
  let confidence = 80;
  let severity: "Critical" | "High" | "Medium" | "Low" = "Low";
  let threatCategory = event.eventType;

  if (rules.length >= 2 || matchedIntel.length > 0 || event.severity === "Critical") {
    classification = "MALICIOUS";
    riskScore = Math.max(82, event.severity === "Critical" ? 92 : 84);
    severity = event.severity === "Critical" ? "Critical" : "High";
    confidence = 94;
  } else if (rules.length === 1 || event.severity === "High" || event.severity === "Medium") {
    classification = "SUSPICIOUS";
    riskScore = event.severity === "High" ? 72 : 55;
    severity = event.severity === "High" ? "High" : "Medium";
    confidence = 86;
  }

  // Threat Category classification
  const desc = (event.description || "").toLowerCase();
  if (desc.includes("powershell") || desc.includes("injection") || desc.includes("process")) {
    threatCategory = "Execution & Endpoint Defense Evasion";
  } else if (desc.includes("phishing") || desc.includes("email") || desc.includes("payroll")) {
    threatCategory = "Initial Access: Targeted Spearphishing";
  } else if (desc.includes("travel") || desc.includes("login") || desc.includes("auth")) {
    threatCategory = "Credential Access: Anomaly & Hijacking";
  } else if (desc.includes("cloud") || desc.includes("s3") || desc.includes("policy")) {
    threatCategory = "Cloud Infrastructure & Data Exposure";
  } else if (desc.includes("port") || desc.includes("reconnaissance") || desc.includes("scan")) {
    threatCategory = "Discovery: Internal Network Reconnaissance";
  } else if (desc.includes("beacon") || desc.includes("c2")) {
    threatCategory = "Command and Control: Encrypted Beaconing";
  }

  const evidence: string[] = [];
  if (event.ip) evidence.push(`Origin IP: ${event.ip}`);
  if (event.hostname) evidence.push(`Asset Host: ${event.hostname}`);
  if (event.user) evidence.push(`Subject Identity: ${event.user}`);
  if (event.indicators) evidence.push(...event.indicators);

  const aiInference = classification === "MALICIOUS"
    ? `Behavioral deduction reveals an active malicious security deviation. The observed telemetry demonstrates signature alignment with ${threatCategory.toLowerCase()}. The high probability of adversary activity is reinforced by ${rules.length} positive deterministic rule triggers and ${matchedIntel.length > 0 ? "cross-correlation with synthetic threat intelligence" : "severe sensor behavioral variance"}.`
    : classification === "SUSPICIOUS"
    ? `Analysis indicates telemetry deviating from expected organizational baseline. While complete adversary command structure cannot be definitively confirmed without auxiliary memory triage, the triggered detection rules warrant elevated SOC queue priority.`
    : `Event attributes fall within standard enterprise operating parameters with nominal risk index.`;

  const summary = `${classification} classification (${severity} severity, Risk Index ${riskScore}/100) assigned based on multi-sensor behavioral correlation.`;

  const recommendedInvestigation: string[] = [];
  if (classification === "MALICIOUS") {
    recommendedInvestigation.push(`Submit host containment request in Human Approval workflow for ${event.hostname || "the affected asset"}.`);
    recommendedInvestigation.push(`Invalidate authentication tokens and reset credentials for user account ${event.user || "associated with session"}.`);
    recommendedInvestigation.push(`Query SIEM logs across adjacent hosts for presence of indicator ${event.ip || event.indicators?.[0] || "reported in event"}.`);
  } else if (classification === "SUSPICIOUS") {
    recommendedInvestigation.push("Review parent-child process execution lineage in EDR telemetry.");
    recommendedInvestigation.push("Correlate gateway proxy access logs for outbound connections within ±15 minutes.");
    recommendedInvestigation.push("Monitor account for repeated anomalous authentication challenges.");
  } else {
    recommendedInvestigation.push("Archive event telemetry in accordance with standard 90-day compliance retention.");
  }

  return {
    eventId: event.eventId,
    classification,
    severity,
    riskScore,
    confidence,
    threatCategory,
    evidence,
    explanation: {
      summary,
      aiInference,
      deterministicRules: rules,
      syntheticTelemetryContext,
      externalIntelligenceContext,
    },
    recommendedInvestigation,
    engine: "rule_heuristic",
  };
}
