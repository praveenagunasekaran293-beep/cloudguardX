import { GoogleGenAI } from "@google/genai";
import { db } from "./db.js";
import { threatIntelService } from "./threatIntel/service.js";

const apiKey = process.env.GEMINI_API_KEY || "";
const ai = new GoogleGenAI({
  apiKey: apiKey,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

export interface PhishingExtractionResult {
  sender: string;
  subject: string;
  urls: string[];
  domains: string[];
  urgencyIndicators: string[];
  credentialRequests: string[];
  suspiciousLanguage: string[];
  socialEngineeringIndicators: Array<{
    principle: string;
    evidence: string;
    explanation: string;
  }>;
}

export interface RiskFactor {
  factor: string;
  points: number;
  reason: string;
  verified?: boolean;
}

export interface PhishingInvestigationResult {
  sender: string;
  subject: string;
  urls: string[];
  domains: string[];
  urgencyIndicators: string[];
  credentialRequests: string[];
  suspiciousLanguage: string[];
  socialEngineeringIndicators: Array<{
    principle: string;
    evidence: string;
    explanation: string;
  }>;
  classification: "Phishing (High Confidence)" | "Suspicious / Potential Phish" | "Benign / Low Risk";
  riskScore: number;
  riskBreakdown: {
    factors: RiskFactor[];
    totalScore: number;
    explanation: string;
  };
  evidence: string[];
  explanation: {
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
  extractedIndicators: Array<{
    indicator: string;
    type: "Domain" | "URL" | "IP" | "Email";
    isVerifiedMalicious: boolean;
    source?: string;
  }>;
  recommendedInvestigation: string[];
  engine: "gemini" | "defensive_rule_engine";
}

/**
 * Defensive Email Parser and Heuristic Extractor
 */
export function extractEmailAttributes(
  emailContent: string,
  senderInput?: string,
  subjectInput?: string
): PhishingExtractionResult {
  // 1. Sender extraction
  const senderMatch =
    senderInput ||
    emailContent.match(/from:\s*([^\r\n]+)/i)?.[1]?.trim() ||
    "Unknown Sender <unspecified@domain.internal>";

  // 2. Subject line extraction
  const subjectMatch =
    subjectInput ||
    emailContent.match(/subject:\s*([^\r\n]+)/i)?.[1]?.trim() ||
    "No Subject Stated";

  // 3. URL extraction using safe structural regex
  const urlRegex = /(https?:\/\/[^\s<>"'\)]+)/gi;
  const rawUrls = Array.from(new Set(emailContent.match(urlRegex) || []));
  const cleanUrls = rawUrls.map((u) => u.replace(/[.,;]$/, ""));

  // 4. Extract unique domains (from sender email & URLs)
  const domainsSet = new Set<string>();
  if (senderMatch.includes("@")) {
    const senderHost = senderMatch.split("@")[1]?.replace(/[<>]/g, "").trim().toLowerCase();
    if (senderHost) domainsSet.add(senderHost);
  }
  for (const u of cleanUrls) {
    try {
      const parsed = new URL(u);
      domainsSet.add(parsed.hostname.toLowerCase());
    } catch {
      // ignore invalid URLs
    }
  }

  const contentLower = emailContent.toLowerCase();

  // 5. Urgency Indicators
  const urgencyDictionary = [
    "urgent",
    "immediate action required",
    "within 24 hours",
    "within 12 hours",
    "within 2 hours",
    "account suspended",
    "suspended immediately",
    "expires today",
    "held indefinitely",
    "action required immediately",
    "salary suspension",
    "terminate your access",
    "penalty",
    "final warning",
  ];
  const urgencyIndicators = urgencyDictionary.filter((phrase) => contentLower.includes(phrase));

  // 6. Credential Requests
  const credentialDictionary = [
    "login",
    "password",
    "sign in",
    "credentials",
    "authenticate",
    "mfa token",
    "security code",
    "sso",
    "verify direct deposit",
    "verify your account",
    "enter your",
    "current credentials",
    "update payment",
    "banking routing",
  ];
  const credentialRequests = credentialDictionary.filter((phrase) => contentLower.includes(phrase));

  // 7. Suspicious Language & Coercive Phrasing
  const suspiciousPhrases = [
    "prevent salary suspension",
    "prevent your email inbox from being locked",
    "do not reply to this email",
    "upcoming bi-weekly paycheck",
    "failure to complete this verification",
    "keep your current password",
    "scheduled system migration",
    "payroll processor",
    "secure employee portal below",
  ];
  const suspiciousLanguage = suspiciousPhrases.filter((phrase) => contentLower.includes(phrase));

  // 8. Social Engineering Indicators
  const socialEngineeringIndicators: Array<{ principle: string; evidence: string; explanation: string }> = [];

  if (urgencyIndicators.length > 0) {
    socialEngineeringIndicators.push({
      principle: "Scarcity & Artificial Time Pressure",
      evidence: `Identified deadline cues: "${urgencyIndicators.slice(0, 3).join('", "')}".`,
      explanation: "Adversaries induce panic to bypass rational cognitive verification and prevent internal validation.",
    });
  }

  if (
    contentLower.includes("hr") ||
    contentLower.includes("payroll") ||
    contentLower.includes("benefits") ||
    contentLower.includes("it support") ||
    contentLower.includes("microsoft") ||
    contentLower.includes("helpdesk") ||
    contentLower.includes("admin")
  ) {
    socialEngineeringIndicators.push({
      principle: "Authority & Brand Impersonation",
      evidence: "Sender poses as authoritative administrative body (Corporate HR, IT Helpdesk, or Payroll).",
      explanation: "Employees are psychologically predisposed to comply rapidly with senior or IT administrative requests.",
    });
  }

  if (
    contentLower.includes("held indefinitely") ||
    contentLower.includes("locked") ||
    contentLower.includes("suspension") ||
    contentLower.includes("termination")
  ) {
    socialEngineeringIndicators.push({
      principle: "Fear, Penalty & Coercion",
      evidence: "Threatens negative consequence (held paycheck, account lockout, or access termination).",
      explanation: "Appeals to fear of administrative censure or financial delay to compel immediate link interaction.",
    });
  }

  if (contentLower.includes("scheduled system migration") || contentLower.includes("security update")) {
    socialEngineeringIndicators.push({
      principle: "Pretexting",
      evidence: "Fabricates a plausible operational scenario (system migration, password expiry).",
      explanation: "Creates an acceptable context for why standard procedures or credential prompts appear different.",
    });
  }

  return {
    sender: senderMatch,
    subject: subjectMatch,
    urls: cleanUrls,
    domains: Array.from(domainsSet),
    urgencyIndicators,
    credentialRequests,
    suspiciousLanguage,
    socialEngineeringIndicators,
  };
}

/**
 * Perform Complete Defensive Phishing Investigation
 */
export async function performPhishingInvestigation(
  emailContent: string,
  senderInput?: string,
  subjectInput?: string
): Promise<PhishingInvestigationResult> {
  const extracted = extractEmailAttributes(emailContent, senderInput, subjectInput);

  // 1. Cross-reference with configured threat intelligence provider
  // CRITICAL RULE: "Do not claim that a URL or domain is malicious unless verified by an actual configured intelligence source."
  const verifiedIndicators: Array<{
    indicator: string;
    type: string;
    reputation: string;
    source: string;
    confidence: number;
  }> = [];

  const unverifiedIndicators: Array<{
    indicator: string;
    type: string;
    reason: string;
  }> = [];

  const extractedIndicatorsList: Array<{
    indicator: string;
    type: "Domain" | "URL" | "IP" | "Email";
    isVerifiedMalicious: boolean;
    source?: string;
  }> = [];

  // Check domains
  for (const dom of extracted.domains) {
    const intel = await threatIntelService.lookup(dom, "Domain");
    if (intel && intel.reputation === "Malicious" && intel.confidence >= 80) {
      verifiedIndicators.push({
        indicator: dom,
        type: "Domain",
        reputation: intel.reputation,
        source: intel.source,
        confidence: intel.confidence,
      });
      extractedIndicatorsList.push({
        indicator: dom,
        type: "Domain",
        isVerifiedMalicious: true,
        source: intel.source,
      });
    } else {
      unverifiedIndicators.push({
        indicator: dom,
        type: "Domain",
        reason: "No confirmed malicious reputation signature in active intelligence provider.",
      });
      extractedIndicatorsList.push({
        indicator: dom,
        type: "Domain",
        isVerifiedMalicious: false,
      });
    }
  }

  // Check URLs
  for (const url of extracted.urls) {
    const intel = await threatIntelService.lookup(url, "URL");
    if (intel && intel.reputation === "Malicious" && intel.confidence >= 80) {
      verifiedIndicators.push({
        indicator: url,
        type: "URL",
        reputation: intel.reputation,
        source: intel.source,
        confidence: intel.confidence,
      });
      extractedIndicatorsList.push({
        indicator: url,
        type: "URL",
        isVerifiedMalicious: true,
        source: intel.source,
      });
    } else {
      unverifiedIndicators.push({
        indicator: url,
        type: "URL",
        reason: "Structural URL pattern parsed; unverified by external configured intelligence source.",
      });
      extractedIndicatorsList.push({
        indicator: url,
        type: "URL",
        isVerifiedMalicious: false,
      });
    }
  }

  // Check sender email domain mismatch
  let senderDomain = "";
  if (extracted.sender.includes("@")) {
    senderDomain = extracted.sender.split("@")[1].replace(/[<>]/g, "").trim().toLowerCase();
  }
  let domainMismatch = false;
  for (const u of extracted.urls) {
    try {
      const parsed = new URL(u);
      if (senderDomain && !parsed.hostname.endsWith(senderDomain) && !senderDomain.endsWith(parsed.hostname)) {
        domainMismatch = true;
      }
    } catch {
      // ignore
    }
  }

  // 2. Transparent Phishing Risk Scoring Calculation
  const factors: RiskFactor[] = [];
  let baseScore = 10;

  // Factor 1: Verified Malicious Threat Intel Match
  if (verifiedIndicators.length > 0) {
    const pts = 30;
    baseScore += pts;
    factors.push({
      factor: "Verified Malicious Threat Intel Correlation",
      points: pts,
      reason: `${verifiedIndicators.length} observable(s) verified as MALICIOUS by configured intelligence source (${verifiedIndicators[0].source}, ${verifiedIndicators[0].confidence}% confidence).`,
      verified: true,
    });
  } else if (unverifiedIndicators.length > 0) {
    factors.push({
      factor: "Unverified Intelligence Status",
      points: 0,
      reason: "Observables are NOT claimed as verified malicious by external intelligence feeds; evaluating purely on structural and heuristic indicators.",
      verified: false,
    });
  }

  // Factor 2: Credential Harvesting Requests
  if (extracted.credentialRequests.length > 0) {
    const pts = 25;
    baseScore += pts;
    factors.push({
      factor: "Direct Credential Harvesting Telemetry",
      points: pts,
      reason: `Message contains credential request markers: "${extracted.credentialRequests.slice(0, 3).join('", "')}".`,
    });
  }

  // Factor 3: High Urgency & Time Pressure
  if (extracted.urgencyIndicators.length > 0) {
    const pts = 20;
    baseScore += pts;
    factors.push({
      factor: "Psychological Urgency & Deadlines",
      points: pts,
      reason: `Coercive urgency cues identified: "${extracted.urgencyIndicators.slice(0, 3).join('", "')}".`,
    });
  }

  // Factor 4: Domain Discrepancy / Mismatch
  if (domainMismatch) {
    const pts = 18;
    baseScore += pts;
    factors.push({
      factor: "Sender vs Destination Domain Discrepancy",
      points: pts,
      reason: `Sender domain (${senderDomain || "corporate"}) diverges from embedded destination web hosts.`,
    });
  }

  // Factor 5: High-Abuse TLD or Suspicious Pattern
  const hasAbuseTld = extracted.urls.some(
    (u) => u.includes(".top") || u.includes(".cc") || u.includes(".xyz") || u.includes(".click") || u.includes(".duckdns")
  );
  if (hasAbuseTld) {
    const pts = 12;
    baseScore += pts;
    factors.push({
      factor: "Suspicious TLD / High-Abuse Hosting Pattern",
      points: pts,
      reason: "Destination link resolves to a known high-abuse TLD (.top, .cc, .xyz, .click).",
    });
  }

  // Factor 6: Social Engineering Pretexting
  if (extracted.socialEngineeringIndicators.length >= 2) {
    const pts = 10;
    baseScore += pts;
    factors.push({
      factor: "Multi-Vector Social Engineering Traps",
      points: pts,
      reason: `${extracted.socialEngineeringIndicators.length} distinct psychological exploitation tactics observed (authority, fear, scarcity).`,
    });
  }

  const finalScore = Math.min(Math.max(baseScore, 5), 98);
  const classification =
    finalScore >= 75
      ? "Phishing (High Confidence)"
      : finalScore >= 45
      ? "Suspicious / Potential Phish"
      : "Benign / Low Risk";

  // 3. Evidence assembly
  const evidence: string[] = [
    `Sender: ${extracted.sender}`,
    `Subject: ${extracted.subject}`,
    ...extracted.urls.map((u) => `Embedded URL: ${u}`),
    ...extracted.domains.map((d) => `Extracted Domain: ${d}`),
    ...extracted.urgencyIndicators.map((u) => `Urgency Cue: ${u}`),
    ...extracted.credentialRequests.map((c) => `Credential Keyword: ${c}`),
  ];

  // 4. Use Gemini to explain the result
  let geminiAssessment = "";
  let engine: "gemini" | "defensive_rule_engine" = "defensive_rule_engine";

  if (apiKey) {
    try {
      const prompt = `You are CyberSentinel X Phishing & Social Engineering Deep Forensic Engine.
Analyze this simulated email defensively for a SOC incident triage platform:

SENDER: ${extracted.sender}
SUBJECT: ${extracted.subject}
EXTRACTED URLS: ${JSON.stringify(extracted.urls)}
EXTRACTED DOMAINS: ${JSON.stringify(extracted.domains)}
URGENCY CUES: ${JSON.stringify(extracted.urgencyIndicators)}
CREDENTIAL KEYWORDS: ${JSON.stringify(extracted.credentialRequests)}
SUSPICIOUS LANGUAGE: ${JSON.stringify(extracted.suspiciousLanguage)}
SOCIAL ENGINEERING TACTICS: ${JSON.stringify(extracted.socialEngineeringIndicators)}

CALCULATED DEFENSIVE RISK SCORE: ${finalScore}/100
ASSIGNED CLASSIFICATION: ${classification}

VERIFIED THREAT INTELLIGENCE MATCHES:
${verifiedIndicators.length > 0 ? JSON.stringify(verifiedIndicators) : "None (Indicators unverified by active external feeds)"}

MANDATORY RULES:
1. Do NOT claim any URL or domain is definitively malicious unless listed under "VERIFIED THREAT INTELLIGENCE MATCHES".
2. If unverified, treat links as "unconfirmed suspicious structural patterns".
3. Provide a clear, professional 3-section forensic assessment:
   - Section 1: Executive Threat Classification & Attack Vector Analysis
   - Section 2: Social Engineering Psychology & Indicator Correlation
   - Section 3: Recommended Defensive SOC Containment Playbook (mail gateway purge, DNS blocks, identity isolation).`;

      const geminiRes = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          systemInstruction: "You are an autonomous enterprise Email Security Gateway (SEG) forensic analyst.",
          temperature: 0.15,
        },
      });

      if (geminiRes.text) {
        geminiAssessment = geminiRes.text;
        engine = "gemini";
      }
    } catch (err: any) {
      console.warn("Gemini phishing explanation call failed, using deterministic fallback:", err?.message || err);
    }
  }

  // Fallback Gemini Explanation if API key not available or call fails
  if (!geminiAssessment) {
    geminiAssessment = `### 1. Executive Threat Classification & Attack Vector Analysis
The submitted payload is classified as **${classification}** with a composite defensive risk index of **${finalScore}/100**. The message demonstrates characteristic hallmarks of a credential harvesting attack targeting corporate identities. The sender identity (${extracted.sender}) utilizes an authoritative disguise to prompt immediate interaction without triggering standard heuristic alarms.

### 2. Social Engineering Psychology & Indicator Correlation
The adversary leverages a combination of **${extracted.socialEngineeringIndicators.map((s) => s.principle).join(", ") || "Urgency and Authority"}**. By fabricating an operational pretext regarding payroll verification or credential expiry, the author creates artificial urgency to circumvent standard verification channels. 
${
  verifiedIndicators.length > 0
    ? `**Intelligence Verification**: Destination observables (${verifiedIndicators.map((v) => v.indicator).join(", ")}) were positively correlated with configured threat intelligence feeds (${verifiedIndicators[0].source}, ${verifiedIndicators[0].confidence}% confidence).`
    : `**Intelligence Feed Status**: Embedded observables (${extracted.domains.join(", ") || "none"}) are uncatalogued in active external intelligence feeds and are classified based strictly on structural anomalies and domain mismatch.`
}

### 3. Recommended Defensive SOC Containment Playbook
1. **Tenant Purge**: Execute automated remediation to remove this message from all recipient mailboxes across the organization.
2. **Perimeter Link Containment**: Deploy defensive egress blocks on perimeter Secure Web Gateways (SWG) for the extracted destination hosts.
3. **Identity Session Triage**: Audit authentication logs for any users who opened this communication within the observation window; force session revocation and password reset if links were traversed.`;
  }

  const summary = `${classification} (${finalScore}/100). ${
    verifiedIndicators.length > 0
      ? `Confirmed malicious correlation with ${verifiedIndicators.length} threat intelligence indicator(s).`
      : `High-risk psychological urgency and credential harvesting markers identified; observables unverified by external intelligence.`
  }`;

  const recommendedInvestigation = [
    "Execute automated message purge across all tenant Exchange / Google Workspace mailboxes.",
    "Query email gateway delivery logs to identify all secondary internal recipients of this sender/subject combination.",
    "Submit extracted URL structure to isolated defensive detonation sandbox for redirection inspection.",
    "Audit Okta / Entra ID sign-in telemetry for anomalous authentication originating from recipient identities within ±1 hour.",
    "Create a formalized SOC Incident record in the Incident Management workflow.",
  ];

  return {
    sender: extracted.sender,
    subject: extracted.subject,
    urls: extracted.urls,
    domains: extracted.domains,
    urgencyIndicators: extracted.urgencyIndicators,
    credentialRequests: extracted.credentialRequests,
    suspiciousLanguage: extracted.suspiciousLanguage,
    socialEngineeringIndicators: extracted.socialEngineeringIndicators,
    classification,
    riskScore: finalScore,
    riskBreakdown: {
      factors,
      totalScore: finalScore,
      explanation: `Calculated from ${factors.length} weighted defensive telemetry and intelligence correlation criteria.`,
    },
    evidence,
    explanation: {
      summary,
      geminiAssessment,
      threatIntelVerification: {
        verifiedIndicators,
        unverifiedIndicators,
      },
    },
    extractedIndicators: extractedIndicatorsList,
    recommendedInvestigation,
    engine,
  };
}

/**
 * Create an Incident from a Phishing Analysis
 * Updates:
 * - Incidents (creates new incident in DB)
 * - Timeline (generates detailed chronological intrusion milestones)
 * - Threat Intelligence (inserts extracted indicators into threat_intel)
 * - Audit Log (records analyst action and AI recommendation)
 * - Dashboard (stats reflect new incident and indicators automatically)
 */
export async function createIncidentFromPhishing(
  analysis: PhishingInvestigationResult,
  options?: {
    customTitle?: string;
    affectedUser?: string;
    analystNotes?: string;
    analystName?: string;
  }
) {
  const timestamp = new Date().toISOString();
  const incId = `INC-PHISH-${Date.now().toString().slice(-4)}`;
  const title = options?.customTitle || `Targeted Phishing Campaign: "${analysis.subject.slice(0, 45)}"`;
  const user = options?.affectedUser || analysis.sender.includes("<")
    ? analysis.sender.match(/<([^>]+)>/)?.[1] || "target.employee@enterprise-corp.internal"
    : "target.employee@enterprise-corp.internal";

  const severity = analysis.riskScore >= 75 ? "Critical" : analysis.riskScore >= 45 ? "High" : "Medium";

  // Format indicators list
  const indicatorsList: string[] = [];
  analysis.urls.forEach((u) => indicatorsList.push(u));
  analysis.domains.forEach((d) => {
    if (!indicatorsList.includes(d)) indicatorsList.push(d);
  });
  if (analysis.sender.includes("@")) {
    const email = analysis.sender.replace(/[<>]/g, " ").split(" ").find((w) => w.includes("@"));
    if (email && !indicatorsList.includes(email)) indicatorsList.push(email);
  }

  // 1. Generate Chronological Timeline Milestones
  const now = new Date();
  const formatTimeStr = (minsAgo: number) => {
    const d = new Date(now.getTime() - minsAgo * 60000);
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
  };

  const timeline = [
    {
      time: formatTimeStr(35),
      event: `Inbound email delivered from ${analysis.sender} with subject "${analysis.subject}"`,
      source: "MailGuard SEG",
      severity: "Medium",
    },
    {
      time: formatTimeStr(25),
      event: `Phishing Detection Engine flagged message as ${analysis.classification} (Risk: ${analysis.riskScore}/100)`,
      source: "CyberSentinel Phishing Analyzer",
      severity: analysis.riskScore >= 75 ? "Critical" : "High",
    },
    {
      time: formatTimeStr(18),
      event: `Correlated ${indicatorsList.length} observable indicator(s) against modular threat intelligence provider`,
      source: "Threat Intelligence Engine",
      severity: analysis.explanation.threatIntelVerification.verifiedIndicators.length > 0 ? "Critical" : "Medium",
    },
    {
      time: formatTimeStr(5),
      event: `SOC Analyst escalated email analysis into active formal incident ${incId}`,
      source: "Analyst Incident Escalation",
      severity: "High",
    },
  ];

  // 2. MITRE ATT&CK Mapping
  const mitreTechniques = [
    { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", status: "Confirmed" },
    { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Defense Evasion", status: "Suspected" },
    { id: "T1204.001", name: "User Execution: Malicious Link", tactic: "Execution", status: "Suspected" },
  ];

  // 3. Risk Breakdown for Incident Record
  const riskBreakdown = {
    factors: analysis.riskBreakdown.factors.map((f) => ({
      name: f.factor,
      points: f.points,
      reason: f.reason,
    })),
    totalScore: analysis.riskScore,
    maxScore: 100,
    explanation: analysis.explanation.summary,
  };

  // 4. Recommendations
  const recommendations = [
    "Tenant-wide email quarantine across all recipient inboxes.",
    "Block destination domain and URL across perimeter firewall and Secure Web Gateway.",
    "Invalidate active OAuth and Kerberos tokens for affected recipient identities.",
    "Review authentication logs for anomalous logins from recipient within the past 4 hours.",
  ];

  // 5. Insert into SQLite `incidents` table
  await db.execute({
    sql: `INSERT INTO incidents (incidentId, title, description, severity, riskScore, status, affectedUser, affectedAssets, relatedEvents, indicators, timeline, mitreTechniques, recommendations, riskBreakdown, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      incId,
      title,
      `Phishing escalation: ${analysis.explanation.summary}. Discovered via automated defensive email analysis.`,
      severity,
      analysis.riskScore,
      "Open",
      user,
      JSON.stringify(["Exchange Online Tenant", "Mail Gateway"]),
      JSON.stringify([]),
      JSON.stringify(indicatorsList),
      JSON.stringify(timeline),
      JSON.stringify(mitreTechniques),
      JSON.stringify(recommendations),
      JSON.stringify(riskBreakdown),
      timestamp,
      timestamp,
    ],
  });

  // 6. Update `threat_intel` table with extracted observables
  for (const item of analysis.extractedIndicators) {
    const isDomain = item.type === "Domain";
    const status = item.isVerifiedMalicious ? "Malicious (Verified)" : "Suspicious (Phish Extract)";
    const confidence = item.isVerifiedMalicious ? 95 : 75;

    await db.execute({
      sql: `INSERT OR REPLACE INTO threat_intel (id, indicator, type, status, confidence, firstSeen, lastSeen, source, threatGroup, tags, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        `TI-PHISH-${Math.abs(item.indicator.split("").reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) | 0, 0))}`,
        item.indicator,
        item.type,
        status,
        confidence,
        timestamp,
        timestamp,
        "Phishing Investigation Extraction (Synthetic Demo Feed)",
        "Targeted Phishing Actor Emulation",
        JSON.stringify(["phishing", "email-investigation", item.type.toLowerCase()]),
        `Observable extracted from Phishing Incident ${incId} (${title}).`,
      ],
    });
  }

  // 7. Insert Audit Log
  await db.execute({
    sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      `AUD-${Date.now().toString().slice(-4)}`,
      timestamp,
      `Incident Created from Phishing Investigation (${incId})`,
      "Incident Creation",
      incId,
      `Phishing Analysis: ${analysis.classification} (Risk: ${analysis.riskScore}/100)`,
      `Analyst escalated email investigation to active SOC incident`,
      `Created incident ${incId} with ${indicatorsList.length} indicators, 4 timeline milestones, and populated threat intelligence records. ${options?.analystNotes || ""}`,
    ],
  });

  return {
    success: true,
    incidentId: incId,
    title,
    severity,
    riskScore: analysis.riskScore,
    indicatorsCount: indicatorsList.length,
    timelineMilestonesCount: timeline.length,
  };
}
