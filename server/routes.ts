import { Router, Request, Response } from "express";
import { db, seedBaselineData } from "./db.js";
import { DEMO_SCENARIOS, loadScenario } from "./scenarios.js";
import { askCopilot, analyzePhishing, analyzeUrlStructure } from "./gemini.js";
import { analyzeSecurityEvent } from "./threatDetection.js";
import { threatIntelService } from "./threatIntel/service.js";
import { performPhishingInvestigation, createIncidentFromPhishing } from "./phishingInvestigation.js";
import { analyzeUrlDefense, createIncidentFromUrl } from "./urlAnalysis.js";

export const apiRouter = Router();

// 1. Dashboard Stats
apiRouter.get("/stats", async (req: Request, res: Response) => {
  try {
    const totalEventsRes = await db.execute("SELECT COUNT(*) as count FROM security_events");
    const totalEvents = Number(totalEventsRes.rows[0].count);

    const incidentsRes = await db.execute("SELECT severity, status, riskScore FROM incidents");
    const incidents = incidentsRes.rows;

    const criticalIncidents = incidents.filter((i) => i.severity === "Critical").length;
    const highRiskIncidents = incidents.filter((i) => Number(i.riskScore) >= 70).length;
    const openIncidents = incidents.filter((i) => i.status === "Open" || i.status === "Investigating").length;

    const susEventsRes = await db.execute("SELECT COUNT(*) as count FROM security_events WHERE severity IN ('High', 'Critical')");
    const suspiciousEvents = Number(susEventsRes.rows[0].count);

    const vulnsRes = await db.execute("SELECT COUNT(*) as count FROM vulnerabilities");
    const totalVulns = Number(vulnsRes.rows[0].count);

    // Severity distribution
    const sevCount: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const allEventsRes = await db.execute("SELECT severity FROM security_events");
    for (const row of allEventsRes.rows) {
      const sev = String(row.severity);
      if (sevCount[sev] !== undefined) sevCount[sev]++;
    }

    // Incident Categories
    const categories = [
      { name: "Phishing / Credential Access", count: 4 },
      { name: "Process Injection & EDR", count: 3 },
      { name: "Cloud IAM Anomaly", count: 2 },
      { name: "Network Beaconing / C2", count: 2 },
      { name: "Vulnerability Probing", count: 2 },
    ];

    // Threat Activity by hour / time
    const timeTrend = [
      { time: "00:00", events: 12, alerts: 1 },
      { time: "04:00", events: 8, alerts: 0 },
      { time: "08:00", events: 45, alerts: 4 },
      { time: "10:00", events: 89, alerts: 9 },
      { time: "12:00", events: 65, alerts: 5 },
      { time: "14:00", events: 110, alerts: 14 },
      { time: "16:00", events: 78, alerts: 6 },
      { time: "20:00", events: 34, alerts: 2 },
    ];

    // MITRE technique frequency
    const mitreDistribution = [
      { technique: "T1566 Spearphishing", count: 6, tactic: "Initial Access" },
      { technique: "T1059.001 PowerShell", count: 5, tactic: "Execution" },
      { technique: "T1078 Valid Accounts", count: 4, tactic: "Defense Evasion" },
      { technique: "T1055 Process Injection", count: 3, tactic: "Privilege Escalation" },
      { technique: "T1071 C2 Protocols", count: 3, tactic: "Command & Control" },
      { technique: "T1530 Cloud Storage", count: 2, tactic: "Collection" },
    ];

    res.json({
      summary: {
        totalSecurityEvents: totalEvents,
        criticalIncidents,
        highRiskIncidents,
        suspiciousEvents,
        openIncidents,
        vulnerabilities: totalVulns,
      },
      severityDistribution: [
        { name: "Critical", count: sevCount["Critical"], color: "#ef4444" },
        { name: "High", count: sevCount["High"], color: "#f97316" },
        { name: "Medium", count: sevCount["Medium"], color: "#eab308" },
        { name: "Low", count: sevCount["Low"], color: "#3b82f6" },
      ],
      incidentCategories: categories,
      timeTrend,
      mitreDistribution,
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to calculate SOC metrics" });
  }
});

// 2. Security Events
apiRouter.get("/events", async (req: Request, res: Response) => {
  try {
    const { severity, sourceType, search, limit = "50" } = req.query;
    let query = "SELECT * FROM security_events WHERE 1=1";
    const args: any[] = [];

    if (severity && severity !== "all") {
      query += " AND severity = ?";
      args.push(severity);
    }
    if (sourceType && sourceType !== "all") {
      query += " AND sourceType = ?";
      args.push(sourceType);
    }
    if (search) {
      query += " AND (description LIKE ? OR user LIKE ? OR ip LIKE ? OR hostname LIKE ? OR eventType LIKE ?)";
      const term = `%${search}%`;
      args.push(term, term, term, term, term);
    }

    query += " ORDER BY timestamp DESC LIMIT ?";
    args.push(Number(limit));

    const result = await db.execute({ sql: query, args });
    const events = result.rows.map((row) => ({
      ...row,
      indicators: row.indicators ? JSON.parse(String(row.indicators)) : [],
      metadata: row.metadata ? JSON.parse(String(row.metadata)) : {},
    }));

    res.json({ events });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to load events" });
  }
});

// Create / ingest synthetic event
apiRouter.post("/events", async (req: Request, res: Response) => {
  try {
    const { source, sourceType, user, ip, hostname, eventType, description, severity, indicators, metadata } = req.body;
    const eventId = `EVT-${Math.floor(1000 + Math.random() * 9000)}`;
    const timestamp = new Date().toISOString();

    await db.execute({
      sql: `INSERT INTO security_events (eventId, timestamp, source, sourceType, user, ip, hostname, eventType, description, severity, indicators, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        eventId,
        timestamp,
        source || "Custom Ingestion",
        sourceType || "Manual SOC Generator",
        user || "unspecified",
        ip || "10.0.4.50",
        hostname || "SIM-HOST-01",
        eventType || "Synthetic Security Event",
        description || "Manually triggered synthetic security alert for SOC validation.",
        severity || "Medium",
        JSON.stringify(indicators || []),
        JSON.stringify(metadata || {}),
      ],
    });

    res.json({ success: true, eventId, timestamp });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to create event" });
  }
});

// AI Threat Detection for an individual security event
apiRouter.post("/events/:id/ai-analyze", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let eventData = req.body.event;

    if (!eventData || !eventData.eventId) {
      const dbRes = await db.execute({
        sql: "SELECT * FROM security_events WHERE eventId = ?",
        args: [id],
      });
      if (dbRes.rows.length === 0) {
        return res.status(404).json({ error: `Security event ${id} not found.` });
      }
      const row = dbRes.rows[0];
      eventData = {
        ...row,
        indicators: row.indicators ? JSON.parse(String(row.indicators)) : [],
        metadata: row.metadata ? JSON.parse(String(row.metadata)) : {},
      };
    }

    const analysis = await analyzeSecurityEvent(eventData);

    // Audit log recording AI threat detection invocation
    try {
      await db.execute({
        sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          `AUD-${Date.now().toString().slice(-4)}`,
          new Date().toISOString(),
          `AI Threat Detection Executed for ${eventData.eventId}`,
          "AI Threat Detection",
          null,
          `Classification: ${analysis.classification} (Risk: ${analysis.riskScore}/100, Severity: ${analysis.severity})`,
          "Analyst Telemetry Triage",
          `Automated threat detection engine (${analysis.engine}) analyzed event ${eventData.eventId}: ${analysis.explanation.summary}`,
        ],
      });
    } catch (e) {
      // non-fatal audit log catch
    }

    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to execute AI Threat Detection" });
  }
});

apiRouter.post("/events/ai-analyze", async (req: Request, res: Response) => {
  try {
    const eventData = req.body.event || req.body;
    if (!eventData || !eventData.eventId || !eventData.description) {
      return res.status(400).json({ error: "Missing required SecurityEvent fields." });
    }

    const analysis = await analyzeSecurityEvent(eventData);
    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to analyze security event" });
  }
});

// 3. Incidents
apiRouter.get("/incidents", async (req: Request, res: Response) => {
  try {
    const result = await db.execute("SELECT * FROM incidents ORDER BY riskScore DESC, createdAt DESC");
    const incidents = result.rows.map((row) => ({
      ...row,
      affectedAssets: row.affectedAssets ? JSON.parse(String(row.affectedAssets)) : [],
      relatedEvents: row.relatedEvents ? JSON.parse(String(row.relatedEvents)) : [],
      indicators: row.indicators ? JSON.parse(String(row.indicators)) : [],
      timeline: row.timeline ? JSON.parse(String(row.timeline)) : [],
      mitreTechniques: row.mitreTechniques ? JSON.parse(String(row.mitreTechniques)) : [],
      recommendations: row.recommendations ? JSON.parse(String(row.recommendations)) : [],
      riskBreakdown: row.riskBreakdown ? JSON.parse(String(row.riskBreakdown)) : null,
    }));
    res.json({ incidents });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to load incidents" });
  }
});

apiRouter.get("/incidents/:id", async (req: Request, res: Response) => {
  try {
    const result = await db.execute({
      sql: "SELECT * FROM incidents WHERE incidentId = ?",
      args: [req.params.id],
    });
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Incident not found" });
    }
    const row = result.rows[0];
    res.json({
      incident: {
        ...row,
        affectedAssets: row.affectedAssets ? JSON.parse(String(row.affectedAssets)) : [],
        relatedEvents: row.relatedEvents ? JSON.parse(String(row.relatedEvents)) : [],
        indicators: row.indicators ? JSON.parse(String(row.indicators)) : [],
        timeline: row.timeline ? JSON.parse(String(row.timeline)) : [],
        mitreTechniques: row.mitreTechniques ? JSON.parse(String(row.mitreTechniques)) : [],
        recommendations: row.recommendations ? JSON.parse(String(row.recommendations)) : [],
        riskBreakdown: row.riskBreakdown ? JSON.parse(String(row.riskBreakdown)) : null,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to fetch incident" });
  }
});

apiRouter.patch("/incidents/:id", async (req: Request, res: Response) => {
  try {
    const { status } = req.body;
    const allowed = ["Open", "Investigating", "Resolved", "Closed"];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${allowed.join(", ")}` });
    }

    await db.execute({
      sql: "UPDATE incidents SET status = ?, updatedAt = ? WHERE incidentId = ?",
      args: [status, new Date().toISOString(), req.params.id],
    });

    // Write audit log
    await db.execute({
      sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        `AUD-${Date.now().toString().slice(-4)}`,
        new Date().toISOString(),
        `Incident Status Changed to: ${status}`,
        "Workflow State Change",
        req.params.id,
        "Maintain proper status tracking throughout containment lifecycle",
        `Analyst set status to ${status}`,
        `Incident ${req.params.id} lifecycle state moved to ${status}.`,
      ],
    });

    res.json({ success: true, status });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to update incident" });
  }
});

// 4. Threat Intelligence (Modular Provider Service)
apiRouter.get("/threat-intel", async (req: Request, res: Response) => {
  try {
    const { type, reputation, search } = req.query;
    const result = await threatIntelService.listIndicators({
      type: typeof type === "string" ? type : undefined,
      reputation: typeof reputation === "string" ? reputation : undefined,
      search: typeof search === "string" ? search : undefined,
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to fetch threat intel" });
  }
});

apiRouter.post("/threat-intel/lookup", async (req: Request, res: Response) => {
  try {
    const { indicator, typeHint } = req.body;
    if (!indicator || typeof indicator !== "string") {
      return res.status(400).json({ error: "Missing indicator query" });
    }

    const match = await threatIntelService.lookup(indicator, typeHint);

    if (match) {
      return res.json({
        found: true,
        indicator: match,
        isSyntheticDemo: true,
      });
    }

    res.json({
      found: false,
      query: indicator,
      message: "Indicator not in active synthetic threat database. No current simulated malicious association recorded.",
      syntheticReputation: "Unknown / Low Risk (Synthetic Feed)",
      confidence: 15,
      isSyntheticDemo: true,
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Threat intel lookup error" });
  }
});

apiRouter.post("/threat-intel/enrich", async (req: Request, res: Response) => {
  try {
    const { indicators } = req.body;
    if (!Array.isArray(indicators)) {
      return res.status(400).json({ error: "Indicators must be an array of strings" });
    }
    const enriched = await threatIntelService.enrichIndicators(indicators);
    const provider = threatIntelService.getActiveProvider();
    res.json({
      enriched,
      count: enriched.length,
      provider: provider.name,
      isSynthetic: provider.isSynthetic,
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to enrich indicators" });
  }
});

apiRouter.get("/threat-intel/providers", async (req: Request, res: Response) => {
  try {
    const providers = threatIntelService.getRegisteredProviders();
    res.json({ providers });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to get providers" });
  }
});

// 5. Vulnerabilities
apiRouter.get("/vulnerabilities", async (req: Request, res: Response) => {
  try {
    const result = await db.execute("SELECT * FROM vulnerabilities ORDER BY priority DESC, cvss DESC");
    res.json({ vulnerabilities: result.rows });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to fetch vulnerabilities" });
  }
});

apiRouter.patch("/vulnerabilities/:id", async (req: Request, res: Response) => {
  try {
    const { remediationStatus } = req.body;
    await db.execute({
      sql: "UPDATE vulnerabilities SET remediationStatus = ? WHERE cveId = ?",
      args: [remediationStatus, req.params.id],
    });

    await db.execute({
      sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        `AUD-${Date.now().toString().slice(-4)}`,
        new Date().toISOString(),
        `Vulnerability Remediation Updated: ${req.params.id}`,
        "Vulnerability Management",
        req.params.id,
        "Remediate according to asset exposure priority score",
        `Status set to: ${remediationStatus}`,
        `Vulnerability ${req.params.id} remediation status updated to "${remediationStatus}".`,
      ],
    });

    res.json({ success: true, remediationStatus });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to update vulnerability" });
  }
});

// 6. MITRE ATT&CK Matrix Mapping
apiRouter.get("/mitre", async (req: Request, res: Response) => {
  try {
    const matrix = [
      {
        tacticId: "TA0001",
        tacticName: "Initial Access",
        techniques: [
          {
            id: "T1566.002",
            name: "Spearphishing Link",
            status: "Active Detection",
            incidents: ["INC-2026-001"],
            reason: "Targeted spearphishing email delivered with synthetic payroll domain link.",
            evidence: "MailGuard SEG event EVT-8821; URL payroll-update-secure.top.",
            detectionGuidance: "Inspect Secure Email Gateway (SEG) logs for domain age < 14 days, SPF softfail, and high-urgency keywords.",
            mitigationGuidance: "Enforce DMARC quarantine/reject policies and implement automated URL sandboxing at the mail gateway.",
          },
          {
            id: "T1190",
            name: "Exploit Public-Facing Application",
            status: "Monitored",
            incidents: ["INC-2026-004"],
            reason: "External perimeter scan probes targeting unpatched gateway or Log4j JNDI injection.",
            evidence: "CVE-2021-44228 / CVE-2023-38606 scanned on asset SRV-INV-02.",
            detectionGuidance: "Monitor WAF blocked request logs for JNDI string patterns and buffer overflow headers.",
            mitigationGuidance: "Apply vendor patches promptly; isolate management interfaces behind multi-factor VPN.",
          },
        ],
      },
      {
        tacticId: "TA0002",
        tacticName: "Execution",
        techniques: [
          {
            id: "T1059.001",
            name: "Command & Scripting: PowerShell",
            status: "Active Detection",
            incidents: ["INC-2026-001"],
            reason: "Base64 encoded PowerShell script spawned from Microsoft Word process.",
            evidence: "CrowdStrike Falcon event EVT-8835; commandLine: powershell.exe -Enc...",
            detectionGuidance: "Enable Script Block Logging (Event ID 4104) and monitor parent process anomalies (e.g. winword.exe spawning powershell).",
            mitigationGuidance: "Enforce ConstrainedLanguageMode via AppLocker or Windows Defender Application Control (WDAC).",
          },
        ],
      },
      {
        tacticId: "TA0004",
        tacticName: "Privilege Escalation",
        techniques: [
          {
            id: "T1055",
            name: "Process Injection",
            status: "Active Detection",
            incidents: ["INC-2026-001"],
            reason: "In-memory code injection into explorer.exe to evade endpoint detection.",
            evidence: "Falcon EDR alerted on CreateRemoteThread into explorer.exe (PID 2840).",
            detectionGuidance: "Sysmon Event ID 8 (CreateRemoteThread) and Event ID 10 (ProcessAccess).",
            mitigationGuidance: "Implement memory integrity protection (HVCI) and latest EDR behavioral heuristics.",
          },
        ],
      },
      {
        tacticId: "TA0005",
        tacticName: "Defense Evasion",
        techniques: [
          {
            id: "T1078.004",
            name: "Valid Accounts: Cloud Accounts",
            status: "Active Detection",
            incidents: ["INC-2026-001"],
            reason: "Adversary logged in using legitimate harvested Okta credentials from Bucharest, Romania.",
            evidence: "Okta IAM event EVT-8829; Impossible Travel velocity 2,450 mph.",
            detectionGuidance: "Correlate geolocations across sequential logins with speed thresholds > 500 mph.",
            mitigationGuidance: "Enforce FIDO2 WebAuthn phishing-resistant hardware keys; restrict login by corporate IP range.",
          },
          {
            id: "T1027",
            name: "Obfuscated Files or Information",
            status: "Observed",
            incidents: ["INC-2026-001"],
            reason: "Base64 encoding used to disguise PowerShell command flags and payloads.",
            evidence: "PowerShell CLI arguments passed with -EncodedCommand.",
            detectionGuidance: "Automated SIEM decoding of Base64 command strings.",
            mitigationGuidance: "Disable execution of unsigned scripts via ExecutionPolicy Restricted.",
          },
        ],
      },
      {
        tacticId: "TA0007",
        tacticName: "Discovery",
        techniques: [
          {
            id: "T1046",
            name: "Network Service Discovery",
            status: "Active Detection",
            incidents: ["INC-2026-001"],
            reason: "Compromised workstation swept internal subnet for SMB (port 445) and RPC (port 135).",
            evidence: "Splunk correlation EVT-8840 showing 1,420 packets to 10.0.0.5.",
            detectionGuidance: "Network flow telemetry alerts for sudden horizontal port scanning from client subnets.",
            mitigationGuidance: "Micro-segment client VLANs to prevent host-to-host lateral communication.",
          },
        ],
      },
      {
        tacticId: "TA0011",
        tacticName: "Command and Control",
        techniques: [
          {
            id: "T1071.001",
            name: "Application Layer: Web Protocols",
            status: "Active Detection",
            incidents: ["INC-2026-003"],
            reason: "Outbound encrypted beaconing over TCP/443 at regular 30-second cadence to synthetic C2 sinkhole.",
            evidence: "Suricata NIDS event EVT-8850 to destination 198.51.100.99.",
            detectionGuidance: "Statistical periodicity analysis of outbound TLS session duration and payload sizing.",
            mitigationGuidance: "Deploy TLS decryption proxy inspection with reputation-based categorical filtering.",
          },
        ],
      },
      {
        tacticId: "TA0009",
        tacticName: "Collection",
        techniques: [
          {
            id: "T1530",
            name: "Data from Cloud Storage Object",
            status: "Active Detection",
            incidents: ["INC-2026-002"],
            reason: "S3 Bucket policy updated to Principal: * allowing unauthenticated archive downloads.",
            evidence: "AWS CloudTrail event EVT-8846.",
            detectionGuidance: "CloudTrail PutBucketPolicy alarms and AWS GuardDuty anomalous data access alerts.",
            mitigationGuidance: "Enforce AWS Organizations Service Control Policy (SCP) preventing removal of S3 Block Public Access.",
          },
        ],
      },
    ];

    res.json({ matrix });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to load MITRE matrix" });
  }
});

// 7. Human Approval Response Workflow
apiRouter.get("/response-actions", async (req: Request, res: Response) => {
  try {
    const result = await db.execute("SELECT * FROM response_actions ORDER BY createdAt DESC");
    res.json({ actions: result.rows });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to fetch response actions" });
  }
});

apiRouter.post("/response-actions/:id/review", async (req: Request, res: Response) => {
  try {
    const { actionId } = req.params;
    const { decision, analystName, justification } = req.body; // 'APPROVED' or 'REJECTED'

    if (!["APPROVED", "REJECTED"].includes(decision)) {
      return res.status(400).json({ error: "Decision must be APPROVED or REJECTED" });
    }

    const actionRes = await db.execute({
      sql: "SELECT * FROM response_actions WHERE id = ?",
      args: [req.params.id],
    });

    if (actionRes.rows.length === 0) {
      return res.status(404).json({ error: "Response action not found" });
    }

    const action = actionRes.rows[0];
    const timestamp = new Date().toISOString();
    const reviewer = analystName || "SOC Analyst (Praveena G.)";

    await db.execute({
      sql: `UPDATE response_actions
            SET status = ?, decidedBy = ?, decidedAt = ?, justification = ?
            WHERE id = ?`,
      args: [decision, reviewer, timestamp, justification || "Reviewed per SOC Incident Response Runbook", req.params.id],
    });

    // Write audit log entry
    await db.execute({
      sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        `AUD-${Date.now().toString().slice(-4)}`,
        timestamp,
        `Analyst ${decision === "APPROVED" ? "Approved" : "Rejected"} Action ${req.params.id}`,
        "Human Response Approval",
        action.incidentId,
        String(action.title),
        `${decision} by ${reviewer}`,
        `Action "${action.title}" (${action.actionType}) status updated to ${decision}. Justification: ${justification || "Default SOC runbook review."}`,
      ],
    });

    res.json({
      success: true,
      actionId: req.params.id,
      status: decision,
      decidedBy: reviewer,
      decidedAt: timestamp,
    });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to process review" });
  }
});

// 8. Audit Logs
apiRouter.get("/audit-logs", async (req: Request, res: Response) => {
  try {
    const result = await db.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100");
    res.json({ logs: result.rows });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to fetch audit logs" });
  }
});

// 9. Phishing Email Analyzer (Defensive, Safe, Threat-Intel Correlated)
apiRouter.post("/analyze/phishing", async (req: Request, res: Response) => {
  try {
    const { emailContent, sender, subject } = req.body;
    if (!emailContent || typeof emailContent !== "string") {
      return res.status(400).json({ error: "Email text content is required." });
    }

    const result = await performPhishingInvestigation(emailContent, sender, subject);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Phishing analysis error" });
  }
});

// Create Incident from Phishing Investigation
apiRouter.post("/phishing/create-incident", async (req: Request, res: Response) => {
  try {
    const { analysis, options } = req.body;
    if (!analysis || !analysis.sender || analysis.riskScore === undefined) {
      return res.status(400).json({ error: "Valid phishing analysis result is required." });
    }

    const created = await createIncidentFromPhishing(analysis, options);
    res.json(created);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to create incident from phishing analysis" });
  }
});

// 10. URL Analyzer (Pure defensive structural evaluation, safe, zero outbound traffic)
apiRouter.post("/analyze/url", async (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "URL string is required." });
    }

    const result = await analyzeUrlDefense(url);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "URL analysis error" });
  }
});

// Create Incident from URL Analysis
apiRouter.post("/url/create-incident", async (req: Request, res: Response) => {
  try {
    const { analysis, options } = req.body;
    if (!analysis || analysis.riskScore === undefined) {
      return res.status(400).json({ error: "Valid URL analysis result is required." });
    }

    const created = await createIncidentFromUrl(analysis, options);
    res.json(created);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to create incident from URL analysis" });
  }
});

// 11. AI Security Copilot
apiRouter.post("/copilot/chat", async (req: Request, res: Response) => {
  try {
    const { query, incidentId } = req.body;
    if (!query || typeof query !== "string") {
      return res.status(400).json({ error: "Query prompt is required." });
    }

    let activeIncident: any = null;
    if (incidentId) {
      const incRes = await db.execute({
        sql: "SELECT * FROM incidents WHERE incidentId = ?",
        args: [incidentId],
      });
      if (incRes.rows.length > 0) {
        const row = incRes.rows[0];
        activeIncident = {
          ...row,
          affectedAssets: row.affectedAssets ? JSON.parse(String(row.affectedAssets)) : [],
          relatedEvents: row.relatedEvents ? JSON.parse(String(row.relatedEvents)) : [],
          indicators: row.indicators ? JSON.parse(String(row.indicators)) : [],
          timeline: row.timeline ? JSON.parse(String(row.timeline)) : [],
          mitreTechniques: row.mitreTechniques ? JSON.parse(String(row.mitreTechniques)) : [],
          recommendations: row.recommendations ? JSON.parse(String(row.recommendations)) : [],
          riskBreakdown: row.riskBreakdown ? JSON.parse(String(row.riskBreakdown)) : null,
        };
      }
    } else {
      // Default to top critical incident for rich context
      const incRes = await db.execute("SELECT * FROM incidents ORDER BY riskScore DESC LIMIT 1");
      if (incRes.rows.length > 0) {
        const row = incRes.rows[0];
        activeIncident = {
          ...row,
          affectedAssets: row.affectedAssets ? JSON.parse(String(row.affectedAssets)) : [],
          indicators: row.indicators ? JSON.parse(String(row.indicators)) : [],
          timeline: row.timeline ? JSON.parse(String(row.timeline)) : [],
          mitreTechniques: row.mitreTechniques ? JSON.parse(String(row.mitreTechniques)) : [],
          recommendations: row.recommendations ? JSON.parse(String(row.recommendations)) : [],
          riskBreakdown: row.riskBreakdown ? JSON.parse(String(row.riskBreakdown)) : null,
        };
      }
    }

    const response = await askCopilot(query, { activeIncident });
    res.json(response);
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Copilot response failed" });
  }
});

// 12. Synthetic Demo Scenarios
apiRouter.get("/scenarios", (req: Request, res: Response) => {
  const list = DEMO_SCENARIOS.map((s) => ({
    id: s.id,
    name: s.name,
    category: s.category,
    description: s.description,
  }));
  res.json({ scenarios: list });
});

apiRouter.post("/scenarios/load", async (req: Request, res: Response) => {
  try {
    const { scenarioId } = req.body;
    if (!scenarioId) {
      return res.status(400).json({ error: "Missing scenarioId" });
    }
    const scenario = await loadScenario(scenarioId);
    res.json({ success: true, scenarioName: scenario.name, incidentId: scenario.incident.incidentId });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Failed to load demo scenario" });
  }
});

// 13. Reset to baseline seed
apiRouter.post("/reset", async (req: Request, res: Response) => {
  try {
    await seedBaselineData();
    res.json({ success: true, message: "Synthetic SOC baseline environment re-seeded successfully." });
  } catch (err: any) {
    res.status(500).json({ error: err?.message || "Reset failed" });
  }
});
