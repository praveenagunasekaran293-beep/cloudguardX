import { createClient, Client } from "@libsql/client";
import { seedVulnerabilityIntelligence } from "./vulnerabilityIntelligence.js";

export const db: Client = createClient({
  url: "file:cyber_sentinel.db",
});

export async function initDatabase() {
  // Create tables if they do not exist
  await db.execute(`
    CREATE TABLE IF NOT EXISTS security_events (
      eventId TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      source TEXT NOT NULL,
      sourceType TEXT NOT NULL,
      user TEXT,
      ip TEXT,
      hostname TEXT,
      eventType TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      indicators TEXT,
      metadata TEXT
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS incidents (
      incidentId TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      riskScore INTEGER NOT NULL,
      status TEXT NOT NULL,
      affectedUser TEXT,
      affectedAssets TEXT,
      relatedEvents TEXT,
      indicators TEXT,
      timeline TEXT,
      mitreTechniques TEXT,
      recommendations TEXT,
      riskBreakdown TEXT,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS threat_intel (
      id TEXT PRIMARY KEY,
      indicator TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL,
      status TEXT NOT NULL,
      confidence INTEGER NOT NULL,
      firstSeen TEXT NOT NULL,
      lastSeen TEXT NOT NULL,
      source TEXT NOT NULL,
      threatGroup TEXT,
      tags TEXT,
      notes TEXT
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      cveId TEXT PRIMARY KEY,
      asset TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss REAL NOT NULL,
      exposure TEXT NOT NULL,
      assetImportance TEXT NOT NULL,
      priority INTEGER NOT NULL,
      priorityExplanation TEXT,
      remediationStatus TEXT NOT NULL,
      remediationPlaybook TEXT,
      description TEXT NOT NULL,
      discoveredAt TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS response_actions (
      id TEXT PRIMARY KEY,
      incidentId TEXT NOT NULL,
      title TEXT NOT NULL,
      actionType TEXT NOT NULL,
      description TEXT NOT NULL,
      recommendedBy TEXT NOT NULL,
      riskLevel TEXT NOT NULL,
      status TEXT NOT NULL,
      decidedBy TEXT,
      decidedAt TEXT,
      justification TEXT,
      createdAt TEXT NOT NULL
    );
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      userAction TEXT NOT NULL,
      actionType TEXT NOT NULL,
      incidentId TEXT,
      aiRecommendation TEXT,
      analystDecision TEXT,
      details TEXT NOT NULL
    );
  `);

  // Ensure vulnerability intelligence columns exist
  try {
    await db.execute("ALTER TABLE vulnerabilities ADD COLUMN assetType TEXT");
  } catch {}
  try {
    await db.execute("ALTER TABLE vulnerabilities ADD COLUMN exploitabilityInfo TEXT");
  } catch {}
  try {
    await db.execute("ALTER TABLE vulnerabilities ADD COLUMN priorityBreakdown TEXT");
  } catch {}
  try {
    await db.execute("ALTER TABLE vulnerabilities ADD COLUMN isSyntheticDemo INTEGER DEFAULT 1");
  } catch {}

  // Check if we need baseline seed data
  const countRes = await db.execute("SELECT COUNT(*) as count FROM security_events");
  const count = Number(countRes.rows[0].count);
  if (count === 0) {
    await seedBaselineData();
  } else {
    // If vulnerabilities is empty or needs seed upgrade
    const vCount = await db.execute("SELECT COUNT(*) as count FROM vulnerabilities WHERE exploitabilityInfo IS NOT NULL");
    if (Number(vCount.rows[0].count) === 0) {
      await seedVulnerabilityIntelligence();
    }
  }
}

export async function seedBaselineData() {
  await db.execute("DELETE FROM security_events");
  await db.execute("DELETE FROM incidents");
  await db.execute("DELETE FROM threat_intel");
  await db.execute("DELETE FROM vulnerabilities");
  await db.execute("DELETE FROM response_actions");
  await db.execute("DELETE FROM audit_logs");

  const now = new Date();
  const formatTime = (minutesAgo: number) => {
    return new Date(now.getTime() - minutesAgo * 60 * 1000).toISOString();
  };

  // Seed Events
  const events = [
    {
      eventId: "EVT-8821",
      timestamp: formatTime(65),
      source: "MailGuard SEG",
      sourceType: "Email Gateway",
      user: "sarah.jenkins@enterprise-corp.internal",
      ip: "198.51.100.44",
      hostname: "mx01.enterprise-corp.internal",
      eventType: "Inbound Phishing Detected",
      description: "Inbound message spoofing HR Payroll portal with urgency cue and suspicious domain link.",
      severity: "High",
      indicators: JSON.stringify(["payroll-update-secure.top", "198.51.100.44", "hr-notice@portal-verify.cc"]),
      metadata: JSON.stringify({ subject: "URGENT: Verify Direct Deposit for Q3 Payroll", spf: "fail", dkim: "none" }),
    },
    {
      eventId: "EVT-8824",
      timestamp: formatTime(55),
      source: "PaloAlto NextGen FW",
      sourceType: "Network Firewall",
      user: "sarah.jenkins",
      ip: "10.0.4.88",
      hostname: "WS-FIN-04.corp.local",
      eventType: "Suspicious DNS Resolution",
      description: "Endpoint resolved known newly-registered domain flagged in threat intelligence feed.",
      severity: "Medium",
      indicators: JSON.stringify(["payroll-update-secure.top", "198.51.100.44"]),
      metadata: JSON.stringify({ queryType: "A", responseIp: "198.51.100.44", ttl: 60 }),
    },
    {
      eventId: "EVT-8829",
      timestamp: formatTime(42),
      source: "Okta Identity Provider",
      sourceType: "Identity Provider (IAM)",
      user: "sarah.jenkins@enterprise-corp.internal",
      ip: "198.51.100.44",
      hostname: "auth.corp.local",
      eventType: "Abnormal Authentication Geolocation",
      description: "Successful login from unfamiliar external IP (Bucharest, RO) 12 minutes after session in Chicago, US (Impossible Travel).",
      severity: "Critical",
      indicators: JSON.stringify(["198.51.100.44", "sarah.jenkins"]),
      metadata: JSON.stringify({ client: "Mozilla/5.0 (Windows NT 10.0; Win64)", mfaUsed: "SMS-OTP-Intercept", travelSpeedMph: 2450 }),
    },
    {
      eventId: "EVT-8835",
      timestamp: formatTime(31),
      source: "CrowdStrike Falcon EDR",
      sourceType: "Endpoint Detection & Response",
      user: "sarah.jenkins",
      ip: "10.0.4.88",
      hostname: "WS-FIN-04.corp.local",
      eventType: "Encoded PowerShell Execution",
      description: "PowerShell spawned with Base64 encoded payload attempting memory injection into explorer.exe.",
      severity: "Critical",
      indicators: JSON.stringify(["WS-FIN-04", "powershell.exe", "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]),
      metadata: JSON.stringify({ parentProcess: "winword.exe", commandLine: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA..." }),
    },
    {
      eventId: "EVT-8840",
      timestamp: formatTime(20),
      source: "Splunk SIEM Correlation",
      sourceType: "SIEM",
      user: "sarah.jenkins",
      ip: "10.0.4.88",
      hostname: "WS-FIN-04.corp.local",
      eventType: "Internal Lateral Reconnaissance",
      description: "Rapid SMB/RPC port scanning directed at Active Directory Domain Controller and Financial Shared Storage.",
      severity: "High",
      indicators: JSON.stringify(["10.0.4.88", "10.0.0.5", "10.0.2.12"]),
      metadata: JSON.stringify({ targetPorts: [445, 135, 3389], packetsSent: 1420 }),
    },
    {
      eventId: "EVT-8846",
      timestamp: formatTime(12),
      source: "AWS CloudTrail",
      sourceType: "Cloud Audit",
      user: "svc-backup-automation",
      ip: "203.0.113.89",
      hostname: "aws-prod-iam",
      eventType: "S3 Bucket Policy Modification",
      description: "S3 bucket financial-reports-archive-prod policy modified to allow public read permissions.",
      severity: "High",
      indicators: JSON.stringify(["203.0.113.89", "arn:aws:s3:::financial-reports-archive-prod"]),
      metadata: JSON.stringify({ action: "PutBucketPolicy", effect: "Allow", principal: "*" }),
    },
    {
      eventId: "EVT-8850",
      timestamp: formatTime(8),
      source: "Suricata NIDS",
      sourceType: "Network IDS",
      user: "N/A",
      ip: "10.0.4.88 -> 198.51.100.99",
      hostname: "GW-CORE-01",
      eventType: "Suspicious Outbound Beaconing",
      description: "Periodic HTTP POST requests (jitter 5s) to untrusted foreign IP matching known C2 heartbeat patterns.",
      severity: "Critical",
      indicators: JSON.stringify(["198.51.100.99", "10.0.4.88"]),
      metadata: JSON.stringify({ protocol: "TCP/443", payloadBytes: 256, intervalSeconds: 30 }),
    },
    {
      eventId: "EVT-8852",
      timestamp: formatTime(3),
      source: "Zscaler Cloud ZPA",
      sourceType: "Secure Web Gateway",
      user: "david.miller",
      ip: "10.0.8.14",
      hostname: "WS-DEV-19.corp.local",
      eventType: "Blocked Untrusted File Download",
      description: "Executable download blocked from dynamic DNS domain with low reputation.",
      severity: "Medium",
      indicators: JSON.stringify(["malware-test-sample.duckdns.org"]),
      metadata: JSON.stringify({ file: "invoice_update.zip", category: "Suspicious" }),
    },
  ];

  for (const ev of events) {
    await db.execute({
      sql: `INSERT INTO security_events (eventId, timestamp, source, sourceType, user, ip, hostname, eventType, description, severity, indicators, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [ev.eventId, ev.timestamp, ev.source, ev.sourceType, ev.user, ev.ip, ev.hostname, ev.eventType, ev.description, ev.severity, ev.indicators, ev.metadata],
    });
  }

  // Seed Incidents
  const incidents = [
    {
      incidentId: "INC-2026-001",
      title: "Credential Phishing & Endpoint PowerShell Execution on Financial Workstation",
      description: "Multi-stage intrusion chain initiated via targeted HR payroll spear-phishing, followed by abnormal Romanian geolocation login (Impossible Travel), leading to Base64 encoded PowerShell execution on WS-FIN-04.",
      severity: "Critical",
      riskScore: 92,
      status: "Investigating",
      affectedUser: "sarah.jenkins@enterprise-corp.internal",
      affectedAssets: JSON.stringify(["WS-FIN-04.corp.local", "Active Directory (CORP-DC-01)", "Okta IAM Tenant"]),
      relatedEvents: JSON.stringify(["EVT-8821", "EVT-8824", "EVT-8829", "EVT-8835", "EVT-8840"]),
      indicators: JSON.stringify(["198.51.100.44", "payroll-update-secure.top", "WS-FIN-04", "hr-notice@portal-verify.cc"]),
      timeline: JSON.stringify([
        { time: formatTime(65), event: "Inbound Spear-Phishing Email Delivered", source: "MailGuard SEG", severity: "High" },
        { time: formatTime(55), event: "User Clicked Link & Resolved Malicious Domain", source: "PaloAlto FW", severity: "Medium" },
        { time: formatTime(42), event: "Impossible Travel Authentication Anomaly (RO)", source: "Okta IAM", severity: "Critical" },
        { time: formatTime(31), event: "Encoded PowerShell Injected into Explorer Process", source: "CrowdStrike EDR", severity: "Critical" },
        { time: formatTime(20), event: "Internal Port Scanning of Domain Controller", source: "Splunk SIEM", severity: "High" },
      ]),
      mitreTechniques: JSON.stringify([
        { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", status: "Confirmed" },
        { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Defense Evasion", status: "Confirmed" },
        { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", status: "Confirmed" },
        { id: "T1055", name: "Process Injection", tactic: "Privilege Escalation", status: "Confirmed" },
        { id: "T1046", name: "Network Service Discovery", tactic: "Discovery", status: "Suspected" },
      ]),
      recommendations: JSON.stringify([
        "Immediately isolate endpoint WS-FIN-04 from the corporate local network via EDR agent.",
        "Revoke all active Okta sessions and force password + hardware FIDO2 MFA reset for sarah.jenkins.",
        "Block ingress/egress for IP 198.51.100.44 and domain payroll-update-secure.top across border firewalls.",
        "Perform memory triage on WS-FIN-04 to identify injected modules.",
      ]),
      riskBreakdown: JSON.stringify({
        factors: [
          { name: "Threat Intelligence Match (Domain & IP)", points: 25, reason: "payroll-update-secure.top flagged on synthetic TI feed with 94% confidence." },
          { name: "Abnormal Authentication / Impossible Travel", points: 30, reason: "Concurrent login Chicago -> Bucharest (2,450 mph velocity)." },
          { name: "High-Privilege Process Injection (EDR)", points: 22, reason: "PowerShell executing Base64 encoded payload inside explorer.exe." },
          { name: "High Value Asset Exposure", points: 15, reason: "Target machine resides in Financial Processing VLAN with SMB probes to Domain Controller." },
        ],
        totalScore: 92,
        maxScore: 100,
        explanation: "Risk score 92/100 denotes a critical, active multi-stage incident requiring immediate containment before data exfiltration occurs.",
      }),
      createdAt: formatTime(60),
      updatedAt: formatTime(5),
    },
    {
      incidentId: "INC-2026-002",
      title: "Public Exposure of Financial Storage via CloudTrail IAM Mutation",
      description: "Automated service account svc-backup-automation modified S3 bucket access policy, opening financial archive to public unauthenticated reads.",
      severity: "High",
      riskScore: 78,
      status: "Open",
      affectedUser: "svc-backup-automation",
      affectedAssets: JSON.stringify(["arn:aws:s3:::financial-reports-archive-prod"]),
      relatedEvents: JSON.stringify(["EVT-8846"]),
      indicators: JSON.stringify(["203.0.113.89", "arn:aws:s3:::financial-reports-archive-prod"]),
      timeline: JSON.stringify([
        { time: formatTime(18), event: "API Key Generated for svc-backup-automation", source: "AWS IAM", severity: "Medium" },
        { time: formatTime(12), event: "PutBucketPolicy API invoked with Principal: *", source: "AWS CloudTrail", severity: "High" },
        { time: formatTime(9), event: "AWS GuardDuty Anomaly Alert: Public Bucket", source: "AWS GuardDuty", severity: "High" },
      ]),
      mitreTechniques: JSON.stringify([
        { id: "T1530", name: "Data from Cloud Storage Object", tactic: "Collection", status: "Suspected" },
        { id: "T1098", name: "Account Manipulation", tactic: "Persistence", status: "Confirmed" },
      ]),
      recommendations: JSON.stringify([
        "Enable S3 Block Public Access at the AWS account root level.",
        "Revert bucket policy to least-privilege KMS encrypted configuration.",
        "Rotate compromised access keys for svc-backup-automation.",
      ]),
      riskBreakdown: JSON.stringify({
        factors: [
          { name: "Public Data Exposure Exposure", points: 35, reason: "Financial archive contains regulated Sarbanes-Oxley audit reports." },
          { name: "Service Account Deviation", points: 25, reason: "Backup account rarely executes PutBucketPolicy calls." },
          { name: "External Originating IP", points: 18, reason: "API call originated from non-corporate residential VPN IP." },
        ],
        totalScore: 78,
        maxScore: 100,
        explanation: "High risk (78/100) due to unencrypted public exposure of regulated financial documents.",
      }),
      createdAt: formatTime(15),
      updatedAt: formatTime(10),
    },
    {
      incidentId: "INC-2026-003",
      title: "External Command & Control Heartbeat Beaconing from Core Gateway",
      description: "Suricata NIDS detected persistent regular beaconing outward over TLS to known synthetic botnet sinkhole.",
      severity: "High",
      riskScore: 71,
      status: "Investigating",
      affectedUser: "N/A",
      affectedAssets: JSON.stringify(["GW-CORE-01", "VLAN-10-SERVERS"]),
      relatedEvents: JSON.stringify(["EVT-8850"]),
      indicators: JSON.stringify(["198.51.100.99"]),
      timeline: JSON.stringify([
        { time: formatTime(40), event: "Initial TCP Syn to sinkhole address", source: "Suricata", severity: "Low" },
        { time: formatTime(25), event: "Beaconing pattern established (30s interval)", source: "Suricata", severity: "High" },
        { time: formatTime(8), event: "NIDS alert raised for C2 signature #203491", source: "Suricata", severity: "High" },
      ]),
      mitreTechniques: JSON.stringify([
        { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control", status: "Confirmed" },
        { id: "T1573", name: "Encrypted Channel", tactic: "Command and Control", status: "Suspected" },
      ]),
      recommendations: JSON.stringify([
        "Enforce perimeter egress drop rule for IP 198.51.100.99.",
        "Inspect proxy access logs to locate specific host initiating TLS session.",
      ]),
      riskBreakdown: JSON.stringify({
        factors: [
          { name: "Periodic Beacon Interval", points: 30, reason: "Strict 30-second cadence characteristic of automated C2 agent." },
          { name: "Blacklisted Threat Intel Node", points: 25, reason: "Destination IP present on synthetic C2 sinkhole lists." },
          { name: "Core Infrastructure Path", points: 16, reason: "Transiting through critical enterprise backbone gateway." },
        ],
        totalScore: 71,
        maxScore: 100,
        explanation: "Threat score 71/100 due to verified automated beaconing signature.",
      }),
      createdAt: formatTime(35),
      updatedAt: formatTime(8),
    },
    {
      incidentId: "INC-2026-004",
      title: "Outdated Apache Log4j Dependency in Internal Inventory Service",
      description: "Automated vulnerability scanner discovered Log4j 2.14.1 on internal asset SRV-INV-02, exposing JNDI injection vulnerability CVE-2021-44228.",
      severity: "Medium",
      riskScore: 54,
      status: "Open",
      affectedUser: "system",
      affectedAssets: JSON.stringify(["SRV-INV-02.internal"]),
      relatedEvents: JSON.stringify([]),
      indicators: JSON.stringify(["CVE-2021-44228"]),
      timeline: JSON.stringify([
        { time: formatTime(180), event: "Weekly Vulnerability Scan Completed", source: "Tenable Nessus", severity: "Medium" },
        { time: formatTime(120), event: "Vulnerability Ticket Automated Creation", source: "Jira Security", severity: "Low" },
      ]),
      mitreTechniques: JSON.stringify([
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", status: "Potential" },
      ]),
      recommendations: JSON.stringify([
        "Patch Log4j to >= 2.17.1 or apply log4j2.formatMsgNoLookups=true system flag.",
        "Verify asset is non-public facing behind internal reverse proxy.",
      ]),
      riskBreakdown: JSON.stringify({
        factors: [
          { name: "High CVSS Score (10.0)", points: 35, reason: "Critical severity vulnerability with known public POCs." },
          { name: "Air-Gapped / Internal Only (-16)", points: -16, reason: "Asset is strictly internal with no direct Internet ingress." },
          { name: "WAF Mitigation Active", points: -5, reason: "ModSecurity WAF rules block ${jndi: patterns." },
          { name: "Core Asset Importance", points: 20, reason: "Handles inventory database transactions." },
        ],
        totalScore: 54,
        maxScore: 100,
        explanation: "Risk adjusted from theoretical 100 down to 54/100 because asset is strictly internal with active WAF regex filtering.",
      }),
      createdAt: formatTime(180),
      updatedAt: formatTime(60),
    },
  ];

  for (const inc of incidents) {
    await db.execute({
      sql: `INSERT INTO incidents (incidentId, title, description, severity, riskScore, status, affectedUser, affectedAssets, relatedEvents, indicators, timeline, mitreTechniques, recommendations, riskBreakdown, createdAt, updatedAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        inc.incidentId,
        inc.title,
        inc.description,
        inc.severity,
        inc.riskScore,
        inc.status,
        inc.affectedUser,
        inc.affectedAssets,
        inc.relatedEvents,
        inc.indicators,
        inc.timeline,
        inc.mitreTechniques,
        inc.recommendations,
        inc.riskBreakdown,
        inc.createdAt,
        inc.updatedAt,
      ],
    });
  }

  // Seed Threat Intelligence (Clearly labelled synthetic/demo indicators)
  const threatIntel = [
    {
      id: "TI-001",
      indicator: "198.51.100.44",
      type: "IP",
      status: "Malicious (Synthetic)",
      confidence: 94,
      firstSeen: "2026-08-10T14:22:00Z",
      lastSeen: "2026-09-24T22:15:00Z",
      source: "CyberSentinel Synthetic Feed / AlienVault OTX Demo",
      threatGroup: "APT-29 Synthetic Emulation",
      tags: JSON.stringify(["phishing", "credential-harvest", "bulletproof-hosting"]),
      notes: "Synthetic IP assigned to demo credential harvester infrastructure mimicking enterprise SSO portals.",
    },
    {
      id: "TI-002",
      indicator: "payroll-update-secure.top",
      type: "Domain",
      status: "Malicious (Synthetic)",
      confidence: 98,
      firstSeen: "2026-09-18T09:10:00Z",
      lastSeen: "2026-09-25T01:10:00Z",
      source: "DomainTools Demo Rep Feed",
      threatGroup: "FIN-7 Synthetic Emulation",
      tags: JSON.stringify(["spearphishing", "spoofed-brand", "fast-flux"]),
      notes: "Newly registered top-level domain (.top) hosting synthetic lookalike corporate payroll verification.",
    },
    {
      id: "TI-003",
      indicator: "https://payroll-update-secure.top/auth/verify?session=99281a",
      type: "URL",
      status: "Malicious (Synthetic)",
      confidence: 99,
      firstSeen: "2026-09-24T18:00:00Z",
      lastSeen: "2026-09-25T01:30:00Z",
      source: "SafeBrowsing Synthetic Simulator",
      threatGroup: "Unknown Phishing Kit",
      tags: JSON.stringify(["credential-phish", "mfa-bypass-proxy"]),
      notes: "Synthetic URL embedded in phishing emails designed to reverse-proxy corporate login prompts.",
    },
    {
      id: "TI-004",
      indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      type: "File Hash (SHA256)",
      status: "Suspicious (Synthetic)",
      confidence: 85,
      firstSeen: "2026-09-01T04:12:00Z",
      lastSeen: "2026-09-24T16:00:00Z",
      source: "VirusTotal Demo Intelligence",
      threatGroup: "CobaltStrike Beacon Stager Demo",
      tags: JSON.stringify(["powershell-dropper", "memory-injector", "stager"]),
      notes: "Synthetic file hash representing an in-memory encoded PowerShell loader.",
    },
    {
      id: "TI-005",
      indicator: "198.51.100.99",
      type: "IP",
      status: "Malicious (Synthetic)",
      confidence: 88,
      firstSeen: "2026-07-15T11:00:00Z",
      lastSeen: "2026-09-25T00:50:00Z",
      source: "AbuseIPDB Synthetic Sinkhole",
      threatGroup: "AsyncRAT Emulation",
      tags: JSON.stringify(["c2-beacon", "sinkholed", "botnet"]),
      notes: "Synthetic command & control node associated with background socket telemetry simulations.",
    },
    {
      id: "TI-006",
      indicator: "portal-verify.cc",
      type: "Domain",
      status: "Suspicious (Synthetic)",
      confidence: 76,
      firstSeen: "2026-09-12T03:00:00Z",
      lastSeen: "2026-09-24T19:30:00Z",
      source: "PassiveTotal Demo",
      threatGroup: "PhishKit Template V3",
      tags: JSON.stringify(["parked-domain", "lookalike"]),
      notes: "Synthetic domain with MX records pointed at disposable webmail relays.",
    },
    {
      id: "TI-007",
      indicator: "203.0.113.89",
      type: "IP",
      status: "Suspicious (Synthetic)",
      confidence: 70,
      firstSeen: "2026-09-20T10:00:00Z",
      lastSeen: "2026-09-25T01:20:00Z",
      source: "AWS GuardDuty Synthetic",
      threatGroup: "Cloud Account Takeover",
      tags: JSON.stringify(["anonymizer-vpn", "cloudtrail-anomaly"]),
      notes: "Commercial VPN exit node associated with unauthorized CloudTrail modifications in demo scenario.",
    },
  ];

  for (const ti of threatIntel) {
    await db.execute({
      sql: `INSERT INTO threat_intel (id, indicator, type, status, confidence, firstSeen, lastSeen, source, threatGroup, tags, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [ti.id, ti.indicator, ti.type, ti.status, ti.confidence, ti.firstSeen, ti.lastSeen, ti.source, ti.threatGroup, ti.tags, ti.notes],
    });
  }

  // Seed Vulnerabilities via Explainable Vulnerability Intelligence Engine
  await seedVulnerabilityIntelligence();

  // Seed Response Actions (Human-in-the-Loop)
  const responseActions = [
    {
      id: "ACT-001",
      incidentId: "INC-2026-001",
      title: "Isolate Endpoint WS-FIN-04 from Network",
      actionType: "Network Quarantine",
      description: "Instruct EDR agent on WS-FIN-04.corp.local to terminate non-management socket connectivity and isolate host from subnet.",
      recommendedBy: "CyberSentinel AI Autonomous Engine",
      riskLevel: "High",
      status: "APPROVED",
      decidedBy: "Lead SOC Analyst (Praveena G.)",
      decidedAt: formatTime(15),
      justification: "Confirmed in-memory process injection and lateral SMB discovery warrants immediate host quarantine to halt propagation.",
      createdAt: formatTime(25),
    },
    {
      id: "ACT-002",
      incidentId: "INC-2026-001",
      title: "Revoke Active Okta Tokens & Trigger Step-Up Auth for sarah.jenkins",
      actionType: "IAM Session Revocation",
      description: "Invalidate OAuth refresh tokens, kill current browser sessions, and place account in password-reset quarantine.",
      recommendedBy: "CyberSentinel AI Autonomous Engine",
      riskLevel: "Medium",
      status: "APPROVED",
      decidedBy: "Lead SOC Analyst (Praveena G.)",
      decidedAt: formatTime(18),
      justification: "Impossible Travel geolocation anomaly proves session hijacking via reverse-proxy credential phish.",
      createdAt: formatTime(28),
    },
    {
      id: "ACT-003",
      incidentId: "INC-2026-001",
      title: "Global Perimeter Firewall Ingress Drop: 198.51.100.44",
      actionType: "Perimeter Block",
      description: "Push ACL entry to Palo Alto perimeter clusters blocking all ingress/egress from IP 198.51.100.44.",
      recommendedBy: "CyberSentinel AI Autonomous Engine",
      riskLevel: "Low",
      status: "PENDING",
      decidedBy: null,
      decidedAt: null,
      justification: null,
      createdAt: formatTime(10),
    },
    {
      id: "ACT-004",
      incidentId: "INC-2026-002",
      title: "Enforce S3 Block Public Access on AWS Account Root",
      actionType: "Cloud Policy Enforcement",
      description: "Apply S3 Account-level BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
      recommendedBy: "CyberSentinel AI Autonomous Engine",
      riskLevel: "Medium",
      status: "PENDING",
      decidedBy: null,
      decidedAt: null,
      justification: null,
      createdAt: formatTime(8),
    },
    {
      id: "ACT-005",
      incidentId: "INC-2026-003",
      title: "Blackhole Sinkhole Route for 198.51.100.99",
      actionType: "BGP / Null-Route",
      description: "Null-route untrusted C2 destination IP on core gateway routing table.",
      recommendedBy: "CyberSentinel AI Autonomous Engine",
      riskLevel: "Low",
      status: "PENDING",
      decidedBy: null,
      decidedAt: null,
      justification: null,
      createdAt: formatTime(5),
    },
  ];

  for (const act of responseActions) {
    await db.execute({
      sql: `INSERT INTO response_actions (id, incidentId, title, actionType, description, recommendedBy, riskLevel, status, decidedBy, decidedAt, justification, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [act.id, act.incidentId, act.title, act.actionType, act.description, act.recommendedBy, act.riskLevel, act.status, act.decidedBy, act.decidedAt, act.justification, act.createdAt],
    });
  }

  // Seed Audit Logs
  const auditLogs = [
    {
      id: "AUD-1001",
      timestamp: formatTime(25),
      userAction: "AI Recommended Response Action Generated",
      actionType: "AI Recommendation",
      incidentId: "INC-2026-001",
      aiRecommendation: "Isolate Endpoint WS-FIN-04 due to High Severity Process Injection.",
      analystDecision: "Pending Review",
      details: "Autonomous detection pipeline generated action ACT-001 with High risk rating.",
    },
    {
      id: "AUD-1002",
      timestamp: formatTime(18),
      userAction: "Analyst Approved Response Action ACT-002",
      actionType: "Human Approval",
      incidentId: "INC-2026-001",
      aiRecommendation: "Revoke Okta sessions for sarah.jenkins.",
      analystDecision: "Approved by Lead SOC Analyst",
      details: "Analyst validated impossible travel timestamp correlation and verified token revocation dispatch.",
    },
    {
      id: "AUD-1003",
      timestamp: formatTime(15),
      userAction: "Analyst Approved Response Action ACT-001",
      actionType: "Human Approval",
      incidentId: "INC-2026-001",
      aiRecommendation: "Isolate Endpoint WS-FIN-04 from Network.",
      analystDecision: "Approved by Lead SOC Analyst",
      details: "Quarantine command sent to CrowdStrike Falcon agent on WS-FIN-04. Local host isolated.",
    },
    {
      id: "AUD-1004",
      timestamp: formatTime(8),
      userAction: "Incident Status Transition: Open -> Investigating",
      actionType: "Workflow State Change",
      incidentId: "INC-2026-001",
      aiRecommendation: "Escalate to Tier 2 Digital Forensics & Incident Response (DFIR)",
      analystDecision: "Investigating state confirmed",
      details: "Incident INC-2026-001 triage assigned to DFIR queue.",
    },
  ];

  for (const log of auditLogs) {
    await db.execute({
      sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [log.id, log.timestamp, log.userAction, log.actionType, log.incidentId, log.aiRecommendation, log.analystDecision, log.details],
    });
  }
}
