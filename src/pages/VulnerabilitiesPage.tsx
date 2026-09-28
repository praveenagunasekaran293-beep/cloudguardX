import React, { useEffect, useMemo, useState } from "react";
import {
  Bug,
  BookOpen,
  HelpCircle,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import { api } from "../services/api";
import { searchNvdCve } from "../services/nvdApi";
import { Vulnerability, SeverityLevel } from "../types";

export const VulnerabilitiesPage: React.FC = () => {
  // =========================================================
  // EXISTING VULNERABILITY DATA
  // =========================================================
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] =
    useState<Vulnerability | null>(null);

  // =========================================================
  // NVD SEARCH
  // =========================================================
  const [cveSearch, setCveSearch] = useState("");
  const [nvdResult, setNvdResult] = useState<any>(null);
  const [nvdLoading, setNvdLoading] = useState(false);

  // =========================================================
  // SAVED CVEs
  // =========================================================
  const [savedCves, setSavedCves] = useState<any[]>([]);
  const [savedCveSearch, setSavedCveSearch] = useState("");
  const [savedSeverityFilter, setSavedSeverityFilter] =
    useState("All");

  // =========================================================
  // LOAD EXISTING VULNERABILITIES
  // =========================================================
  const loadVulns = async () => {
    try {
      setLoading(true);

      const data = await api.getVulnerabilities();

      setVulns(data.vulnerabilities || []);
    } catch (err) {
      console.error("Failed to load vulnerabilities:", err);
    } finally {
      setLoading(false);
    }
  };

  // =========================================================
  // LOAD SAVED CVEs FROM LOCALSTORAGE
  // =========================================================
  useEffect(() => {
    try {
      const saved = JSON.parse(
        localStorage.getItem("cybersentinel_saved_cves") || "[]"
      );

      if (Array.isArray(saved)) {
        setSavedCves(saved);
      } else {
        setSavedCves([]);
      }
    } catch (err) {
      console.error("Failed to load saved CVEs:", err);
      setSavedCves([]);
    }
  }, []);

  // =========================================================
  // INITIAL LOAD
  // =========================================================
  useEffect(() => {
    loadVulns();
  }, []);

  // =========================================================
  // SEARCH CVE IN NVD
  // =========================================================
  const handleCveSearch = async () => {
    const query = cveSearch.trim();

    if (!query) {
      return;
    }

    try {
      setNvdLoading(true);
      setNvdResult(null);

      const result = await searchNvdCve(query);

      setNvdResult(result);
    } catch (err: any) {
      console.error("NVD search error:", err);

      setNvdResult({
        error:
          err?.message ||
          "Unable to fetch CVE information from NVD.",
      });
    } finally {
      setNvdLoading(false);
    }
  };

  // =========================================================
  // SAVE CVE
  // =========================================================
  const handleSaveCve = () => {
    if (!nvdResult || nvdResult.error || !nvdResult.id) {
      return;
    }

    try {
      const existing = JSON.parse(
        localStorage.getItem("cybersentinel_saved_cves") || "[]"
      );

      const safeExisting = Array.isArray(existing)
        ? existing
        : [];

      const alreadySaved = safeExisting.some(
        (cve: any) => cve.id === nvdResult.id
      );

      if (alreadySaved) {
        alert(`${nvdResult.id} is already saved.`);
        return;
      }

      const updated = [...safeExisting, nvdResult];

      localStorage.setItem(
        "cybersentinel_saved_cves",
        JSON.stringify(updated)
      );

      setSavedCves(updated);

      alert(`${nvdResult.id} saved successfully.`);
    } catch (err) {
      console.error("Failed to save CVE:", err);

      alert("Unable to save this CVE.");
    }
  };

  // =========================================================
  // DELETE SAVED CVE
  // =========================================================
  const handleDeleteCve = (cveId: string) => {
    try {
      const updated = savedCves.filter(
        (cve: any) => cve.id !== cveId
      );

      localStorage.setItem(
        "cybersentinel_saved_cves",
        JSON.stringify(updated)
      );

      setSavedCves(updated);
    } catch (err) {
      console.error("Failed to delete CVE:", err);
    }
  };

  // =========================================================
  // FILTER SAVED CVEs
  // =========================================================
  const filteredSavedCves = useMemo(() => {
    return savedCves.filter((cve: any) => {
      const search = savedCveSearch
        .toLowerCase()
        .trim();

      const id = (cve.id || "").toLowerCase();

      const description =
        cve.descriptions
          ?.find((d: any) => d.lang === "en")
          ?.value?.toLowerCase() || "";

      const severity =
        cve.metrics?.cvssMetricV31?.[0]?.cvssData
          ?.baseSeverity ??
        cve.metrics?.cvssMetricV30?.[0]?.cvssData
          ?.baseSeverity ??
        "";

      const matchesSearch =
        !search ||
        id.includes(search) ||
        description.includes(search);

      const matchesSeverity =
        savedSeverityFilter === "All" ||
        severity ===
          savedSeverityFilter.toUpperCase();

      return (
        matchesSearch && matchesSeverity
      );
    });
  }, [
    savedCves,
    savedCveSearch,
    savedSeverityFilter,
  ]);

  // =========================================================
  // REMEDIATION STATUS
  // =========================================================
  const handleStatusChange = async (
    cveId: string,
    newStatus: string
  ) => {
    try {
      await api.updateVulnerabilityStatus(
        cveId,
        newStatus
      );

      setVulns((prev) =>
        prev.map((v) =>
          v.cveId === cveId
            ? {
                ...v,
                remediationStatus: newStatus,
              }
            : v
        )
      );

      if (
        selectedVuln &&
        selectedVuln.cveId === cveId
      ) {
        setSelectedVuln({
          ...selectedVuln,
          remediationStatus: newStatus,
        });
      }
    } catch (err) {
      console.error(
        "Failed to update remediation status:",
        err
      );
    }
  };

  // =========================================================
  // SEVERITY BADGE
  // =========================================================
  const getSeverityBadge = (
    severity: SeverityLevel
  ) => {
    switch (severity) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border border-red-500/40";

      case "High":
        return "bg-orange-500/20 text-orange-400 border border-orange-500/40";

      case "Medium":
        return "bg-amber-500/20 text-amber-300 border border-amber-500/40";

      case "Low":
        return "bg-blue-500/20 text-blue-400 border border-blue-500/40";

      default:
        return "bg-slate-500/20 text-slate-400 border border-slate-500/40";
    }
  };

  // =========================================================
  // CSV EXPORT
  // =========================================================
  const handleExportCsv = () => {
    if (savedCves.length === 0) {
      return;
    }

    try {
      const header = [
        "CVE",
        "Severity",
        "CVSS",
        "Exploitability",
        "Impact",
        "Description",
        "Published",
        "LastModified",
      ];

      const rows = savedCves.map((cve: any) => {
        const cvssData =
          cve.metrics?.cvssMetricV31?.[0]?.cvssData ??
          cve.metrics?.cvssMetricV30?.[0]?.cvssData ??
          {};

        const exploitability =
          cve.metrics?.cvssMetricV31?.[0]
            ?.exploitabilityScore ??
          cve.metrics?.cvssMetricV30?.[0]
            ?.exploitabilityScore ??
          "";

        const impact =
          cve.metrics?.cvssMetricV31?.[0]
            ?.impactScore ??
          cve.metrics?.cvssMetricV30?.[0]
            ?.impactScore ??
          "";

        const description =
          cve.descriptions
            ?.find((d: any) => d.lang === "en")
            ?.value || "";

        return [
          cve.id || "",
          cvssData.baseSeverity || "",
          cvssData.baseScore ?? "",
          exploitability,
          impact,
          description,
          cve.published || "",
          cve.lastModified || "",
        ];
      });

      const escapeCsvValue = (value: any) => {
        const text = String(value ?? "");

        return `"${text.replace(/"/g, '""')}"`;
      };

      const csv = [
        header.map(escapeCsvValue).join(","),
        ...rows.map((row) =>
          row.map(escapeCsvValue).join(",")
        ),
      ].join("\n");

      const blob = new Blob([csv], {
        type: "text/csv;charset=utf-8;",
      });

      const url = URL.createObjectURL(blob);

      const link = document.createElement("a");

      link.href = url;
      link.download =
        "cybersentinel-vulnerability-report.csv";

      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      URL.revokeObjectURL(url);
    } catch (err) {
      console.error(
        "Failed to export vulnerability report:",
        err
      );

      alert("Unable to export CSV report.");
    }
  };

  // =========================================================
  // REMEDIATION COUNTS
  // =========================================================
  const remediationStatuses = [
  "Open",
  "In Progress",
  "Pending Maintenance Window",
  "Patch Scheduled",
  "Remediated",
];

  return (
    <div className="space-y-6">

      {/* =====================================================
          PAGE HEADER
      ====================================================== */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          Vulnerability Intelligence &
          Exposure Prioritization
        </h1>

        <p className="text-xs text-slate-400 mt-1">
          Contextual risk prioritization:
          correlates raw CVSS v3.1 severity with
          asset criticality and internet exposure
          to eliminate vulnerability alert fatigue.
        </p>
      </div>

      {/* =====================================================
          NVD CVE SEARCH
      ====================================================== */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">

        <div className="flex items-center gap-2 mb-3">
          <Bug className="w-4 h-4 text-cyan-400" />

          <h2 className="text-sm font-bold text-white">
            NVD CVE Intelligence Search
          </h2>
        </div>

        {/* SEARCH BAR */}
        <div className="flex flex-col sm:flex-row gap-2">

          <input
            type="text"
            value={cveSearch}
            onChange={(e) =>
              setCveSearch(e.target.value)
            }
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                handleCveSearch();
              }
            }}
            placeholder="Enter CVE ID (e.g. CVE-2021-44228)"
            className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />

          <button
            onClick={() => {
              setCveSearch("");
              setNvdResult(null);
            }}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg border border-slate-700"
          >
            Clear
          </button>

          <button
            onClick={handleCveSearch}
            disabled={nvdLoading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center justify-center gap-2"
          >
            <RefreshCw
              className={`w-3 h-3 ${
                nvdLoading ? "animate-spin" : ""
              }`}
            />

            {nvdLoading
              ? "Searching..."
              : "Search CVE"}
          </button>

        </div>

        {/* =================================================
            NVD RESULT
        ================================================== */}
        {nvdResult && (
          <div className="mt-4 bg-slate-950 border border-slate-800 rounded-lg p-4">

            {/* ERROR */}
            {nvdResult.error ? (
              <p className="text-red-400 text-xs">
                {nvdResult.error}
              </p>
            ) : (
              <>

                {/* CVE HEADER */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">

                  <div>
                    <span className="font-mono font-bold text-cyan-400">
                      {nvdResult.id}
                    </span>

                    <span className="ml-3 text-[10px] text-slate-500">
                      NVD
                    </span>
                  </div>

                  <button
                    onClick={handleSaveCve}
                    className="px-3 py-1.5 text-[11px] font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white"
                  >
                    Add to Vulnerability List
                  </button>

                </div>

                {/* CVSS + SEVERITY */}
                <div className="flex flex-wrap items-center gap-6 mb-4">

                  <div>
                    <span className="text-[10px] text-slate-500 block">
                      CVSS SCORE
                    </span>

                    <span className="text-lg font-bold text-amber-400">
                      {nvdResult.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
                        nvdResult.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
                        "N/A"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-slate-500 block">
                      SEVERITY
                    </span>

                    <span className="text-sm font-bold text-red-400">
                      {nvdResult.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
                        nvdResult.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
                        "N/A"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-slate-500 block">
                      EXPLOITABILITY
                    </span>

                    <span className="text-sm font-bold text-orange-400">
                      {nvdResult.metrics?.cvssMetricV31?.[0]?.exploitabilityScore ??
                        nvdResult.metrics?.cvssMetricV30?.[0]?.exploitabilityScore ??
                        "N/A"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-slate-500 block">
                      IMPACT
                    </span>

                    <span className="text-sm font-bold text-red-400">
                      {nvdResult.metrics?.cvssMetricV31?.[0]?.impactScore ??
                        nvdResult.metrics?.cvssMetricV30?.[0]?.impactScore ??
                        "N/A"}
                    </span>
                  </div>

                </div>

                {/* CVSS VECTOR */}
                <div className="mb-4">

                  <span className="text-[10px] text-slate-500 block">
                    CVSS VECTOR
                  </span>

                  <span className="text-[10px] text-slate-400 font-mono break-all">
                    {nvdResult.metrics?.cvssMetricV31?.[0]?.cvssData?.vectorString ??
                      nvdResult.metrics?.cvssMetricV30?.[0]?.cvssData?.vectorString ??
                      "N/A"}
                  </span>

                </div>

                {/* AFFECTED PRODUCTS */}
                <div className="mb-4">

                  <span className="text-[10px] text-slate-500 block mb-1">
                    AFFECTED PRODUCTS / VERSIONS
                  </span>

                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-2">

                    {nvdResult.configurations?.[0]?.nodes?.[0]?.cpeMatch
                      ?.slice(0, 5)
                      .map(
                        (
                          item: any,
                          index: number
                        ) => (
                          <div
                            key={index}
                            className="text-[11px] text-slate-300 font-mono py-1 break-all"
                          >
                            {item.criteria ||
                              "Affected product information unavailable"}
                          </div>
                        )
                      ) || (
                        <span className="text-[11px] text-slate-500">
                          No affected product information available.
                        </span>
                      )}

                  </div>

                </div>

                {/* PUBLISHED / MODIFIED */}
                <div className="flex flex-wrap items-center gap-6 mb-4">

                  <div>
                    <span className="text-[10px] text-slate-500 block">
                      PUBLISHED
                    </span>

                    <span className="text-[11px] text-slate-300">
                      {nvdResult.published
                        ? new Date(
                            nvdResult.published
                          ).toLocaleDateString()
                        : "N/A"}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-slate-500 block">
                      LAST MODIFIED
                    </span>

                    <span className="text-[11px] text-slate-300">
                      {nvdResult.lastModified
                        ? new Date(
                            nvdResult.lastModified
                          ).toLocaleDateString()
                        : "N/A"}
                    </span>
                  </div>

                </div>

                {/* CWE */}
                <div className="mb-4">

                  <span className="text-[10px] text-slate-500 block mb-1">
                    WEAKNESS / CWE
                  </span>

                  <div className="flex flex-wrap gap-2">

                    {(() => {
                      const cweItems =
                        nvdResult.weaknesses?.flatMap(
                          (weakness: any) =>
                            weakness.description
                              ?.filter(
                                (item: any) =>
                                  item.lang === "en"
                              )
                              ?.map(
                                (item: any) =>
                                  item.value
                              ) || []
                        ) || [];

                      if (cweItems.length === 0) {
                        return (
                          <span className="text-[11px] text-slate-500">
                            No CWE information available.
                          </span>
                        );
                      }

                      return cweItems.map(
                        (
                          value: string,
                          index: number
                        ) => (
                          <span
                            key={`${value}-${index}`}
                            className="px-2 py-1 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[10px] font-mono"
                          >
                            {value}
                          </span>
                        )
                      );
                    })()}

                  </div>

                </div>

                {/* NVD REFERENCES */}
                <div className="mb-4">

                  <span className="text-[10px] text-slate-500 block mb-1">
                    NVD REFERENCES
                  </span>

                  <div className="space-y-1">

                    {nvdResult.references?.length > 0 ? (
                      nvdResult.references
                        .slice(0, 5)
                        .map(
                          (
                            ref: any,
                            index: number
                          ) => (
                            <a
                              key={index}
                              href={ref.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-2 text-[11px] text-cyan-400 hover:text-cyan-300 break-all"
                            >
                              <ExternalLink className="w-3 h-3 shrink-0" />

                              {ref.url}
                            </a>
                          )
                        )
                    ) : (
                      <span className="text-[11px] text-slate-500">
                        No references available.
                      </span>
                    )}

                  </div>

                </div>

                {/* DESCRIPTION */}
                <div>

                  <span className="text-[10px] text-slate-500 block mb-1">
                    DESCRIPTION
                  </span>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {nvdResult.descriptions?.find(
                      (d: any) =>
                        d.lang === "en"
                    )?.value ||
                      "No English description available."}
                  </p>

                </div>

              </>
            )}

          </div>
        )}

      </div>

      {/* =====================================================
          PRIORITIZATION FORMULA
      ====================================================== */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 space-y-2">

        <div className="flex items-center gap-2 text-cyan-400 font-bold">
          <HelpCircle className="w-4 h-4" />

          <span>
            Explainable Prioritization Formula:
          </span>
        </div>

        <p className="text-slate-400 leading-relaxed">
          Raw CVSS evaluates theoretical impact,
          but real SOC operational urgency requires
          adjusting for exposure and business
          criticality.
        </p>

        <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 break-words">
        Priority Score =
        Technical Severity (35) +
        Asset Importance (25) +
        Internet Exposure (20) +
        Exploitability Information (20)

        </div>

      </div>

      {/* =====================================================
          VULNERABILITY STATISTICS
      ====================================================== */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">

        {/* TOTAL */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">

          <p className="text-[10px] text-slate-500 uppercase font-semibold">
            Total Vulnerabilities
          </p>

          <p className="text-2xl font-bold text-white mt-1">
            {vulns.length}
          </p>

        </div>

        {/* CRITICAL */}
        <div className="bg-slate-900 border border-red-500/20 rounded-xl p-4">

          <p className="text-[10px] text-slate-500 uppercase font-semibold">
            Critical
          </p>

          <p className="text-2xl font-bold text-red-400 mt-1">
            {
              vulns.filter(
                (v) => v.severity === "Critical"
              ).length
            }
          </p>

        </div>

        {/* HIGH */}
        <div className="bg-slate-900 border border-orange-500/20 rounded-xl p-4">

          <p className="text-[10px] text-slate-500 uppercase font-semibold">
            High
          </p>

          <p className="text-2xl font-bold text-orange-400 mt-1">
            {
              vulns.filter(
                (v) => v.severity === "High"
              ).length
            }
          </p>

        </div>

        {/* REMEDIATED */}
        <div className="bg-slate-900 border border-emerald-500/20 rounded-xl p-4">

          <p className="text-[10px] text-slate-500 uppercase font-semibold">
            Remediated
          </p>

          <p className="text-2xl font-bold text-emerald-400 mt-1">
            {
              vulns.filter(
                (v) =>
                  v.remediationStatus ===
                  "Remediated"
              ).length
            }
          </p>

        </div>

      </div>

      {/* =====================================================
          SEVERITY DISTRIBUTION
      ====================================================== */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">

        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-sm font-bold text-white">
              Severity Distribution
            </h2>

            <p className="text-[11px] text-slate-500 mt-1">
              Saved CVEs grouped by NVD severity level.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">

          {/* CRITICAL */}
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">

            <p className="text-[10px] text-red-400 font-semibold uppercase">
              Critical
            </p>

            <p className="text-xl font-bold text-red-400 mt-1">
              {
                savedCves.filter(
                  (cve: any) => {
                    const severity =
                      cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
                      cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
                      "";

                    return (
                      severity === "CRITICAL"
                    );
                  }
                ).length
              }
            </p>

          </div>

          {/* HIGH */}
          <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3">

            <p className="text-[10px] text-orange-400 font-semibold uppercase">
              High
            </p>

            <p className="text-xl font-bold text-orange-400 mt-1">
              {
                savedCves.filter(
                  (cve: any) => {
                    const severity =
                      cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
                      cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
                      "";

                    return (
                      severity === "HIGH"
                    );
                  }
                ).length
              }
            </p>

          </div>

          {/* MEDIUM */}
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">

            <p className="text-[10px] text-amber-300 font-semibold uppercase">
              Medium
            </p>

            <p className="text-xl font-bold text-amber-300 mt-1">
              {
                savedCves.filter(
                  (cve: any) => {
                    const severity =
                      cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
                      cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
                      "";

                    return (
                      severity === "MEDIUM"
                    );
                  }
                ).length
              }
            </p>

          </div>

          {/* LOW */}
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">

            <p className="text-[10px] text-blue-400 font-semibold uppercase">
              Low
            </p>

            <p className="text-xl font-bold text-blue-400 mt-1">
              {
                savedCves.filter(
                  (cve: any) => {
                    const severity =
                      cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
                      cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
                      "";

                    return (
                      severity === "LOW"
                    );
                  }
                ).length
              }
            </p>

          </div>

        </div>

      </div>

      {/* =====================================================
          REMEDIATION PROGRESS
      ====================================================== */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">

        <div className="mb-3">
          <h2 className="text-sm font-bold text-white">
            Remediation Progress
          </h2>

          <p className="text-[11px] text-slate-500 mt-1">
            Current remediation status across tracked
            vulnerabilities.
          </p>
        </div>

        <div className="space-y-3">

          {remediationStatuses.map(
            (status) => {
              const count =
                vulns.filter(
                  (v) =>
                    v.remediationStatus ===
                    status
                ).length;

              const percentage =
                vulns.length > 0
                  ? Math.round(
                      (count / vulns.length) *
                        100
                    )
                  : 0;

              return (
                <div key={status}>

                  <div className="flex items-center justify-between mb-1">

                    <span className="text-[11px] text-slate-300">
                      {status}
                    </span>

                    <span className="text-[10px] text-slate-500">
                      {count} ({percentage}%)
                    </span>

                  </div>

                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">

                    <div
                      className="h-full bg-cyan-500 rounded-full transition-all"
                      style={{
                        width: `${percentage}%`,
                      }}
                    />

                  </div>

                </div>
              );
            }
          )}

        </div>

      </div>

      {/* =====================================================
          SAVED VULNERABILITY INVENTORY
      ====================================================== */}
      {savedCves.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">

          {/* HEADER */}
          <div className="p-4 border-b border-slate-800">

            <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">

              <div className="flex-1">

                <div className="flex items-center gap-3">

                  <div>
                    <h2 className="text-sm font-bold text-white">
                      Saved Vulnerability
                      Inventory
                    </h2>

                    <p className="text-[11px] text-slate-500 mt-1">
                      CVE intelligence collected from
                      the NVD database.
                    </p>
                  </div>

                </div>

                {/* SEARCH */}
                <div className="mt-3">

                  <input
                    type="text"
                    value={savedCveSearch}
                    onChange={(e) =>
                      setSavedCveSearch(
                        e.target.value
                      )
                    }
                    placeholder="Search saved CVE..."
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />

                </div>

                {/* SEVERITY FILTER */}
                <div className="mt-2">

                  <select
                    value={
                      savedSeverityFilter
                    }
                    onChange={(e) =>
                      setSavedSeverityFilter(
                        e.target.value
                      )
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="All">
                      All Severities
                    </option>

                    <option value="Critical">
                      Critical
                    </option>

                    <option value="High">
                      High
                    </option>

                    <option value="Medium">
                      Medium
                    </option>

                    <option value="Low">
                      Low
                    </option>
                  </select>

                </div>

              </div>

              {/* RIGHT SIDE */}
              <div className="flex items-center gap-2 shrink-0">

                <span className="px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-[10px] font-bold">
                  {savedCves.length} CVE
                  {savedCves.length !== 1
                    ? "s"
                    : ""}
                </span>

                <button
                  onClick={handleExportCsv}
                  disabled={
                    savedCves.length === 0
                  }
                  className="px-3 py-1.5 text-[10px] font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-white"
                >
                  Export CSV
                </button>

              </div>

            </div>

          </div>

          {/* SAVED CVE LIST */}
          <div className="divide-y divide-slate-800">

            {filteredSavedCves.map(
              (cve: any) => {
                const cvss =
                  cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
                  cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
                  "N/A";

                const severity =
                  cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ??
                  cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity ??
                  "N/A";

                const description =
                  cve.descriptions
                    ?.find(
                      (d: any) =>
                        d.lang === "en"
                    )
                    ?.value ||
                  "No English description available.";

                return (
                  <div
                    key={cve.id}
                    className="p-4 hover:bg-slate-800/30 transition"
                  >

                    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">

                      <div className="min-w-0 flex-1">

                        <div className="flex flex-wrap items-center gap-2 mb-1">

                          <span className="font-mono font-bold text-cyan-400 text-xs">
                            {cve.id}
                          </span>

                          <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[9px] font-bold">
                            {severity}
                          </span>

                        </div>

                        <p className="text-[11px] text-slate-400 line-clamp-2">
                          {description}
                        </p>

                        {/* ACTION BUTTONS */}
                        <div className="mt-2 flex items-center gap-2">

                          <button
                            onClick={() =>
                              setNvdResult(cve)
                            }
                            className="px-2.5 py-1 text-[10px] font-semibold rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                          >
                            View Details
                          </button>

                          <button
                            onClick={() =>
                              handleDeleteCve(
                                cve.id
                              )
                            }
                            className="px-2.5 py-1 text-[10px] font-semibold rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30"
                          >
                            Delete
                          </button>

                        </div>

                      </div>

                      <div className="text-right shrink-0">

                        <span className="text-[9px] text-slate-500 block">
                          CVSS
                        </span>

                        <span className="text-sm font-bold text-amber-400">
                          {cvss}
                        </span>

                      </div>

                    </div>

                  </div>
                );
              }
            )}

            {/* NO MATCHING RESULT */}
            {savedCves.length > 0 &&
              filteredSavedCves.length ===
                0 && (
                <div className="p-6 text-center text-slate-500 text-xs">
                  No matching
                  vulnerabilities found.
                </div>
              )}

          </div>

        </div>
      )}

      {/* =====================================================
          VULNERABILITY TABLE
      ====================================================== */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">

        <div className="overflow-x-auto">

          <table className="w-full text-left text-xs">

            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">

              <tr>

                <th className="py-3 px-3">
                  CVE Identifier
                </th>

                <th className="py-3 px-3">
                  Impacted Asset
                </th>

                <th className="py-3 px-3">
                  Severity & CVSS
                </th>

                <th className="py-3 px-3">
                  Exposure Context
                </th>

                <th className="py-3 px-3">
                  Asset Criticality
                </th>

                <th className="py-3 px-3">
                  SOC Priority Index
                </th>

                <th className="py-3 px-3">
                  Remediation Status
                </th>

                <th className="py-3 px-3 text-right">
                  Playbook
                </th>

              </tr>

            </thead>

            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">

              {loading ? (
                <tr>

                  <td
                    colSpan={8}
                    className="py-12 text-center text-slate-400"
                  >

                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 inline mr-2" />

                    Loading vulnerability
                    database...

                  </td>

                </tr>
              ) : vulns.length === 0 ? (
                <tr>

                  <td
                    colSpan={8}
                    className="py-12 text-center text-slate-500"
                  >
                    No vulnerabilities available.
                  </td>

                </tr>
              ) : (
                vulns.map((v) => {

                  const priorityColor =
                    v.priority >= 85
                      ? "text-red-400"
                      : v.priority >= 70
                      ? "text-amber-400"
                      : "text-emerald-400";

                  return (
                    <tr
                      key={v.cveId}
                      onClick={() =>
                        setSelectedVuln(v)
                      }
                      className="hover:bg-slate-800/40 cursor-pointer transition"
                    >

                      {/* CVE */}
                      <td className="py-3 px-3 font-mono font-bold text-cyan-400">
                        {v.cveId}
                      </td>

                      {/* ASSET */}
                      <td className="py-3 px-3 font-medium text-slate-200">

                        <div>
                          {v.asset}
                        </div>

                        <div className="text-[10px] text-slate-400 line-clamp-1">
                          {v.title}
                        </div>

                      </td>

                      {/* SEVERITY */}
                      <td className="py-3 px-3 whitespace-nowrap">

                        <div className="flex items-center gap-1.5">

                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(
                              v.severity
                            )}`}
                          >
                            {v.severity}
                          </span>

                          <span className="font-mono font-bold text-slate-300">
                            v3.1 {v.cvss}
                          </span>

                        </div>

                      </td>

                      {/* EXPOSURE */}
                      <td className="py-3 px-3 text-slate-300 text-[11px] whitespace-nowrap">

                        <span
                          className={
                            v.exposure.includes(
                              "Internet"
                            )
                              ? "text-red-400 font-semibold"
                              : "text-slate-400"
                          }
                        >
                          {v.exposure}
                        </span>

                      </td>

                      {/* CRITICALITY */}
                      <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                        {v.assetImportance}
                      </td>

                      {/* PRIORITY */}
                      <td className="py-3 px-3 font-mono">

                        <div className="flex items-center gap-1">

                          <span
                            className={`text-base font-black ${priorityColor}`}
                          >
                            {v.priority}
                          </span>

                          <span className="text-[10px] text-slate-500">
                            /100
                          </span>

                        </div>

                      </td>

                      {/* REMEDIATION STATUS */}
                      <td className="py-3 px-3">

                        <select
                          aria-label={`Update remediation status for ${v.cveId}`}
                          value={
                            v.remediationStatus
                          }
                          onClick={(e) =>
                            e.stopPropagation()
                          }
                          onChange={(e) =>
                            handleStatusChange(
                              v.cveId,
                              e.target.value
                            )
                          }
                          className="bg-slate-950 border border-slate-700 text-[11px] rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
                        >

                          <option value="Open">
                            Open
                          </option>

                          <option value="In Progress">
                            In Progress
                          </option>

                          <option value="Pending Maintenance Window">
                            Pending Maintenance
                          </option>

                          <option value="Patch Scheduled">
                            Patch Scheduled
                          </option>

                          <option value="Remediated">
                            Remediated
                          </option>

                        </select>

                      </td>

                      {/* PLAYBOOK */}
                      <td className="py-3 px-3 text-right">

                        <button
                          onClick={(e) => {
                            e.stopPropagation();

                            setSelectedVuln(v);
                          }}
                          className="px-2.5 py-1 text-[11px] font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 inline-flex items-center gap-1"
                        >

                          <BookOpen className="w-3 h-3 text-cyan-400" />

                          View

                        </button>

                      </td>

                    </tr>
                  );
                })
              )}

            </tbody>

          </table>

        </div>

      </div>

      {/* =====================================================
          SAVED CVE COUNT
      ====================================================== */}
      {savedCves.length > 0 && (
        <div className="text-[11px] text-slate-500">

          Saved NVD vulnerabilities:{" "}

          <span className="text-cyan-400 font-bold">
            {savedCves.length}
          </span>

        </div>
      )}

      {/* =====================================================
          VULNERABILITY DETAILS MODAL
      ====================================================== */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">

          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl text-xs max-h-[90vh] overflow-y-auto">

            {/* HEADER */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">

              <div>

                <div className="flex flex-wrap items-center gap-2">

                  <span className="font-mono text-cyan-400 font-bold text-sm">
                    {selectedVuln.cveId}
                  </span>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(
                      selectedVuln.severity
                    )}`}
                  >
                    {selectedVuln.severity}
                  </span>

                  <span className="font-mono text-slate-400">
                    CVSS {selectedVuln.cvss}
                  </span>

                </div>

                <h3 className="text-base font-bold text-white mt-1">
                  {selectedVuln.title}
                </h3>

              </div>

              <button
                onClick={() =>
                  setSelectedVuln(null)
                }
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800"
              >
                ✕
              </button>

            </div>

            {/* DESCRIPTION */}
            <div className="space-y-1">

              <span className="text-slate-400 font-medium">
                Vulnerability Description:
              </span>

              <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                {selectedVuln.description}
              </p>

            </div>

            {/* PRIORITIZATION RATIONALE */}
            <div className="bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 space-y-1.5">

              <span className="font-bold text-cyan-400 block">
                Why is this priority{" "}
                {selectedVuln.priority}/100?
              </span>

              <p className="text-slate-300">
                {selectedVuln.priorityExplanation}
              </p>

            </div>

            {/* REMEDIATION PLAYBOOK */}
            <div className="space-y-1">

              <span className="font-bold text-slate-200 block">
                Recommended Remediation Playbook:
              </span>

              <div className="bg-emerald-950/20 border border-emerald-800/40 p-3 rounded-lg text-emerald-300 font-mono text-[11px] break-words">
                {selectedVuln.remediationPlaybook ||
                  "Apply vendor standard emergency security patch."}
              </div>

            </div>

            {/* FOOTER */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-2 border-t border-slate-800">

              <span className="text-slate-500">
                Asset: {selectedVuln.asset}
              </span>

              <button
                onClick={() =>
                  setSelectedVuln(null)
                }
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-white"
              >
                Close
              </button>

            </div>

          </div>

        </div>
      )}

    </div>
  );
};