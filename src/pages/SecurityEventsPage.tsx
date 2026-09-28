import React, { useState, useEffect } from "react";
import {
  Radio,
  Search,
  Filter,
  PlusCircle,
  Clock,
  User,
  Monitor,
  Network,
  Tag,
  AlertCircle,
  CheckCircle,
  X,
  ExternalLink,
  ChevronDown,
  Brain,
  Sparkles,
} from "lucide-react";
import { api } from "../services/api";
import { SecurityEvent, SeverityLevel } from "../types";
import { AIThreatAnalysisModal } from "../components/AIThreatAnalysisModal";

interface SecurityEventsPageProps {
  onNavigate?: (tab: any, incidentId?: string) => void;
}

export const SecurityEventsPage: React.FC<SecurityEventsPageProps> = ({ onNavigate }) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [aiModalEvent, setAiModalEvent] = useState<SecurityEvent | null>(null);

  // New simulated event form state
  const [newEvent, setNewEvent] = useState({
    source: "CrowdStrike Falcon EDR",
    sourceType: "Endpoint EDR",
    user: "alex.turner@corp.internal",
    ip: "10.0.8.21",
    hostname: "WS-ENG-09.corp.local",
    eventType: "LSASS Memory Dump Attempt",
    description: "Suspicious taskmgr.exe process requested PROCESS_VM_READ access handle to lsass.exe.",
    severity: "High" as SeverityLevel,
    indicators: "lsass.exe, 10.0.8.21",
  });

  const loadEvents = async () => {
    setLoading(true);
    try {
      const data = await api.getEvents({
        severity: severityFilter,
        sourceType: sourceFilter,
        search,
      });
      setEvents(data.events || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [severityFilter, sourceFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadEvents();
  };

  const handleCreateEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createEvent({
        ...newEvent,
        indicators: newEvent.indicators.split(",").map((s) => s.trim()).filter(Boolean),
        metadata: { simulatedVia: "SOC Synthetic Generator", analystTriggered: true },
      });
      setShowCreateModal(false);
      loadEvents();
    } catch (err) {
      console.error(err);
    }
  };

  const getSeverityBadge = (severity: SeverityLevel) => {
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
        return "bg-slate-700 text-slate-300";
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Security Event Telemetry
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Synthetic multi-source ingestion log: EDR, NextGen Firewalls, Identity Providers, SEG, and CloudTrail sensors.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm transition"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Ingest Synthetic Event</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[260px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search description, hostname, user identity, IP, or event type..."
            className="w-full bg-slate-950 border border-slate-750 text-xs rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </form>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Severity:</span>
            <select
              aria-label="Filter events by severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="all">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>Sensor Source:</span>
            <select
              aria-label="Filter events by sensor source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <option value="all">All Sensor Types</option>
              <option value="Endpoint Detection & Response">Endpoint EDR</option>
              <option value="Identity Provider (IAM)">Identity Provider (IAM)</option>
              <option value="Network Firewall">Network Firewall</option>
              <option value="Email Gateway">Email Gateway</option>
              <option value="SIEM">SIEM</option>
              <option value="Cloud Audit">Cloud Audit</option>
            </select>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-3">Event ID</th>
                <th className="py-3 px-3">Timestamp</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Event Classification</th>
                <th className="py-3 px-3">Source Sensor</th>
                <th className="py-3 px-3">Identity & Host</th>
                <th className="py-3 px-3">Indicators</th>
                <th className="py-3 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <Radio className="w-4 h-4 animate-spin text-cyan-400" />
                      Loading synthetic telemetry records...
                    </div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No security events match the current filter criteria.
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr
                    key={evt.eventId}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-3 px-3 font-mono font-bold text-cyan-400">{evt.eventId}</td>
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                      {new Date(evt.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(evt.severity)}`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-100">{evt.eventType}</div>
                      <div className="text-[11px] text-slate-400 line-clamp-1 max-w-xs">{evt.description}</div>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      <div>{evt.source}</div>
                      <div className="text-[10px] text-slate-400">{evt.sourceType}</div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="text-slate-200">{evt.user || "N/A"}</div>
                      <div className="text-[10px] font-mono text-slate-400">{evt.hostname || evt.ip}</div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1 max-w-[180px]">
                        {(evt.indicators || []).slice(0, 2).map((ind, i) => (
                          <span
                            key={i}
                            className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 truncate max-w-[140px]"
                          >
                            {ind}
                          </span>
                        ))}
                        {(evt.indicators || []).length > 2 && (
                          <span className="text-[10px] text-slate-400">+{evt.indicators.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setAiModalEvent(evt);
                          }}
                          className="px-2.5 py-1 text-[11px] font-semibold rounded bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/60 flex items-center gap-1.5 transition shadow-xs cursor-pointer"
                          title="Run autonomous AI Threat Detection on this telemetry event"
                        >
                          <Brain className="w-3.5 h-3.5 text-cyan-400" />
                          <span>View AI Analysis</span>
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(evt);
                          }}
                          className="px-2 py-1 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                        >
                          Inspect
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Drawer / Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-cyan-400 font-bold">{selectedEvent.eventId}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityBadge(selectedEvent.severity)}`}>
                    {selectedEvent.severity}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-1">{selectedEvent.eventType}</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300 bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
              {selectedEvent.description}
            </p>

            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="space-y-1">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" /> Timestamp:
                </span>
                <span className="font-mono text-slate-200">{new Date(selectedEvent.timestamp).toLocaleString()}</span>
              </div>
              <div className="space-y-1">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Radio className="w-3.5 h-3.5 text-cyan-400" /> Sensor Source:
                </span>
                <span className="text-slate-200">{selectedEvent.source} ({selectedEvent.sourceType})</span>
              </div>
              <div className="space-y-1">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-cyan-400" /> User Identity:
                </span>
                <span className="font-mono text-slate-200">{selectedEvent.user || "N/A"}</span>
              </div>
              <div className="space-y-1">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Monitor className="w-3.5 h-3.5 text-cyan-400" /> Hostname / IP:
                </span>
                <span className="font-mono text-slate-200">{selectedEvent.hostname} ({selectedEvent.ip})</span>
              </div>
            </div>

            {/* Extracted Indicators */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-1 flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-cyan-400" /> Extracted Threat Indicators:
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {selectedEvent.indicators && selectedEvent.indicators.length > 0 ? (
                  selectedEvent.indicators.map((ind, i) => (
                    <span
                      key={i}
                      className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-cyan-900/60"
                    >
                      {ind}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-400 text-xs">No explicit indicators recorded.</span>
                )}
              </div>
            </div>

            {/* Raw Metadata */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-1">Telemetry Sensor Metadata:</h4>
              <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-36">
                {JSON.stringify(selectedEvent.metadata || {}, null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <button
                onClick={() => {
                  setAiModalEvent(selectedEvent);
                }}
                className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-xs transition cursor-pointer"
              >
                <Brain className="w-4 h-4" />
                <span>View AI Analysis</span>
              </button>
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-white transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ingest Synthetic Event Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateEvent}
            className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-xl"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <PlusCircle className="w-4 h-4 text-cyan-400" /> Ingest Synthetic Security Telemetry
              </h3>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Source Name</label>
                <input
                  type="text"
                  value={newEvent.source}
                  onChange={(e) => setNewEvent({ ...newEvent, source: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                  required
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Source Type</label>
                <input
                  type="text"
                  value={newEvent.sourceType}
                  onChange={(e) => setNewEvent({ ...newEvent, sourceType: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                  required
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">User Identity</label>
                <input
                  type="text"
                  value={newEvent.user}
                  onChange={(e) => setNewEvent({ ...newEvent, user: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Hostname / Device</label>
                <input
                  type="text"
                  value={newEvent.hostname}
                  onChange={(e) => setNewEvent({ ...newEvent, hostname: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Severity Level</label>
                <select
                  value={newEvent.severity}
                  onChange={(e) => setNewEvent({ ...newEvent, severity: e.target.value as SeverityLevel })}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
              <div>
                <label className="text-slate-400 block mb-1">IP Address</label>
                <input
                  type="text"
                  value={newEvent.ip}
                  onChange={(e) => setNewEvent({ ...newEvent, ip: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                />
              </div>
            </div>

            <div className="text-xs">
              <label className="text-slate-400 block mb-1">Event Type / Classification</label>
              <input
                type="text"
                value={newEvent.eventType}
                onChange={(e) => setNewEvent({ ...newEvent, eventType: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                required
              />
            </div>

            <div className="text-xs">
              <label className="text-slate-400 block mb-1">Event Description</label>
              <textarea
                value={newEvent.description}
                onChange={(e) => setNewEvent({ ...newEvent, description: e.target.value })}
                rows={2}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200"
                required
              />
            </div>

            <div className="text-xs">
              <label className="text-slate-400 block mb-1">Indicators (comma separated)</label>
              <input
                type="text"
                value={newEvent.indicators}
                onChange={(e) => setNewEvent({ ...newEvent, indicators: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white"
              >
                Inject Telemetry
              </button>
            </div>
          </form>
        </div>
      )}
      {/* AI Threat Detection & Investigation Modal */}
      {aiModalEvent && (
        <AIThreatAnalysisModal
          event={aiModalEvent}
          isOpen={!!aiModalEvent}
          onClose={() => setAiModalEvent(null)}
          onNavigateToCopilot={(question) => {
            if (onNavigate) {
              onNavigate("copilot");
            }
          }}
        />
      )}
    </div>
  );
};
