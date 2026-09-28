import React, { useState, useEffect, useRef } from "react";
import {
  Bot,
  Send,
  Sparkles,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Layers,
  Crosshair,
  User,
  Clock,
  RotateCcw,
} from "lucide-react";
import { api } from "../services/api";
import { Incident } from "../types";

interface CopilotPageProps {
  initialIncidentId?: string;
}

interface Message {
  id: string;
  sender: "user" | "copilot";
  text: string;
  timestamp: string;
  evidence?: string[];
  recommendedActions?: string[];
  mitreMatches?: string[];
  source?: "gemini" | "heuristic_fallback";
}

const PRESET_QUESTIONS = [
  "What happened in this incident?",
  "Why is this incident high risk?",
  "What evidence supports this classification?",
  "What should the analyst investigate next?",
  "Which MITRE technique is relevant?",
];

export const CopilotPage: React.FC<CopilotPageProps> = ({ initialIncidentId }) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(initialIncidentId || "");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.getIncidents().then((res) => {
      const list = res.incidents || [];
      setIncidents(list);
      if (!selectedIncidentId && list.length > 0) {
        setSelectedIncidentId(list[0].incidentId);
      }
    }).catch(console.error);
  }, []);

  useEffect(() => {
    if (initialIncidentId) {
      setSelectedIncidentId(initialIncidentId);
    }
  }, [initialIncidentId]);

  useEffect(() => {
    // Initial welcome message
    if (messages.length === 0) {
      setMessages([
        {
          id: "welcome",
          sender: "copilot",
          text: `Welcome to CyberSentinel X Security Copilot. I am your Tier 3 SOC intelligence assistant, powered server-side by Gemini 3.8.
I am grounded in the defensive telemetry, forensic timelines, and MITRE ATT&CK techniques of your current security incidents.
Select an active incident and click any preset question or type a custom inquiry below.`,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          source: "gemini",
        },
      ]);
    }
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const handleSend = async (userPrompt: string) => {
    if (!userPrompt.trim()) return;

    const userMsg: Message = {
      id: Date.now().toString(),
      sender: "user",
      text: userPrompt,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setQuery("");
    setLoading(true);

    try {
      const res = await api.askCopilot(userPrompt, selectedIncidentId);
      const botMsg: Message = {
        id: (Date.now() + 1).toString(),
        sender: "copilot",
        text: res.answer,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        evidence: res.evidence,
        recommendedActions: res.recommendedActions,
        mitreMatches: res.mitreMatches,
        source: res.source,
      };
      setMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        id: (Date.now() + 1).toString(),
        sender: "copilot",
        text: "I encountered an error retrieving defensive telemetry for this query. Please check server logs.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const activeIncident = incidents.find((i) => i.incidentId === selectedIncidentId);

  return (
    <div className="space-y-6">
      {/* Title & Incident Context Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            AI Security Copilot
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Gemini-powered defensive Tier 3 SOC intelligence assistant grounded strictly in verified application evidence.
          </p>
        </div>

        {/* Incident Context Selector */}
        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs">
          <span className="text-slate-400 font-medium">Grounded Context:</span>
          <select
            aria-label="Select grounded incident context"
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono cursor-pointer"
          >
            {incidents.map((inc) => (
              <option key={inc.incidentId} value={inc.incidentId}>
                {inc.incidentId} - {inc.title.slice(0, 36)}... (Score: {inc.riskScore})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Preset Question Chips */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-slate-400 flex items-center gap-1 mr-2">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> Quick Analyst Inquiries:
        </span>
        {PRESET_QUESTIONS.map((q, idx) => (
          <button
            key={idx}
            disabled={loading}
            onClick={() => handleSend(q)}
            className="px-2.5 py-1 text-xs font-medium rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-750 hover:border-cyan-700 transition"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Main Chat Window */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-sm flex flex-col h-[580px] overflow-hidden">
        {/* Messages feed */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4 text-xs">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex gap-3 max-w-3xl ${m.sender === "user" ? "ml-auto flex-row-reverse" : ""}`}
            >
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                  m.sender === "user"
                    ? "bg-blue-600 text-white"
                    : "bg-gradient-to-br from-cyan-600 to-blue-700 text-white shadow-sm border border-cyan-400/30"
                }`}
              >
                {m.sender === "user" ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              <div className="space-y-2 max-w-2xl">
                <div
                  className={`p-4 rounded-xl leading-relaxed whitespace-pre-line ${
                    m.sender === "user"
                      ? "bg-blue-600 text-white rounded-tr-none"
                      : "bg-slate-950 border border-slate-800 text-slate-200 rounded-tl-none shadow-xs"
                  }`}
                >
                  {m.text}
                </div>

                {/* Evidence & Action Chips */}
                {m.evidence && m.evidence.length > 0 && (
                  <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-bold uppercase text-slate-400 block">
                      Forensic Artifacts Referenced:
                    </span>
                    <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                      {m.evidence.map((ev, i) => (
                        <span key={i} className="px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-cyan-900/60">
                          {ev}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {m.recommendedActions && m.recommendedActions.length > 0 && (
                  <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-bold uppercase text-slate-400 block">
                      Recommended Human Review Actions:
                    </span>
                    <div className="space-y-1 text-[11px] text-slate-300">
                      {m.recommendedActions.map((act, i) => (
                        <div key={i} className="flex items-center gap-1.5">
                          <span className="text-cyan-400">→</span>
                          <span>{act}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between text-[10px] text-slate-400 px-1">
                  <span>{m.timestamp}</span>
                  {m.source && (
                    <span className="font-mono text-[9px] uppercase tracking-wider text-cyan-400">
                      Engine: {m.source}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 max-w-xl">
              <div className="w-8 h-8 rounded-lg bg-cyan-900/40 border border-cyan-800 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4 text-cyan-400 animate-pulse" />
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs text-slate-400 flex items-center gap-2">
                <RotateCcw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Grounded incident telemetry synthesis in progress...</span>
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-3 bg-slate-950 border-t border-slate-800">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend(query);
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask Copilot regarding evidence, risk factors, next investigation steps, or MITRE mapping..."
              className="flex-1 bg-slate-900 border border-slate-750 text-xs rounded-lg px-3.5 py-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={loading || !query.trim()}
              className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 transition"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
