import React, { useState, useEffect } from "react";
import {
  Crosshair,
  Shield,
  Eye,
  FileCheck,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Layers,
  Sparkles,
} from "lucide-react";
import { api } from "../services/api";
import { MitreTacticGroup, MitreTechniqueDetailed } from "../types";

export const MitreAttackPage: React.FC = () => {
  const [matrix, setMatrix] = useState<MitreTacticGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechniqueDetailed | null>(null);

  useEffect(() => {
    api.getMitreMatrix().then((res) => {
      setMatrix(res.matrix || []);
      if (res.matrix?.[0]?.techniques?.[0]) {
        setSelectedTechnique(res.matrix[0].techniques[0]);
      }
      setLoading(false);
    }).catch(console.error);
  }, []);

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          MITRE ATT&CK Enterprise Matrix Alignment
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Adversary behavioral mapping across enterprise tactics: maps active incident artifacts to concrete detection telemetry rules and mitigation frameworks.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Tactics & Techniques Navigation */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-4 max-h-[750px] overflow-y-auto">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-cyan-400" /> Enterprise Tactics & Techniques
          </h2>

          <div className="space-y-3">
            {matrix.map((tactic) => (
              <div key={tactic.tacticId} className="space-y-1.5">
                <div className="text-[11px] font-bold text-slate-300 px-2 py-1 bg-slate-950/80 rounded border border-slate-800/80 flex items-center justify-between">
                  <span>{tactic.tacticName}</span>
                  <span className="font-mono text-cyan-400 text-[10px]">{tactic.tacticId}</span>
                </div>

                <div className="space-y-1 pl-1">
                  {tactic.techniques.map((tech) => {
                    const isSelected = selectedTechnique?.id === tech.id;
                    return (
                      <button
                        key={tech.id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`w-full text-left p-2 rounded-lg text-xs transition flex items-center justify-between group ${
                          isSelected
                            ? "bg-cyan-950/80 border border-cyan-700/60 text-cyan-300 font-semibold"
                            : "hover:bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-transparent"
                        }`}
                      >
                        <div className="truncate">
                          <span className="font-mono text-[11px] text-cyan-400 mr-1.5">{tech.id}</span>
                          <span>{tech.name}</span>
                        </div>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                          {tech.status}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Technique Detail Inspector */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm space-y-5">
          {selectedTechnique ? (
            <div className="space-y-5 text-xs">
              {/* Header */}
              <div className="border-b border-slate-800 pb-4">
                <div className="flex items-center gap-2 text-cyan-400 font-mono font-bold">
                  <Crosshair className="w-4 h-4" />
                  <span>{selectedTechnique.id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-sans">
                    {selectedTechnique.status}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white mt-1">{selectedTechnique.name}</h2>
              </div>

              {/* Reason for Mapping */}
              <div className="space-y-1.5">
                <h3 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" /> Reason for Adversary Mapping:
                </h3>
                <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 text-slate-300 leading-relaxed">
                  {selectedTechnique.reason}
                </div>
              </div>

              {/* Observed Forensic Evidence */}
              <div className="space-y-1.5">
                <h3 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <Eye className="w-3.5 h-3.5 text-amber-400" /> Correlated Sensor Telemetry & Evidence:
                </h3>
                <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 font-mono text-[11px] text-amber-300">
                  {selectedTechnique.evidence}
                </div>
              </div>

              {/* Detection Guidance */}
              <div className="space-y-1.5">
                <h3 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-blue-400" /> Detection Guidance (Blue Team SOC):
                </h3>
                <div className="bg-blue-950/20 border border-blue-900/40 p-3.5 rounded-lg text-slate-300 leading-relaxed">
                  {selectedTechnique.detectionGuidance}
                </div>
              </div>

              {/* Mitigation Guidance */}
              <div className="space-y-1.5">
                <h3 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                  <FileCheck className="w-3.5 h-3.5 text-emerald-400" /> Mitigation & Hardening Guidance:
                </h3>
                <div className="bg-emerald-950/20 border border-emerald-900/40 p-3.5 rounded-lg text-emerald-300/90 leading-relaxed">
                  {selectedTechnique.mitigationGuidance}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-500 text-xs">
              Select a MITRE ATT&CK technique from the left matrix.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
