import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getIOCs, createIOC, deleteIOC, enableIOC, disableIOC, importIOCs,
} from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";

const INDICATOR_TYPES = ["ip", "domain", "url", "md5", "sha1", "sha256"];
const THREAT_LEVELS = ["unknown", "low", "medium", "high", "critical"];

const emptyForm = { indicator: "", indicator_type: "ip", threat_level: "unknown", confidence: 50,
                    source: "", description: "" };

function CreateIOCForm({ onCreated }) {
  const [form, setForm] = useState(emptyForm);
  const mutation = useMutation({
    mutationFn: () => createIOC({ ...form, confidence: Number(form.confidence) }),
    onSuccess: () => {
      setForm(emptyForm);
      onCreated();
    },
  });

  return (
    <div className="panel">
      <h3>Add IOC</h3>
      <div className="ioc-form">
        <input
          placeholder="Indicator (e.g. 185.10.10.10)"
          value={form.indicator}
          onChange={(e) => setForm({ ...form, indicator: e.target.value })}
        />
        <select value={form.indicator_type} onChange={(e) => setForm({ ...form, indicator_type: e.target.value })}>
          {INDICATOR_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={form.threat_level} onChange={(e) => setForm({ ...form, threat_level: e.target.value })}>
          {THREAT_LEVELS.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          type="number" min="0" max="100"
          placeholder="Confidence (0-100)"
          value={form.confidence}
          onChange={(e) => setForm({ ...form, confidence: e.target.value })}
        />
        <input
          placeholder="Source (e.g. internal)"
          value={form.source}
          onChange={(e) => setForm({ ...form, source: e.target.value })}
        />
        <textarea
          placeholder="Description (optional)"
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
        />
      </div>
      <button
        disabled={!form.indicator.trim() || mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        {mutation.isPending ? "Adding…" : "Add IOC"}
      </button>
      {mutation.isError && (
        <p className="auth-error">{mutation.error?.response?.data?.error}</p>
      )}
    </div>
  );
}

function ImportPanel({ onImported }) {
  const [csvText, setCsvText] = useState(
    "indicator,indicator_type,threat_level,confidence,source\n185.10.10.10,ip,high,90,internal"
  );
  const [result, setResult] = useState(null);

  const mutation = useMutation({
    mutationFn: () => {
      const rows = csvText.trim().split("\n");
      const headers = rows[0].split(",").map((h) => h.trim());
      const iocs = rows.slice(1).filter(Boolean).map((row) => {
        const values = row.split(",");
        return Object.fromEntries(headers.map((h, i) => [h, (values[i] ?? "").trim()]));
      });
      return importIOCs(iocs);
    },
    onSuccess: (data) => {
      setResult(data);
      onImported();
    },
  });

  return (
    <div className="panel import-panel">
      <h3>Import IOCs (CSV)</h3>
      <p className="ml-status-line">
        Columns: indicator, indicator_type, threat_level, confidence, source (description optional).
        One malformed row won't fail the whole import.
      </p>
      <textarea value={csvText} onChange={(e) => setCsvText(e.target.value)} />
      <div className="filter-bar">
        <button disabled={mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? "Importing…" : "Import"}
        </button>
      </div>
      {result && (
        <p className="ml-status-line">
          Total {result.total} · Imported {result.imported} · Updated {result.updated} ·
          Skipped {result.skipped} · Errors {result.errors}
        </p>
      )}
    </div>
  );
}

export default function IOCs() {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState({ type: "", threat_level: "", indicator: "" });

  const params = Object.fromEntries(Object.entries(filters).filter(([, v]) => v));
  const { data, isLoading } = useQuery({
    queryKey: ["iocs", params],
    queryFn: () => getIOCs(params),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["iocs"] });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }) => (enabled ? disableIOC(id) : enableIOC(id)),
    onSuccess: invalidate,
  });
  const deleteMutation = useMutation({
    mutationFn: (id) => deleteIOC(id),
    onSuccess: invalidate,
  });

  return (
    <div>
      <div className="page-header">
        <h2>Threat Intelligence</h2>
      </div>

      {can("iocs.manage") && (
        <>
          <CreateIOCForm onCreated={invalidate} />
          <ImportPanel onImported={invalidate} />
        </>
      )}

      <div className="filter-bar">
        <input
          className="search-input"
          style={{ marginBottom: 0, width: 220 }}
          placeholder="Search indicator…"
          value={filters.indicator}
          onChange={(e) => setFilters({ ...filters, indicator: e.target.value })}
        />
        <select value={filters.type} onChange={(e) => setFilters({ ...filters, type: e.target.value })}>
          <option value="">all types</option>
          {INDICATOR_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={filters.threat_level} onChange={(e) => setFilters({ ...filters, threat_level: e.target.value })}>
          <option value="">all threat levels</option>
          {THREAT_LEVELS.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {isLoading ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Indicator</th><th>Type</th><th>Threat</th><th>Confidence</th>
              <th>Source</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((ioc) => (
              <tr key={ioc.id}>
                <td className="raw-msg">{ioc.indicator}</td>
                <td>{ioc.indicator_type}</td>
                <td><span className={`threat-${ioc.threat_level}`}>{ioc.threat_level.toUpperCase()}</span></td>
                <td>{ioc.confidence}%</td>
                <td>{ioc.source || "—"}</td>
                <td>
                  <span className={`pill ${ioc.enabled ? "pill-active" : "pill-inactive"}`}>
                    {ioc.enabled ? "active" : "disabled"}
                  </span>
                </td>
                <td className="row-actions">
                  {can("iocs.manage") && (
                    <>
                      <button
                        onClick={() => toggleMutation.mutate({ id: ioc.id, enabled: ioc.enabled })}
                        disabled={toggleMutation.isPending}
                      >
                        {ioc.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        onClick={() => deleteMutation.mutate(ioc.id)}
                        disabled={deleteMutation.isPending}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {deleteMutation.isError && (
        <p className="auth-error">{deleteMutation.error?.response?.data?.error}</p>
      )}
    </div>
  );
}
