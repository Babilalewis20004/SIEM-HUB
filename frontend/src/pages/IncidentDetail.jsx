import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getIncident, assignIncident, setIncidentStatus, addIncidentNote, getUsers,
} from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";
import { useRealtime } from "../hooks/useRealtime.js";
import { MitreBadgeList } from "../components/MitreBadge.jsx";

const STATUSES = ["open", "investigating", "contained", "resolved", "closed"];

export default function IncidentDetail() {
  const { id } = useParams();
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const [note, setNote] = useState("");
  const [nextStatus, setNextStatus] = useState("");

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => getIncident(id),
  });
  const { data: users } = useQuery({ queryKey: ["users"], queryFn: getUsers, enabled: can("incidents.assign") });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["incident", id] });
    queryClient.invalidateQueries({ queryKey: ["incidents"] });
  };

  // Live investigation timeline (Part 10): a new alert/note/status change
  // on THIS incident refreshes the detail view without a manual reload.
  // Events for other incidents are ignored here (still covered by the
  // Incidents list page's own broader invalidation).
  const onRealtimeIncidentEvent = (envelope) => {
    const eventIncidentId = envelope.data.id ?? envelope.data.incident_id;
    if (eventIncidentId === id) invalidate();
  };
  useRealtime("incident.updated", onRealtimeIncidentEvent);
  useRealtime("incident.assigned", onRealtimeIncidentEvent);
  useRealtime("incident.status_changed", onRealtimeIncidentEvent);
  useRealtime("incident.note_added", onRealtimeIncidentEvent);

  const assignMutation = useMutation({
    mutationFn: (userId) => assignIncident(id, userId || null),
    onSuccess: invalidate,
  });
  const statusMutation = useMutation({
    mutationFn: ({ status, reopen }) => setIncidentStatus(id, status, reopen),
    onSuccess: invalidate,
  });
  const noteMutation = useMutation({
    mutationFn: (content) => addIncidentNote(id, content),
    onSuccess: () => {
      setNote("");
      invalidate();
    },
  });

  if (isLoading || !incident) return <p>Loading…</p>;

  const handleStatusChange = () => {
    if (!nextStatus) return;
    statusMutation.mutate({ status: nextStatus, reopen: incident.status === "closed" });
  };

  return (
    <div>
      <div className="page-header">
        <h2>Incident #{incident.id.slice(0, 8)} — {incident.title}</h2>
      </div>

      <div className="panel incident-summary">
        <dl className="detail-grid">
          <dt>Severity</dt><dd>{incident.severity}</dd>
          <dt>Status</dt><dd><span className={`pill pill-status-${incident.status}`}>{incident.status}</span></dd>
          <dt>Priority</dt><dd>{incident.priority}</dd>
          <dt>Tags</dt>
          <dd>
            {(incident.tags ?? []).length === 0
              ? "—"
              : incident.tags.map((tag) => <span key={tag} className="pill" style={{ marginRight: 6 }}>{tag}</span>)}
          </dd>
          <dt>Assigned</dt>
          <dd>
            {can("incidents.assign") ? (
              <select
                value={incident.assigned_to || ""}
                onChange={(e) => assignMutation.mutate(e.target.value)}
              >
                <option value="">Unassigned</option>
                {(users ?? []).filter((u) => u.is_active).map((u) => (
                  <option key={u.id} value={u.id}>{u.email}</option>
                ))}
              </select>
            ) : (incident.assigned_to || "Unassigned")}
          </dd>
          <dt>First Seen</dt><dd>{incident.first_seen_at ? new Date(incident.first_seen_at).toLocaleString() : "—"}</dd>
          <dt>Last Seen</dt><dd>{incident.last_seen_at ? new Date(incident.last_seen_at).toLocaleString() : "—"}</dd>
        </dl>

        {incident.description && <p>{incident.description}</p>}

        {can("incidents.update") && (
          <div className="filter-bar">
            <select value={nextStatus} onChange={(e) => setNextStatus(e.target.value)}>
              <option value="">Change status…</option>
              {STATUSES.filter((s) => s !== incident.status).map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <button onClick={handleStatusChange} disabled={!nextStatus || statusMutation.isPending}>
              Apply
            </button>
          </div>
        )}
        {statusMutation.isError && (
          <p className="auth-error">{statusMutation.error?.response?.data?.error}</p>
        )}
      </div>

      <div className="panel">
        <h3>Threat Intelligence &amp; MITRE ATT&amp;CK</h3>
        <div className="enrichment-section-label">MITRE ATT&amp;CK techniques observed</div>
        <MitreBadgeList techniques={incident.enrichment_summary?.mitre_techniques} />
        <div className="enrichment-section-label" style={{ marginTop: 10 }}>IOC matches</div>
        {(incident.enrichment_summary?.ioc_matches ?? []).length === 0 ? (
          <span className="enrichment-empty">No threat intelligence matches.</span>
        ) : (
          <div>
            {incident.enrichment_summary.ioc_matches.map((m) => (
              <span className="ioc-chip" key={m.indicator}>
                <span className="ioc-indicator">{m.indicator}</span>
                <span className={`ioc-meta threat-${m.threat_level || "unknown"}`}>
                  {m.indicator_type} · {(m.threat_level || "unknown").toUpperCase()}
                </span>
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="panel">
        <h3>Related Alerts</h3>
        {incident.alerts.length === 0 ? (
          <p>No alerts attached.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Title</th><th>Severity</th><th>Source</th><th>MITRE</th><th></th></tr>
            </thead>
            <tbody>
              {incident.alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>{alert.created_at ? new Date(alert.created_at).toLocaleString() : "—"}</td>
                  <td>{alert.title || alert.rule_name}</td>
                  <td>{alert.severity}</td>
                  <td>{alert.detection_source}</td>
                  <td>{alert.mitre_technique || "—"}</td>
                  <td>
                    {alert.event_id && (
                      <Link to={`/logs?event=${alert.event_id}`}>View Event</Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h3>Investigation Notes</h3>
        {(incident.notes ?? []).map((n) => (
          <div key={n.id} className="note-card">
            <div className="note-meta">{n.author_id || "System (playbook)"} · {new Date(n.created_at).toLocaleString()}</div>
            <div>{n.content}</div>
          </div>
        ))}

        {can("incidents.update") && (
          <div className="note-form">
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Add an investigation note…"
              rows={3}
            />
            <button
              disabled={!note.trim() || noteMutation.isPending}
              onClick={() => noteMutation.mutate(note.trim())}
            >
              Add Note
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
