import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { getIncidents } from "../api/client";
import { useRealtime } from "../hooks/useRealtime.js";
import Loading from "../components/Loading.jsx";

const SEVERITY_COLORS = { info: "#4f8cff", low: "#4f8cff", medium: "#f5a623", high: "#e6493d", critical: "#e6493d" };
const STATUSES = ["", "open", "investigating", "contained", "resolved", "closed"];

export default function Incidents() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const navigate = useNavigate();

  const queryClient = useQueryClient();
  const filters = { status: status || undefined, severity: severity || undefined, per_page: 100 };
  const { data, isLoading } = useQuery({
    queryKey: ["incidents", filters],
    queryFn: () => getIncidents(filters),
  });

  // List membership/order depends on filters + severity/status, so this
  // invalidates rather than patching individual rows in place.
  const invalidateIncidents = () => queryClient.invalidateQueries({ queryKey: ["incidents"] });
  useRealtime("incident.created", invalidateIncidents);
  useRealtime("incident.updated", invalidateIncidents);
  useRealtime("incident.assigned", invalidateIncidents);
  useRealtime("incident.status_changed", invalidateIncidents);

  return (
    <div>
      <h2>Incidents</h2>

      <div className="filter-bar">
        {STATUSES.map((s) => (
          <button key={s || "all"} className={status === s ? "active" : ""} onClick={() => setStatus(s)}>
            {s || "all"}
          </button>
        ))}
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {isLoading ? (
        <Loading />
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Title</th><th>Severity</th><th>Priority</th><th>Status</th>
              <th>Alerts</th><th>Assigned</th><th>First Seen</th><th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((incident) => (
              <tr key={incident.id} className="clickable-row"
                  onClick={() => navigate(`/incidents/${incident.id}`)}>
                <td>{incident.title}</td>
                <td>
                  <span className="severity-dot" style={{ background: SEVERITY_COLORS[incident.severity] }} />
                  {incident.severity}
                </td>
                <td>{incident.priority}</td>
                <td><span className={`pill pill-status-${incident.status}`}>{incident.status}</span></td>
                <td>{incident.alert_count}</td>
                <td>{incident.assigned_to || "—"}</td>
                <td>{incident.first_seen_at ? new Date(incident.first_seen_at).toLocaleString() : "—"}</td>
                <td>{incident.last_seen_at ? new Date(incident.last_seen_at).toLocaleString() : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
