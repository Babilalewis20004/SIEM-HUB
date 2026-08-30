import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getLogs, getLog, uploadLogs } from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";

const SEVERITY_COLORS = {
  info: "#4f8cff",
  low: "#f5a623",
  medium: "#f5a623",
  high: "#e6493d",
  critical: "#e6493d",
};

function EventDetail({ event, onClose }) {
  return (
    <div className="panel event-detail">
      <div className="page-header">
        <h3>Event Details</h3>
        <button onClick={onClose}>Close</button>
      </div>

      <dl className="detail-grid">
        <dt>Timestamp</dt><dd>{new Date(event.timestamp).toLocaleString()}</dd>
        <dt>Event Type</dt><dd>{event.event_type}</dd>
        <dt>Category</dt><dd>{event.category}</dd>
        <dt>Source Type</dt><dd>{event.source_type}</dd>
        <dt>Source IP</dt><dd>{event.source_ip || "—"}</dd>
        <dt>Destination IP</dt><dd>{event.destination_ip || "—"}</dd>
        <dt>Ports</dt><dd>{event.source_port || "—"} → {event.destination_port || "—"}</dd>
        <dt>Username</dt><dd>{event.username || "—"}</dd>
        <dt>Hostname</dt><dd>{event.hostname || "—"}</dd>
        <dt>Action</dt><dd>{event.action || "—"}</dd>
        <dt>Outcome</dt><dd>{event.outcome || "—"}</dd>
        <dt>Severity</dt>
        <dd>
          <span className="severity-dot" style={{ background: SEVERITY_COLORS[event.severity] }} />
          {event.severity}
        </dd>
      </dl>

      <h4>Raw Message</h4>
      <pre className="raw-msg-block">{event.raw_message}</pre>

      <h4>Parsed Fields</h4>
      <pre className="raw-msg-block">{JSON.stringify(event.parsed_fields || {}, null, 2)}</pre>
    </div>
  );
}

export default function Logs() {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [file, setFile] = useState(null);
  const [selected, setSelected] = useState(null);
  const [searchParams] = useSearchParams();
  const { can } = usePermissions();
  const queryClient = useQueryClient();

  // Deep link from Alerts/Incidents ("View Event") — jump straight to that
  // event's detail panel.
  useEffect(() => {
    const eventId = searchParams.get("event");
    if (eventId) {
      getLog(eventId).then(setSelected).catch(() => {});
    }
  }, [searchParams]);

  const filters = {
    q: search || undefined,
    category: category || undefined,
    severity: severity || undefined,
    per_page: 50,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["logs", filters],
    queryFn: () => getLogs(filters),
  });

  const uploadMutation = useMutation({
    mutationFn: (formData) => uploadLogs(formData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["logs"] });
      setFile(null);
    },
  });

  const handleUpload = () => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    uploadMutation.mutate(formData);
  };

  return (
    <div>
      <h2>Log Explorer</h2>

      {can("logs.upload") && (
        <div className="panel">
          <h3>Upload Log File</h3>
          <input type="file" onChange={(e) => setFile(e.target.files[0])} />
          <button onClick={handleUpload} disabled={!file || uploadMutation.isPending}>
            {uploadMutation.isPending ? "Uploading…" : "Upload"}
          </button>
          {uploadMutation.isSuccess && (
            <span>
              {" "}Ingested {uploadMutation.data.stored} of {uploadMutation.data.total_lines} lines
              ({uploadMutation.data.failed} failed to parse).
            </span>
          )}
        </div>
      )}

      <div className="filter-bar">
        <input
          className="search-input"
          placeholder="Search raw log messages…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          <option value="authentication">Authentication</option>
          <option value="web">Web</option>
          <option value="application">Application</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}

      {isLoading ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th><th>Severity</th><th>Event Type</th><th>Category</th>
              <th>Source</th><th>Source IP</th><th>Username</th><th>Hostname</th><th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((event) => (
              <tr key={event.id} className="clickable-row" onClick={() => setSelected(event)}>
                <td>{new Date(event.timestamp).toLocaleString()}</td>
                <td>
                  <span className="severity-dot" style={{ background: SEVERITY_COLORS[event.severity] }} />
                  {event.severity}
                </td>
                <td>{event.event_type}</td>
                <td>{event.category}</td>
                <td>{event.source_type}</td>
                <td>{event.source_ip || "—"}</td>
                <td>{event.username || "—"}</td>
                <td>{event.hostname || "—"}</td>
                <td>{event.outcome || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
