import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getLogs, getGroupedLogs, getLog, uploadLogs } from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";

const SEVERITY_COLORS = {
  info: "#4f8cff",
  low: "#f5a623",
  medium: "#f5a623",
  high: "#e6493d",
  critical: "#e6493d",
};

// Mirrors backend GROUPABLE_FIELDS (app/routes/logs.py) -- kept as a small
// hand-written list here rather than fetched, same as the category/severity
// <select> options below.
const GROUP_BY_OPTIONS = [
  { value: "", label: "No grouping" },
  { value: "source_ip", label: "Source IP" },
  { value: "destination_ip", label: "Destination IP" },
  { value: "username", label: "Username" },
  { value: "hostname", label: "Hostname" },
  { value: "category", label: "Category" },
  { value: "severity", label: "Severity" },
  { value: "event_type", label: "Event Type" },
  { value: "outcome", label: "Outcome" },
  { value: "source_type", label: "Source Type" },
];

const SORTABLE_COLUMNS = [
  { field: "timestamp", label: "Time" },
  { field: "severity", label: "Severity" },
  { field: "event_type", label: "Event Type" },
  { field: "category", label: "Category" },
  { field: "source_type", label: "Source" },
  { field: "source_ip", label: "Source IP" },
  { field: "username", label: "Username" },
  { field: "hostname", label: "Hostname" },
  { field: "outcome", label: "Outcome" },
];

function SeverityDot({ severity }) {
  return <span className="severity-dot" style={{ background: SEVERITY_COLORS[severity] }} />;
}

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
        <dd><SeverityDot severity={event.severity} />{event.severity}</dd>
      </dl>

      <h4>Raw Message</h4>
      <p className="field-caption">The original log line, exactly as ingested.</p>
      <pre className="raw-msg-block">{event.raw_message}</pre>

      <h4>Normalized Fields</h4>
      <p className="field-caption">
        Format-specific data extracted by this event's parser, transformed into a
        common shape by the normalization pipeline (see docs/ARCHITECTURE.md).
      </p>
      <pre className="raw-msg-block">{JSON.stringify(event.parsed_fields || {}, null, 2)}</pre>
    </div>
  );
}

function SortableHeader({ field, label, sortBy, order, onSort }) {
  const active = sortBy === field;
  return (
    <th className="sortable" onClick={() => onSort(field)}>
      {label}{active ? (order === "asc" ? " ▲" : " ▼") : ""}
    </th>
  );
}

function GroupedLogsTable({ groups, groupByLabel, onDrillDown }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>{groupByLabel}</th><th>Count</th><th>Max Severity</th><th>Last Seen</th>
        </tr>
      </thead>
      <tbody>
        {groups.map((g) => (
          <tr key={String(g.key)} className="clickable-row" onClick={() => onDrillDown(g.key)}>
            <td>{g.key ?? "—"}</td>
            <td>{g.count}</td>
            <td><SeverityDot severity={g.max_severity} />{g.max_severity}</td>
            <td>{g.last_seen ? new Date(g.last_seen).toLocaleString() : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Logs() {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [destinationIp, setDestinationIp] = useState("");
  const [hostname, setHostname] = useState("");
  const [username, setUsername] = useState("");
  const [outcome, setOutcome] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [sortBy, setSortBy] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  const [groupBy, setGroupBy] = useState("");
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

  const sharedFilters = {
    q: search || undefined,
    category: category || undefined,
    severity: severity || undefined,
    source_type: sourceType || undefined,
    source_ip: sourceIp || undefined,
    destination_ip: destinationIp || undefined,
    hostname: hostname || undefined,
    username: username || undefined,
    outcome: outcome || undefined,
    start: start || undefined,
    end: end || undefined,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["logs", sharedFilters, sortBy, sortOrder],
    queryFn: () => getLogs({ ...sharedFilters, sort: sortBy, order: sortOrder, per_page: 50 }),
    enabled: !groupBy,
  });

  const { data: groupedData, isLoading: groupedLoading } = useQuery({
    queryKey: ["logs-grouped", sharedFilters, groupBy],
    queryFn: () => getGroupedLogs({ ...sharedFilters, group_by: groupBy, per_page: 100 }),
    enabled: !!groupBy,
  });

  const uploadMutation = useMutation({
    mutationFn: (formData) => uploadLogs(formData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["logs"] });
      queryClient.invalidateQueries({ queryKey: ["logs-grouped"] });
      setFile(null);
    },
  });

  const handleUpload = () => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    uploadMutation.mutate(formData);
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(field);
      setSortOrder("desc");
    }
  };

  // Drill-down: clicking a group row filters straight to that value and
  // drops back to the raw event list, instead of leaving the analyst to
  // re-type the value into a filter field by hand.
  const FIELD_SETTERS = {
    source_ip: setSourceIp,
    destination_ip: setDestinationIp,
    username: setUsername,
    hostname: setHostname,
    category: setCategory,
    severity: setSeverity,
    outcome: setOutcome,
    source_type: setSourceType,
  };
  const handleDrillDown = (key) => {
    const setter = FIELD_SETTERS[groupBy];
    if (setter) setter(key ?? "");
    setGroupBy("");
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

      <input
        className="search-input"
        placeholder="Search raw log messages…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      <div className="filter-bar">
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          <option value="authentication">Authentication</option>
          <option value="web">Web</option>
          <option value="network">Network</option>
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
        <select value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
          <option value="">All sources</option>
          <option value="ssh">SSH</option>
          <option value="nginx">Nginx</option>
          <option value="apache">Apache</option>
          <option value="firewall">Firewall</option>
          <option value="windows_security">Windows Security</option>
          <option value="syslog">Syslog</option>
          <option value="generic">Generic</option>
        </select>
        <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">All outcomes</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
          <option value="blocked">Blocked</option>
          <option value="denied">Denied</option>
          <option value="unknown">Unknown</option>
        </select>
        <input
          type="text" placeholder="Source IP"
          value={sourceIp} onChange={(e) => setSourceIp(e.target.value)}
        />
        <input
          type="text" placeholder="Destination IP"
          value={destinationIp} onChange={(e) => setDestinationIp(e.target.value)}
        />
        <input
          type="text" placeholder="Hostname"
          value={hostname} onChange={(e) => setHostname(e.target.value)}
        />
        <input
          type="text" placeholder="Username"
          value={username} onChange={(e) => setUsername(e.target.value)}
        />
        <label className="filter-datetime">
          From
          <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
        </label>
        <label className="filter-datetime">
          To
          <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
        </label>
        <select value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
          {GROUP_BY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>

      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}

      {groupBy ? (
        groupedLoading ? (
          <p>Loading…</p>
        ) : (
          <>
            <p className="field-caption">
              Grouped by {GROUP_BY_OPTIONS.find((o) => o.value === groupBy)?.label} — click a row to
              filter to just that value.
            </p>
            <GroupedLogsTable
              groups={groupedData?.groups ?? []}
              groupByLabel={GROUP_BY_OPTIONS.find((o) => o.value === groupBy)?.label}
              onDrillDown={handleDrillDown}
            />
          </>
        )
      ) : isLoading ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              {SORTABLE_COLUMNS.map((col) => (
                <SortableHeader
                  key={col.field} field={col.field} label={col.label}
                  sortBy={sortBy} order={sortOrder} onSort={handleSort}
                />
              ))}
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((event) => (
              <tr key={event.id} className="clickable-row" onClick={() => setSelected(event)}>
                <td>{new Date(event.timestamp).toLocaleString()}</td>
                <td><SeverityDot severity={event.severity} />{event.severity}</td>
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
