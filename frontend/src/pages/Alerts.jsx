import { useState, Fragment } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getAlerts, updateAlert, runDetection, getMlStatus, trainModel } from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";
import { useRealtime } from "../hooks/useRealtime.js";
import EnrichmentPanel from "../components/EnrichmentPanel.jsx";

const SEVERITY_COLORS = { info: "#4f8cff", warning: "#f5a623", critical: "#e6493d" };

function MlPanel() {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const { data: mlStatus } = useQuery({ queryKey: ["ml-status"], queryFn: getMlStatus });

  const trainMutation = useMutation({
    mutationFn: () => trainModel(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["ml-status"] }),
  });

  return (
    <div className="panel">
      <div className="page-header">
        <h3>ML Anomaly Detection (Isolation Forest)</h3>
        {can("ml.train") && (
          <button onClick={() => trainMutation.mutate()} disabled={trainMutation.isPending}>
            {trainMutation.isPending ? "Training…" : mlStatus?.trained ? "Retrain Model" : "Train Model"}
          </button>
        )}
      </div>

      {mlStatus?.trained ? (
        <p className="ml-status-line">
          Trained on <strong>{mlStatus.training_samples}</strong> activity buckets,
          last trained {new Date(mlStatus.trained_at).toLocaleString()}.
          Scoring runs automatically alongside rule-based detection.
        </p>
      ) : (
        <p className="ml-status-line">
          No model trained yet.{can("ml.train") && " Ingest some logs, then click \"Train Model\" to learn a baseline of normal traffic per source IP — new alerts will flag activity that doesn't fit that baseline."}
        </p>
      )}

      {trainMutation.data && !trainMutation.data.trained && (
        <p className="ml-status-line ml-warning">{trainMutation.data.reason}</p>
      )}
    </div>
  );
}

export default function Alerts() {
  const [status, setStatus] = useState("open");
  const [expandedId, setExpandedId] = useState(null);
  const { can } = usePermissions();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["alerts", status],
    queryFn: () => getAlerts({ status: status || undefined }),
  });

  const mutation = useMutation({
    mutationFn: ({ id, data }) => updateAlert(id, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });

  const detectionMutation = useMutation({
    mutationFn: runDetection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["ml-status"] });
    },
  });

  // New/changed alerts can shift which rows belong in the currently
  // selected status filter, so this invalidates rather than patching the
  // cache directly (Part 14's guidance for relationship-sensitive updates).
  const invalidateAlerts = () => queryClient.invalidateQueries({ queryKey: ["alerts"] });
  useRealtime("alert.created", invalidateAlerts);
  useRealtime("alert.updated", invalidateAlerts);

  return (
    <div>
      <div className="page-header">
        <h2>Alerts</h2>
        {can("detection.run") && (
          <button onClick={() => detectionMutation.mutate()} disabled={detectionMutation.isPending}>
            {detectionMutation.isPending ? "Running…" : "Run Detection Now"}
          </button>
        )}
      </div>

      <MlPanel />

      <div className="filter-bar">
        {["open", "acknowledged", "resolved", ""].map((s) => (
          <button
            key={s || "all"}
            className={status === s ? "active" : ""}
            onClick={() => setStatus(s)}
          >
            {s || "all"}
          </button>
        ))}
      </div>

      {isLoading ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th><th>Rule</th><th>Description</th><th>Created</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {(data?.items ?? []).map((alert) => {
              const isMl = alert.detection_source === "ml";
              const hasEnrichment = (alert.mitre?.length > 0) || (alert.ioc_matches?.length > 0);
              const isExpanded = expandedId === alert.id;
              return (
                <Fragment key={alert.id}>
                  <tr>
                    <td>
                      <span
                        className="severity-dot"
                        style={{ background: SEVERITY_COLORS[alert.severity] }}
                      />
                      {alert.severity}
                    </td>
                    <td>
                      {isMl && <span className="ml-badge">ML</span>}
                      <button
                        className="expand-toggle"
                        onClick={() => setExpandedId(isExpanded ? null : alert.id)}
                      >
                        {alert.title || alert.rule_name} {isExpanded ? "▾" : "▸"}
                      </button>
                      {hasEnrichment && !isExpanded && (
                        <span className="ioc-meta"> (enrichment available)</span>
                      )}
                    </td>
                    <td>
                      {alert.description}
                      {isMl && alert.anomaly_score !== null && alert.anomaly_score !== undefined && (
                        <div className="ml-score">score: {alert.anomaly_score}</div>
                      )}
                    </td>
                    <td>{new Date(alert.created_at).toLocaleString()}</td>
                    <td>{alert.status}</td>
                    <td className="row-actions">
                      {alert.status === "open" && can("alerts.acknowledge") && (
                        <button
                          onClick={() => mutation.mutate({ id: alert.id, data: { status: "acknowledged" } })}
                        >
                          Acknowledge
                        </button>
                      )}
                      {alert.status !== "resolved" && can("alerts.resolve") && (
                        <button
                          onClick={() => mutation.mutate({ id: alert.id, data: { status: "resolved" } })}
                        >
                          Resolve
                        </button>
                      )}
                      {alert.incident_id && (
                        <Link to={`/incidents/${alert.incident_id}`}>View Incident</Link>
                      )}
                      {alert.event_id && (
                        <Link to={`/logs?event=${alert.event_id}`}>View Event</Link>
                      )}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={6}>
                        <EnrichmentPanel
                          mitre={alert.mitre}
                          iocMatches={alert.ioc_matches}
                          risk={alert.risk}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
