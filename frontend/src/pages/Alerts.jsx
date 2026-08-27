import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getAlerts, updateAlert, runDetection, getMlStatus, trainModel } from "../api/client";

const SEVERITY_COLORS = { info: "#4f8cff", warning: "#f5a623", critical: "#e6493d" };

function MlPanel() {
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
        <button onClick={() => trainMutation.mutate()} disabled={trainMutation.isPending}>
          {trainMutation.isPending ? "Training…" : mlStatus?.trained ? "Retrain Model" : "Train Model"}
        </button>
      </div>

      {mlStatus?.trained ? (
        <p className="ml-status-line">
          Trained on <strong>{mlStatus.training_samples}</strong> activity buckets,
          last trained {new Date(mlStatus.trained_at).toLocaleString()}.
          Scoring runs automatically alongside rule-based detection.
        </p>
      ) : (
        <p className="ml-status-line">
          No model trained yet. Ingest some logs, then click "Train Model" to learn a
          baseline of normal traffic per source IP — new alerts will flag activity that
          doesn't fit that baseline.
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

  return (
    <div>
      <div className="page-header">
        <h2>Alerts</h2>
        <button onClick={() => detectionMutation.mutate()} disabled={detectionMutation.isPending}>
          {detectionMutation.isPending ? "Running…" : "Run Detection Now"}
        </button>
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
              const isMl = alert.rule_name === "ml_isolation_forest";
              return (
                <tr key={alert.id}>
                  <td>
                    <span
                      className="severity-dot"
                      style={{ background: SEVERITY_COLORS[alert.severity] }}
                    />
                    {alert.severity}
                  </td>
                  <td>
                    {isMl && <span className="ml-badge">ML</span>}
                    {alert.rule_name}
                  </td>
                  <td>
                    {alert.description}
                    {isMl && alert.context?.anomaly_score !== undefined && (
                      <div className="ml-score">score: {alert.context.anomaly_score}</div>
                    )}
                  </td>
                  <td>{new Date(alert.created_at).toLocaleString()}</td>
                  <td>{alert.status}</td>
                  <td>
                    {alert.status !== "resolved" && (
                      <button
                        onClick={() => mutation.mutate({ id: alert.id, data: { status: "resolved" } })}
                      >
                        Resolve
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
