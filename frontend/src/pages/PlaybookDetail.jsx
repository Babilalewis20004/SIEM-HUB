import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getPlaybook, getPlaybookActions, executePlaybook, getPlaybookExecutions,
} from "../api/client";
import { usePermissions } from "../context/PermissionContext.jsx";

export default function PlaybookDetail() {
  const { id } = useParams();
  const { can } = usePermissions();
  const queryClient = useQueryClient();

  const { data: playbook, isLoading } = useQuery({ queryKey: ["playbook", id], queryFn: () => getPlaybook(id) });
  const { data: actions } = useQuery({ queryKey: ["playbook-actions"], queryFn: getPlaybookActions });
  const { data: executions } = useQuery({
    queryKey: ["playbook-executions", { playbook_id: id }],
    queryFn: () => getPlaybookExecutions({ playbook_id: id, per_page: 10 }),
  });

  const executeMutation = useMutation({
    mutationFn: () => executePlaybook(id, { mode: "manual" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["playbook-executions"] }),
  });

  if (isLoading || !playbook) return <p>Loading…</p>;

  const actionSpec = (name) => (actions ?? []).find((a) => a.name === name);

  return (
    <div>
      <div className="page-header">
        <h2>{playbook.title || playbook.name}</h2>
        {can("playbooks.execute") && playbook.trigger_type === "manual" && (
          <button onClick={() => executeMutation.mutate()} disabled={executeMutation.isPending || !playbook.enabled}>
            {executeMutation.isPending ? "Running…" : "Execute"}
          </button>
        )}
      </div>

      <div className="panel">
        <dl className="detail-grid">
          <dt>Trigger</dt><dd>{playbook.trigger_type}</dd>
          <dt>Condition</dt><dd><code>{JSON.stringify(playbook.trigger_condition)}</code></dd>
          <dt>Status</dt>
          <dd><span className={`pill ${playbook.enabled ? "pill-active" : "pill-inactive"}`}>
            {playbook.enabled ? "Enabled" : "Disabled"}
          </span></dd>
        </dl>
        {playbook.description && <p>{playbook.description}</p>}
      </div>

      <div className="panel">
        <h3>Steps</h3>
        <ol className="playbook-step-list">
          {playbook.steps.map((step, i) => {
            const spec = actionSpec(step.action);
            const requiresApproval = spec?.risk_level === "high" || spec?.risk_level === "critical" || step.approval_required;
            return (
              <li key={i}>
                <strong>{step.action}</strong>
                {spec && <span className={`risk-badge risk-${spec.risk_level}`} style={{ marginLeft: 8 }}>{spec.risk_level}</span>}
                {requiresApproval && <em> — requires approval</em>}
                <div className="ml-status-line">{JSON.stringify(step.parameters ?? {})}</div>
              </li>
            );
          })}
        </ol>
      </div>

      <div className="panel">
        <h3>Recent Executions</h3>
        {(executions?.items ?? []).length === 0 ? (
          <p>No executions yet.</p>
        ) : (
          <table className="data-table">
            <thead><tr><th>Started</th><th>Status</th><th>Mode</th><th></th></tr></thead>
            <tbody>
              {executions.items.map((ex) => (
                <tr key={ex.id}>
                  <td>{ex.started_at ? new Date(ex.started_at).toLocaleString() : "—"}</td>
                  <td>{ex.status}</td>
                  <td>{ex.mode}</td>
                  <td>
                    {ex.incident_id && <Link to={`/incidents/${ex.incident_id}`}>View Incident</Link>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
